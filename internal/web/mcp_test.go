package web

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"nori/internal/deploytemplate"
	"nori/internal/docker"
	"nori/internal/mcpauth"
	"nori/internal/store"
)

func TestValidateMCPServiceRejectsInvalidTemplateServiceName(t *testing.T) {
	svc := &store.Service{
		Name:           strings.Repeat("a", 64),
		WatchedImage:   "ghcr.io/acme/api:latest",
		Policy:         store.PolicyManual,
		DeploymentMode: store.DeploymentModeSingleContainer,
		TemplateConfig: `{"version":1,"internal_port":8080,"restart_policy":"always","health":{"command":"true","timeout_seconds":5}}`,
	}
	env := ""
	if err := validateMCPService(context.Background(), svc, &env); err == nil || !strings.Contains(err.Error(), "template service name") {
		t.Fatalf("expected template service name validation error, got %v", err)
	}
}

func TestMCPServiceLifecycleAndScopes(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(filepath.Join(t.TempDir(), "mcp.db"), make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	dk := &docker.Fake{Containers: map[string][]docker.Container{"app": {{ID: "c1", State: "running"}}}}
	s := &Server{store: st, docker: dk}
	handler := s.newMCPHandler()
	var scopes atomic.Value
	scopes.Store("nori:read nori:write nori:secrets")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handler.ServeHTTP(w, r.WithContext(mcpauth.WithIdentity(r.Context(), mcpauth.Identity{ClientID: "test", Scope: scopes.Load().(string)})))
	}))
	defer srv.Close()
	client := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "1"}, nil)
	session, err := client.Connect(ctx, &mcp.StreamableClientTransport{Endpoint: srv.URL}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	listed, err := session.ListTools(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(listed.Tools) != 16 {
		t.Fatalf("tools=%d", len(listed.Tools))
	}
	call := func(name string, args map[string]any, wantError bool) *mcp.CallToolResult {
		t.Helper()
		res, err := session.CallTool(ctx, &mcp.CallToolParams{Name: name, Arguments: args})
		if err != nil {
			t.Fatal(err)
		}
		if res.IsError != wantError {
			t.Fatalf("%s error=%t result=%+v", name, res.IsError, res)
		}
		return res
	}
	call("create_service", map[string]any{"name": "app", "watched_image": "nginx:latest", "deploy_script": "echo ok", "env_file": "SECRET='[REDACTED]'"}, false)
	svc, err := st.GetServiceByName(ctx, "app")
	if err != nil {
		t.Fatal(err)
	}
	args := map[string]any{"service_id": svc.ID}
	call("set_service_secret", map[string]any{"service_id": svc.ID, "key": "SECRET", "value": "unlisted"}, false)
	call("set_service_secret", map[string]any{"service_id": svc.ID, "key": "UNKNOWN", "value": "never-echo"}, true)
	call("update_service", map[string]any{"service_id": svc.ID, "env_file": "SECRET=plaintext"}, true)
	call("set_service_environment", map[string]any{"service_id": svc.ID, "env_file": "SECRET=plaintext"}, true)
	for _, name := range []string{"list_services", "get_service"} {
		a := args
		if name == "list_services" {
			a = map[string]any{}
		}
		res := call(name, a, false)
		data, _ := json.Marshal(res)
		if bytes.Contains(data, []byte("unlisted")) {
			t.Fatal("environment leaked")
		}
	}
	call("update_service", map[string]any{"service_id": svc.ID, "health_url": "https://example.com/health"}, false)
	got, _ := st.GetService(ctx, svc.ID)
	if got.DeployScript != "echo ok" || got.WatchedImage != "nginx:latest" {
		t.Fatal("partial update lost fields")
	}
	env, _ := st.GetEnvFile(ctx, svc.ID)
	if env != "SECRET=\"unlisted\"\n" {
		t.Fatal("partial update lost environment")
	}
	call("stop_service", args, false)
	if dk.Containers["app"][0].State != "exited" {
		t.Fatal("container not stopped")
	}
	call("start_service", args, false)
	if dk.Containers["app"][0].State != "running" {
		t.Fatal("container not started")
	}
	call("start_service", map[string]any{"service_id": 999}, true)
	call("get_container_logs", map[string]any{"service_id": svc.ID, "container_id": "another-service"}, true)
	d := &store.Deployment{ServiceID: svc.ID, Trigger: store.TriggerManual, Status: store.DeployRunning, Log: "sensitive-log-output unlisted"}
	if err := st.CreateDeployment(ctx, d); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"list_deployments", "get_deployment"} {
		a := args
		if name == "get_deployment" {
			a = map[string]any{"deployment_id": d.ID}
		}
		res := call(name, a, false)
		data, _ := json.Marshal(res)
		if bytes.Contains(data, []byte("sensitive-log-output")) {
			t.Fatal("logs returned without explicit request")
		}
	}
	logResult := call("get_deployment", map[string]any{"deployment_id": d.ID, "include_logs": true}, false)
	logJSON, _ := json.Marshal(logResult)
	if bytes.Contains(logJSON, []byte("unlisted")) || !bytes.Contains(logJSON, []byte("[REDACTED]")) {
		t.Fatal("deployment log exposed secret")
	}
	if !bytes.Contains(logJSON, []byte("sensitive-log-output")) {
		t.Fatal("explicit logs missing")
	}

	// Both text and structured content must be redacted, including values from
	// other services and secrets split by the byte limit.
	other := &store.Service{Name: "other", WatchedImage: "nginx", Policy: store.PolicyManual}
	if err := st.CreateService(ctx, other); err != nil {
		t.Fatal(err)
	}
	if err := st.SetEnvFile(ctx, other.ID, "TOKEN=cross-service-secret"); err != nil {
		t.Fatal(err)
	}
	dk.LogData = map[string]string{"c1": "unlisted cross-service-secret"}
	res := call("get_container_logs", map[string]any{"service_id": svc.ID, "container_id": "c1"}, false)
	raw, _ := json.Marshal(res)
	if bytes.Contains(raw, []byte("unlisted")) || bytes.Contains(raw, []byte("cross-service-secret")) || !bytes.Contains(raw, []byte("[REDACTED]")) {
		t.Fatal("container logs leaked values")
	}
	if err := st.SetEnvFile(ctx, other.ID, "TOKEN=cross-service-secret\nMULTILINE='first-line\nsecond-line'"); err != nil {
		t.Fatal(err)
	}
	// Model Docker's tail=1 response: the preceding secret line is already gone.
	dk.LogData["c1"] = "second-line\n"
	res = call("get_container_logs", map[string]any{"service_id": svc.ID, "container_id": "c1", "tail": 1}, false)
	raw, _ = json.Marshal(res)
	if bytes.Contains(raw, []byte("second-line")) {
		t.Fatal("Docker line tail exposed multiline secret suffix")
	}
	dk.LogData["c1"] = strings.Repeat("x", mcpLogLimit-3) + "unlisted suffix"
	res = call("get_container_logs", map[string]any{"service_id": svc.ID, "container_id": "c1"}, false)
	structured := res.StructuredContent.(map[string]any)
	if strings.Contains(structured["logs"].(string), "unl") || len(structured["logs"].(string)) > mcpLogLimit || structured["truncated"] != true {
		t.Fatal("container log truncation leaked secret prefix")
	}
	boundary := &store.Deployment{ServiceID: svc.ID, Trigger: store.TriggerManual, Status: store.DeployRunning, Log: "unlisted" + strings.Repeat("x", mcpLogLimit-3)}
	if err := st.CreateDeployment(ctx, boundary); err != nil {
		t.Fatal(err)
	}
	res = call("get_deployment", map[string]any{"deployment_id": boundary.ID, "include_logs": true}, false)
	structured = res.StructuredContent.(map[string]any)
	logText := structured["deployment"].(map[string]any)["Log"].(string)
	if strings.Contains(logText, "ted") || len(logText) > mcpLogLimit || structured["logs_truncated"] != true {
		t.Fatal("deployment log truncation leaked secret suffix")
	}
	// Unknown values are not heuristically censored; the guarantee is known
	// dotenv values. If decryption fails, fail closed instead of exposing logs.
	dk.LogData["c1"] = "unlisted"
	if err := st.SetEnvFile(ctx, other.ID, "INVALID"); err != nil {
		t.Fatal(err)
	}
	call("get_container_logs", map[string]any{"service_id": svc.ID, "container_id": "c1"}, true)
	if err := st.SetEnvFile(ctx, other.ID, "TOKEN=cross-service-secret"); err != nil {
		t.Fatal(err)
	}

	dk.LogData["c1"] = "newly-rotated-secret"
	s.docker = &mcpUpdatingDocker{Fake: dk, beforeLogs: func() error {
		return st.SetEnvSecret(ctx, svc.ID, "SECRET", "newly-rotated-secret")
	}}
	res = call("get_container_logs", map[string]any{"service_id": svc.ID, "container_id": "c1"}, false)
	raw, _ = json.Marshal(res)
	if bytes.Contains(raw, []byte("newly-rotated-secret")) {
		t.Fatal("secret rotated during log read leaked")
	}
	if err := st.SetEnvSecret(ctx, svc.ID, "SECRET", "unlisted"); err != nil {
		t.Fatal(err)
	}
	longer := strings.Repeat("long-new-secret", 10)
	dk.LogData["c1"] = strings.Repeat("x", mcpLogLimit-3) + longer
	s.docker = &mcpUpdatingDocker{Fake: dk, beforeLogs: func() error {
		return st.SetEnvSecret(ctx, svc.ID, "SECRET", longer)
	}}
	call("get_container_logs", map[string]any{"service_id": svc.ID, "container_id": "c1"}, true)
	s.docker = dk
	if err := st.SetEnvSecret(ctx, svc.ID, "SECRET", "unlisted"); err != nil {
		t.Fatal(err)
	}

	scopes.Store("nori:read")
	call("get_service_environment", args, false)
	call("set_service_secret", map[string]any{"service_id": svc.ID, "key": "SECRET", "value": "forbidden"}, true)
	call("delete_service", args, true)
	scopes.Store("nori:read nori:secrets")
	res = call("get_service_environment", args, false)
	data, _ := json.Marshal(res)
	if bytes.Contains(data, []byte("unlisted")) || !bytes.Contains(data, []byte("[REDACTED]")) {
		t.Fatal("environment must only expose placeholders")
	}
	scopes.Store("nori:read nori:write")
	call("set_service_secret", map[string]any{"service_id": svc.ID, "key": "SECRET", "value": "forbidden"}, true)
	scopes.Store("nori:read nori:write nori:secrets")
	self, err := st.EnsureSelfService(ctx, "nginx:latest")
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"delete_service", "start_service", "stop_service", "deploy_service"} {
		call(name, map[string]any{"service_id": self.ID}, true)
	}
	call("set_service_secret", map[string]any{"service_id": self.ID, "key": "SECRET", "value": "forbidden"}, true)
	call("get_service_environment", map[string]any{"service_id": self.ID}, true)
	call("update_service", map[string]any{"service_id": self.ID, "deploy_script": "echo unsafe"}, true)
	call("set_service_environment", map[string]any{"service_id": self.ID, "env_file": "A=B"}, true)
	call("set_service_environment", map[string]any{"service_id": svc.ID, "env_file": "NEW='[REDACTED]'"}, false)
	call("delete_service", args, false)
	if _, err := st.GetService(ctx, svc.ID); err != store.ErrNotFound {
		t.Fatalf("not deleted: %v", err)
	}
}

func TestMCPTemplateConfigurationUsesSharedValidation(t *testing.T) {
	svc := &store.Service{Name: "api", WatchedImage: "ghcr.io/acme/api:latest", Policy: store.PolicyManual}
	config := &deploytemplate.Config{
		Version: 1, InternalPort: 8080, RestartPolicy: deploytemplate.RestartAlways,
		Health: deploytemplate.HealthCheck{Command: "true", TimeoutSeconds: 5},
	}
	if err := setMCPDeploymentTemplate(svc, string(store.DeploymentModeSingleContainer), config); err != nil {
		t.Fatal(err)
	}
	env := "PORT='[REDACTED]'\n"
	if err := validateMCPService(context.Background(), svc, &env); err != nil {
		t.Fatalf("valid template MCP input rejected: %v", err)
	}
	if svc.DeploymentMode != store.DeploymentModeSingleContainer || !strings.Contains(svc.TemplateConfig, `"internal_port":8080`) {
		t.Fatalf("template configuration was not normalized: %+v", svc)
	}
	if svc.DeployScript != "" {
		t.Fatalf("template service should not require a Custom script, got %q", svc.DeployScript)
	}
	if err := setMCPDeploymentTemplate(svc, string(store.DeploymentModeCustom), config); err == nil {
		t.Fatal("template configuration must not be accepted for Custom deployment mode")
	}

	if err := setMCPDeploymentTemplate(svc, string(store.DeploymentModePostgres), &deploytemplate.Config{
		Version: 1, InternalPort: 8080, RestartPolicy: deploytemplate.RestartAlways,
		Health:   deploytemplate.HealthCheck{Command: "true", TimeoutSeconds: 5},
		Postgres: &deploytemplate.PostgresConfig{Image: "postgres:latest"},
	}); err == nil {
		t.Fatal("mutable PostgreSQL image must be rejected through MCP too")
	}
}

// A short dotenv value occurring inside a container ID must not destroy the
// identifiers clients need to request logs, and get_container_logs must accept
// an exact container name resolved against the service's own containers.
func TestMCPContainerLogsIdentification(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(filepath.Join(t.TempDir(), "mcp-ident.db"), make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	app := &store.Service{Name: "abc-app", WatchedImage: "nginx", Policy: store.PolicyManual}
	if err := st.CreateService(ctx, app); err != nil {
		t.Fatal(err)
	}
	if err := st.SetEnvFile(ctx, app.ID, "TOKEN=abc"); err != nil {
		t.Fatal(err)
	}
	if err := st.CreateService(ctx, &store.Service{Name: "other", WatchedImage: "nginx", Policy: store.PolicyManual}); err != nil {
		t.Fatal(err)
	}
	dk := &docker.Fake{
		Containers: map[string][]docker.Container{
			"abc-app": {
				{ID: "abc123fullid", Name: "abc-web", Image: "registry.example/abc-image:1", State: "running"},
				{ID: "worker456id", Name: "plain-worker", State: "running"},
			},
			"other": {{ID: "zzz999zzz", Name: "other-web", State: "running"}},
		},
		LogData: map[string]string{
			"abc123fullid": "hello abc world",
			"worker456id":  "worker log",
			"zzz999zzz":    "other log",
		},
	}
	s := &Server{store: st, docker: dk}
	handler := s.newMCPHandler()
	var scopes atomic.Value
	scopes.Store("nori:read")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handler.ServeHTTP(w, r.WithContext(mcpauth.WithIdentity(r.Context(), mcpauth.Identity{ClientID: "test", Scope: scopes.Load().(string)})))
	}))
	defer srv.Close()
	client := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "1"}, nil)
	session, err := client.Connect(ctx, &mcp.StreamableClientTransport{Endpoint: srv.URL}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	call := func(name string, args map[string]any) (*mcp.CallToolResult, bool) {
		t.Helper()
		res, err := session.CallTool(ctx, &mcp.CallToolParams{Name: name, Arguments: args})
		if err != nil {
			t.Fatal(err)
		}
		return res, res.IsError
	}

	res, isErr := call("get_service", map[string]any{"service_id": app.ID})
	if isErr {
		t.Fatalf("get_service: %+v", res)
	}
	containers := res.StructuredContent.(map[string]any)["containers"].([]any)
	first := containers[0].(map[string]any)
	if first["ID"] != "abc123fullid" || first["Name"] != "abc-web" {
		t.Fatalf("container identifiers redacted: %+v", first)
	}
	// The exemption covers only container ID/Name/Digest: other container
	// fields and the service itself stay redacted.
	if first["Image"] != "registry.example/[REDACTED]-image:1" {
		t.Fatalf("container image not redacted: %+v", first)
	}
	service := res.StructuredContent.(map[string]any)["service"].(map[string]any)
	if service["Name"] != "[REDACTED]-app" {
		t.Fatalf("service name not redacted: %+v", service)
	}

	res, isErr = call("get_container_logs", map[string]any{"service_id": app.ID, "container_name": "plain-worker"})
	if isErr {
		t.Fatalf("logs by container name: %+v", res)
	}
	if logs := res.StructuredContent.(map[string]any)["logs"]; logs != "worker log" {
		t.Fatalf("wrong container logs: %q", logs)
	}
	res, isErr = call("get_container_logs", map[string]any{"service_id": app.ID, "container_name": "abc-web"})
	if isErr {
		t.Fatalf("logs by redacted-value name: %+v", res)
	}
	logs := res.StructuredContent.(map[string]any)["logs"].(string)
	if strings.Contains(logs, "abc") || !strings.Contains(logs, "[REDACTED]") || !strings.Contains(logs, "hello") {
		t.Fatalf("logs by name exposed env value: %q", logs)
	}

	if _, isErr := call("get_container_logs", map[string]any{"service_id": app.ID, "container_name": "other-web", "container_id": "abc123fullid"}); !isErr {
		t.Fatal("foreign container name accepted")
	}
	if _, isErr := call("get_container_logs", map[string]any{"service_id": app.ID, "container_name": "no-such"}); !isErr {
		t.Fatal("unknown container name accepted")
	}
	if _, isErr := call("get_container_logs", map[string]any{"service_id": app.ID}); !isErr {
		t.Fatal("missing container identifier accepted")
	}
	res, isErr = call("get_container_logs", map[string]any{"service_id": app.ID, "container_id": "abc123fullid"})
	if isErr {
		t.Fatalf("logs by container id: %+v", res)
	}
	logs = res.StructuredContent.(map[string]any)["logs"].(string)
	if strings.Contains(logs, "abc") || !strings.Contains(logs, "[REDACTED]") {
		t.Fatalf("logs by id exposed env value: %q", logs)
	}
}

func TestValidateMCPService(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*store.Service)
	}{
		{"name", func(s *store.Service) { s.Name = "../bad" }},
		{"reserved", func(s *store.Service) { s.Name = store.SelfServiceName }},
		{"image", func(s *store.Service) { s.WatchedImage = "not an image" }},
		{"policy", func(s *store.Service) { s.Policy = "unknown" }},
		{"cron", func(s *store.Service) { s.Policy = store.PolicyScheduled; s.CronExpr = "bad" }},
		{"script", func(s *store.Service) { s.DeployScript = "if" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			svc := &store.Service{Name: "app", WatchedImage: "nginx", Policy: store.PolicyManual, DeployScript: "true"}
			tc.change(svc)
			if err := validateMCPService(context.Background(), svc, nil); err == nil {
				t.Fatal("accepted invalid config")
			}
		})
	}
}

// Mutate between the tool's initial snapshot and receipt of external log data.
type mcpUpdatingDocker struct {
	*docker.Fake
	beforeLogs func() error
}

func (d *mcpUpdatingDocker) Logs(ctx context.Context, id string, tail int) (io.ReadCloser, error) {
	if err := d.beforeLogs(); err != nil {
		return nil, err
	}
	return d.Fake.Logs(ctx, id, tail)
}
