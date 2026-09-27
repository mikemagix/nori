package web

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/distribution/reference"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/robfig/cron/v3"
	"nori/internal/docker"
	"nori/internal/envfile"
	"nori/internal/executor"
	"nori/internal/mcpauth"
	"nori/internal/store"
)

const mcpLogLimit = 256 * 1024

type mcpID struct {
	ServiceID int64 `json:"service_id" jsonschema:"Service ID"`
}
type mcpCreate struct {
	Name         string  `json:"name"`
	WatchedImage string  `json:"watched_image"`
	DeployScript string  `json:"deploy_script"`
	Policy       string  `json:"policy,omitempty"`
	CronExpr     string  `json:"cron_expr,omitempty"`
	HealthURL    string  `json:"health_url,omitempty"`
	EnvFile      *string `json:"env_file,omitempty" jsonschema:"Dotenv template: every value must be [REDACTED]; insert values with set_service_secret"`
}
type mcpUpdate struct {
	ServiceID             int64   `json:"service_id"`
	ExpectedConfigVersion int64   `json:"expected_config_version" jsonschema:"Configuration generation returned by get_service; required for updates"`
	WatchedImage          *string `json:"watched_image,omitempty"`
	DeployScript          *string `json:"deploy_script,omitempty"`
	Policy                *string `json:"policy,omitempty"`
	CronExpr              *string `json:"cron_expr,omitempty"`
	HealthURL             *string `json:"health_url,omitempty"`
	EnvFile               *string `json:"env_file,omitempty" jsonschema:"Dotenv template: every value must be [REDACTED]; omitted keys are removed; insert values with set_service_secret"`
}
type mcpHistory struct {
	ServiceID int64 `json:"service_id"`
	Limit     int   `json:"limit,omitempty" jsonschema:"Maximum deployments, defaults to 20, at most 100"`
}
type mcpDeployment struct {
	DeploymentID int64 `json:"deployment_id"`
	IncludeLogs  bool  `json:"include_logs,omitempty" jsonschema:"Include logs with known dotenv values redacted"`
}
type mcpLogs struct {
	ServiceID     int64  `json:"service_id"`
	ContainerID   string `json:"container_id,omitempty" jsonschema:"Container ID belonging to this service, as returned by get_service"`
	ContainerName string `json:"container_name,omitempty" jsonschema:"Exact container name belonging to this service; takes precedence over container_id"`
	Tail          int    `json:"tail,omitempty" jsonschema:"Lines, defaults to 100, maximum 1000"`
}
type mcpSecret struct {
	ServiceID             int64  `json:"service_id"`
	ExpectedConfigVersion int64  `json:"expected_config_version" jsonschema:"Configuration generation returned by get_service; required for updates"`
	Key                   string `json:"key" jsonschema:"Environment variable name already declared in the service configuration"`
	Value                 string `json:"value" jsonschema:"Literal secret value; never returned"`
}

type mcpEnv struct {
	ServiceID             int64  `json:"service_id"`
	ExpectedConfigVersion int64  `json:"expected_config_version" jsonschema:"Configuration generation returned by get_service; required for updates"`
	EnvFile               string `json:"env_file" jsonschema:"Replacement dotenv template: every value must be [REDACTED]; existing values are preserved by name"`
}

// addNoriTool puts authorization before all tool side effects. The OAuth HTTP
// middleware supplies the authenticated principal on every stateless request.
func addNoriTool[I any](s *Server, server *mcp.Server, name, description, scope string, run func(context.Context, I) (any, error)) {
	mcp.AddTool(server, &mcp.Tool{Name: name, Description: description, Annotations: &mcp.ToolAnnotations{ReadOnlyHint: scope == mcpauth.ScopeRead}}, func(ctx context.Context, _ *mcp.CallToolRequest, in I) (*mcp.CallToolResult, any, error) {
		if err := mcpauth.RequireScope(ctx, scope); err != nil {
			return nil, nil, err
		}
		redactor, err := s.mcpRedactor(ctx)
		if err != nil {
			return nil, nil, errors.New("could not safely read environment values for redaction")
		}
		ctx = context.WithValue(ctx, mcpRedactorKey{}, redactor)
		out, err := run(ctx, in)
		if scope == mcpauth.ScopeWrite {
			identity, _ := mcpauth.FromContext(ctx)
			var serviceID int64
			switch v := any(in).(type) {
			case mcpID:
				serviceID = v.ServiceID
			case mcpUpdate:
				serviceID = v.ServiceID
			case mcpEnv:
				serviceID = v.ServiceID
			case mcpSecret:
				serviceID = v.ServiceID
			}
			log.Printf("mcp: client=%q tool=%s service_id=%d success=%t", identity.ClientID, name, serviceID, err == nil)
		}
		if refreshErr := s.refreshMCPRedactor(ctx); refreshErr != nil {
			return nil, nil, refreshErr
		}
		if err != nil {
			return nil, nil, errors.New(redactor.Redact(err.Error()))
		}
		// This tool constructs its response solely from names and fixed markers.
		if name == "get_service_environment" {
			return nil, out, nil
		}
		// Redact decoded strings, not serialized JSON: quotes/newlines in secrets
		// must match in both the SDK's text and structured response representations.
		data, err := json.Marshal(out)
		if err != nil {
			return nil, nil, errors.New("could not encode tool result")
		}
		var safe any
		decoder := json.NewDecoder(bytes.NewReader(data))
		decoder.UseNumber()
		if err := decoder.Decode(&safe); err != nil {
			return nil, nil, errors.New("could not encode tool result")
		}
		return nil, redactMCPResult(safe, redactor, name == "get_deployment" || name == "get_container_logs"), nil
	})
}

func (s *Server) newMCPHandler() http.Handler {
	server := mcp.NewServer(&mcp.Implementation{Name: "nori", Version: "1.0.0"}, nil)
	addNoriTool(s, server, "list_services", "List service configurations without environment values.", mcpauth.ScopeRead, func(ctx context.Context, _ struct{}) (any, error) { return s.store.ListServices(ctx) })
	addNoriTool(s, server, "get_service", "Get a service configuration and its containers; environment values are redacted except when they are substrings of container IDs, names or digests.", mcpauth.ScopeRead, func(ctx context.Context, in mcpID) (any, error) {
		svc, err := s.mcpService(ctx, in.ServiceID, false)
		if err != nil {
			return nil, err
		}
		containers, err := s.docker.ListByService(ctx, svc.Name)
		if err != nil {
			return nil, err
		}
		return map[string]any{"service": svc, "containers": containers}, nil
	})
	addNoriTool(s, server, "create_service", "Create a service with a Bash deployment script. Scripts execute on the server with Docker access.", mcpauth.ScopeWrite, func(ctx context.Context, in mcpCreate) (any, error) {
		if in.Policy == "" {
			in.Policy = string(store.PolicyManual)
		}
		svc := &store.Service{Name: in.Name, WatchedImage: in.WatchedImage, DeployScript: in.DeployScript, Policy: store.Policy(in.Policy), CronExpr: in.CronExpr, HealthURL: in.HealthURL}
		if _, err := s.saveOrdinaryService(ctx, ordinaryWrite{Service: svc, Environment: in.EnvFile, EnvironmentMode: templateEnvironment}); err != nil {
			var validationErr *ordinaryValidationError
			if errors.As(err, &validationErr) {
				return nil, errors.New("invalid service configuration; check the name, image, policy, schedule, script, health URL, and environment format")
			}
			return nil, errors.New("could not create service; check that its name is unique")
		}
		return svc, nil
	})
	addNoriTool(s, server, "update_service", "Update supplied configuration fields; omitted fields are preserved and names are immutable. Scripts execute on the server with Docker access.", mcpauth.ScopeWrite, func(ctx context.Context, in mcpUpdate) (any, error) {
		if in.ExpectedConfigVersion <= 0 {
			return nil, errors.New("expected_config_version is required")
		}
		svc, err := s.mcpService(ctx, in.ServiceID, true)
		if err != nil {
			return nil, err
		}
		expected := &store.Service{ID: svc.ID, Name: svc.Name, ConfigVersion: in.ExpectedConfigVersion}
		if in.WatchedImage != nil {
			svc.WatchedImage = *in.WatchedImage
		}
		if in.DeployScript != nil {
			svc.DeployScript = *in.DeployScript
		}
		if in.Policy != nil {
			svc.Policy = store.Policy(*in.Policy)
		}
		if in.CronExpr != nil {
			svc.CronExpr = *in.CronExpr
		}
		if in.HealthURL != nil {
			svc.HealthURL = *in.HealthURL
		}
		if _, err := s.saveOrdinaryService(ctx, ordinaryWrite{Service: svc, Previous: expected, Environment: in.EnvFile, EnvironmentMode: templateEnvironment}); err != nil {
			if errors.Is(err, store.ErrServiceConflict) {
				return nil, errors.New("configuration changed; read it again and retry")
			}
			var validationErr *ordinaryValidationError
			if errors.As(err, &validationErr) {
				return nil, errors.New("invalid service configuration; check the image, policy, schedule, script, health URL, and environment format")
			}
			return nil, errors.New("could not update service")
		}
		return svc, nil
	})
	for _, action := range []string{"delete", "start", "stop", "deploy"} {
		addNoriTool(s, server, action+"_service", map[string]string{"delete": "Delete service configuration and deployment history; does not remove containers.", "start": "Start existing containers belonging to a service.", "stop": "Stop all containers belonging to a service.", "deploy": "Run the service deployment script asynchronously; returns deployment ID."}[action], mcpauth.ScopeWrite, func(ctx context.Context, in mcpID) (any, error) {
			svc, err := s.mcpService(ctx, in.ServiceID, true)
			if err != nil {
				return nil, err
			}
			switch action {
			case "delete":
				err = s.store.DeleteService(ctx, svc.ID)
			case "start":
				err = s.docker.StartByService(ctx, svc.Name)
			case "stop":
				err = s.docker.StopByService(ctx, svc.Name)
			case "deploy":
				id, e := s.executor.Deploy(ctx, svc.ID, store.TriggerManual)
				if e != nil {
					return nil, errors.New("deployment could not start")
				}
				return map[string]any{"deployment_id": id}, nil
			}
			if err != nil {
				return nil, fmt.Errorf("could not %s service", action)
			}
			return map[string]any{"service_id": svc.ID, "success": true}, nil
		})
	}
	addNoriTool(s, server, "list_deployments", "Recent deployment metadata without logs.", mcpauth.ScopeRead, func(ctx context.Context, in mcpHistory) (any, error) {
		if _, err := s.mcpService(ctx, in.ServiceID, false); err != nil {
			return nil, err
		}
		if in.Limit == 0 {
			in.Limit = 20
		}
		if in.Limit < 1 || in.Limit > 100 {
			return nil, errors.New("limit must be 1..100")
		}
		return s.store.ListDeploymentSummaries(ctx, in.ServiceID, in.Limit)
	})
	addNoriTool(s, server, "get_deployment", "Deployment details; optional logs redact known dotenv values and are limited to 256 KiB.", mcpauth.ScopeRead, func(ctx context.Context, in mcpDeployment) (any, error) {
		if in.DeploymentID <= 0 {
			return nil, errors.New("invalid deployment_id")
		}
		limit := 0
		if in.IncludeLogs {
			limit = mcpLogLimit + max(1, mcpLogRedactor(ctx).MaxLen)
		}
		d, err := s.store.GetDeploymentWithLogLimit(ctx, in.DeploymentID, limit)
		if err != nil {
			return nil, err
		}
		if in.IncludeLogs {
			previousMax := mcpLogRedactor(ctx).MaxLen
			if err := s.refreshMCPRedactor(ctx); err != nil {
				return nil, err
			}
			if mcpLogRedactor(ctx).MaxLen > previousMax && len(d.Log) == limit {
				return nil, errors.New("environment changed during log read; retry")
			}
		}
		truncated := false
		if !in.IncludeLogs {
			d.Log = ""
		} else {
			truncated = len(d.Log) > mcpLogLimit
			d.Log = mcpLogRedactor(ctx).Window(d.Log, max(0, len(d.Log)-mcpLogLimit), len(d.Log))
			if len(d.Log) > mcpLogLimit {
				d.Log = d.Log[len(d.Log)-mcpLogLimit:]
				truncated = true
			}
		}
		return map[string]any{"deployment": d, "logs_truncated": truncated}, nil
	})
	addNoriTool(s, server, "get_container_logs", "Read bounded container logs with known dotenv values redacted. Identify the container with container_name or container_id. Maximum 1000 lines and 256 KiB.", mcpauth.ScopeRead, func(ctx context.Context, in mcpLogs) (any, error) {
		svc, err := s.mcpService(ctx, in.ServiceID, false)
		if err != nil {
			return nil, err
		}
		if in.Tail == 0 {
			in.Tail = 100
		}
		if in.Tail < 1 || in.Tail > 1000 {
			return nil, errors.New("tail must be 1..1000")
		}
		ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
		defer cancel()
		cs, err := s.docker.ListByService(ctx, svc.Name)
		if err != nil {
			return nil, errors.New("could not list containers")
		}
		var id string
		switch {
		case in.ContainerName != "":
			for _, c := range cs {
				if c.Name == in.ContainerName {
					id = c.ID
					break
				}
			}
		case in.ContainerID != "":
			for _, c := range cs {
				if c.ID == in.ContainerID {
					id = c.ID
					break
				}
			}
		default:
			return nil, errors.New("container_id or container_name is required")
		}
		if id == "" {
			return nil, errors.New("container does not belong to this service")
		}
		rc, err := s.docker.Logs(ctx, id, in.Tail)
		if err != nil {
			return nil, errors.New("could not read container logs")
		}
		defer rc.Close()
		output, truncated, err := docker.ReadLogsBounded(rc, mcpLogLimit+max(1, mcpLogRedactor(ctx).MaxLen))
		if err != nil {
			return nil, errors.New("could not decode container logs")
		}
		previousMax := mcpLogRedactor(ctx).MaxLen
		if err := s.refreshMCPRedactor(ctx); err != nil {
			return nil, err
		}
		if truncated && mcpLogRedactor(ctx).MaxLen > previousMax {
			return nil, errors.New("environment changed during log read; retry")
		}
		truncated = truncated || len(output) > mcpLogLimit
		output = mcpLogRedactor(ctx).Window(output, 0, min(len(output), mcpLogLimit))
		if len(output) > mcpLogLimit {
			output = output[:mcpLogLimit]
			truncated = true
		}
		return map[string]any{"logs": output, "truncated": truncated}, nil
	})
	addNoriTool(s, server, "get_service_environment", "Read the service dotenv structure with [REDACTED] placeholders for all values. Comments are omitted. Never returns secrets.", mcpauth.ScopeRead, func(ctx context.Context, in mcpID) (any, error) {
		svc, err := s.mcpService(ctx, in.ServiceID, false)
		if err != nil {
			return nil, err
		}
		if svc.IsSelf {
			return nil, errors.New("managed self-service environment is unavailable through MCP")
		}
		env, err := s.store.GetEnvFile(ctx, svc.ID)
		if err != nil {
			return nil, errors.New("could not read environment")
		}
		template, err := envfile.Template(env)
		if err != nil {
			return nil, errors.New("could not read environment structure")
		}
		return map[string]any{"env_file": template}, nil
	})
	addNoriTool(s, server, "set_service_environment", "Replace the dotenv structure using [REDACTED] for every value. Preserves existing values by name; new keys start empty; omitted keys are removed. Use set_service_secret to insert values.", mcpauth.ScopeWrite, func(ctx context.Context, in mcpEnv) (any, error) {
		if in.ExpectedConfigVersion <= 0 {
			return nil, errors.New("expected_config_version is required")
		}
		svc, err := s.mcpService(ctx, in.ServiceID, true)
		if err != nil {
			return nil, err
		}
		in.EnvFile = executor.NormalizeNewlines(in.EnvFile)
		if len(in.EnvFile) > 128*1024 {
			return nil, errors.New("environment must be at most 128 KiB")
		}
		if _, err := envfile.ResolveTemplate("", in.EnvFile); err != nil {
			return nil, err
		}
		version, err := s.store.SetEnvTemplateAtVersion(ctx, svc.ID, in.ExpectedConfigVersion, in.EnvFile)
		if err != nil {
			if errors.Is(err, store.ErrServiceConflict) {
				return nil, errors.New("configuration changed; read it again and retry")
			}
			return nil, errors.New("could not save environment")
		}
		return map[string]any{"service_id": svc.ID, "config_version": version, "success": true}, nil
	})

	addNoriTool(s, server, "set_service_secret", "Set a literal value for an environment variable already declared in the service configuration. Write-only: never reads or returns values. Requires nori:write and nori:secrets.", mcpauth.ScopeWrite, func(ctx context.Context, in mcpSecret) (any, error) {
		if in.ExpectedConfigVersion <= 0 {
			return nil, errors.New("expected_config_version is required")
		}
		if err := mcpauth.RequireScope(ctx, mcpauth.ScopeSecrets); err != nil {
			return nil, err
		}
		svc, err := s.mcpService(ctx, in.ServiceID, true)
		if err != nil {
			return nil, err
		}
		if len(in.Value) > envfile.MaxSize {
			return nil, errors.New("environment value must be at most 128 KiB")
		}
		version, err := s.store.SetEnvSecretAtVersion(ctx, svc.ID, in.ExpectedConfigVersion, in.Key, in.Value)
		if err != nil {
			if errors.Is(err, store.ErrServiceConflict) {
				return nil, errors.New("configuration changed; read it again and retry")
			}
			return nil, errors.New("could not set secret; check the variable exists, its value is valid dotenv, and the environment is at most 128 KiB")
		}
		return map[string]any{"service_id": svc.ID, "config_version": version, "success": true}, nil
	})
	return mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return server }, &mcp.StreamableHTTPOptions{Stateless: true, JSONResponse: true, MaxRequestBodyBytes: 1 << 20})
}

type mcpRedactorKey struct{}

func mcpLogRedactor(ctx context.Context) *envfile.Redactor {
	return ctx.Value(mcpRedactorKey{}).(*envfile.Redactor)
}

func (s *Server) refreshMCPRedactor(ctx context.Context) error {
	current, err := s.mcpRedactor(ctx)
	if err != nil {
		return errors.New("could not safely read environment values for redaction")
	}
	mcpLogRedactor(ctx).Merge(current)
	return nil
}

// Snapshot before mutations so deleted/replaced values cannot leak in a result.
// Include all services: scripts can print another service's environment.
func (s *Server) mcpRedactor(ctx context.Context) (*envfile.Redactor, error) {
	services, err := s.store.ListServices(ctx)
	if err != nil {
		return nil, err
	}
	r := &envfile.Redactor{}
	for _, svc := range services {
		content, err := s.store.GetEnvFile(ctx, svc.ID)
		if err != nil {
			return nil, err
		}
		if err := r.Add(content); err != nil {
			return nil, err
		}
	}
	return r, nil
}

func redactMCPResult(value any, r *envfile.Redactor, logsRedacted bool) any {
	return redactMCPValue(value, r, logsRedacted, false)
}

func redactMCPValue(value any, r *envfile.Redactor, logsRedacted, containers bool) any {
	switch v := value.(type) {
	case string:
		return r.Redact(v)
	case []any:
		for i := range v {
			v[i] = redactMCPValue(v[i], r, logsRedacted, containers)
		}
	case map[string]any:
		for key := range v {
			// Logs have already been redacted with their truncation context.
			if logsRedacted && (key == "Log" || key == "logs") {
				continue
			}
			// Container IDs, names and digests are structural, not secret:
			// redacting them leaves clients unable to address the container in
			// get_container_logs, so they pass through verbatim. Accepted
			// trade-off: an env value that is a substring of an identifier
			// becomes visible inside get_service output.
			if containers && (key == "ID" || key == "Name" || key == "Digest") {
				continue
			}
			v[key] = redactMCPValue(v[key], r, logsRedacted, key == "containers")
		}
	}
	return value
}

func (s *Server) mcpService(ctx context.Context, id int64, mutation bool) (*store.Service, error) {
	if id <= 0 {
		return nil, errors.New("invalid service_id")
	}
	svc, err := s.store.GetService(ctx, id)
	if err != nil {
		return nil, err
	}
	if mutation && svc.IsSelf {
		return nil, errors.New("managed self-service cannot be changed through MCP; use instance settings")
	}
	return svc, nil
}

var mcpServiceName = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$`)

func validateMCPService(ctx context.Context, svc *store.Service, env *string) error {
	return validateOrdinaryService(ctx, svc, env, true, true)
}

func validateOrdinaryService(ctx context.Context, svc *store.Service, env *string, template, validateName bool) error {
	if validateName && (!mcpServiceName.MatchString(svc.Name) || svc.Name == store.SelfServiceName) {
		return errors.New("invalid or reserved service name")
	}
	if strings.TrimSpace(svc.WatchedImage) == "" || len(svc.WatchedImage) > 512 {
		return errors.New("watched_image is required and must be at most 512 bytes")
	}
	if _, err := reference.ParseNormalizedNamed(svc.WatchedImage); err != nil {
		return errors.New("invalid watched_image reference")
	}
	switch svc.Policy {
	case store.PolicyManual, store.PolicyImmediate:
	case store.PolicyScheduled:
		if _, err := cron.ParseStandard(svc.CronExpr); err != nil {
			return errors.New("invalid cron expression")
		}
	default:
		return errors.New("policy must be manual, immediate or scheduled")
	}
	if strings.TrimSpace(svc.DeployScript) == "" || len(svc.DeployScript) > 128*1024 {
		return errors.New("deploy_script is required and must be at most 128 KiB")
	}
	svc.DeployScript = executor.NormalizeNewlines(svc.DeployScript)
	form := serviceForm(svc)
	if env != nil {
		if len(*env) > 128*1024 {
			return errors.New("environment must be at most 128 KiB")
		}
		*env = executor.NormalizeNewlines(*env)
		if template {
			if _, err := envfile.ResolveTemplate("", *env); err != nil {
				return err
			}
		}
		form.EnvFile = *env
	}
	if err := validateServiceForm(ctx, form); err != nil {
		return errors.New("invalid service configuration: check Bash syntax, dotenv syntax and health URL")
	}
	return nil
}
