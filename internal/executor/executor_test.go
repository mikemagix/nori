package executor

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"nori/internal/deploytemplate"
	"nori/internal/docker"
	"nori/internal/notify"
	"nori/internal/store"
)

// envFileValue returns the ENV_FILE=... path from a script environment.
func envFileValue(env []string) string {
	for _, kv := range env {
		if strings.HasPrefix(kv, "ENV_FILE=") {
			return strings.TrimPrefix(kv, "ENV_FILE=")
		}
	}
	return ""
}

// crlfScript is a valid Bash script carrying Windows (CRLF) line endings,
// as a browser submits a <textarea>. Bash rejects the stray carriage
// return before "do" unless newlines are normalized first.
const crlfScript = "echo start\r\nfor i in 1 2 3; do\r\n  echo \"line $i\"\r\ndone\r\n"

func TestValidateScript_AcceptsCRLFLineEndings(t *testing.T) {
	if err := ValidateScript(context.Background(), crlfScript); err != nil {
		t.Fatalf("CRLF script must validate after normalization: %v", err)
	}
}

func TestOSRunner_RunsCRLFScript(t *testing.T) {
	var out bytes.Buffer
	if err := (OSRunner{}).Run(context.Background(), crlfScript, nil, &out, &out); err != nil {
		t.Fatalf("Run CRLF script: %v (output=%q)", err, out.String())
	}
	if !strings.Contains(out.String(), "line 2") {
		t.Fatalf("unexpected output: %q", out.String())
	}
}

type fakeRunner struct {
	err    error
	log    string
	called bool
}

type runnerFunc func(ctx context.Context, script string, env []string, stdout, stderr io.Writer) error

func (f runnerFunc) Run(ctx context.Context, script string, env []string, stdout, stderr io.Writer) error {
	return f(ctx, script, env, stdout, stderr)
}

func (f *fakeRunner) Run(ctx context.Context, script string, env []string, stdout, stderr io.Writer) error {
	f.called = true
	if f.log != "" {
		io.WriteString(stdout, f.log)
	}
	return f.err
}

func TestPinnedImage(t *testing.T) {
	cases := []struct {
		name   string
		ref    string
		digest string
		want   string
	}{
		{"registry and tag", "ghcr.io/you/app:latest", "sha256:abc", "ghcr.io/you/app@sha256:abc"},
		{"registry port and tag", "registry:5000/you/app:tag", "sha256:abc", "registry:5000/you/app@sha256:abc"},
		{"registry port no tag", "registry:5000/you/app", "sha256:abc", "registry:5000/you/app@sha256:abc"},
		{"already digest pinned", "ghcr.io/you/app@sha256:old", "sha256:abc", "ghcr.io/you/app@sha256:abc"},
		{"no registry with tag", "app:latest", "sha256:abc", "app@sha256:abc"},
		{"bare name", "image", "sha256:abc", "image@sha256:abc"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := pinnedImage(tc.ref, tc.digest); got != tc.want {
				t.Errorf("pinnedImage(%q, %q) = %q, want %q", tc.ref, tc.digest, got, tc.want)
			}
		})
	}
}

func TestDeploy_InvalidBashIsRejectedBeforeRun(t *testing.T) {
	st := openTestStore(t)
	ctx := context.Background()
	svc := &store.Service{Name: "app", WatchedImage: "ghcr.io/me/app:latest", Policy: store.PolicyManual, DeployScript: "if true; then\n  echo broken"}
	if err := st.CreateService(ctx, svc); err != nil {
		t.Fatal(err)
	}

	runner := &fakeRunner{}
	ex := New(st, runner, func(context.Context, string) (string, error) {
		return "sha256:new", nil
	}, 0)
	if _, err := ex.Deploy(ctx, svc.ID, store.TriggerManual); err == nil {
		t.Fatal("expected invalid Bash to be rejected")
	}
	if runner.called {
		t.Fatal("invalid Bash must not be executed")
	}
	assertNoDeployments(t, st, svc.ID)
}

func TestDeploy_InvalidEnvFileIsRejectedBeforeRun(t *testing.T) {
	st := openTestStore(t)
	ctx := context.Background()
	svc := &store.Service{Name: "app", WatchedImage: "ghcr.io/me/app:latest", Policy: store.PolicyManual, DeployScript: "echo ok"}
	if err := st.CreateService(ctx, svc); err != nil {
		t.Fatal(err)
	}
	if err := st.SetEnvFile(ctx, svc.ID, "NOT VALID"); err != nil {
		t.Fatal(err)
	}

	runner := &fakeRunner{}
	ex := New(st, runner, func(context.Context, string) (string, error) {
		return "sha256:new", nil
	}, 0)
	if _, err := ex.Deploy(ctx, svc.ID, store.TriggerManual); err == nil {
		t.Fatal("expected invalid environment file to be rejected")
	}
	if runner.called {
		t.Fatal("a deployment with an invalid environment must not run")
	}
	assertNoDeployments(t, st, svc.ID)
}

func TestBuildEnv_UsesCompleteDotenvFile(t *testing.T) {
	st := openTestStore(t)
	ctx := context.Background()
	svc := &store.Service{Name: "app", WatchedImage: "image", Policy: store.PolicyManual}
	if err := st.CreateService(ctx, svc); err != nil {
		t.Fatal(err)
	}
	if err := st.SetEnvFile(ctx, svc.ID, "PORT=8080\nGREETING=\"hello world\"\n"); err != nil {
		t.Fatal(err)
	}
	ex := New(st, &fakeRunner{}, nil, 0)
	env, envFile, err := ex.buildEnv(ctx, svc, "sha256:abc")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(envFile)
	joined := strings.Join(env, "\n")
	for _, want := range []string{"SERVICE=app", "TARGET_DIGEST=sha256:abc", "PORT=8080", "GREETING=hello world"} {
		if !strings.Contains(joined, want) {
			t.Errorf("environment missing %q: %v", want, env)
		}
	}
}

func TestBuildEnv_InjectsImageAndEnvFile(t *testing.T) {
	st := openTestStore(t)
	ctx := context.Background()
	svc := &store.Service{Name: "app", WatchedImage: "ghcr.io/me/app:latest", Policy: store.PolicyManual}
	if err := st.CreateService(ctx, svc); err != nil {
		t.Fatal(err)
	}
	if err := st.SetEnvFile(ctx, svc.ID, "PORT=8080\nGREETING=\"hello world\"\n"); err != nil {
		t.Fatal(err)
	}
	ex := New(st, &fakeRunner{}, nil, 0)
	env, envFile, err := ex.buildEnv(ctx, svc, "sha256:abc")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(envFile)

	joined := strings.Join(env, "\n")
	for _, want := range []string{
		"SERVICE=app",
		"IMAGE=ghcr.io/me/app:latest",
		"TARGET_DIGEST=sha256:abc",
		"TARGET_IMAGE=ghcr.io/me/app@sha256:abc",
		"ENV_FILE=" + envFile,
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("environment missing %q: %v", want, env)
		}
	}

	// The materialized file is a docker --env-file: resolved KEY=VALUE lines
	// (quotes already stripped), holding only the service env — not the
	// nori metadata variables.
	info, err := os.Stat(envFile)
	if err != nil {
		t.Fatalf("stat env file: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("env file mode = %o, want 600", perm)
	}
	data, err := os.ReadFile(envFile)
	if err != nil {
		t.Fatalf("read env file: %v", err)
	}
	got := string(data)
	if !strings.Contains(got, "PORT=8080") || !strings.Contains(got, "GREETING=hello world") {
		t.Errorf("env file content = %q", got)
	}
	if strings.Contains(got, "SERVICE=") || strings.Contains(got, "TARGET_DIGEST=") {
		t.Errorf("env file must contain only the service env, got %q", got)
	}
}

func TestDeploy_RemovesEnvFileAfterRun(t *testing.T) {
	st := openTestStore(t)
	ctx := context.Background()
	svc := &store.Service{Name: "app", WatchedImage: "ghcr.io/me/app:latest", Policy: store.PolicyManual, DeployScript: "echo hi"}
	if err := st.CreateService(ctx, svc); err != nil {
		t.Fatal(err)
	}

	type capture struct {
		path             string
		existedDuringRun bool
	}
	seen := make(chan capture, 1)
	runner := runnerFunc(func(_ context.Context, _ string, env []string, stdout, _ io.Writer) error {
		io.WriteString(stdout, "ok\n")
		path := envFileValue(env)
		_, err := os.Stat(path)
		seen <- capture{path: path, existedDuringRun: err == nil}
		return nil
	})
	ex := New(st, runner, func(context.Context, string) (string, error) { return "sha256:new", nil }, 0)
	if _, err := ex.Deploy(ctx, svc.ID, store.TriggerManual); err != nil {
		t.Fatal(err)
	}

	var cap capture
	select {
	case cap = <-seen:
	case <-time.After(time.Second):
		t.Fatal("deploy did not run")
	}
	if cap.path == "" {
		t.Fatal("ENV_FILE was not injected into the script environment")
	}
	if !cap.existedDuringRun {
		t.Fatal("env file must exist while the deploy script runs")
	}
	// After the deploy finishes, the decrypted env file must be removed so
	// secrets do not linger on disk.
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(cap.path); os.IsNotExist(err) {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("env file %s was not removed after the deploy", cap.path)
}

func TestDeploy_Success(t *testing.T) {
	st := openTestStore(t)
	ctx := context.Background()
	svc := &store.Service{Name: "app", WatchedImage: "ghcr.io/me/app:latest", Policy: store.PolicyManual, DeployScript: "echo hi"}
	if err := st.CreateService(ctx, svc); err != nil {
		t.Fatal(err)
	}

	runner := &fakeRunner{log: "deployed\n"}
	ex := New(st, runner, func(ctx context.Context, image string) (string, error) {
		return "sha256:new", nil
	}, 0)

	id, err := ex.Deploy(ctx, svc.ID, store.TriggerManual)
	if err != nil {
		t.Fatalf("Deploy: %v", err)
	}

	// wait for async deploy
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		d, err := st.GetDeployment(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		if d.Status != store.DeployRunning {
			if d.Status != store.DeploySuccess {
				t.Fatalf("status = %s", d.Status)
			}
			if !strings.Contains(d.Log, "deployed") {
				t.Fatalf("log = %q", d.Log)
			}
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("deploy did not finish")
}

func TestDeploy_FailureCooldown(t *testing.T) {
	st := openTestStore(t)
	ctx := context.Background()
	svc := &store.Service{Name: "app", WatchedImage: "ghcr.io/me/app:latest", Policy: store.PolicyImmediate, DeployScript: "exit 1"}
	if err := st.CreateService(ctx, svc); err != nil {
		t.Fatal(err)
	}

	runner := &fakeRunner{err: errors.New("boom")}
	latest := func(ctx context.Context, image string) (string, error) { return "sha256:bad", nil }
	ex := New(st, runner, latest, time.Minute)

	if id, err := ex.Deploy(ctx, svc.ID, store.TriggerAuto); err != nil || id == 0 {
		t.Fatalf("expected deploy to start, id=%d err=%v", id, err)
	}
	time.Sleep(100 * time.Millisecond)
	if _, err := ex.Deploy(ctx, svc.ID, store.TriggerAuto); err == nil {
		t.Fatal("expected cooldown block")
	}
}

func TestDeploy_SelfHandoffStaysRunningAndGetsLauncherEnv(t *testing.T) {
	t.Setenv("NORI_CONFIG_VOLUME", "nori-config")
	t.Setenv("NORI_SELF_IMAGE", "ghcr.io/acme/nori:latest")
	st := openTestStore(t)
	ctx := context.Background()
	svc := &store.Service{
		Name:         store.SelfServiceName,
		WatchedImage: "ghcr.io/acme/nori:latest",
		Policy:       store.PolicyManual,
		DeployScript: store.SelfDeployScript,
		IsSelf:       true,
	}
	if err := st.CreateService(ctx, svc); err != nil {
		t.Fatal(err)
	}
	done := make(chan []string, 1)
	runner := runnerFunc(func(_ context.Context, _ string, env []string, stdout, _ io.Writer) error {
		io.WriteString(stdout, "updater launched\n")
		done <- env
		return nil
	})
	ex := New(st, runner, func(context.Context, string) (string, error) {
		return "sha256:new", nil
	}, 0)
	id, err := ex.Deploy(ctx, svc.ID, store.TriggerManual)
	if err != nil {
		t.Fatal(err)
	}
	var env []string
	select {
	case env = <-done:
	case <-time.After(time.Second):
		t.Fatal("self handoff was not executed")
	}
	// The runner has returned; give the asynchronous executor a moment to
	// persist its intentionally-running handoff record before reading SQLite.
	time.Sleep(20 * time.Millisecond)
	d, err := st.GetDeployment(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if d.Status != store.DeployRunning || d.FinishedAt != nil {
		t.Fatalf("self deployment was finalized before replacement: %+v", d)
	}
	joined := strings.Join(env, "\n")
	for _, want := range []string{"NORI_CONFIG_VOLUME=nori-config", "NORI_SELF_IMAGE=ghcr.io/acme/nori:latest"} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing %q from handoff environment: %v", want, env)
		}
	}
}

func TestDeploy_SelfHandoffFailureIsFinalized(t *testing.T) {
	t.Setenv("NORI_CONFIG_VOLUME", "nori-config")
	t.Setenv("NORI_SELF_IMAGE", "image")
	st := openTestStore(t)
	ctx := context.Background()
	svc := &store.Service{Name: store.SelfServiceName, WatchedImage: "image", Policy: store.PolicyManual, DeployScript: "exit 1", IsSelf: true}
	if err := st.CreateService(ctx, svc); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{}, 1)
	ex := New(st, runnerFunc(func(_ context.Context, _ string, _ []string, _ io.Writer, _ io.Writer) error {
		done <- struct{}{}
		return errors.New("handoff failed")
	}), func(context.Context, string) (string, error) { return "sha256:new", nil }, 0)
	id, err := ex.Deploy(ctx, svc.ID, store.TriggerManual)
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("self handoff did not execute")
	}
	time.Sleep(20 * time.Millisecond)
	d, err := st.GetDeployment(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if d.Status != store.DeployFailed || d.FinishedAt == nil {
		t.Fatalf("failed self handoff was not finalized: %+v", d)
	}
}

func TestDeploy_TemplatePromotesHealthyCandidateWithoutRunningCustomScript(t *testing.T) {
	st := openTestStore(t)
	ctx := context.Background()
	svc := &store.Service{
		Name:           "api",
		WatchedImage:   "ghcr.io/acme/api:latest",
		Policy:         store.PolicyManual,
		DeploymentMode: store.DeploymentModeSingleContainer,
		TemplateConfig: `{"version":1,"internal_port":8080,"restart_policy":"always","serving_network":"proxy","health":{"command":"true","timeout_seconds":5}}`,
	}
	if err := st.CreateService(ctx, svc); err != nil {
		t.Fatal(err)
	}

	dk := &docker.Fake{Networks: map[string]docker.ManagedResource{"proxy": {Name: "proxy"}}}
	runner := &fakeRunner{}
	ex := New(st, runner, func(context.Context, string) (string, error) { return "sha256:new", nil }, 0)
	ex.SetDocker(dk)

	id, err := ex.Deploy(ctx, svc.ID, store.TriggerManual)
	if err != nil {
		t.Fatalf("Deploy: %v", err)
	}
	deployment := waitForDeployment(t, st, id)
	if deployment.Status != store.DeploySuccess {
		t.Fatalf("template deployment status = %s, log = %q", deployment.Status, deployment.Log)
	}
	if runner.called {
		t.Fatal("template deployment must not execute the custom Bash runner")
	}
	if _, ok := dk.ManagedContainers["nori-"+strconv.FormatInt(svc.ID, 10)+"-app"]; !ok {
		t.Fatalf("promoted application container missing: %+v", dk.ManagedContainers)
	}
	if _, ok := dk.ManagedContainers["nori-"+strconv.FormatInt(svc.ID, 10)+"-app-candidate"]; ok {
		t.Fatalf("candidate must be renamed after health succeeds: %+v", dk.ManagedContainers)
	}
	if len(dk.Operations) == 0 || dk.Operations[0] != "pull ghcr.io/acme/api@sha256:new" {
		t.Fatalf("image must be pulled before resource changes, operations = %v", dk.Operations)
	}
}

func TestDeploy_TemplateHealthFailureRemovesCandidateAndKeepsCurrentApp(t *testing.T) {
	st := openTestStore(t)
	ctx := context.Background()
	svc := &store.Service{
		Name:           "api",
		WatchedImage:   "ghcr.io/acme/api:latest",
		Policy:         store.PolicyManual,
		DeploymentMode: store.DeploymentModeSingleContainer,
		TemplateConfig: `{"version":1,"internal_port":8080,"restart_policy":"always","health":{"command":"false","timeout_seconds":5}}`,
	}
	if err := st.CreateService(ctx, svc); err != nil {
		t.Fatal(err)
	}
	labels := map[string]string{
		"nori.service": "api", "nori.template": "1", "nori.service-id": strconv.FormatInt(svc.ID, 10), "nori.role": "app",
	}
	current := "nori-" + strconv.FormatInt(svc.ID, 10) + "-app"
	dk := &docker.Fake{
		ManagedContainers: map[string]docker.ManagedContainer{current: {ManagedContainerSpec: docker.ManagedContainerSpec{Name: current, Labels: labels}, State: "running"}},
		HealthErr:         errors.New("application health check failed"),
	}
	ex := New(st, &fakeRunner{}, func(context.Context, string) (string, error) { return "sha256:new", nil }, 0)
	ex.SetDocker(dk)

	id, err := ex.Deploy(ctx, svc.ID, store.TriggerManual)
	if err != nil {
		t.Fatalf("Deploy: %v", err)
	}
	deployment := waitForDeployment(t, st, id)
	if deployment.Status != store.DeployFailed {
		t.Fatalf("template deployment status = %s, log = %q", deployment.Status, deployment.Log)
	}
	if got := dk.ManagedContainers[current].State; got != "running" {
		t.Fatalf("current application state = %q, want running", got)
	}
	if _, ok := dk.ManagedContainers["nori-"+strconv.FormatInt(svc.ID, 10)+"-app-candidate"]; ok {
		t.Fatalf("failed candidate must be removed: %+v", dk.ManagedContainers)
	}
}

func TestDeploy_PostgresTemplateReusesOwnedDatabaseAndRecordsIdentity(t *testing.T) {
	st := openTestStore(t)
	ctx := context.Background()
	svc := &store.Service{
		Name:           "api",
		WatchedImage:   "ghcr.io/acme/api:latest",
		Policy:         store.PolicyManual,
		DeploymentMode: store.DeploymentModePostgres,
		TemplateConfig: `{"version":1,"internal_port":8080,"restart_policy":"always","health":{"command":"true","timeout_seconds":5},"postgres":{"image":"postgres:16.4","database":"api","user":"api","password_env":"POSTGRES_PASSWORD","connection_url_env":"DATABASE_URL","ready_timeout_seconds":5}}`,
	}
	if err := st.CreateService(ctx, svc); err != nil {
		t.Fatal(err)
	}
	if err := st.SetEnvFile(ctx, svc.ID, "POSTGRES_DB=api\nPOSTGRES_USER=api\nPOSTGRES_PASSWORD=s3cret\nDATABASE_URL=postgres://api:s3cret@nori-1-postgres/api?sslmode=disable\n"); err != nil {
		t.Fatal(err)
	}
	dk := &docker.Fake{}
	ex := New(st, &fakeRunner{}, func(context.Context, string) (string, error) { return "sha256:new", nil }, 0)
	ex.SetDocker(dk)

	firstID, err := ex.Deploy(ctx, svc.ID, store.TriggerManual)
	if err != nil {
		t.Fatalf("first Deploy: %v", err)
	}
	if deployment := waitForDeployment(t, st, firstID); deployment.Status != store.DeploySuccess {
		t.Fatalf("first deployment status = %s, log = %q", deployment.Status, deployment.Log)
	}
	state, err := st.GetTemplateState(ctx, svc.ID)
	if err != nil || state.DatabaseIdentityFingerprint == "" {
		t.Fatalf("managed database identity = %+v, %v", state, err)
	}
	databaseName := "nori-" + strconv.FormatInt(svc.ID, 10) + "-postgres"
	if got := dk.ManagedContainers[databaseName].State; got != "running" {
		t.Fatalf("database state = %q, want running", got)
	}
	if !containsOperation(dk.Operations, "probe network nori-"+strconv.FormatInt(svc.ID, 10)+"-db-internal") {
		t.Fatalf("database readiness must run across the private network, operations = %v", dk.Operations)
	}

	secondID, err := ex.Deploy(ctx, svc.ID, store.TriggerManual)
	if err != nil {
		t.Fatalf("second Deploy: %v", err)
	}
	if deployment := waitForDeployment(t, st, secondID); deployment.Status != store.DeploySuccess {
		t.Fatalf("second deployment status = %s, log = %q", deployment.Status, deployment.Log)
	}
	if got := dk.ManagedContainers[databaseName].State; got != "running" {
		t.Fatalf("database must remain running across application redeploy, got %q", got)
	}
}

func TestDeploy_PostgresReadinessFailureKeepsCurrentAppAndRedactsSecrets(t *testing.T) {
	st := openTestStore(t)
	ctx := context.Background()
	svc := &store.Service{
		Name:           "api",
		WatchedImage:   "ghcr.io/acme/api:latest",
		Policy:         store.PolicyManual,
		DeploymentMode: store.DeploymentModePostgres,
		TemplateConfig: `{"version":1,"internal_port":8080,"restart_policy":"always","health":{"command":"true","timeout_seconds":5},"postgres":{"image":"postgres:16.4","database":"api","user":"api","password_env":"POSTGRES_PASSWORD","connection_url_env":"DATABASE_URL","ready_timeout_seconds":5}}`,
	}
	if err := st.CreateService(ctx, svc); err != nil {
		t.Fatal(err)
	}
	secret := "s3cret"
	if err := st.SetEnvFile(ctx, svc.ID, "POSTGRES_DB=api\nPOSTGRES_USER=api\nPOSTGRES_PASSWORD="+secret+"\nDATABASE_URL=postgres://api:"+secret+"@nori-1-postgres/api?sslmode=disable\n"); err != nil {
		t.Fatal(err)
	}
	current := "nori-" + strconv.FormatInt(svc.ID, 10) + "-app"
	dk := &docker.Fake{
		ManagedContainers: map[string]docker.ManagedContainer{current: {ManagedContainerSpec: docker.ManagedContainerSpec{
			Name: current, Labels: map[string]string{"nori.service": "api", "nori.template": "1", "nori.service-id": strconv.FormatInt(svc.ID, 10), "nori.role": "app"},
		}, State: "running"}},
		HealthErr: errors.New("authentication failed for password " + secret),
	}
	ex := New(st, &fakeRunner{}, func(context.Context, string) (string, error) { return "sha256:new", nil }, 0)
	ex.SetDocker(dk)

	id, err := ex.Deploy(ctx, svc.ID, store.TriggerManual)
	if err != nil {
		t.Fatalf("Deploy: %v", err)
	}
	deployment := waitForDeployment(t, st, id)
	if deployment.Status != store.DeployFailed {
		t.Fatalf("deployment status = %s, log = %q", deployment.Status, deployment.Log)
	}
	if got := dk.ManagedContainers[current].State; got != "running" {
		t.Fatalf("database readiness failure changed current application state to %q", got)
	}
	if strings.Contains(deployment.Log, secret) {
		t.Fatalf("deployment log leaked database secret: %q", deployment.Log)
	}
}

func TestApplicationSpecAddsProxyConfigurationWithoutMutatingServiceEnvironment(t *testing.T) {
	plan, err := deploytemplate.BuildPlan(deploytemplate.Input{
		ServiceID: 1, ServiceName: "api", TargetImage: "ghcr.io/acme/api@sha256:new",
		Config: deploytemplate.Config{
			Mode: deploytemplate.ModeSingleContainer, Version: 1, InternalPort: 8080,
			RestartPolicy: deploytemplate.RestartAlways, ServingNetwork: "proxy",
			Proxy:  &deploytemplate.ProxyConfig{Network: "proxy", Domain: "api.example.test", Port: 8080},
			Health: deploytemplate.HealthCheck{Command: "true", TimeoutSeconds: 5},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	serviceEnv := map[string]string{"SECRET": "s3cret"}
	spec := applicationSpec(plan, serviceEnv)
	if !containsEnv(spec.Env, "VIRTUAL_HOST=api.example.test") || !containsEnv(spec.Env, "VIRTUAL_PORT=8080") {
		t.Fatalf("proxy settings missing from container environment: %v", spec.Env)
	}
	if spec.PublishedPort != 8080 {
		t.Fatalf("published port = %d, want 8080", spec.PublishedPort)
	}
	if _, ok := serviceEnv["VIRTUAL_HOST"]; ok {
		t.Fatalf("template-only proxy settings mutated the service environment: %+v", serviceEnv)
	}
}

func containsEnv(env []string, want string) bool {
	for _, item := range env {
		if item == want {
			return true
		}
	}
	return false
}

func containsOperation(operations []string, want string) bool {
	for _, operation := range operations {
		if operation == want {
			return true
		}
	}
	return false
}

func waitForDeployment(t *testing.T, st *store.Store, id int64) *store.Deployment {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		deployment, err := st.GetDeployment(context.Background(), id)
		if err != nil {
			t.Fatal(err)
		}
		if deployment.Status != store.DeployRunning {
			return deployment
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("deployment did not finish")
	return nil
}

// capturingNotifier records every notification event it receives.
type capturingNotifier struct {
	mu     sync.Mutex
	events []capturedNotifyEvent
}

type capturedNotifyEvent struct {
	kind string
	evt  notify.Event
}

func (c *capturingNotifier) NotifyServiceDown(_ context.Context, evt notify.Event) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.events = append(c.events, capturedNotifyEvent{kind: "down", evt: evt})
	return nil
}

func (c *capturingNotifier) NotifyServiceRecovered(_ context.Context, evt notify.Event) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.events = append(c.events, capturedNotifyEvent{kind: "recovered", evt: evt})
	return nil
}

func (c *capturingNotifier) NotifyDeploySuccess(_ context.Context, evt notify.Event) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.events = append(c.events, capturedNotifyEvent{kind: "success", evt: evt})
	return nil
}

func (c *capturingNotifier) snapshot() []capturedNotifyEvent {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]capturedNotifyEvent, len(c.events))
	copy(out, c.events)
	return out
}

func TestExecutor_FailureFiresNotifierOnce(t *testing.T) {
	st := openTestStore(t)
	ctx := context.Background()
	svc := &store.Service{
		Name:         "app",
		WatchedImage: "ghcr.io/me/app:latest",
		Policy:       store.PolicyManual,
		DeployScript: "exit 1",
	}
	if err := st.CreateService(ctx, svc); err != nil {
		t.Fatal(err)
	}
	cap := &capturingNotifier{}
	ex := New(st, &fakeRunner{err: errors.New("deploy boom")}, func(context.Context, string) (string, error) {
		return "sha256:bad", nil
	}, 0)
	ex.SetNotifier(cap)
	ex.SetBotName("staging")

	id, err := ex.Deploy(ctx, svc.ID, store.TriggerManual)
	if err != nil {
		t.Fatalf("Deploy: %v", err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		d, derr := st.GetDeployment(ctx, id)
		if derr != nil {
			t.Fatal(derr)
		}
		if d.Status == store.DeployFailed {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	deadline = time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if len(cap.snapshot()) > 0 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	events := cap.snapshot()
	if len(events) != 1 {
		t.Fatalf("got %d notify events, want 1: %+v", len(events), events)
	}
	evt := events[0].evt
	if evt.ServiceName != "app" || evt.Trigger != store.TriggerManual {
		t.Errorf("unexpected event: %+v", evt)
	}
	if evt.Digest == "" || !strings.Contains(evt.Reason, "deploy boom") {
		t.Errorf("unexpected event payload: %+v", evt)
	}
	if evt.BotName != "staging" {
		t.Errorf("BotName = %q, want staging", evt.BotName)
	}
	if evt.DeploymentID != id {
		t.Errorf("DeploymentID = %d, want %d", evt.DeploymentID, id)
	}
	if events[0].kind != "down" {
		t.Errorf("kind = %q, want down", events[0].kind)
	}
}

func TestExecutor_SuccessFiresSuccessNotifier(t *testing.T) {
	st := openTestStore(t)
	ctx := context.Background()
	svc := &store.Service{Name: "app", WatchedImage: "img", Policy: store.PolicyManual, DeployScript: "echo ok"}
	if err := st.CreateService(ctx, svc); err != nil {
		t.Fatal(err)
	}
	cap := &capturingNotifier{}
	ex := New(st, &fakeRunner{log: "ok"}, func(context.Context, string) (string, error) {
		return "sha256:good0123456789", nil
	}, 0)
	ex.SetNotifier(cap)

	id, err := ex.Deploy(ctx, svc.ID, store.TriggerAuto)
	if err != nil {
		t.Fatalf("Deploy: %v", err)
	}
	waitForSuccess(t, st, ctx, id)
	got := cap.snapshot()
	if len(got) != 1 {
		t.Fatalf("got %d notify events, want 1: %+v", len(got), got)
	}
	if got[0].kind != "success" {
		t.Errorf("kind = %q, want success", got[0].kind)
	}
	evt := got[0].evt
	if evt.ServiceName != "app" || evt.Trigger != store.TriggerAuto {
		t.Errorf("unexpected event: %+v", evt)
	}
	if evt.Digest == "" || evt.Reason != "" {
		t.Errorf("success event must carry a digest and no reason: %+v", evt)
	}
	if evt.DeploymentID != id {
		t.Errorf("DeploymentID = %d, want %d", evt.DeploymentID, id)
	}
}

func TestDeploy_SelfHandoffSuccessDoesNotNotify(t *testing.T) {
	t.Setenv("NORI_CONFIG_VOLUME", "nori-config")
	t.Setenv("NORI_SELF_IMAGE", "image")
	st := openTestStore(t)
	ctx := context.Background()
	svc := &store.Service{Name: store.SelfServiceName, WatchedImage: "image", Policy: store.PolicyManual, DeployScript: "echo ok", IsSelf: true}
	if err := st.CreateService(ctx, svc); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{}, 1)
	cap := &capturingNotifier{}
	ex := New(st, runnerFunc(func(_ context.Context, _ string, _ []string, _ io.Writer, _ io.Writer) error {
		done <- struct{}{}
		return nil
	}), func(context.Context, string) (string, error) { return "sha256:new", nil }, 0)
	ex.SetNotifier(cap)

	id, err := ex.Deploy(ctx, svc.ID, store.TriggerManual)
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("self handoff did not execute")
	}
	// The handoff record stays running until the replacement instance
	// resolves it; nothing about the handoff may notify.
	time.Sleep(50 * time.Millisecond)
	if got := cap.snapshot(); len(got) != 0 {
		t.Fatalf("self handoff must not notify; got %+v", got)
	}
	d, err := st.GetDeployment(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if d.Status != store.DeployRunning || d.FinishedAt != nil {
		t.Fatalf("self deployment was finalized before replacement: %+v", d)
	}
}

// waitForSuccess blocks until the deploy record for id reaches DeploySuccess,
// giving the notifier call inside alertSuccess time to land.
func waitForSuccess(t *testing.T, st *store.Store, ctx context.Context, id int64) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		d, err := st.GetDeployment(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		if d.Status == store.DeploySuccess {
			// alertSuccess runs after finish(); a tiny cushion lets the
			// notifier call return before we read the capture.
			time.Sleep(20 * time.Millisecond)
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("deploy did not finish as success")
}

// giving the synchronous notifier call inside alertFailure time to land.
func waitForFailure(t *testing.T, st *store.Store, ctx context.Context, id int64) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		d, err := st.GetDeployment(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		if d.Status == store.DeployFailed {
			// alertFailure runs before finish(); a tiny cushion lets the
			// notifier call return before we read the capture.
			time.Sleep(20 * time.Millisecond)
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("deploy did not finish as failed")
}

// TestExecutor_AlertsAreNotGatedByLegacyMode locks in that the executor
// forwards events unconditionally: suppression lives in the notifier chain
// (notify.Route), not here. A stored legacy notify_mode must not gate it.
func TestExecutor_AlertsAreNotGatedByLegacyMode(t *testing.T) {
	st := openTestStore(t)
	ctx := context.Background()
	if err := st.SetSetting(ctx, store.SettingNotifyMode, "never"); err != nil {
		t.Fatal(err)
	}
	svc := &store.Service{Name: "app", WatchedImage: "img", Policy: store.PolicyManual, DeployScript: "exit 1"}
	if err := st.CreateService(ctx, svc); err != nil {
		t.Fatal(err)
	}
	cap := &capturingNotifier{}
	ex := New(st, &fakeRunner{err: errors.New("boom")},
		func(context.Context, string) (string, error) { return "sha256:x", nil }, 0)
	ex.SetNotifier(cap)

	id, err := ex.Deploy(ctx, svc.ID, store.TriggerManual)
	if err != nil {
		t.Fatalf("Deploy: %v", err)
	}
	waitForFailure(t, st, ctx, id)
	if got := cap.snapshot(); len(got) != 1 {
		t.Fatalf("executor must forward alerts regardless of stored mode; got %+v", got)
	}
}

func openTestStore(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.Open(t.TempDir()+"/test.db", make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

func assertNoDeployments(t *testing.T, st *store.Store, serviceID int64) {
	t.Helper()
	deployments, err := st.ListDeployments(context.Background(), serviceID, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(deployments) != 0 {
		t.Fatalf("invalid configuration created %d deployment records", len(deployments))
	}
}
