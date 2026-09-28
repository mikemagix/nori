package executor

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"sort"
	"strings"
	"sync"
	"time"

	"nori/internal/deploytemplate"
	"nori/internal/docker"
	"nori/internal/envfile"
	"nori/internal/notify"
	"nori/internal/store"
)

type LatestDigestFunc func(ctx context.Context, image string) (string, error)

// pinnedImage returns a digest-pinned reference (repo@digest) for the watched
// image. It drops any existing tag or digest from ref before appending the
// resolved digest. A registry port (the colon in "host:5000/repo") is preserved
// because it appears before the final path segment.
func pinnedImage(ref, digest string) string {
	name := ref
	if at := strings.LastIndex(name, "@"); at != -1 {
		name = name[:at]
	}
	if colon := strings.LastIndex(name, ":"); colon > strings.LastIndex(name, "/") {
		name = name[:colon]
	}
	return name + "@" + digest
}

type CommandRunner interface {
	Run(ctx context.Context, script string, env []string, stdout, stderr io.Writer) error
}

type OSRunner struct{}

// NormalizeNewlines converts Windows (CRLF) and classic-Mac (CR) line
// endings to Unix (LF). Browsers submit <textarea> content with CRLF
// newlines, and Bash rejects a stray carriage return inside compound
// commands (e.g. "do\r"), so scripts must be normalized before Bash
// parses or runs them.
func NormalizeNewlines(s string) string {
	s = strings.ReplaceAll(s, "\r\n", "\n")
	return strings.ReplaceAll(s, "\r", "\n")
}

// ValidateScript asks Bash to parse the script without executing it.
func ValidateScript(ctx context.Context, script string) error {
	cmd := exec.CommandContext(ctx, "bash", "-n")
	cmd.Stdin = strings.NewReader(NormalizeNewlines(script))
	output, err := cmd.CombinedOutput()
	if err == nil {
		return nil
	}
	message := strings.TrimSpace(string(output))
	if message == "" {
		message = err.Error()
	}
	return fmt.Errorf("invalid bash syntax: %s", message)
}

func (OSRunner) Run(ctx context.Context, script string, env []string, stdout, stderr io.Writer) error {
	cmd := exec.CommandContext(ctx, "bash", "-c", NormalizeNewlines(script))
	cmd.Env = env
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	return cmd.Run()
}

type Executor struct {
	store    *store.Store
	runner   CommandRunner
	latest   LatestDigestFunc
	cooldown time.Duration
	notify   notify.Notifier
	botName  string
	managed  docker.ManagedClient

	locks    sync.Map // int64 -> *sync.Mutex
	inFlight sync.Map // int64 -> struct{} for template deployments
	failures sync.Map // int64 -> failureRecord
}

type failureRecord struct {
	digest string
	until  time.Time
}

func New(st *store.Store, runner CommandRunner, latest LatestDigestFunc, cooldown time.Duration) *Executor {
	if cooldown == 0 {
		cooldown = 15 * time.Minute
	}
	return &Executor{
		store:    st,
		runner:   runner,
		latest:   latest,
		cooldown: cooldown,
		notify:   notify.Noop{},
	}
}

// SetNotifier installs the alert notifier used for service-down events. The
// default is a no-op; pass a *notify.Twilio (typically wrapped in
// *notify.LogFailures) to enable SMS alerts. SetBotName should be called
// alongside it so the alert identifies the source instance.
func (e *Executor) SetNotifier(n notify.Notifier) {
	if n == nil {
		n = notify.Noop{}
	}
	e.notify = n
}

// SetBotName sets the instance display name used in alert bodies.
func (e *Executor) SetBotName(name string) {
	e.botName = name
}

// SetDocker installs the narrow typed Docker capability used exclusively by
// structured deployment templates. Custom-script deployments remain on their
// existing isolated Bash path.
func (e *Executor) SetDocker(dk docker.ManagedClient) {
	e.managed = dk
}

func (e *Executor) Deploy(ctx context.Context, serviceID int64, trigger string) (int64, error) {
	mu := e.lockFor(serviceID)
	mu.Lock()
	defer mu.Unlock()

	svc, err := e.store.GetService(ctx, serviceID)
	if err != nil {
		return 0, err
	}
	isTemplate := svc.DeploymentMode != "" && svc.DeploymentMode != store.DeploymentModeCustom
	if isTemplate && svc.IsSelf {
		return 0, errors.New("the launcher-managed self-service cannot use a deployment template")
	}
	templateClaimed := false
	if isTemplate {
		if _, loaded := e.inFlight.LoadOrStore(serviceID, struct{}{}); loaded {
			return 0, errors.New("a deployment is already running for this service")
		}
		templateClaimed = true
		defer func() {
			if templateClaimed {
				e.inFlight.Delete(serviceID)
			}
		}()
	}
	if !isTemplate {
		if err := ValidateScript(ctx, svc.DeployScript); err != nil {
			return 0, err
		}
	}
	digest, err := e.latest(ctx, svc.WatchedImage)
	if err != nil {
		return 0, fmt.Errorf("latest digest: %w", err)
	}
	var plan *deploytemplate.Plan
	if isTemplate {
		config, err := deploytemplate.ParseConfig(deploytemplate.Mode(svc.DeploymentMode), svc.TemplateConfig)
		if err != nil {
			return 0, fmt.Errorf("invalid deployment template: %w", err)
		}
		built, err := deploytemplate.BuildPlan(deploytemplate.Input{
			ServiceID: svc.ID, ServiceName: svc.Name, TargetImage: pinnedImage(svc.WatchedImage, digest), Config: config,
		})
		if err != nil {
			return 0, fmt.Errorf("invalid deployment template: %w", err)
		}
		if e.managed == nil {
			return 0, errors.New("deployment templates require Docker to be configured")
		}
		plan = &built
	}
	env, envFile, err := e.buildEnv(ctx, svc, digest)
	if err != nil {
		return 0, fmt.Errorf("invalid environment file: %w", err)
	}

	if trigger == store.TriggerAuto && e.inCooldown(serviceID, digest) {
		removeEnvFile(envFile)
		return 0, fmt.Errorf("service %q in failure cooldown for digest %s", svc.Name, digest)
	}

	deploy := &store.Deployment{
		ServiceID:    serviceID,
		Trigger:      trigger,
		TargetDigest: digest,
		Status:       store.DeployRunning,
	}
	if err := e.store.CreateDeployment(ctx, deploy); err != nil {
		removeEnvFile(envFile)
		return 0, err
	}

	log.Printf("deploy: %s %q started (id=%d digest=%s)", trigger, svc.Name, deploy.ID, shortDigest(digest))
	go func() {
		e.runDeploy(svc, deploy, env, envFile, plan)
		if isTemplate {
			e.inFlight.Delete(serviceID)
		}
	}()
	templateClaimed = false
	return deploy.ID, nil
}

func (e *Executor) runDeploy(svc *store.Service, deploy *store.Deployment, env []string, envFile string, plan *deploytemplate.Plan) {
	// The env file holds decrypted secrets; drop it once the script no longer
	// needs it, whichever way this deploy ends (including the self handoff).
	defer removeEnvFile(envFile)
	ctx := context.Background()

	var logBuf bytes.Buffer
	var err error
	if plan == nil {
		err = e.runner.Run(ctx, svc.DeployScript, env, &logBuf, &logBuf)
	} else {
		err = e.runTemplateDeploy(ctx, svc, *plan, env, &logBuf)
	}
	deploy.Log = redactDeploymentText(logBuf.String(), env)

	if err != nil {
		err = errors.New(redactDeploymentText(err.Error(), env))
		log.Printf("deploy: %s %q failed (id=%d): %v", deploy.Trigger, svc.Name, deploy.ID, err)
		e.recordFailure(svc.ID, deploy.TargetDigest)
		e.alertFailure(svc, deploy, err)
		e.finish(ctx, deploy, store.DeployFailed, "\nfailed: "+err.Error())
		return
	}

	e.clearFailure(svc.ID)
	if svc.IsSelf {
		// The detached updater has only been handed off at this point. The
		// launcher will stop this process next, so the newly booted instance
		// resolves this record from its actual running digest.
		log.Printf("deploy: %s %q handed off (id=%d)", deploy.Trigger, svc.Name, deploy.ID)
		_ = e.store.UpdateDeployment(ctx, deploy)
		return
	}
	log.Printf("deploy: %s %q succeeded (id=%d)", deploy.Trigger, svc.Name, deploy.ID)
	e.finish(ctx, deploy, store.DeploySuccess, "")
	e.alertSuccess(svc, deploy)
}

type templatePreflight struct {
	current   bool
	candidate bool
	rollback  bool
	database  bool
}

type postgresRuntime struct {
	fingerprint string
	databaseURL string
	password    string
}

// runTemplateDeploy performs only the typed Docker lifecycle compiled by the
// template planner. It never invokes a generated shell script or writes a
// dotenv value to a log.
func (e *Executor) runTemplateDeploy(ctx context.Context, svc *store.Service, plan deploytemplate.Plan, env []string, output io.Writer) error {
	values := deploymentEnvironment(env)
	var postgres *postgresRuntime
	if plan.Postgres != nil {
		prepared, err := postgresEnvironment(plan, values)
		if err != nil {
			return err
		}
		state, err := e.store.GetTemplateState(ctx, svc.ID)
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			return fmt.Errorf("read managed database state: %w", err)
		}
		if state != nil && state.DatabaseIdentityFingerprint != prepared.fingerprint {
			return store.ErrTemplateDatabaseMigrationRequired
		}
		postgres = &prepared
	}

	dk := e.managed
	if _, err := fmt.Fprintf(output, "Pulling application image %s\n", plan.TargetImage); err != nil {
		return err
	}
	if err := dk.Pull(ctx, plan.TargetImage); err != nil {
		return fmt.Errorf("pull application image: %w", err)
	}
	if plan.Database != nil {
		if _, err := fmt.Fprintf(output, "Pulling PostgreSQL image %s\n", plan.Database.Image); err != nil {
			return err
		}
		if err := dk.Pull(ctx, plan.Database.Image); err != nil {
			return fmt.Errorf("pull PostgreSQL image: %w", err)
		}
	}

	preflight, err := preflightTemplateResources(ctx, dk, plan)
	if err != nil {
		return err
	}
	if err := ensureTemplateResources(ctx, dk, plan); err != nil {
		return err
	}
	if plan.Database != nil {
		if err := e.ensurePostgres(ctx, svc, plan, *postgres, preflight.database, values, output); err != nil {
			return err
		}
	}

	if preflight.candidate {
		if _, err := fmt.Fprintf(output, "Removing a previous owned candidate %s\n", plan.AppCandidate.Name); err != nil {
			return err
		}
		if err := dk.RemoveContainer(ctx, plan.AppCandidate.Name); err != nil {
			return fmt.Errorf("remove previous candidate: %w", err)
		}
	}
	currentStopped := false
	if preflight.current && plan.Proxy == nil && plan.ExternalNetwork == "" {
		if _, err := fmt.Fprintf(output, "Stopping current application %s to release host port\n", plan.AppCurrent.Name); err != nil {
			return err
		}
		if err := dk.StopContainer(ctx, plan.AppCurrent.Name); err != nil {
			return fmt.Errorf("stop current application for host port: %w", err)
		}
		currentStopped = true
		defer func() {
			if currentStopped {
				_ = dk.StartContainer(context.Background(), plan.AppCurrent.Name)
			}
		}()
	}
	if _, err := fmt.Fprintf(output, "Creating candidate %s\n", plan.AppCandidate.Name); err != nil {
		return err
	}
	if err := dk.CreateContainer(ctx, applicationSpec(plan, values, true)); err != nil {
		return fmt.Errorf("create application candidate: %w", err)
	}
	if err := dk.StartContainer(ctx, plan.AppCandidate.Name); err != nil {
		_ = dk.RemoveContainer(context.Background(), plan.AppCandidate.Name)
		return fmt.Errorf("start application candidate: %w", err)
	}
	if _, err := fmt.Fprintf(output, "Checking candidate health for up to %d seconds\n", plan.Health.TimeoutSeconds); err != nil {
		return err
	}
	if err := e.waitForApplicationHealth(ctx, plan); err != nil {
		_ = dk.RemoveContainer(context.Background(), plan.AppCandidate.Name)
		return fmt.Errorf("application candidate health check failed: %w", err)
	}
	if err := promoteCandidate(ctx, dk, plan, preflight); err != nil {
		return err
	}
	currentStopped = false
	_, err = fmt.Fprintf(output, "Promoted healthy application candidate %s\n", plan.AppCurrent.Name)
	return err
}

func preflightTemplateResources(ctx context.Context, dk docker.ManagedClient, plan deploytemplate.Plan) (templatePreflight, error) {
	if plan.ExternalNetwork != "" {
		if _, err := dk.InspectNetwork(ctx, plan.ExternalNetwork); err != nil {
			if errors.Is(err, docker.ErrManagedNotFound) {
				return templatePreflight{}, fmt.Errorf("external serving network %q does not exist", plan.ExternalNetwork)
			}
			return templatePreflight{}, fmt.Errorf("inspect external serving network: %w", err)
		}
	}
	if plan.InternalNetwork != nil {
		if err := inspectManagedResource(ctx, dk.InspectNetwork, *plan.InternalNetwork); err != nil {
			return templatePreflight{}, err
		}
	}
	for _, volume := range plan.Volumes {
		if err := inspectManagedResource(ctx, dk.InspectVolume, volume); err != nil {
			return templatePreflight{}, err
		}
	}
	current, err := inspectTemplateContainer(ctx, dk, plan.AppCurrent, "app", "candidate", "rollback")
	if err != nil {
		return templatePreflight{}, err
	}
	candidate, err := inspectTemplateContainer(ctx, dk, plan.AppCandidate, "app", "candidate", "rollback")
	if err != nil {
		return templatePreflight{}, err
	}
	rollback, err := inspectTemplateContainer(ctx, dk, plan.AppRollback, "app", "candidate", "rollback")
	if err != nil {
		return templatePreflight{}, err
	}
	preflight := templatePreflight{current: current, candidate: candidate, rollback: rollback}
	if plan.Database != nil {
		database, err := inspectTemplateContainer(ctx, dk, *plan.Database, "db")
		if err != nil {
			return templatePreflight{}, err
		}
		preflight.database = database
	}
	return preflight, nil
}

func inspectManagedResource(ctx context.Context, inspect func(context.Context, string) (docker.ManagedResource, error), resource deploytemplate.Resource) error {
	got, err := inspect(ctx, resource.Name)
	if errors.Is(err, docker.ErrManagedNotFound) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect managed %s %q: %w", resource.Kind, resource.Name, err)
	}
	if !hasExactLabels(got.Labels, resource.Labels) {
		return fmt.Errorf("managed %s %q has conflicting ownership", resource.Kind, resource.Name)
	}
	return nil
}

func inspectTemplateContainer(ctx context.Context, dk docker.ManagedClient, resource deploytemplate.Resource, allowedRoles ...string) (bool, error) {
	got, err := dk.InspectContainer(ctx, resource.Name)
	if errors.Is(err, docker.ErrManagedNotFound) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("inspect managed container %q: %w", resource.Name, err)
	}
	if !hasTemplateContainerLabels(got.Labels, resource.Labels, allowedRoles...) {
		return false, fmt.Errorf("managed container %q has conflicting ownership", resource.Name)
	}
	return true, nil
}

func hasExactLabels(got, want map[string]string) bool {
	for key, expected := range want {
		if got[key] != expected {
			return false
		}
	}
	return true
}

func hasTemplateContainerLabels(got, want map[string]string, allowedRoles ...string) bool {
	for key, expected := range want {
		if key == "nori.role" {
			continue
		}
		if got[key] != expected {
			return false
		}
	}
	for _, role := range allowedRoles {
		if got["nori.role"] == role {
			return true
		}
	}
	return false
}

func ensureTemplateResources(ctx context.Context, dk docker.ManagedClient, plan deploytemplate.Plan) error {
	if plan.InternalNetwork != nil {
		if err := dk.EnsureNetwork(ctx, asManagedResource(*plan.InternalNetwork)); err != nil {
			return fmt.Errorf("ensure private network: %w", err)
		}
	}
	for _, volume := range plan.Volumes {
		if err := dk.EnsureVolume(ctx, asManagedResource(volume)); err != nil {
			return fmt.Errorf("ensure volume %q: %w", volume.Name, err)
		}
	}
	return nil
}

func asManagedResource(resource deploytemplate.Resource) docker.ManagedResource {
	return docker.ManagedResource{Name: resource.Name, Labels: resource.Labels}
}

func applicationSpec(plan deploytemplate.Plan, values map[string]string, publishPort bool) docker.ManagedContainerSpec {
	containerEnv := make(map[string]string, len(values)+2)
	for key, value := range values {
		containerEnv[key] = value
	}
	if plan.Proxy != nil {
		containerEnv["VIRTUAL_HOST"] = plan.Proxy.Domain
		containerEnv["VIRTUAL_PORT"] = fmt.Sprintf("%d", plan.Proxy.Port)
	}
	spec := docker.ManagedContainerSpec{
		Name: plan.AppCandidate.Name, Image: plan.AppCandidate.Image, Labels: plan.AppCandidate.Labels,
		Env: sortedEnvironment(containerEnv), Networks: append([]string(nil), plan.AppCandidate.Networks...),
		RestartPolicy: string(plan.AppCandidate.RestartPolicy),
	}
	if publishPort {
		spec.PublishedPort = plan.InternalPort
	}
	for _, mount := range plan.AppCandidate.Mounts {
		spec.Mounts = append(spec.Mounts, docker.ManagedMount{
			Source: fmt.Sprintf("nori-%d-volume-%s", plan.ServiceID, mount.Name), Target: mount.Target,
		})
	}
	return spec
}

func (e *Executor) waitForApplicationHealth(ctx context.Context, plan deploytemplate.Plan) error {
	deadline, cancel := context.WithTimeout(ctx, time.Duration(plan.Health.TimeoutSeconds)*time.Second)
	defer cancel()
	if plan.Health.Command != "" {
		var lastErr error
		for {
			attempt, cancelAttempt := context.WithTimeout(deadline, 5*time.Second)
			lastErr = e.managed.RunProbe(attempt, docker.ManagedProbe{Container: plan.AppCandidate.Name, Command: plan.Health.Command})
			cancelAttempt()
			if lastErr == nil {
				return nil
			}
			select {
			case <-deadline.Done():
				return fmt.Errorf("timed out waiting for health: %w", lastErr)
			case <-time.After(250 * time.Millisecond):
			}
		}
	}
	return waitForHTTPHealth(deadline, plan.Health.URL)
}

func waitForHTTPHealth(ctx context.Context, healthURL string) error {
	client := &http.Client{Timeout: 5 * time.Second}
	var lastErr error
	for {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, healthURL, nil)
		if err != nil {
			return err
		}
		resp, err := client.Do(req)
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode >= http.StatusOK && resp.StatusCode < http.StatusMultipleChoices {
				return nil
			}
			err = fmt.Errorf("health URL returned status %d", resp.StatusCode)
		}
		lastErr = err
		select {
		case <-ctx.Done():
			if lastErr != nil {
				return fmt.Errorf("timed out waiting for health: %w", lastErr)
			}
			return ctx.Err()
		case <-time.After(250 * time.Millisecond):
		}
	}
}

func promoteCandidate(ctx context.Context, dk docker.ManagedClient, plan deploytemplate.Plan, preflight templatePreflight) error {
	if preflight.rollback {
		if err := dk.RemoveContainer(ctx, plan.AppRollback.Name); err != nil {
			return fmt.Errorf("remove stale rollback container: %w", err)
		}
	}
	renamedCurrent := false
	if preflight.current {
		if err := dk.RenameContainer(ctx, plan.AppCurrent.Name, plan.AppRollback.Name); err != nil {
			return fmt.Errorf("preserve current application for rollback: %w", err)
		}
		renamedCurrent = true
	}
	if err := dk.RenameContainer(ctx, plan.AppCandidate.Name, plan.AppCurrent.Name); err != nil {
		if renamedCurrent {
			_ = dk.RenameContainer(context.Background(), plan.AppRollback.Name, plan.AppCurrent.Name)
		}
		return fmt.Errorf("promote application candidate: %w", err)
	}
	if renamedCurrent {
		if err := dk.RemoveContainer(ctx, plan.AppRollback.Name); err != nil {
			return fmt.Errorf("retire previous application after promotion: %w", err)
		}
	}
	return nil
}

func (e *Executor) ensurePostgres(ctx context.Context, svc *store.Service, plan deploytemplate.Plan, runtime postgresRuntime, exists bool, values map[string]string, output io.Writer) error {
	if plan.Database == nil || plan.Postgres == nil || plan.InternalNetwork == nil {
		return errors.New("incomplete PostgreSQL deployment plan")
	}
	if !exists {
		if _, err := fmt.Fprintf(output, "Creating PostgreSQL container %s\n", plan.Database.Name); err != nil {
			return err
		}
		databaseVolume := fmt.Sprintf("nori-%d-volume-postgres-data", plan.ServiceID)
		spec := docker.ManagedContainerSpec{
			Name: plan.Database.Name, Image: plan.Database.Image, Labels: plan.Database.Labels,
			RestartPolicy: string(deploytemplate.RestartUnlessStopped),
			Networks:      append([]string(nil), plan.Database.Networks...),
			Env: []string{
				"POSTGRES_DB=" + plan.Postgres.Database,
				"POSTGRES_USER=" + plan.Postgres.User,
				plan.Postgres.PasswordEnv + "=" + runtime.password,
			},
			Mounts: []docker.ManagedMount{{Source: databaseVolume, Target: "/var/lib/postgresql/data"}},
		}
		if err := e.managed.CreateContainer(ctx, spec); err != nil {
			return fmt.Errorf("create PostgreSQL container: %w", err)
		}
		if err := e.managed.StartContainer(ctx, plan.Database.Name); err != nil {
			_ = e.managed.RemoveContainer(context.Background(), plan.Database.Name)
			return fmt.Errorf("start PostgreSQL container: %w", err)
		}
	} else {
		database, err := e.managed.InspectContainer(ctx, plan.Database.Name)
		if err != nil {
			return fmt.Errorf("inspect PostgreSQL container before readiness check: %w", err)
		}
		storedPassword, ok := containerEnvironmentValue(database.Env, plan.Postgres.PasswordEnv)
		if !ok || storedPassword != runtime.password {
			return errors.New("PostgreSQL password changed; recreate the managed database container explicitly before deploying")
		}
		if database.State != "running" {
			if _, err := fmt.Fprintf(output, "Starting existing PostgreSQL container %s\n", plan.Database.Name); err != nil {
				return err
			}
			if err := e.managed.StartContainer(ctx, plan.Database.Name); err != nil {
				return fmt.Errorf("start existing PostgreSQL container: %w", err)
			}
		}
	}
	if _, err := fmt.Fprintf(output, "Running authenticated PostgreSQL readiness probe\n"); err != nil {
		return err
	}
	probeCtx, cancel := context.WithTimeout(ctx, time.Duration(plan.Postgres.ReadyTimeoutSeconds)*time.Second)
	defer cancel()
	command := fmt.Sprintf("psql \"$%s\" -v ON_ERROR_STOP=1 -c 'SELECT 1'", plan.Postgres.ConnectionURLEnv)
	var lastErr error
	for {
		attemptCtx, cancelAttempt := context.WithTimeout(probeCtx, 10*time.Second)
		lastErr = e.managed.RunProbe(attemptCtx, docker.ManagedProbe{
			Image: plan.Database.Image, Network: plan.InternalNetwork.Name,
			Env: []string{plan.Postgres.ConnectionURLEnv + "=" + runtime.databaseURL}, Command: command,
		})
		cancelAttempt()
		if lastErr == nil {
			break
		}
		select {
		case <-probeCtx.Done():
			return fmt.Errorf("PostgreSQL readiness probe: %w", lastErr)
		case <-time.After(time.Second):
		}
	}
	state, err := e.store.GetTemplateState(ctx, svc.ID)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return fmt.Errorf("read managed database state: %w", err)
	}
	if state == nil {
		if err := e.store.RecordTemplateDatabaseIdentity(ctx, svc.ID, runtime.fingerprint); err != nil {
			return err
		}
	}
	return nil
}

func containerEnvironmentValue(env []string, key string) (string, bool) {
	prefix := key + "="
	for _, item := range env {
		if strings.HasPrefix(item, prefix) {
			return strings.TrimPrefix(item, prefix), true
		}
	}
	return "", false
}

func postgresEnvironment(plan deploytemplate.Plan, values map[string]string) (postgresRuntime, error) {
	if plan.Postgres == nil || plan.Database == nil {
		return postgresRuntime{}, errors.New("incomplete PostgreSQL deployment plan")
	}
	config := plan.Postgres
	if values["POSTGRES_DB"] != config.Database {
		return postgresRuntime{}, errors.New("POSTGRES_DB must match the configured PostgreSQL database")
	}
	if values["POSTGRES_USER"] != config.User {
		return postgresRuntime{}, errors.New("POSTGRES_USER must match the configured PostgreSQL user")
	}
	password := values[config.PasswordEnv]
	if password == "" {
		return postgresRuntime{}, fmt.Errorf("%s is required for PostgreSQL", config.PasswordEnv)
	}
	databaseURL := values[config.ConnectionURLEnv]
	parsed, err := url.Parse(databaseURL)
	if err != nil || (parsed.Scheme != "postgres" && parsed.Scheme != "postgresql") || parsed.User == nil || parsed.Hostname() != plan.Database.Name || strings.TrimPrefix(parsed.EscapedPath(), "/") != config.Database || parsed.User.Username() != config.User {
		return postgresRuntime{}, errors.New("application connection URL must target the configured private PostgreSQL database")
	}
	urlPassword, ok := parsed.User.Password()
	if !ok || urlPassword != password {
		return postgresRuntime{}, errors.New("application connection URL password must match the configured PostgreSQL password binding")
	}
	identity := postgresIdentity(config)
	return postgresRuntime{fingerprint: identity, databaseURL: databaseURL, password: password}, nil
}

func postgresIdentity(config *deploytemplate.PostgresConfig) string {
	image := config.Image
	if colon := strings.LastIndex(image, ":"); colon >= 0 {
		tag := image[colon+1:]
		if dot := strings.IndexByte(tag, '.'); dot >= 0 {
			image = image[:colon+1] + tag[:dot]
		}
	}
	sum := sha256.Sum256([]byte(strings.Join([]string{image, config.Database, config.User}, "\x00")))
	return fmt.Sprintf("%x", sum[:])
}

func deploymentEnvironment(env []string) map[string]string {
	values := map[string]string{}
	for index, entry := range env {
		if strings.HasPrefix(entry, "ENV_FILE=") {
			for _, variable := range env[index+1:] {
				key, value, ok := strings.Cut(variable, "=")
				if ok {
					values[key] = value
				}
			}
			break
		}
	}
	return values
}

func sortedEnvironment(values map[string]string) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	env := make([]string, 0, len(keys))
	for _, key := range keys {
		env = append(env, key+"="+values[key])
	}
	return env
}

func redactDeploymentText(text string, env []string) string {
	for index, entry := range env {
		if !strings.HasPrefix(entry, "ENV_FILE=") {
			continue
		}
		var redactor envfile.Redactor
		if err := redactor.Add(strings.Join(env[index+1:], "\n")); err == nil {
			return redactor.Redact(text)
		}
		break
	}
	return text
}

func shortDigest(digest string) string {
	const prefix = "sha256:"
	if strings.HasPrefix(digest, prefix) && len(digest) > len(prefix)+12 {
		return digest[:len(prefix)+12]
	}
	if len(digest) > 19 {
		return digest[:19]
	}
	return digest
}

// buildEnv assembles the script environment and materializes the service's
// resolved env vars as a docker --env-file (referenced by $ENV_FILE). The
// caller owns the returned path and must remove it once the deploy finishes.
func (e *Executor) buildEnv(ctx context.Context, svc *store.Service, digest string) ([]string, string, error) {
	content, err := e.store.GetEnvFile(ctx, svc.ID)
	if err != nil {
		return nil, "", err
	}
	fileEnv, err := envfile.Parse(content)
	if err != nil {
		return nil, "", err
	}
	env := []string{
		fmt.Sprintf("SERVICE=%s", svc.Name),
		fmt.Sprintf("IMAGE=%s", svc.WatchedImage),
		fmt.Sprintf("TARGET_DIGEST=%s", digest),
		fmt.Sprintf("TARGET_IMAGE=%s", pinnedImage(svc.WatchedImage, digest)),
	}
	if svc.IsSelf {
		for _, key := range []string{"NORI_CONFIG_VOLUME", "NORI_SELF_IMAGE"} {
			value := os.Getenv(key)
			if value == "" {
				return nil, "", fmt.Errorf("self-update requires %s", key)
			}
			env = append(env, key+"="+value)
		}
	}
	// Materialize last, after all validation, so failed builds leave no file.
	envFile, err := writeEnvFile(fileEnv)
	if err != nil {
		return nil, "", err
	}
	env = append(env, "ENV_FILE="+envFile)
	env = append(env, fileEnv...)
	return env, envFile, nil
}

// writeEnvFile writes the resolved "KEY=VALUE" pairs to a private temp file in
// docker --env-file format. It always creates a file, even when there are no
// vars, so $ENV_FILE is a usable path on every deploy.
func writeEnvFile(vars []string) (string, error) {
	f, err := os.CreateTemp("", "nori-env-*.env")
	if err != nil {
		return "", err
	}
	defer f.Close()
	var b strings.Builder
	for _, kv := range vars {
		b.WriteString(kv)
		b.WriteByte('\n')
	}
	if _, err := f.WriteString(b.String()); err != nil {
		os.Remove(f.Name())
		return "", err
	}
	return f.Name(), nil
}

func removeEnvFile(path string) {
	if path != "" {
		os.Remove(path)
	}
}

func (e *Executor) finish(ctx context.Context, d *store.Deployment, status string, extra string) {
	d.Status = status
	if extra != "" {
		d.Log += extra
	}
	now := time.Now().UTC()
	d.FinishedAt = &now
	_ = e.store.UpdateDeployment(ctx, d)
}

func (e *Executor) lockFor(id int64) *sync.Mutex {
	v, _ := e.locks.LoadOrStore(id, &sync.Mutex{})
	return v.(*sync.Mutex)
}

func (e *Executor) inCooldown(serviceID int64, digest string) bool {
	v, ok := e.failures.Load(serviceID)
	if !ok {
		return false
	}
	rec := v.(failureRecord)
	return rec.digest == digest && time.Now().Before(rec.until)
}

func (e *Executor) recordFailure(serviceID int64, digest string) {
	e.failures.Store(serviceID, failureRecord{digest: digest, until: time.Now().Add(e.cooldown)})
}

// alertFailure sends a service-down notification. The call has its own
// timeout so a slow notifier cannot stall the deploy pipeline, and the
// notifier is expected to swallow send errors itself (see notify.LogFailures)
// so a Twilio outage can never fail a deploy. Which channels receive which
// events is decided downstream by the notifier chain (notify.Route); the
// executor forwards unconditionally.
func (e *Executor) alertFailure(svc *store.Service, deploy *store.Deployment, cause error) {
	if e.notify == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	evt := notify.Event{
		BotName:      e.botName,
		ServiceName:  svc.Name,
		DeploymentID: deploy.ID,
		Trigger:      deploy.Trigger,
		Digest:       shortDigest(deploy.TargetDigest),
		Reason:       truncateReason(cause.Error()),
	}
	_ = e.notify.NotifyServiceDown(ctx, evt)
}

// alertSuccess sends a deploy-success notification with the same timeout and
// error-swallowing contract as alertFailure.
func (e *Executor) alertSuccess(svc *store.Service, deploy *store.Deployment) {
	if e.notify == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	evt := notify.Event{
		BotName:      e.botName,
		ServiceName:  svc.Name,
		DeploymentID: deploy.ID,
		Trigger:      deploy.Trigger,
		Digest:       shortDigest(deploy.TargetDigest),
	}
	_ = e.notify.NotifyDeploySuccess(ctx, evt)
}

// truncateReason keeps the SMS body short. Twilio rejects bodies longer than
// 1600 chars; an unbounded script error log could exceed that.
func truncateReason(s string) string {
	const max = 200
	if len(s) <= max {
		return s
	}
	return s[:max-1] + "…"
}

func (e *Executor) clearFailure(serviceID int64) {
	e.failures.Delete(serviceID)
}
