package deploytemplate

import (
	"strings"
	"testing"
)

func TestBuildPlanSingleContainerUsesPinnedImageAndOwnedResources(t *testing.T) {
	plan, err := BuildPlan(Input{
		ServiceID:   42,
		ServiceName: "blog",
		TargetImage: "ghcr.io/acme/blog@sha256:abc",
		Config: Config{
			Mode:           ModeSingleContainer,
			Version:        1,
			InternalPort:   8080,
			RestartPolicy:  RestartUnlessStopped,
			ServingNetwork: "proxy",
			Volumes:        []VolumeMount{{Name: "uploads", Target: "/app/uploads"}},
			Health:         HealthCheck{URL: "http://127.0.0.1:8080/health", TimeoutSeconds: 30},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if plan.AppCandidate.Name != "nori-42-app-candidate" {
		t.Fatalf("candidate name = %q", plan.AppCandidate.Name)
	}
	if plan.AppCandidate.Image != "ghcr.io/acme/blog@sha256:abc" {
		t.Fatalf("candidate image = %q", plan.AppCandidate.Image)
	}
	for key, want := range map[string]string{
		"nori.service":    "blog",
		"nori.template":   "1",
		"nori.service-id": "42",
		"nori.role":       "candidate",
	} {
		if got := plan.AppCandidate.Labels[key]; got != want {
			t.Fatalf("candidate label %s = %q, want %q", key, got, want)
		}
	}
	if len(plan.Volumes) != 1 || plan.Volumes[0].Name != "nori-42-volume-uploads" {
		t.Fatalf("volumes = %+v", plan.Volumes)
	}
	if len(plan.Actions) == 0 || !strings.Contains(plan.Actions[0].Description, "Pull ghcr.io/acme/blog@sha256:abc") {
		t.Fatalf("first action = %+v", plan.Actions)
	}
	preview := plan.Preview()
	if strings.Contains(preview, "SECRET=top-secret") {
		t.Fatalf("preview leaked a value: %q", preview)
	}
}

func TestBuildPlanPostgresRejectsMutableImageAndUnsafeHealth(t *testing.T) {
	_, err := BuildPlan(Input{
		ServiceID: 1, ServiceName: "api", TargetImage: "example/api@sha256:abc",
		Config: Config{
			Mode: ModePostgres, Version: 1, InternalPort: 8080, RestartPolicy: RestartAlways,
			Health:   HealthCheck{Command: "curl -f http://localhost/health", TimeoutSeconds: 0},
			Postgres: &PostgresConfig{Image: "postgres:latest", Database: "api", User: "api", PasswordEnv: "POSTGRES_PASSWORD", ConnectionURLEnv: "DATABASE_URL"},
		},
	})
	if err == nil {
		t.Fatal("expected invalid postgres template")
	}
	if !strings.Contains(err.Error(), "postgres image") {
		t.Fatalf("error = %v", err)
	}
}

func TestBuildPlanPostgresRejectsShellSyntaxInImage(t *testing.T) {
	_, err := BuildPlan(Input{
		ServiceID: 1, ServiceName: "api", TargetImage: "example/api@sha256:abc",
		Config: Config{
			Mode: ModePostgres, Version: 1, InternalPort: 8080, RestartPolicy: RestartAlways,
			Health:   HealthCheck{Command: "true", TimeoutSeconds: 5},
			Postgres: &PostgresConfig{Image: "postgres:16.4$(touch-pwned)", Database: "api", User: "api", PasswordEnv: "POSTGRES_PASSWORD", ConnectionURLEnv: "DATABASE_URL", ReadyTimeoutSeconds: 5},
		},
	})
	if err == nil {
		t.Fatal("expected shell syntax in postgres image to be rejected")
	}
	if !strings.Contains(err.Error(), "postgres image") {
		t.Fatalf("error = %v", err)
	}
}

func TestRenderCustomScriptUsesRuntimeReferencesWithoutSecretValues(t *testing.T) {
	plan, err := BuildPlan(Input{
		ServiceID: 7, ServiceName: "api", TargetImage: "example/api@sha256:abc",
		Config: Config{
			Mode: ModeSingleContainer, Version: 1, InternalPort: 3000, RestartPolicy: RestartAlways,
			ServingNetwork: "proxy",
			Proxy:          &ProxyConfig{Network: "proxy", Domain: "api.example.test", Port: 3000},
			Health:         HealthCheck{Command: "true", TimeoutSeconds: 15},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	script, err := plan.RenderCustomScript()
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"$SERVICE", "$TARGET_IMAGE", "$ENV_FILE", "nori.service=\"$SERVICE\""} {
		if !strings.Contains(script, want) {
			t.Fatalf("script missing %q:\n%s", want, script)
		}
	}
	for _, want := range []string{
		"health_deadline=$((SECONDS+15))",
		"timeout 1s docker exec 'nori-7-app-candidate'",
		"docker rm -f \"nori-7-app-rollback\"",
		"--env VIRTUAL_HOST='api.example.test' --env VIRTUAL_PORT=3000",
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("script missing bounded promotion safeguard %q:\n%s", want, script)
		}
	}
	if strings.Contains(script, "top-secret") || strings.Contains(script, "set -x") {
		t.Fatalf("unsafe script:\n%s", script)
	}
}

func TestRenderCustomScriptChecksOwnershipBeforeReusingResources(t *testing.T) {
	plan, err := BuildPlan(Input{
		ServiceID: 7, ServiceName: "api", TargetImage: "example/api@sha256:abc",
		Config: Config{
			Mode: ModeSingleContainer, Version: 1, InternalPort: 3000, RestartPolicy: RestartAlways,
			Volumes: []VolumeMount{{Name: "uploads", Target: "/app/uploads"}},
			Health:  HealthCheck{Command: "true", TimeoutSeconds: 15},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	script, err := plan.RenderCustomScript()
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"check_owned_resource volume 'nori-7-volume-uploads' 'data-volume'",
		"check_owned_container 'nori-7-app-candidate'",
		"check_owned_container 'nori-7-app'",
		"check_owned_container 'nori-7-app-rollback'",
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("script missing ownership check %q:\n%s", want, script)
		}
	}
}

func TestRenderPostgresCustomScriptMaterializesDatabaseBeforeApp(t *testing.T) {
	plan, err := BuildPlan(Input{
		ServiceID: 8, ServiceName: "api", TargetImage: "example/api@sha256:abc",
		Config: Config{
			Mode: ModePostgres, Version: 1, InternalPort: 8080, RestartPolicy: RestartAlways,
			Health: HealthCheck{Command: "true", TimeoutSeconds: 15},
			Postgres: &PostgresConfig{
				Image: "postgres:16.4", Database: "api", User: "api",
				PasswordEnv: "POSTGRES_PASSWORD", ConnectionURLEnv: "DATABASE_URL", ReadyTimeoutSeconds: 30,
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	script, err := plan.RenderCustomScript()
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"nori-8-postgres", "POSTGRES_PASSWORD", "nori-8-db-internal", "docker pull 'postgres:16.4'"} {
		if !strings.Contains(script, want) {
			t.Fatalf("script missing %q:\n%s", want, script)
		}
	}
	for _, want := range []string{
		"db_deadline=$((SECONDS+30))",
		"timeout 1s docker exec 'nori-8-postgres'",
		"--restart \"unless-stopped\"",
		"--env POSTGRES_DB --env POSTGRES_USER --env POSTGRES_PASSWORD",
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("script missing postgres/proxy safeguard %q:\n%s", want, script)
		}
	}
	if strings.Contains(script, "--env-file \"$ENV_FILE\" postgres:16.4") {
		t.Fatalf("database container must not receive the full application environment:\n%s", script)
	}
	if strings.Index(script, "docker pull 'postgres:16.4'") > strings.Index(script, "nori-8-postgres") {
		t.Fatalf("database must be pulled before it is created:\n%s", script)
	}
}

func TestRenderCustomScriptPublishesHostPortWithoutExternalNetwork(t *testing.T) {
	plan, err := BuildPlan(Input{
		ServiceID: 9, ServiceName: "api", TargetImage: "example/api@sha256:abc",
		Config: Config{
			Mode: ModeSingleContainer, Version: 1, InternalPort: 8080,
			RestartPolicy: RestartUnlessStopped,
			Health:        HealthCheck{Command: "true", TimeoutSeconds: 15},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	script, err := plan.RenderCustomScript()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(script, " -p 8080:8080") {
		t.Fatalf("custom conversion must publish the host port without an external network:\n%s", script)
	}
}
