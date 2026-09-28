package store

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestEnvVar_SecretEncryptedAtRest(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	svc := &Service{Name: "app", WatchedImage: "ghcr.io/me/app:latest", Policy: PolicyManual}
	if err := st.CreateService(ctx, svc); err != nil {
		t.Fatal(err)
	}

	secret := "hunter2"
	if err := st.SetEnvVar(ctx, &EnvVar{ServiceID: svc.ID, Key: "DB_PASS", Value: secret, IsSecret: true}); err != nil {
		t.Fatalf("SetEnvVar: %v", err)
	}

	// Raw column must not equal the plaintext.
	var raw []byte
	if err := st.db.QueryRowContext(ctx, `SELECT value FROM env_var WHERE key='DB_PASS'`).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	if string(raw) == secret {
		t.Fatal("secret stored in plaintext")
	}

	// Read-back decrypts.
	vars, err := st.ListEnvVars(ctx, svc.ID)
	if err != nil {
		t.Fatalf("ListEnvVars: %v", err)
	}
	if len(vars) != 1 || vars[0].Value != secret {
		t.Fatalf("decrypt mismatch: %+v", vars)
	}
}

func TestEnvVar_NonSecretPlaintext(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	svc := &Service{Name: "app", WatchedImage: "x", Policy: PolicyManual}
	st.CreateService(ctx, svc)
	if err := st.SetEnvVar(ctx, &EnvVar{ServiceID: svc.ID, Key: "PORT", Value: "8080"}); err != nil {
		t.Fatal(err)
	}
	var raw []byte
	st.db.QueryRowContext(ctx, `SELECT value FROM env_var WHERE key='PORT'`).Scan(&raw)
	if string(raw) != "8080" {
		t.Fatalf("non-secret should be plaintext, got %q", raw)
	}
}

func TestEnvFile_EncryptedAtRestAndRoundTrips(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	svc := &Service{Name: "app", WatchedImage: "x", Policy: PolicyManual}
	if err := st.CreateService(ctx, svc); err != nil {
		t.Fatal(err)
	}

	content := "# production\nDB_PASSWORD=very-secret\nPORT=8080\n"
	if err := st.SetEnvFile(ctx, svc.ID, content); err != nil {
		t.Fatal(err)
	}

	var raw []byte
	if err := st.db.QueryRowContext(ctx, `SELECT content FROM service_env WHERE service_id=?`, svc.ID).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "very-secret") {
		t.Fatal("env file stored in plaintext")
	}

	got, err := st.GetEnvFile(ctx, svc.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got != content {
		t.Fatalf("GetEnvFile() = %q, want %q", got, content)
	}
}

func TestEnvFile_ReadsLegacyPerVariableRows(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	svc := &Service{Name: "legacy", WatchedImage: "x", Policy: PolicyManual}
	if err := st.CreateService(ctx, svc); err != nil {
		t.Fatal(err)
	}
	for _, item := range []*EnvVar{
		{ServiceID: svc.ID, Key: "PORT", Value: "8080"},
		{ServiceID: svc.ID, Key: "DB_PASSWORD", Value: "secret value", IsSecret: true},
	} {
		if err := st.SetEnvVar(ctx, item); err != nil {
			t.Fatal(err)
		}
	}

	content, err := st.GetEnvFile(ctx, svc.ID)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"PORT=8080", "DB_PASSWORD=\"secret value\""} {
		if !strings.Contains(content, want) {
			t.Errorf("converted dotenv file missing %q: %q", want, content)
		}
	}
	if err := st.SetEnvFile(ctx, svc.ID, content); err != nil {
		t.Fatal(err)
	}
	var legacyCount int
	if err := st.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM env_var WHERE service_id=?`, svc.ID).Scan(&legacyCount); err != nil {
		t.Fatal(err)
	}
	if legacyCount != 0 {
		t.Fatalf("legacy env rows were not removed: %d", legacyCount)
	}
}

func TestEnvTemplateAndSecretUpdates(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	svc := &Service{Name: "template", WatchedImage: "x", Policy: PolicyManual}
	if err := st.CreateService(ctx, svc); err != nil {
		t.Fatal(err)
	}
	if err := st.SetEnvVar(ctx, &EnvVar{ServiceID: svc.ID, Key: "TOKEN", Value: "legacy", IsSecret: true}); err != nil {
		t.Fatal(err)
	}
	if err := st.SetEnvTemplate(ctx, svc.ID, "TOKEN='[REDACTED]'\nNEW='[REDACTED]'"); err != nil {
		t.Fatal(err)
	}
	if err := st.SetEnvSecret(ctx, svc.ID, "TOKEN", "rotated"); err != nil {
		t.Fatal(err)
	}
	// A template read before rotation must preserve the current value on save.
	svc, err := st.GetService(ctx, svc.ID)
	if err != nil {
		t.Fatal(err)
	}
	previous := *svc
	if err := st.SaveServiceConfigTemplate(ctx, svc, ptrEnv("TOKEN='[REDACTED]'\nNEW='[REDACTED]'"), &previous); err != nil {
		t.Fatal(err)
	}
	content, err := st.GetEnvFile(ctx, svc.ID)
	if err != nil || content != "NEW=\"\"\nTOKEN=\"rotated\"\n" {
		t.Fatal("template did not preserve current values")
	}
	for _, err := range []error{
		st.SetEnvSecret(ctx, svc.ID, "UNKNOWN", "never-insert"),
		st.SetEnvSecret(ctx, svc.ID, "TOKEN", strings.Repeat("x", 128*1024)),
		st.SetEnvTemplate(ctx, svc.ID, "TOKEN=plaintext"),
	} {
		if err == nil {
			t.Fatal("invalid mutation succeeded")
		}
	}
	after, _ := st.GetEnvFile(ctx, svc.ID)
	if after != content {
		t.Fatal("failed mutation changed environment")
	}
	var raw []byte
	if err := st.db.QueryRowContext(ctx, `SELECT content FROM service_env WHERE service_id=?`, svc.ID).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "rotated") {
		t.Fatal("secret not encrypted")
	}
	if err := st.SetEnvTemplate(ctx, svc.ID, "NEW='[REDACTED]'"); err != nil {
		t.Fatal(err)
	}
	if err := st.SetEnvSecret(ctx, svc.ID, "TOKEN", "removed"); err == nil {
		t.Fatal("removed key reintroduced")
	}
}

func TestEnvironmentWritesAdvanceServiceVersion(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	svc := &Service{Name: "app", WatchedImage: "nginx", Policy: PolicyManual}
	if err := st.CreateService(ctx, svc); err != nil {
		t.Fatal(err)
	}
	if svc.ConfigVersion != 1 {
		t.Fatalf("created config version = %d, want 1", svc.ConfigVersion)
	}
	if err := st.SetEnvFile(ctx, svc.ID, "TOKEN=first\n"); err != nil {
		t.Fatal(err)
	}
	if err := st.SetEnvTemplate(ctx, svc.ID, "TOKEN='[REDACTED]'\n"); err != nil {
		t.Fatal(err)
	}
	if err := st.SetEnvSecret(ctx, svc.ID, "TOKEN", "second"); err != nil {
		t.Fatal(err)
	}
	got, err := st.GetService(ctx, svc.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.ConfigVersion != 4 {
		t.Fatalf("config version after environment writes = %d, want 4", got.ConfigVersion)
	}
}

func TestVersionedSecretWriteRejectsStaleGeneration(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	svc := &Service{Name: "app", WatchedImage: "nginx", Policy: PolicyManual}
	if err := st.CreateService(ctx, svc); err != nil {
		t.Fatal(err)
	}
	if err := st.SetEnvFile(ctx, svc.ID, "TOKEN=first\n"); err != nil {
		t.Fatal(err)
	}
	current, err := st.GetService(ctx, svc.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.SetEnvSecretAtVersion(ctx, svc.ID, current.ConfigVersion, "TOKEN", "second"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.SetEnvSecretAtVersion(ctx, svc.ID, current.ConfigVersion, "TOKEN", "stale"); !errors.Is(err, ErrServiceConflict) {
		t.Fatalf("stale secret write = %v, want ErrServiceConflict", err)
	}
	got, err := st.GetEnvFile(ctx, svc.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got != "TOKEN=\"second\"\n" {
		t.Fatalf("environment after stale secret write = %q, want current value", got)
	}
}

func ptrEnv(v string) *string { return &v }
