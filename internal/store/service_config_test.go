package store

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestSaveServiceConfigAtomic(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	svc := &Service{Name: "app", WatchedImage: "nginx:latest", Policy: PolicyManual, DeployScript: "true"}
	env := "SECRET=original\n"
	if err := st.SaveServiceConfig(ctx, svc, &env, nil); err != nil {
		t.Fatal(err)
	}
	var raw []byte
	if err := st.db.QueryRow(`SELECT content FROM service_env WHERE service_id=?`, svc.ID).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "original") {
		t.Fatal("plaintext secret persisted")
	}
	// Force a failure in the second half of the transaction.
	if _, err := st.db.Exec(`CREATE TRIGGER fail_env BEFORE UPDATE ON service_env BEGIN SELECT RAISE(ABORT, 'test'); END`); err != nil {
		t.Fatal(err)
	}
	previous := *svc
	svc.WatchedImage = "nginx:alpine"
	env = "SECRET=changed\n"
	if err := st.SaveServiceConfig(ctx, svc, &env, &previous); err == nil {
		t.Fatal("expected environment failure")
	}
	got, err := st.GetService(ctx, svc.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.WatchedImage != "nginx:latest" {
		t.Fatal("partial config committed")
	}
	gotEnv, err := st.GetEnvFile(ctx, svc.ID)
	if err != nil {
		t.Fatal(err)
	}
	if gotEnv != "SECRET=original\n" {
		t.Fatal("environment changed")
	}
	missing := &Service{ID: 999, Name: "missing"}
	if err := st.SaveServiceConfig(ctx, missing, &env, missing); !errors.Is(err, ErrServiceConflict) {
		t.Fatalf("missing service: %v", err)
	}
}

func TestSaveServiceConfigCreateRollback(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	if _, err := st.db.Exec(`CREATE TRIGGER fail_env BEFORE INSERT ON service_env BEGIN SELECT RAISE(ABORT, 'test'); END`); err != nil {
		t.Fatal(err)
	}
	svc := &Service{Name: "app", WatchedImage: "nginx", Policy: PolicyManual}
	env := "A=B"
	if err := st.SaveServiceConfig(ctx, svc, &env, nil); err == nil {
		t.Fatal("expected failure")
	}
	if svc.ID != 0 {
		t.Fatal("ID changed after rollback")
	}
	if _, err := st.GetServiceByName(ctx, "app"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("orphan service: %v", err)
	}
}

func TestSaveServiceConfigRejectsStaleUpdate(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	svc := &Service{Name: "app", WatchedImage: "nginx:latest", Policy: PolicyManual, DeployScript: "true"}
	if err := st.SaveServiceConfig(ctx, svc, nil, nil); err != nil {
		t.Fatal(err)
	}
	before := *svc
	first, second := before, before
	first.HealthURL = "https://example.com/health"
	if err := st.SaveServiceConfig(ctx, &first, nil, &before); err != nil {
		t.Fatal(err)
	}
	second.WatchedImage = "nginx:alpine"
	env := "SECRET=must-not-commit"
	if err := st.SaveServiceConfig(ctx, &second, &env, &before); !errors.Is(err, ErrServiceConflict) {
		t.Fatalf("stale save: %v", err)
	}
	got, _ := st.GetService(ctx, svc.ID)
	if got.HealthURL != first.HealthURL || got.WatchedImage != before.WatchedImage {
		t.Fatal("stale update lost prior change")
	}
	gotEnv, _ := st.GetEnvFile(ctx, svc.ID)
	if gotEnv != "" {
		t.Fatal("conflicting update saved environment")
	}
}

func TestSaveServiceConfigAdvancesVersionAndRejectsStaleEnvironment(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	svc := &Service{Name: "app", WatchedImage: "nginx:latest", Policy: PolicyManual, DeployScript: "true"}
	initialEnv := "TOKEN=first\n"
	if err := st.SaveServiceConfig(ctx, svc, &initialEnv, nil); err != nil {
		t.Fatal(err)
	}
	if svc.ConfigVersion != 1 {
		t.Fatalf("created config version = %d, want 1", svc.ConfigVersion)
	}

	stale := *svc
	current := *svc
	current.DeployScript = "echo current"
	if err := st.SaveServiceConfig(ctx, &current, nil, &stale); err != nil {
		t.Fatal(err)
	}
	if current.ConfigVersion != 2 {
		t.Fatalf("updated config version = %d, want 2", current.ConfigVersion)
	}

	staleEnv := "TOKEN=stale\n"
	if err := st.SaveServiceConfig(ctx, &stale, &staleEnv, &stale); !errors.Is(err, ErrServiceConflict) {
		t.Fatalf("stale environment save = %v, want ErrServiceConflict", err)
	}
	got, err := st.GetEnvFile(ctx, svc.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got != initialEnv {
		t.Fatalf("environment after stale save = %q, want %q", got, initialEnv)
	}
}
