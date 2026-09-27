package store

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
)

func testStore(t *testing.T) *Store {
	t.Helper()
	path := filepath.Join(t.TempDir(), "test.db")
	st, err := Open(path, make([]byte, 32))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

func TestServiceCRUD(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	svc := &Service{Name: "blog", WatchedImage: "ghcr.io/me/blog:latest", Policy: PolicyManual}
	if err := st.CreateService(ctx, svc); err != nil {
		t.Fatalf("CreateService: %v", err)
	}
	if svc.ID == 0 {
		t.Fatal("ID not set")
	}
	if svc.CreatedAt.IsZero() {
		t.Fatal("CreatedAt not set")
	}

	got, err := st.GetService(ctx, svc.ID)
	if err != nil {
		t.Fatalf("GetService: %v", err)
	}
	if got.Name != "blog" || got.WatchedImage != "ghcr.io/me/blog:latest" || got.Policy != PolicyManual {
		t.Fatalf("round-trip mismatch: %+v", got)
	}

	list, err := st.ListServices(ctx)
	if err != nil {
		t.Fatalf("ListServices: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("len = %d, want 1", len(list))
	}
}

func TestCreateServicePersistsDeploymentConfig(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	wantConfig := `{"version":1,"port":8080}`
	svc := &Service{
		Name:           "managed-blog",
		WatchedImage:   "ghcr.io/me/blog:latest",
		Policy:         PolicyManual,
		DeploymentMode: DeploymentModeSingleContainer,
		TemplateConfig: wantConfig,
	}
	if err := st.CreateService(ctx, svc); err != nil {
		t.Fatal(err)
	}

	got, err := st.GetService(ctx, svc.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.DeploymentMode != DeploymentModeSingleContainer || got.TemplateConfig != wantConfig {
		t.Fatalf("deployment config = (%q, %q), want (%q, %q)", got.DeploymentMode, got.TemplateConfig, DeploymentModeSingleContainer, wantConfig)
	}
}

func TestUpdateServicePersistsDeploymentConfig(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	svc := &Service{Name: "managed-update", WatchedImage: "ghcr.io/me/blog:latest", Policy: PolicyManual}
	if err := st.CreateService(ctx, svc); err != nil {
		t.Fatal(err)
	}

	wantConfig := `{"version":1,"database":"blog"}`
	svc.DeploymentMode = DeploymentModePostgres
	svc.TemplateConfig = wantConfig
	if err := st.UpdateService(ctx, svc); err != nil {
		t.Fatal(err)
	}
	got, err := st.GetService(ctx, svc.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.DeploymentMode != DeploymentModePostgres || got.TemplateConfig != wantConfig {
		t.Fatalf("deployment config = (%q, %q), want (%q, %q)", got.DeploymentMode, got.TemplateConfig, DeploymentModePostgres, wantConfig)
	}
}

func TestGetService_NotFound(t *testing.T) {
	st := testStore(t)
	if _, err := st.GetService(context.Background(), 999); err != ErrNotFound {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}

func TestEnsureSelfServiceIsManagedAndKeepsPolicy(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	self, err := st.EnsureSelfService(ctx, "ghcr.io/acme/nori:latest")
	if err != nil {
		t.Fatal(err)
	}
	if !self.IsSelf || self.Name != SelfServiceName || self.Policy != PolicyManual {
		t.Fatalf("unexpected self service: %+v", self)
	}
	if self.DeployScript != SelfDeployScript {
		t.Fatal("self service did not receive managed handoff script")
	}
	self.Policy = PolicyScheduled
	self.CronExpr = "0 3 * * *"
	if err := st.UpdateService(ctx, self); err != nil {
		t.Fatal(err)
	}
	again, err := st.EnsureSelfService(ctx, "ghcr.io/acme/nori:v2")
	if err != nil {
		t.Fatal(err)
	}
	if again.ID != self.ID || again.Policy != PolicyScheduled || again.WatchedImage != "ghcr.io/acme/nori:v2" {
		t.Fatalf("self service was not safely refreshed: %+v", again)
	}
}

func TestEnsureSelfServiceRenamesPersistedManagedService(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	legacy := &Service{
		Name:         "legacy-self",
		WatchedImage: "ghcr.io/acme/legacy:latest",
		Policy:       PolicyManual,
		DeployScript: "exit 1",
		IsSelf:       true,
	}
	if err := st.CreateService(ctx, legacy); err != nil {
		t.Fatal(err)
	}

	self, err := st.EnsureSelfService(ctx, "ghcr.io/acme/nori:latest")
	if err != nil {
		t.Fatal(err)
	}
	if self.Name != SelfServiceName {
		t.Fatalf("self service name = %q, want %q", self.Name, SelfServiceName)
	}
	persisted, err := st.GetService(ctx, legacy.ID)
	if err != nil {
		t.Fatal(err)
	}
	if persisted.Name != SelfServiceName {
		t.Fatalf("persisted self service name = %q, want %q", persisted.Name, SelfServiceName)
	}
}

func TestOpenMigratesExistingServiceTable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TABLE service (
		id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL UNIQUE, watched_image TEXT NOT NULL,
		policy TEXT NOT NULL, cron_expr TEXT NOT NULL DEFAULT '', deploy_script TEXT NOT NULL DEFAULT '',
		created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL
	)`); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	st, err := Open(path, make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if _, err := st.EnsureSelfService(context.Background(), "image"); err != nil {
		t.Fatalf("migration did not add is_self: %v", err)
	}
}

func TestOpenMigratesLegacyServiceToCustomDeployment(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy-template.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TABLE service (
		id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL UNIQUE, watched_image TEXT NOT NULL,
		policy TEXT NOT NULL, cron_expr TEXT NOT NULL DEFAULT '', deploy_script TEXT NOT NULL DEFAULT '',
		health_url TEXT NOT NULL DEFAULT '', is_self INTEGER NOT NULL DEFAULT 0,
		created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL
	);
	INSERT INTO service (name,watched_image,policy,created_at,updated_at)
	VALUES ('legacy','image','manual',1,1)`); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	st, err := Open(path, make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	got, err := st.GetServiceByName(context.Background(), "legacy")
	if err != nil {
		t.Fatal(err)
	}
	if got.DeploymentMode != DeploymentModeCustom {
		t.Fatalf("deployment mode = %q, want %q", got.DeploymentMode, DeploymentModeCustom)
	}
	if got.TemplateConfig != "{}" {
		t.Fatalf("template config = %q, want {}", got.TemplateConfig)
	}
}
