package store

import (
	"context"
	"errors"
	"testing"
)

func TestRecordTemplateDatabaseIdentityRejectsChanges(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	svc := &Service{Name: "postgres", WatchedImage: "image", Policy: PolicyManual}
	if err := st.CreateService(ctx, svc); err != nil {
		t.Fatal(err)
	}
	if err := st.RecordTemplateDatabaseIdentity(ctx, svc.ID, "sha256:identity-a"); err != nil {
		t.Fatal(err)
	}
	if err := st.RecordTemplateDatabaseIdentity(ctx, svc.ID, "sha256:identity-a"); err != nil {
		t.Fatalf("same identity: %v", err)
	}
	if err := st.RecordTemplateDatabaseIdentity(ctx, svc.ID, "sha256:identity-b"); !errors.Is(err, ErrTemplateDatabaseMigrationRequired) {
		t.Fatalf("changed identity: %v", err)
	}
	state, err := st.GetTemplateState(ctx, svc.ID)
	if err != nil {
		t.Fatal(err)
	}
	if state.DatabaseIdentityFingerprint != "sha256:identity-a" {
		t.Fatalf("identity = %q, want original", state.DatabaseIdentityFingerprint)
	}
	if err := st.DeleteService(ctx, svc.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := st.GetTemplateState(ctx, svc.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("deleted service state: %v", err)
	}
}
