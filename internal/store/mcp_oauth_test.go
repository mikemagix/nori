package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func containsAny(s string, values ...string) bool {
	for _, value := range values {
		if strings.Contains(s, value) {
			return true
		}
	}
	return false
}

func TestGetOAuthMissingRecordReturnsErrNotFound(t *testing.T) {
	st := testStore(t)
	_, err := st.GetOAuth(context.Background(), "missing", "client")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing OAuth record error = %v, want ErrNotFound", err)
	}
}

func TestOAuthGrantManagementRevokesExactlyOneFamily(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	now := time.Now().Truncate(time.Second)
	clientKey := "client-a"
	if err := st.PutOAuth(ctx, OAuthRecord{Key: clientKey, Kind: "client", Data: []byte(`{"secret_hash":"must-not-escape"}`), Expires: now.Add(time.Hour).Unix()}); err != nil {
		t.Fatalf("store client: %v", err)
	}

	first, err := st.ApproveOAuthGrant(ctx, OAuthGrantApproval{
		ClientKey: clientKey, ClientName: "Calendar", ClientExpiresAt: now.Add(24 * time.Hour),
		ApprovedAt: now, Family: "family-a", FamilyExpiresAt: now.Add(time.Hour), Scopes: "nori:read",
		Code: OAuthRecord{Key: "code-a", Kind: "code", Family: "family-a", Data: []byte(`{"code":"must-not-escape"}`), Expires: now.Add(time.Minute).Unix()},
	})
	if err != nil {
		t.Fatalf("approve first grant: %v", err)
	}
	second, err := st.ApproveOAuthGrant(ctx, OAuthGrantApproval{
		ClientKey: clientKey, ClientName: "Calendar", ClientExpiresAt: now.Add(24 * time.Hour),
		ApprovedAt: now, Family: "family-b", FamilyExpiresAt: now.Add(time.Hour), Scopes: "nori:read nori:write",
		Code: OAuthRecord{Key: "code-b", Kind: "code", Family: "family-b", Data: []byte(`{"code":"must-not-escape"}`), Expires: now.Add(time.Minute).Unix()},
	})
	if err != nil {
		t.Fatalf("approve second grant: %v", err)
	}

	registrations, err := st.ListOAuthGrantManagement(ctx)
	if err != nil {
		t.Fatalf("list grants: %v", err)
	}
	if len(registrations) != 1 || registrations[0].ClientName != "Calendar" || len(registrations[0].Grants) != 2 {
		t.Fatalf("safe projection = %+v", registrations)
	}
	if got := registrations[0].Grants[0]; got.Status != OAuthGrantActive || got.ManagementID == "" || got.Scopes == "" {
		t.Fatalf("first safe grant = %+v", got)
	}
	if got := string(mustJSON(t, registrations)); containsAny(got, "must-not-escape", "family-a", clientKey) {
		t.Fatalf("safe list leaked private OAuth data: %s", got)
	}
	confirmation, err := st.GetOAuthGrantManagement(ctx, first.ManagementID)
	if err != nil || confirmation.ClientName != "Calendar" || confirmation.Status != OAuthGrantActive {
		t.Fatalf("safe confirmation = %+v, %v", confirmation, err)
	}

	if err := st.RevokeOAuthGrant(ctx, first.ManagementID); err != nil {
		t.Fatalf("revoke first grant: %v", err)
	}
	if _, err := st.GetOAuthGrantManagement(ctx, first.ManagementID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("revoked grant lookup error = %v, want ErrNotFound", err)
	}
	if err := st.RevokeOAuthGrant(ctx, first.ManagementID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("repeat revoke error = %v, want ErrNotFound", err)
	}
	if err := st.RevokeOAuthGrant(ctx, "not-a-management-id"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown revoke error = %v, want ErrNotFound", err)
	}

	registrations, err = st.ListOAuthGrantManagement(ctx)
	if err != nil {
		t.Fatalf("list after revoke: %v", err)
	}
	if len(registrations) != 1 || len(registrations[0].Grants) != 2 {
		t.Fatalf("registration/grants changed unexpectedly: %+v", registrations)
	}
	states := map[string]OAuthGrantStatus{}
	for _, g := range registrations[0].Grants {
		states[g.ManagementID] = g.Status
	}
	if states[first.ManagementID] != OAuthGrantRevoked || states[second.ManagementID] != OAuthGrantActive {
		t.Fatalf("grant states = %+v", states)
	}
	for _, key := range []string{"code-a", "code-b"} {
		rec, err := st.GetOAuth(ctx, key, "code")
		if err != nil {
			t.Fatalf("get %s: %v", key, err)
		}
		if got, want := rec.Used, key == "code-a"; got != want {
			t.Errorf("%s used = %v, want %v", key, got, want)
		}
	}
}

func TestOAuthGrantManagementFamilyRevocationMarksProjectionAndBlocksNewCredentials(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	now := time.Now().Truncate(time.Second)
	if err := st.PutOAuth(ctx, OAuthRecord{Key: "client", Kind: "client", Data: []byte(`{}`), Expires: now.Add(time.Hour).Unix()}); err != nil {
		t.Fatal(err)
	}
	grant, err := st.ApproveOAuthGrant(ctx, OAuthGrantApproval{
		ClientKey: "client", ClientName: "Terminal", ClientExpiresAt: now.Add(time.Hour),
		ApprovedAt: now, Family: "family", FamilyExpiresAt: now.Add(30 * time.Minute), Scopes: "nori:read",
		Code: OAuthRecord{Key: "code", Kind: "code", Family: "family", Data: []byte(`{}`), Expires: now.Add(time.Minute).Unix()},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := st.RevokeOAuthFamily(ctx, "family"); err != nil {
		t.Fatal(err)
	}
	registrations, err := st.ListOAuthGrantManagement(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(registrations) != 1 || len(registrations[0].Grants) != 1 || registrations[0].Grants[0].ManagementID != grant.ManagementID || registrations[0].Grants[0].Status != OAuthGrantRevoked {
		t.Fatalf("family revoke did not update projection: %+v", registrations)
	}
	if err := st.PutOAuth(ctx, OAuthRecord{Key: "late-access", Kind: "access", Family: "family", Data: []byte(`{}`), Expires: now.Add(time.Minute).Unix()}); err == nil {
		t.Fatal("tombstoned family accepted a new credential")
	}
}

func TestBootstrapOAuthGrantReturnsNotFoundWhenExpiryRaces(t *testing.T) {
	st := testStore(t)
	now := time.Now()
	err := st.BootstrapOAuthGrant(context.Background(), OAuthGrantBootstrap{
		ClientKey:       "client",
		ClientName:      "Legacy client",
		ClientExpiresAt: now.Add(-time.Second),
		ApprovedAt:      now.Add(-time.Minute),
		Family:          "family",
		FamilyExpiresAt: now.Add(time.Hour),
		Scopes:          "nori:read",
	})
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("expired client metadata error = %v, want ErrNotFound", err)
	}
}

func TestOAuthGrantManagementHidesRetentionExpiredProjection(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	now := time.Now().Unix()
	registrationKey := oauthManagementKey("oauth-managed-registration", "client")
	registrationData, err := json.Marshal(oauthManagedRegistration{ClientName: "Expired", ApprovedAt: now - 100, ExpiresAt: now + 100})
	if err != nil {
		t.Fatal(err)
	}
	grantData, err := json.Marshal(oauthManagedGrant{ManagementID: "opaque-id", RegistrationKey: registrationKey, ClientName: "Expired", Scopes: "nori:read", ApprovedAt: now - 100, GrantExpiresAt: now - 10})
	if err != nil {
		t.Fatal(err)
	}
	if err := st.PutOAuth(ctx, OAuthRecord{Key: registrationKey, Kind: oauthManagedRegistrationKind, Data: registrationData, Expires: now + 100}); err != nil {
		t.Fatal(err)
	}
	grantKey := oauthManagementKey("oauth-managed-grant", "opaque-id")
	if err := st.PutOAuth(ctx, OAuthRecord{Key: grantKey, Kind: oauthManagedGrantKind, Data: grantData, Family: "family", Expires: now + 100}); err != nil {
		t.Fatal(err)
	}
	registrations, err := st.ListOAuthGrantManagement(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(registrations) != 1 || len(registrations[0].Grants) != 1 || registrations[0].Grants[0].Status != OAuthGrantExpired {
		t.Fatalf("expired projection state = %+v", registrations)
	}
	if _, err := st.db.ExecContext(ctx, `UPDATE mcp_oauth SET expires=? WHERE key=?`, now-1, grantKey); err != nil {
		t.Fatal(err)
	}
	registrations, err = st.ListOAuthGrantManagement(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(registrations) != 1 || len(registrations[0].Grants) != 0 {
		t.Fatalf("retention-expired projection remained visible: %+v", registrations)
	}
}

func TestOAuthGrantManagementOrdersRegistrationsAndGrantsByApprovalTime(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	now := time.Now().Truncate(time.Second)
	for _, key := range []string{"client-earlier", "client-later"} {
		if err := st.PutOAuth(ctx, OAuthRecord{Key: key, Kind: "client", Data: []byte(`{}`), Expires: now.Add(time.Hour).Unix()}); err != nil {
			t.Fatalf("store %s: %v", key, err)
		}
	}
	earlier := now.Add(-3 * time.Minute)
	later := now.Add(-time.Minute)
	if _, err := st.ApproveOAuthGrant(ctx, OAuthGrantApproval{
		ClientKey: "client-earlier", ClientName: "Zulu", ClientExpiresAt: now.Add(time.Hour),
		ApprovedAt: earlier, Family: "zulu-first", FamilyExpiresAt: now.Add(30 * time.Minute), Scopes: "nori:read",
		Code: OAuthRecord{Key: "zulu-first-code", Kind: "code", Family: "zulu-first", Data: []byte(`{}`), Expires: now.Add(time.Minute).Unix()},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.ApproveOAuthGrant(ctx, OAuthGrantApproval{
		ClientKey: "client-later", ClientName: "Alpha", ClientExpiresAt: now.Add(time.Hour),
		ApprovedAt: later, Family: "alpha-only", FamilyExpiresAt: now.Add(30 * time.Minute), Scopes: "nori:read",
		Code: OAuthRecord{Key: "alpha-code", Kind: "code", Family: "alpha-only", Data: []byte(`{}`), Expires: now.Add(time.Minute).Unix()},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.ApproveOAuthGrant(ctx, OAuthGrantApproval{
		ClientKey: "client-earlier", ClientName: "Zulu", ClientExpiresAt: now.Add(time.Hour),
		ApprovedAt: later, Family: "zulu-later", FamilyExpiresAt: now.Add(30 * time.Minute), Scopes: "nori:read nori:write",
		Code: OAuthRecord{Key: "zulu-later-code", Kind: "code", Family: "zulu-later", Data: []byte(`{}`), Expires: now.Add(time.Minute).Unix()},
	}); err != nil {
		t.Fatal(err)
	}

	registrations, err := st.ListOAuthGrantManagement(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(registrations) != 2 || registrations[0].ClientName != "Zulu" || registrations[1].ClientName != "Alpha" {
		t.Fatalf("registration order = %+v", registrations)
	}
	if len(registrations[0].Grants) != 2 || !registrations[0].Grants[0].ApprovedAt.Equal(later) || !registrations[0].Grants[1].ApprovedAt.Equal(earlier) {
		t.Fatalf("grant order = %+v", registrations[0].Grants)
	}
}

func TestOAuthGrantManagementRevocationRaceLeavesNoLiveFamilyCredential(t *testing.T) {
	path := filepath.Join(t.TempDir(), "race.db")
	ctx := context.Background()
	first, err := Open(path, make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	second, err := Open(path, make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	now := time.Now().Truncate(time.Second)
	if err := first.PutOAuth(ctx, OAuthRecord{Key: "client", Kind: "client", Data: []byte(`{}`), Expires: now.Add(time.Hour).Unix()}); err != nil {
		t.Fatal(err)
	}
	grant, err := first.ApproveOAuthGrant(ctx, OAuthGrantApproval{
		ClientKey: "client", ClientName: "Race", ClientExpiresAt: now.Add(time.Hour),
		ApprovedAt: now, Family: "family", FamilyExpiresAt: now.Add(30 * time.Minute), Scopes: "nori:read",
		Code: OAuthRecord{Key: "code", Kind: "code", Family: "family", Data: []byte(`{}`), Expires: now.Add(time.Minute).Unix()},
	})
	if err != nil {
		t.Fatal(err)
	}
	start := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(2)
	var revokeErr, putErr error
	go func() {
		defer wg.Done()
		<-start
		revokeErr = first.RevokeOAuthGrant(ctx, grant.ManagementID)
	}()
	go func() {
		defer wg.Done()
		<-start
		putErr = second.PutOAuth(ctx, OAuthRecord{Key: "race-access", Kind: "access", Family: "family", Data: []byte(`{}`), Expires: now.Add(time.Minute).Unix()})
	}()
	close(start)
	wg.Wait()
	if revokeErr != nil {
		t.Fatalf("revoke race: %v", revokeErr)
	}
	if putErr == nil {
		record, err := first.GetOAuth(ctx, "race-access", "access")
		if err != nil {
			t.Fatalf("get raced credential: %v", err)
		}
		if !record.Used {
			t.Fatal("raced credential remained usable after revocation")
		}
	}
	var live int
	if err := first.db.QueryRowContext(ctx, `SELECT count(*) FROM mcp_oauth WHERE family=? AND kind != ? AND used=0`, "family", oauthRevokedKind).Scan(&live); err != nil {
		t.Fatal(err)
	}
	if live != 0 {
		t.Fatalf("revoked family retained %d live record(s)", live)
	}
}

func TestOpenPreservesPreFeatureOAuthRows(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pre-feature.db")
	db, err := sql.Open("sqlite", dsn(path))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TABLE mcp_oauth (
key TEXT PRIMARY KEY, kind TEXT NOT NULL, data BLOB NOT NULL, expires INTEGER NOT NULL,
family TEXT NOT NULL DEFAULT '', used INTEGER NOT NULL DEFAULT 0)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO mcp_oauth(key,kind,data,expires,family,used) VALUES ('legacy-code','code','{}',?, 'legacy-family',0)`, time.Now().Add(time.Hour).Unix()); err != nil {
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
	if _, err := st.GetOAuth(context.Background(), "legacy-code", "code"); err != nil {
		t.Fatalf("pre-feature OAuth row lost after Open: %v", err)
	}
}

func TestOAuthGrantManagementPersistsRevocationAndGlobalResetClearsProjection(t *testing.T) {
	path := filepath.Join(t.TempDir(), "oauth.db")
	ctx := context.Background()
	st, err := Open(path, make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().Truncate(time.Second)
	if err := st.PutOAuth(ctx, OAuthRecord{Key: "client", Kind: "client", Data: []byte(`{}`), Expires: now.Add(time.Hour).Unix()}); err != nil {
		t.Fatal(err)
	}
	grant, err := st.ApproveOAuthGrant(ctx, OAuthGrantApproval{
		ClientKey: "client", ClientName: "CLI", ClientExpiresAt: now.Add(time.Hour),
		ApprovedAt: now, Family: "family", FamilyExpiresAt: now.Add(30 * time.Minute), Scopes: "nori:read",
		Code: OAuthRecord{Key: "code", Kind: "code", Family: "family", Data: []byte(`{}`), Expires: now.Add(time.Minute).Unix()},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := st.RevokeOAuthGrant(ctx, grant.ManagementID); err != nil {
		t.Fatal(err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	st, err = Open(path, make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	registrations, err := st.ListOAuthGrantManagement(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(registrations) != 1 || len(registrations[0].Grants) != 1 || registrations[0].Grants[0].Status != OAuthGrantRevoked {
		t.Fatalf("reopened projection = %+v", registrations)
	}
	if err := st.SetMCPConfig(ctx, true, "https://nori.example", true); err != nil {
		t.Fatal(err)
	}
	registrations, err = st.ListOAuthGrantManagement(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(registrations) != 0 {
		t.Fatalf("global reset retained grant projections: %+v", registrations)
	}
}
