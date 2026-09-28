package mcpauth

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"nori/internal/auth"
	"nori/internal/store"
)

func TestOAuthFlowAndAttacks(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "test.db"), make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	// Settings are intentionally initialized through the same persisted instance settings API.
	if err := st.SetMCPConfig(context.Background(), true, "https://nori.example", false); err != nil {
		t.Fatal(err)
	}
	hash, _ := auth.HashPassword("password")
	a, _ := auth.New(hash, make([]byte, 32))
	s := New(st, a)
	call := func(method, path, body string, cookies []*http.Cookie, origins ...string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, "https://nori.example"+path, strings.NewReader(body))
		if method == "POST" {
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			r.Header.Set("Origin", "https://nori.example")
		}
		if len(origins) > 0 {
			r.Header.Set("Origin", origins[0])
		}
		for _, c := range cookies {
			r.AddCookie(c)
		}
		w := httptest.NewRecorder()
		s.ServeHTTP(w, r)
		return w
	}
	callbacks := []struct{ uri, source string }{
		{"http://localhost:8765/callback", "http://localhost:8765"},
		{"https://agent.example/callback?next=other;value,more", "https://agent.example"},
		{"https://agent.example:8443/oauth/callback", "https://agent.example:8443"},
		{"http://127.0.0.1:8765/callback", "http://127.0.0.1:8765"},
		{"https://host;name.example/callback", "https://host%3Bname.example"},
		{"https://host,name.example/callback", "https://host%2Cname.example"},
		{"https://*.example/callback", "https://%2A.example"},
	}
	redirects := make([]string, len(callbacks))
	for i, callback := range callbacks {
		redirects[i] = callback.uri
	}
	metadata, err := json.Marshal(map[string]any{"client_name": "Test agent", "redirect_uris": redirects, "token_endpoint_auth_method": "none"})
	if err != nil {
		t.Fatal(err)
	}
	registration := call("POST", "/oauth/register", string(metadata), nil)
	if registration.Code != 201 {
		t.Fatalf("registration: %d %s", registration.Code, registration.Body)
	}
	var client map[string]any
	_ = json.Unmarshal(registration.Body.Bytes(), &client)
	id := client["client_id"].(string)
	pending, err := st.GetOAuth(context.Background(), digest(id), "client")
	if err != nil || pending.Expires > time.Now().Add(11*time.Minute).Unix() {
		t.Fatalf("unapproved registration lifetime: %+v %v", pending, err)
	}
	verifier := strings.Repeat("a", 43)
	h := sha256.Sum256([]byte(verifier))
	params := url.Values{"client_id": {id}, "redirect_uri": {"http://localhost:8765/callback"}, "response_type": {"code"}, "code_challenge_method": {"S256"}, "code_challenge": {base64.RawURLEncoding.EncodeToString(h[:])}, "resource": {"https://nori.example/mcp"}, "scope": {"nori:read nori:write"}, "state": {"original-state"}}
	unauth := call("GET", "/oauth/authorize?"+params.Encode(), "", nil)
	if unauth.Code != 303 || !strings.HasPrefix(unauth.Header().Get("Location"), "/login?next=") {
		t.Fatalf("login redirect %d %s", unauth.Code, unauth.Header())
	}
	lw := httptest.NewRecorder()
	lr := httptest.NewRequest("POST", "https://nori.example/login", nil)
	if err := a.Login(lw, lr, "password", false); err != nil {
		t.Fatal(err)
	}
	cookies := lw.Result().Cookies()
	csrf := ""
	for _, c := range cookies {
		if c.Name == "nori_csrf" {
			csrf = c.Value
		}
	}
	consent := call("GET", "/oauth/authorize?"+params.Encode(), "", cookies)
	if consent.Code != 200 || !strings.Contains(consent.Body.String(), "Docker host") {
		t.Fatalf("consent %d %s", consent.Code, consent.Body)
	}
	// HTML form POSTs under no-referrer carry Origin: null and are rejected
	// by the same-origin consent guard. Preserve Origin without forwarding the
	// authorization query to the client's callback.
	if got := consent.Header().Get("Referrer-Policy"); got != "same-origin" {
		t.Errorf("consent form must preserve its POST Origin; Referrer-Policy=%q", got)
	}
	// Browsers apply form-action to the POST's redirect as well. Allow only
	// this request's registered callback origin, without letting URL syntax
	// inject policy directives, extra policies, or wildcard sources.
	for _, callback := range callbacks {
		params.Set("redirect_uri", callback.uri)
		page := call("GET", "/oauth/authorize?"+params.Encode(), "", cookies)
		want := "default-src 'none'; style-src 'self'; form-action 'self' " + callback.source + "; frame-ancestors 'none'; base-uri 'none'"
		if got := page.Header().Get("Content-Security-Policy"); page.Code != 200 || got != want {
			t.Errorf("consent must permit its callback %q without broadening CSP: status=%d policy=%q, want %q", callback.uri, page.Code, got, want)
		}
	}
	params.Set("redirect_uri", callbacks[0].uri)
	for _, origin := range []string{"", "null", "https://chatgpt.com", "https://other-client.example", "http://localhost", "http://localhost:8765", "http://127.0.0.1:8765", "http://[::1]:8765"} {
		unauth := call("GET", "/oauth/authorize?"+params.Encode(), "", nil, origin)
		if unauth.Code != 303 || !strings.HasPrefix(unauth.Header().Get("Location"), "/login?next=") {
			t.Errorf("login navigation from %q: %d %s", origin, unauth.Code, unauth.Body)
		}
		w := call("GET", "/oauth/authorize?"+params.Encode(), "", cookies, origin)
		if w.Code != 200 {
			t.Errorf("consent navigation from %q: %d %s", origin, w.Code, w.Body)
		}
		if w.Header().Get("Access-Control-Allow-Origin") != "" {
			t.Error("consent page must not enable cross-origin reads")
		}
	}
	originalRedirect := params.Get("redirect_uri")
	params.Set("redirect_uri", "https://attacker.example/callback")
	if w := call("GET", "/oauth/authorize?"+params.Encode(), "", cookies); w.Code != 400 || w.Header().Get("Location") != "" {
		t.Fatal("unregistered redirect accepted")
	}
	params.Set("redirect_uri", originalRedirect)
	params.Set("decision", "allow")
	denied := call("POST", "/oauth/authorize", params.Encode(), cookies)
	if denied.Code != 403 {
		t.Fatalf("CSRF accepted %d", denied.Code)
	}
	params.Set("csrf_token", csrf)
	for _, origin := range []string{"", "http://localhost:8765", "http://127.0.0.1:8765", "https://evil.example", "null"} {
		w := call("POST", "/oauth/authorize", params.Encode(), cookies, origin)
		if w.Code != 403 {
			t.Errorf("consent submission from %q accepted: %d", origin, w.Code)
		}
	}
	params.Set("decision", "deny")
	refused := call("POST", "/oauth/authorize", params.Encode(), cookies)
	refusedURL, err := url.Parse(refused.Header().Get("Location"))
	if err != nil || refused.Code != 303 || refusedURL.Query().Get("error") != "access_denied" || refusedURL.Query().Get("code") != "" || refusedURL.Query().Get("state") != "original-state" {
		t.Fatalf("denied consent: %d %s", refused.Code, refused.Header().Get("Location"))
	}
	params.Set("decision", "allow")
	issueCode := func() string {
		t.Helper()
		w := call("POST", "/oauth/authorize", params.Encode(), cookies)
		if w.Code != 303 {
			t.Fatalf("authorize %d %s", w.Code, w.Body)
		}
		u, _ := url.Parse(w.Header().Get("Location"))
		if u.Scheme+"://"+u.Host+u.Path != originalRedirect {
			t.Fatal("authorization did not return to the registered localhost callback")
		}
		if u.Query().Get("state") != "original-state" {
			t.Fatal("state lost")
		}
		return u.Query().Get("code")
	}
	code := issueCode()
	approvedClient, err := st.GetOAuth(context.Background(), digest(id), "client")
	if err != nil || approvedClient.Expires < time.Now().Add(300*24*time.Hour).Unix() {
		t.Fatalf("approved registration not retained: %+v %v", approvedClient, err)
	}
	// Anonymous registration abuse must not exhaust the token budget of an
	// already-approved client. Only a few short-lived registrations are retained.
	for i := 0; i < 130; i++ {
		w := call("POST", "/oauth/register", `{"redirect_uris":["http://localhost:8765/callback"],"token_endpoint_auth_method":"none"}`, nil)
		if i > 10 && w.Code != 429 {
			t.Fatalf("unbounded registration: %d", w.Code)
		}
	}
	tokenParams := url.Values{"client_id": {id}, "grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {params.Get("redirect_uri")}, "resource": {params.Get("resource")}, "code_verifier": {"wrong"}}
	bad := call("POST", "/oauth/token", tokenParams.Encode(), nil)
	if bad.Code != 400 {
		t.Fatalf("bad PKCE accepted %d", bad.Code)
	}
	tokenParams.Set("code_verifier", verifier)
	tokenParams.Set("resource", "https://other.example/mcp")
	if w := call("POST", "/oauth/token", tokenParams.Encode(), nil); w.Code != 400 {
		t.Fatal("wrong audience accepted")
	}
	tokenParams.Set("resource", params.Get("resource"))
	exchange := func(p url.Values) map[string]any {
		t.Helper()
		w := call("POST", "/oauth/token", p.Encode(), nil)
		if w.Code != 200 {
			t.Fatalf("token %d %s", w.Code, w.Body)
		}
		var v map[string]any
		_ = json.Unmarshal(w.Body.Bytes(), &v)
		return v
	}
	tokens := exchange(tokenParams)
	protect := func(access, host, origin string) int {
		r := httptest.NewRequest("POST", "https://"+host+"/mcp", nil)
		r.Header.Set("Authorization", "Bearer "+access)
		if origin != "" {
			r.Header.Set("Origin", origin)
		}
		w := httptest.NewRecorder()
		s.Protect(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if RequireScope(r.Context(), "nori:write") != nil {
				t.Error("scope lost")
			}
			if RequireScope(r.Context(), "nori:secrets") == nil {
				t.Error("scope escalation")
			}
			w.WriteHeader(204)
		})).ServeHTTP(w, r)
		return w.Code
	}
	access := tokens["access_token"].(string)
	if protect(access, "nori.example", "") != 204 {
		t.Fatal("access rejected")
	}
	if protect(access, "evil.example", "") != 403 || protect(access, "nori.example", "https://evil.example") != 403 {
		t.Fatal("host/origin attack accepted")
	}
	refresh := url.Values{"client_id": {id}, "grant_type": {"refresh_token"}, "refresh_token": {tokens["refresh_token"].(string)}, "resource": {params.Get("resource")}}
	rotated := exchange(refresh)
	replay := call("POST", "/oauth/token", refresh.Encode(), nil)
	if replay.Code != 400 {
		t.Fatal("refresh replay accepted")
	}
	if protect(rotated["access_token"].(string), "nori.example", "") != 401 {
		t.Fatal("replayed family still valid")
	}
	tokenParams.Set("code", issueCode())
	tokens = exchange(tokenParams)
	if err := st.SetMCPConfig(context.Background(), false, "", false); err != nil {
		t.Fatal(err)
	}
	if protect(tokens["access_token"].(string), "nori.example", "") != 404 {
		t.Fatal("disabled server accessible")
	}
	if err := st.SetMCPConfig(context.Background(), true, "https://nori.example", false); err != nil {
		t.Fatal(err)
	}
	if protect(tokens["access_token"].(string), "nori.example", "") != 401 {
		t.Fatal("old epoch token accepted")
	}
}

func TestAuthorizationCreatesManagedGrantWithOriginalApprovedScopes(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(filepath.Join(t.TempDir(), "test.db"), make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := st.SetMCPConfig(ctx, true, "https://nori.example", false); err != nil {
		t.Fatal(err)
	}
	hash, _ := auth.HashPassword("password")
	a, _ := auth.New(hash, make([]byte, 32))
	s := New(st, a)
	call := func(method, path, body string, cookies []*http.Cookie) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, "https://nori.example"+path, strings.NewReader(body))
		if method == http.MethodPost {
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			r.Header.Set("Origin", "https://nori.example")
		}
		for _, cookie := range cookies {
			r.AddCookie(cookie)
		}
		w := httptest.NewRecorder()
		s.ServeHTTP(w, r)
		return w
	}
	registration := call(http.MethodPost, "/oauth/register", `{"client_name":"Calendar agent","redirect_uris":["http://localhost:8765/callback"],"token_endpoint_auth_method":"none"}`, nil)
	if registration.Code != http.StatusCreated {
		t.Fatalf("registration: %d %s", registration.Code, registration.Body)
	}
	var client map[string]any
	if err := json.Unmarshal(registration.Body.Bytes(), &client); err != nil {
		t.Fatal(err)
	}
	if registrations, err := s.ListOAuthGrantManagement(ctx); err != nil || len(registrations) != 0 {
		t.Fatalf("pending registration appeared in management inventory: %+v %v", registrations, err)
	}
	clientID := client["client_id"].(string)
	verifier := strings.Repeat("a", 43)
	challenge := sha256.Sum256([]byte(verifier))
	params := url.Values{
		"client_id":             {clientID},
		"redirect_uri":          {"http://localhost:8765/callback"},
		"response_type":         {"code"},
		"code_challenge_method": {"S256"},
		"code_challenge":        {base64.RawURLEncoding.EncodeToString(challenge[:])},
		"resource":              {"https://nori.example/mcp"},
		"scope":                 {"nori:read nori:write"},
	}
	lw := httptest.NewRecorder()
	lr := httptest.NewRequest(http.MethodPost, "https://nori.example/login", nil)
	if err := a.Login(lw, lr, "password", false); err != nil {
		t.Fatal(err)
	}
	cookies := lw.Result().Cookies()
	for _, cookie := range cookies {
		if cookie.Name == "nori_csrf" {
			params.Set("csrf_token", cookie.Value)
		}
	}
	if params.Get("csrf_token") == "" {
		t.Fatal("login did not issue a CSRF token")
	}
	issueCode := func() string {
		t.Helper()
		params.Set("decision", "allow")
		w := call(http.MethodPost, "/oauth/authorize", params.Encode(), cookies)
		if w.Code != http.StatusSeeOther {
			t.Fatalf("authorize: %d %s", w.Code, w.Body)
		}
		redirect, err := url.Parse(w.Header().Get("Location"))
		if err != nil {
			t.Fatal(err)
		}
		code := redirect.Query().Get("code")
		if code == "" {
			t.Fatal("authorization did not issue a code")
		}
		return code
	}
	code := issueCode()
	registrations, err := s.ListOAuthGrantManagement(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(registrations) != 1 || len(registrations[0].Grants) != 1 {
		t.Fatalf("authorization did not create one managed grant: %+v", registrations)
	}
	first := registrations[0].Grants[0]
	if registrations[0].ClientName != "Calendar agent" || first.ClientName != "Calendar agent" || first.ManagementID == "" || first.Scopes != "nori:read nori:write" || first.Status != store.OAuthGrantActive {
		t.Fatalf("unsafe or incomplete grant projection: %+v", first)
	}
	token := url.Values{
		"client_id":     {clientID},
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {params.Get("redirect_uri")},
		"resource":      {params.Get("resource")},
		"code_verifier": {verifier},
	}
	tokenResult := call(http.MethodPost, "/oauth/token", token.Encode(), nil)
	if tokenResult.Code != http.StatusOK {
		t.Fatalf("code exchange: %d %s", tokenResult.Code, tokenResult.Body)
	}
	var tokens tokenResponse
	if err := json.Unmarshal(tokenResult.Body.Bytes(), &tokens); err != nil {
		t.Fatal(err)
	}
	refresh := url.Values{"client_id": {clientID}, "grant_type": {"refresh_token"}, "refresh_token": {tokens.Refresh}, "resource": {params.Get("resource")}, "scope": {ScopeRead}}
	narrowed := call(http.MethodPost, "/oauth/token", refresh.Encode(), nil)
	if narrowed.Code != http.StatusOK {
		t.Fatalf("narrowed refresh: %d %s", narrowed.Code, narrowed.Body)
	}
	registrations, err = s.ListOAuthGrantManagement(ctx)
	if err != nil || registrations[0].Grants[0].Scopes != "nori:read nori:write" {
		t.Fatalf("refresh narrowing changed the original approved scopes: %+v %v", registrations, err)
	}
	if w := call(http.MethodPost, "/oauth/token", refresh.Encode(), nil); w.Code != http.StatusBadRequest {
		t.Fatalf("refresh replay: %d %s", w.Code, w.Body)
	}
	registrations, err = s.ListOAuthGrantManagement(ctx)
	if err != nil || registrations[0].Grants[0].ManagementID != first.ManagementID || registrations[0].Grants[0].Status != store.OAuthGrantRevoked {
		t.Fatalf("refresh replay did not revoke its managed family: %+v %v", registrations, err)
	}
	secondCode := issueCode()
	registrations, err = s.ListOAuthGrantManagement(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(registrations) != 1 || len(registrations[0].Grants) != 2 || registrations[0].Grants[0].ManagementID == registrations[0].Grants[1].ManagementID {
		t.Fatalf("separate authorization did not create a distinct managed grant: %+v", registrations)
	}
	secondToken := url.Values{
		"client_id":     {clientID},
		"grant_type":    {"authorization_code"},
		"code":          {secondCode},
		"redirect_uri":  {params.Get("redirect_uri")},
		"resource":      {params.Get("resource")},
		"code_verifier": {verifier},
	}
	secondTokenResult := call(http.MethodPost, "/oauth/token", secondToken.Encode(), nil)
	if secondTokenResult.Code != http.StatusOK {
		t.Fatalf("second code exchange: %d %s", secondTokenResult.Code, secondTokenResult.Body)
	}
	var secondTokens tokenResponse
	if err := json.Unmarshal(secondTokenResult.Body.Bytes(), &secondTokens); err != nil {
		t.Fatal(err)
	}
	if w := call(http.MethodPost, "/oauth/revoke", url.Values{"client_id": {clientID}, "token": {secondTokens.Refresh}}.Encode(), nil); w.Code != http.StatusOK {
		t.Fatalf("self revocation: %d %s", w.Code, w.Body)
	}
	registrations, err = s.ListOAuthGrantManagement(ctx)
	if err != nil {
		t.Fatal(err)
	}
	states := map[string]store.OAuthGrantStatus{}
	for _, managedGrant := range registrations[0].Grants {
		states[managedGrant.ManagementID] = managedGrant.Status
	}
	if states[first.ManagementID] != store.OAuthGrantRevoked {
		t.Fatalf("replayed grant status = %q, want revoked", states[first.ManagementID])
	}
	for id, status := range states {
		if id != first.ManagementID && status != store.OAuthGrantRevoked {
			t.Fatalf("self-revoked grant status = %q, want revoked", status)
		}
	}
}

func TestApprovalFailureLeavesNoCodeOrManagedGrantProjection(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(filepath.Join(t.TempDir(), "test.db"), make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	now := time.Now().Truncate(time.Second)
	s := New(st, nil)
	cl := storedClient{Client: client{ID: "client", Name: "Calendar", Method: "none"}, Epoch: "epoch"}
	if err := s.put(ctx, cl.Client.ID, "client", "", now.Add(time.Minute), cl); err != nil {
		t.Fatal(err)
	}
	if err := s.put(ctx, "occupied-code", "code", "occupied-family", now.Add(time.Minute), grant{}); err != nil {
		t.Fatal(err)
	}
	_, err = st.ApproveOAuthGrant(ctx, store.OAuthGrantApproval{
		ClientKey:       digest(cl.Client.ID),
		ClientName:      cl.Client.Name,
		ClientExpiresAt: now.Add(approvedClientLifetime),
		ApprovedAt:      now,
		Family:          "new-family",
		FamilyExpiresAt: now.Add(grantLifetime),
		Scopes:          ScopeRead,
		Code: store.OAuthRecord{
			Key:     digest("occupied-code"),
			Kind:    "code",
			Family:  "new-family",
			Data:    []byte(`{}`),
			Expires: now.Add(authorizationCodeLifetime).Unix(),
		},
	})
	if err == nil {
		t.Fatal("approval with an occupied code key succeeded")
	}
	if registrations, err := s.ListOAuthGrantManagement(ctx); err != nil || len(registrations) != 0 {
		t.Fatalf("failed approval left a managed projection: %+v %v", registrations, err)
	}
	clientRecord, err := st.GetOAuth(ctx, digest(cl.Client.ID), "client")
	if err != nil {
		t.Fatal(err)
	}
	if clientRecord.Expires != now.Add(time.Minute).Unix() {
		t.Fatalf("failed approval extended client lifetime: %d", clientRecord.Expires)
	}
	occupied, err := st.GetOAuth(ctx, digest("occupied-code"), "code")
	if err != nil || occupied.Family != "occupied-family" {
		t.Fatalf("failed approval changed the occupied code: %+v %v", occupied, err)
	}
}

func TestListOAuthGrantManagementBootstrapsLiveCodeGrant(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(filepath.Join(t.TempDir(), "test.db"), make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := st.SetMCPConfig(ctx, true, "https://nori.example", false); err != nil {
		t.Fatal(err)
	}
	cfg, err := st.GetMCPConfig(ctx)
	if err != nil {
		t.Fatal(err)
	}
	s := New(st, nil)
	now := time.Now().Truncate(time.Second)
	cl := storedClient{Client: client{ID: "legacy-client", Method: "none"}, Epoch: cfg.Epoch}
	if err := s.put(ctx, cl.Client.ID, "client", "", now.Add(approvedClientLifetime), cl); err != nil {
		t.Fatal(err)
	}
	g := grant{ClientID: cl.Client.ID, Resource: cfg.PublicURL + "/mcp", Scope: ScopeRead + " " + ScopeWrite, Epoch: cfg.Epoch, Family: "legacy-family", FamilyExpires: now.Add(grantLifetime).Unix()}
	if err := s.put(ctx, "legacy-code", "code", g.Family, now.Add(authorizationCodeLifetime), g); err != nil {
		t.Fatal(err)
	}

	registrations, err := s.ListOAuthGrantManagement(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(registrations) != 1 || registrations[0].ClientName != "Unnamed client" || len(registrations[0].Grants) != 1 {
		t.Fatalf("legacy management projection = %+v", registrations)
	}
	managed := registrations[0].Grants[0]
	if managed.Scopes != ScopeRead+" "+ScopeWrite || managed.Status != store.OAuthGrantActive {
		t.Fatalf("legacy managed grant = %+v", managed)
	}
	registrations, err = s.ListOAuthGrantManagement(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(registrations) != 1 || len(registrations[0].Grants) != 1 || registrations[0].Grants[0].ManagementID != managed.ManagementID {
		t.Fatalf("bootstrap was not idempotent: %+v", registrations)
	}
}

func TestBootstrapOAuthGrantManagementSkipsExistingProjectionWrites(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "test.db")
	st, err := store.Open(path, make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := st.SetMCPConfig(ctx, true, "https://nori.example", false); err != nil {
		t.Fatal(err)
	}
	cfg, err := st.GetMCPConfig(ctx)
	if err != nil {
		t.Fatal(err)
	}
	s := New(st, nil)
	now := time.Now().Truncate(time.Second)
	cl := storedClient{Client: client{ID: "legacy-client", Name: "Legacy client", Method: "none"}, Epoch: cfg.Epoch}
	if err := s.put(ctx, cl.Client.ID, "client", "", now.Add(approvedClientLifetime), cl); err != nil {
		t.Fatal(err)
	}
	g := grant{ClientID: cl.Client.ID, Resource: cfg.PublicURL + "/mcp", Scope: ScopeRead, Epoch: cfg.Epoch, Family: "legacy-family", FamilyExpires: now.Add(grantLifetime).Unix()}
	if err := s.put(ctx, "legacy-code", "code", g.Family, now.Add(authorizationCodeLifetime), g); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ListOAuthGrantManagement(ctx); err != nil {
		t.Fatal(err)
	}

	lockedDB, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer lockedDB.Close()
	if _, err := lockedDB.Exec("BEGIN IMMEDIATE"); err != nil {
		t.Fatal(err)
	}
	defer lockedDB.Exec("ROLLBACK")

	checkCtx, cancel := context.WithTimeout(ctx, 50*time.Millisecond)
	defer cancel()
	if err := s.bootstrapOAuthGrantManagement(checkCtx); err != nil {
		t.Fatalf("existing projection triggered a write while the database was locked: %v", err)
	}
}

func TestListOAuthGrantManagementBootstrapsLiveRefreshGrant(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(filepath.Join(t.TempDir(), "test.db"), make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := st.SetMCPConfig(ctx, true, "https://nori.example", false); err != nil {
		t.Fatal(err)
	}
	cfg, err := st.GetMCPConfig(ctx)
	if err != nil {
		t.Fatal(err)
	}
	s := New(st, nil)
	now := time.Now().Truncate(time.Second)
	cl := storedClient{Client: client{ID: "legacy-client", Name: "Legacy client", Method: "none"}, Epoch: cfg.Epoch}
	if err := s.put(ctx, cl.Client.ID, "client", "", now.Add(approvedClientLifetime), cl); err != nil {
		t.Fatal(err)
	}
	g := grant{ClientID: cl.Client.ID, Resource: cfg.PublicURL + "/mcp", Epoch: cfg.Epoch, Family: "legacy-family", FamilyExpires: now.Add(grantLifetime).Unix()}
	for _, record := range []struct {
		key   string
		scope string
	}{
		{key: "legacy-refresh-read", scope: ScopeRead},
		{key: "legacy-refresh-write", scope: ScopeWrite},
	} {
		g.Scope = record.scope
		if err := s.put(ctx, record.key, "refresh", g.Family, time.Unix(g.FamilyExpires, 0), g); err != nil {
			t.Fatal(err)
		}
	}

	registrations, err := s.ListOAuthGrantManagement(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(registrations) != 1 || registrations[0].ClientName != "Legacy client" || len(registrations[0].Grants) != 1 {
		t.Fatalf("legacy refresh management projection = %+v", registrations)
	}
	managed := registrations[0].Grants[0]
	if managed.Scopes != ScopeRead+" "+ScopeWrite || managed.Status != store.OAuthGrantActive {
		t.Fatalf("legacy refresh managed grant = %+v", managed)
	}
}

func TestRedirectValidation(t *testing.T) {
	for _, v := range []string{"https://example.com/callback", "http://localhost", "http://localhost:8765/callback", "http://127.0.0.1:123/cb", "http://[::1]:123/cb"} {
		if !validRedirect(v) {
			t.Errorf("rejected %s", v)
		}
	}
	for _, v := range []string{"http://example.com/cb", "javascript:alert(1)", "https://a.example/cb#token", "https://user:pass@example.com/cb", "//example.com"} {
		if validRedirect(v) {
			t.Errorf("accepted %s", v)
		}
	}
}

func TestConfidentialClientRevocationAndExpiry(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "test.db"), make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	if err := st.SetMCPConfig(ctx, true, "https://nori.example", false); err != nil {
		t.Fatal(err)
	}
	cfg, _ := st.GetMCPConfig(ctx)
	s := New(st, nil)
	cl := storedClient{Client: client{ID: "client", Method: "client_secret_basic"}, SecretHash: digest("secret"), Epoch: cfg.Epoch}
	if err := s.put(ctx, "client", "client", "", time.Now().Add(time.Hour), cl); err != nil {
		t.Fatal(err)
	}
	g := grant{ClientID: "client", Scope: "nori:read", Epoch: cfg.Epoch, Resource: cfg.PublicURL + "/mcp", Family: "family", FamilyExpires: time.Now().Add(time.Hour).Unix()}
	if err := s.put(ctx, "access", "access", g.Family, time.Now().Add(time.Minute), g); err != nil {
		t.Fatal(err)
	}
	request := func(secret string) int {
		r := httptest.NewRequest("POST", cfg.PublicURL+"/oauth/revoke", strings.NewReader("token=access"))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.SetBasicAuth("client", secret)
		w := httptest.NewRecorder()
		s.ServeHTTP(w, r)
		return w.Code
	}
	if request("wrong") != 401 {
		t.Fatal("bad client secret accepted")
	}
	rec, _ := st.GetOAuth(ctx, digest("access"), "access")
	if rec.Used {
		t.Fatal("unauthorized revocation")
	}
	if request("secret") != 200 {
		t.Fatal("revocation failed")
	}
	rec, _ = st.GetOAuth(ctx, digest("access"), "access")
	if !rec.Used {
		t.Fatal("token not revoked")
	}
	if err := s.put(ctx, "new-access", "access", g.Family, time.Now().Add(time.Minute), g); err == nil {
		t.Fatal("revoked family resurrected by concurrent issuance")
	}
	for _, kind := range []string{"code", "access", "refresh"} {
		if err := s.put(ctx, "expired-"+kind, kind, "other", time.Now().Add(-time.Minute), g); err != nil {
			t.Fatal(err)
		}
		if _, err := st.GetOAuth(ctx, digest("expired-"+kind), kind); err == nil {
			t.Fatalf("expired %s record returned", kind)
		}
	}
}
