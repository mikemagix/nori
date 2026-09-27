package web

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"golang.org/x/oauth2"
	"nori/internal/auth"
	"nori/internal/docker"
	"nori/internal/executor"
	"nori/internal/poller"
	"nori/internal/store"
)

func mcpSettingsServer(t *testing.T) (*Server, *store.Store) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "settings.db"), make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	hash, _ := auth.HashPassword("test")
	a, _ := auth.New(hash, make([]byte, 32))
	ex := executor.New(st, &executor.OSRunner{}, func(context.Context, string) (string, error) { return "", nil }, 0)
	pl := poller.New(st, func(context.Context, string) (string, error) { return "", nil }, ex, 0)
	return NewServer(st, &docker.Fake{}, ex, pl, a, Channels{}), st
}

func seedManagedGrant(t *testing.T, st *store.Store, clientKey, clientName, family string) store.OAuthGrant {
	t.Helper()
	ctx := context.Background()
	now := time.Now()
	if err := st.PutOAuth(ctx, store.OAuthRecord{Key: clientKey, Kind: "client", Data: []byte(`{}`), Expires: now.Add(time.Hour).Unix()}); err != nil {
		t.Fatal(err)
	}
	grant, err := st.ApproveOAuthGrant(ctx, store.OAuthGrantApproval{
		ClientKey:       clientKey,
		ClientName:      clientName,
		ClientExpiresAt: now.Add(time.Hour),
		ApprovedAt:      now,
		Family:          family,
		FamilyExpiresAt: now.Add(time.Hour),
		Scopes:          "nori:read nori:write",
		Code: store.OAuthRecord{
			Key:     "code-" + family,
			Kind:    "code",
			Data:    []byte(`{}`),
			Family:  family,
			Expires: now.Add(time.Minute).Unix(),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return grant
}

func settingsRequest(t *testing.T, srv *Server, cookies []*http.Cookie, method, target, body, origin string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, target, strings.NewReader(body))
	if body != "" {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	if origin != "" {
		req.Header.Add("Origin", origin)
	}
	for _, cookie := range cookies {
		req.AddCookie(cookie)
	}
	rr := httptest.NewRecorder()
	srv.ServeHTTP(rr, req)
	return rr
}

func TestMCPGrantManagementSettingsConfirmationAndIsolation(t *testing.T) {
	srv, st := mcpSettingsServer(t)
	ctx := context.Background()
	if err := st.SetMCPConfig(ctx, true, "https://nori.example", false); err != nil {
		t.Fatal(err)
	}
	first := seedManagedGrant(t, st, "client-one", `Calendar <script>alert("x")</script>`, "family-one")
	second := seedManagedGrant(t, st, "client-two", "Deploy agent", "family-two")
	cookies := loginCookies(t, srv)

	unauthenticated := httptest.NewRecorder()
	srv.ServeHTTP(unauthenticated, httptest.NewRequest(http.MethodGet, "/settings/mcp/grants/"+first.ManagementID+"/revoke", nil))
	if unauthenticated.Code != http.StatusSeeOther {
		t.Fatalf("unauthenticated confirmation = %d", unauthenticated.Code)
	}

	settings := settingsRequest(t, srv, cookies, http.MethodGet, "https://nori.example/settings", "", "")
	if settings.Code != http.StatusOK {
		t.Fatalf("settings = %d: %s", settings.Code, settings.Body)
	}
	body := settings.Body.String()
	if !strings.Contains(body, "Connected OAuth clients") || !strings.Contains(body, "Deploy agent") || !strings.Contains(body, "nori:read nori:write") {
		t.Fatalf("safe grant inventory missing: %s", body)
	}
	if strings.Contains(body, `<script>alert("x")</script>`) || !strings.Contains(body, "Calendar &lt;script&gt;") {
		t.Fatalf("client name was not escaped: %s", body)
	}
	if strings.Contains(body, "family-one") || strings.Contains(body, "code-family-one") {
		t.Fatalf("inventory disclosed OAuth internals: %s", body)
	}
	if !strings.Contains(body, `oauth-grant-inventory`) || !strings.Contains(body, `aria-label="Revoke Calendar`) {
		t.Fatalf("inventory lacks accessible responsive markup: %s", body)
	}

	confirmation := settingsRequest(t, srv, cookies, http.MethodGet, "https://nori.example/settings/mcp/grants/"+first.ManagementID+"/revoke", "", "")
	if confirmation.Code != http.StatusOK || !strings.Contains(confirmation.Body.String(), "Revoke connection") || !strings.Contains(confirmation.Body.String(), "Calendar &lt;script&gt;") {
		t.Fatalf("confirmation = %d: %s", confirmation.Code, confirmation.Body)
	}
	csrf := csrfFromBody(confirmation.Body.String())
	cancel := settingsRequest(t, srv, cookies, http.MethodPost, "https://nori.example/settings/mcp/grants/"+first.ManagementID+"/revoke", url.Values{"csrf_token": {csrf}, "decision": {"cancel"}}.Encode(), "https://nori.example")
	if cancel.Code != http.StatusSeeOther {
		t.Fatalf("cancel = %d: %s", cancel.Code, cancel.Body)
	}
	if _, err := st.GetOAuthGrantManagement(ctx, first.ManagementID); err != nil {
		t.Fatalf("cancelled connection is no longer active: %v", err)
	}

	confirmed := settingsRequest(t, srv, cookies, http.MethodPost, "https://nori.example/settings/mcp/grants/"+first.ManagementID+"/revoke", url.Values{"csrf_token": {csrf}, "decision": {"revoke"}}.Encode(), "https://nori.example")
	if confirmed.Code != http.StatusSeeOther || !strings.Contains(confirmed.Header().Get("Location"), "mcp_grant_revoked=1") {
		t.Fatalf("confirmed revoke = %d location=%q body=%s", confirmed.Code, confirmed.Header().Get("Location"), confirmed.Body)
	}
	if _, err := st.GetOAuthGrantManagement(ctx, first.ManagementID); err == nil {
		t.Fatal("confirmed revoke left selected grant active")
	}
	if _, err := st.GetOAuthGrantManagement(ctx, second.ManagementID); err != nil {
		t.Fatalf("confirmed revoke affected sibling grant: %v", err)
	}

	result := settingsRequest(t, srv, cookies, http.MethodGet, "https://nori.example/settings?mcp_grant_revoked=1", "", "")
	if result.Code != http.StatusOK || !strings.Contains(result.Body.String(), `role="status"`) || !strings.Contains(result.Body.String(), "Connection revoked") {
		t.Fatalf("revocation result = %d: %s", result.Code, result.Body)
	}
}

func TestMCPDestructiveSettingsMutationsRequireBoundedExactOrigin(t *testing.T) {
	srv, st := mcpSettingsServer(t)
	ctx := context.Background()
	if err := st.SetMCPConfig(ctx, true, "https://nori.example:8443", false); err != nil {
		t.Fatal(err)
	}
	grant := seedManagedGrant(t, st, "client-one", "Calendar", "family-one")
	cookies := loginCookies(t, srv)
	settings := settingsRequest(t, srv, cookies, http.MethodGet, "https://nori.example:8443/settings", "", "")
	csrf := csrfFromBody(settings.Body.String())
	body := url.Values{"csrf_token": {csrf}, "decision": {"revoke"}}.Encode()
	target := "https://nori.example:8443/settings/mcp/grants/" + grant.ManagementID + "/revoke"

	for _, tc := range []struct {
		name    string
		target  string
		origin  []string
		headers map[string]string
	}{
		{name: "missing origin", target: target},
		{name: "null origin", target: target, origin: []string{"null"}},
		{name: "foreign origin", target: target, origin: []string{"https://evil.example"}},
		{name: "duplicate origin", target: target, origin: []string{"https://nori.example:8443", "https://evil.example"}},
		{name: "host port mismatch", target: "https://nori.example/settings/mcp/grants/" + grant.ManagementID + "/revoke", origin: []string{"https://nori.example:8443"}},
		{name: "forwarded spoof", target: "https://evil.example/settings/mcp/grants/" + grant.ManagementID + "/revoke", origin: []string{"https://nori.example:8443"}, headers: map[string]string{"Forwarded": "host=nori.example:8443;proto=https", "X-Forwarded-Host": "nori.example:8443"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, tc.target, strings.NewReader(body))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			for _, origin := range tc.origin {
				req.Header.Add("Origin", origin)
			}
			for name, value := range tc.headers {
				req.Header.Set(name, value)
			}
			for _, cookie := range cookies {
				req.AddCookie(cookie)
			}
			rr := httptest.NewRecorder()
			srv.ServeHTTP(rr, req)
			if rr.Code != http.StatusForbidden {
				t.Fatalf("status = %d: %s", rr.Code, rr.Body)
			}
			if _, err := st.GetOAuthGrantManagement(ctx, grant.ManagementID); err != nil {
				t.Fatalf("rejected request changed grant: %v", err)
			}
		})
	}

	for _, tc := range []struct {
		name string
		body string
		code int
	}{
		{name: "missing csrf", body: url.Values{"decision": {"revoke"}}.Encode(), code: http.StatusForbidden},
		{name: "invalid csrf", body: url.Values{"csrf_token": {"wrong"}, "decision": {"revoke"}}.Encode(), code: http.StatusForbidden},
		{name: "duplicate decision", body: url.Values{"csrf_token": {csrf}, "decision": {"cancel", "revoke"}}.Encode(), code: http.StatusBadRequest},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rr := settingsRequest(t, srv, cookies, http.MethodPost, target, tc.body, "https://nori.example:8443")
			if rr.Code != tc.code {
				t.Fatalf("status = %d: %s", rr.Code, rr.Body)
			}
			if _, err := st.GetOAuthGrantManagement(ctx, grant.ManagementID); err != nil {
				t.Fatalf("rejected request changed grant: %v", err)
			}
		})
	}

	unknown := settingsRequest(t, srv, cookies, http.MethodPost, "https://nori.example:8443/settings/mcp/grants/not-an-opaque-id/revoke", body, "https://nori.example:8443")
	if unknown.Code != http.StatusConflict {
		t.Fatalf("unknown opaque id = %d: %s", unknown.Code, unknown.Body)
	}
	if _, err := st.GetOAuthGrantManagement(ctx, grant.ManagementID); err != nil {
		t.Fatalf("unknown id changed selected grant: %v", err)
	}

	settingsChange := url.Values{"csrf_token": {csrf}, "bot_name": {"Nori"}, "mcp_enabled": {"0"}, "mcp_public_url": {"https://nori.example:8443"}}.Encode()
	missingSettingsOrigin := settingsRequest(t, srv, cookies, http.MethodPost, "https://nori.example:8443/settings", settingsChange, "")
	if missingSettingsOrigin.Code != http.StatusForbidden {
		t.Fatalf("configured settings change without origin = %d: %s", missingSettingsOrigin.Code, missingSettingsOrigin.Body)
	}
	if cfg, err := st.GetMCPConfig(ctx); err != nil || !cfg.Enabled || cfg.PublicURL != "https://nori.example:8443" {
		t.Fatalf("rejected settings change altered config: %+v %v", cfg, err)
	}

	tooLarge := url.Values{"csrf_token": {csrf}, "decision": {"revoke"}, "padding": {strings.Repeat("x", 17<<10)}}.Encode()
	large := settingsRequest(t, srv, cookies, http.MethodPost, target, tooLarge, "https://nori.example:8443")
	if large.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized body = %d: %s", large.Code, large.Body)
	}
	if _, err := st.GetOAuthGrantManagement(ctx, grant.ManagementID); err != nil {
		t.Fatalf("oversized request changed grant: %v", err)
	}

	global := settingsRequest(t, srv, cookies, http.MethodPost, "https://nori.example:8443/settings/mcp/revoke", url.Values{"csrf_token": {csrf}}.Encode(), "https://nori.example:8443")
	if global.Code != http.StatusSeeOther {
		t.Fatalf("global revoke = %d: %s", global.Code, global.Body)
	}
	if _, err := st.GetOAuthGrantManagement(ctx, grant.ManagementID); err == nil {
		t.Fatal("global revoke left grant active")
	}
}

func TestMCPGrantManagementUncertainResultIsAnnounced(t *testing.T) {
	var body bytes.Buffer
	if err := SettingsPage("Nori", "csrf", "", false, store.MCPConfig{Enabled: true}, mcpSettingsView{GrantError: "Could not confirm that the connection was revoked. It may still be active."}, Channels{}, nil).Render(context.Background(), &body); err != nil {
		t.Fatal(err)
	}
	page := body.String()
	if !strings.Contains(page, `role="alert"`) || !strings.Contains(page, "Couldn’t revoke connection") || !strings.Contains(page, "may still be active") {
		t.Fatalf("uncertain revocation response is not an announced alert: %s", page)
	}
}

func TestMCPOAuthEndToEnd(t *testing.T) {
	srv, st := mcpSettingsServer(t)
	httpServer := httptest.NewServer(srv)
	defer httpServer.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := st.SetMCPConfig(ctx, true, httpServer.URL, false); err != nil {
		t.Fatal(err)
	}
	cookies := loginCookies(t, srv)
	call := func(method, path, body, contentType string, authenticated bool) *httptest.ResponseRecorder {
		t.Helper()
		r := httptest.NewRequest(method, httpServer.URL+path, strings.NewReader(body))
		r.Header.Set("Content-Type", contentType)
		if authenticated {
			r.Header.Set("Origin", httpServer.URL)
			for _, c := range cookies {
				r.AddCookie(c)
			}
		}
		w := httptest.NewRecorder()
		srv.ServeHTTP(w, r)
		return w
	}
	registration := call("POST", "/oauth/register", `{"client_name":"Integration client","redirect_uris":["http://127.0.0.1:8765/callback"],"token_endpoint_auth_method":"none"}`, "application/json", false)
	if registration.Code != 201 {
		t.Fatalf("register: %d %s", registration.Code, registration.Body)
	}
	var client struct {
		ID string `json:"client_id"`
	}
	if err := json.Unmarshal(registration.Body.Bytes(), &client); err != nil {
		t.Fatal(err)
	}
	verifier := strings.Repeat("x", 43)
	hash := sha256.Sum256([]byte(verifier))
	params := url.Values{"client_id": {client.ID}, "redirect_uri": {"http://127.0.0.1:8765/callback"}, "response_type": {"code"}, "code_challenge_method": {"S256"}, "code_challenge": {base64.RawURLEncoding.EncodeToString(hash[:])}, "resource": {httpServer.URL + "/mcp"}, "state": {"test-state"}}
	// Omitted scope uses the advertised management permissions, not secrets.
	page := call("GET", "/oauth/authorize?"+params.Encode(), "", "", true)
	if page.Code != 200 {
		t.Fatalf("consent: %d %s", page.Code, page.Body)
	}
	params.Set("csrf_token", csrfFromBody(page.Body.String()))
	params.Set("decision", "allow")
	approved := call("POST", "/oauth/authorize", params.Encode(), "application/x-www-form-urlencoded", true)
	if approved.Code != 303 {
		t.Fatalf("approve: %d %s", approved.Code, approved.Body)
	}
	u, err := url.Parse(approved.Header().Get("Location"))
	if err != nil || u.Query().Get("state") != "test-state" {
		t.Fatalf("callback: %v %v", u, err)
	}
	token := call("POST", "/oauth/token", url.Values{"grant_type": {"authorization_code"}, "code": {u.Query().Get("code")}, "code_verifier": {verifier}, "client_id": {client.ID}, "redirect_uri": {"http://127.0.0.1:8765/callback"}, "resource": {httpServer.URL + "/mcp"}}.Encode(), "application/x-www-form-urlencoded", false)
	if token.Code != 200 {
		t.Fatalf("token: %d %s", token.Code, token.Body)
	}
	var credentials struct {
		AccessToken string `json:"access_token"`
		Scope       string `json:"scope"`
	}
	if err := json.Unmarshal(token.Body.Bytes(), &credentials); err != nil {
		t.Fatal(err)
	}
	if credentials.Scope != "nori:read nori:write" {
		t.Fatalf("default scope: %q", credentials.Scope)
	}
	mcpClient := mcp.NewClient(&mcp.Implementation{Name: "integration", Version: "1"}, nil)
	session, err := mcpClient.Connect(ctx, &mcp.StreamableClientTransport{Endpoint: httpServer.URL + "/mcp", HTTPClient: &http.Client{Transport: &oauth2.Transport{Source: oauth2.StaticTokenSource(&oauth2.Token{AccessToken: credentials.AccessToken})}}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	result, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "create_service", Arguments: map[string]any{"name": "oauth-created", "watched_image": "nginx:latest", "deploy_script": "true"}})
	if err != nil || result.IsError {
		t.Fatalf("authenticated create: %+v %v", result, err)
	}
	svc, err := st.GetServiceByName(ctx, "oauth-created")
	if err != nil {
		t.Fatal(err)
	}
	result, err = session.CallTool(ctx, &mcp.CallToolParams{Name: "get_service_environment", Arguments: map[string]any{"service_id": svc.ID}})
	if err != nil || result.IsError {
		t.Fatalf("default grant cannot read environment structure: %+v %v", result, err)
	}
	if rr := settingsRequest(t, srv, cookies, http.MethodPost, httpServer.URL+"/settings/mcp/revoke", url.Values{"csrf_token": {csrfFromBody(page.Body.String())}}.Encode(), httpServer.URL); rr.Code != http.StatusSeeOther {
		t.Fatalf("origin-bound global revoke = %d: %s", rr.Code, rr.Body)
	}
	if _, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "list_services", Arguments: map[string]any{}}); err == nil {
		t.Fatal("existing MCP connection survived grant revocation")
	}
}

func TestMCPSettingsRoutesAndRevocation(t *testing.T) {
	srv, st := mcpSettingsServer(t)
	cookies := loginCookies(t, srv)
	body := getAuthed(t, srv, cookies, "/settings")
	if !strings.Contains(body, `name="mcp_enabled"><option value="0" selected`) {
		t.Fatal("MCP must be disabled by default")
	}
	for _, path := range []string{"/mcp", "/oauth/authorize", "/oauth/token", "/oauth/register", "/oauth/revoke", "/.well-known/oauth-authorization-server", "/.well-known/oauth-protected-resource/mcp"} {
		rr := httptest.NewRecorder()
		srv.ServeHTTP(rr, httptest.NewRequest("GET", path, nil))
		if rr.Code != 404 {
			t.Errorf("disabled %s = %d", path, rr.Code)
		}
	}
	form := url.Values{"bot_name": {"Nori"}, "notify_mode": {"always"}, "mcp_enabled": {"1"}, "mcp_public_url": {"https://nori.example"}, "csrf_token": {csrfFromBody(body)}}
	// Session cookies alone must never enable the server without CSRF proof.
	bad := url.Values{}
	for k, v := range form {
		bad[k] = v
	}
	bad.Del("csrf_token")
	r := httptest.NewRequest("POST", "/settings", strings.NewReader(bad.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, c := range cookies {
		r.AddCookie(c)
	}
	rr := httptest.NewRecorder()
	srv.ServeHTTP(rr, r)
	if rr.Code != 403 {
		t.Fatalf("settings without CSRF = %d", rr.Code)
	}
	postAuthed(t, srv, cookies, "/settings", form.Encode())
	cfg, _ := st.GetMCPConfig(context.Background())
	if !cfg.Enabled {
		t.Fatal("MCP not enabled")
	}
	rr = httptest.NewRecorder()
	r = httptest.NewRequest("POST", "https://nori.example/mcp", strings.NewReader(`{}`))
	for _, c := range cookies {
		r.AddCookie(c)
	}
	srv.ServeHTTP(rr, r)
	if rr.Code != 401 || !strings.Contains(rr.Header().Get("WWW-Authenticate"), "resource_metadata=") {
		t.Fatalf("MCP cookie-only request: %d %s", rr.Code, rr.Body)
	}
	body = getAuthed(t, srv, cookies, "/settings")
	if !strings.Contains(body, "https://nori.example/mcp") {
		t.Fatal("settings omit MCP URL")
	}
	if rr := settingsRequest(t, srv, cookies, http.MethodPost, "https://nori.example/settings/mcp/revoke", url.Values{"csrf_token": {csrfFromBody(body)}}.Encode(), "https://nori.example"); rr.Code != http.StatusSeeOther {
		t.Fatalf("origin-bound global revoke = %d: %s", rr.Code, rr.Body)
	}
	revoked, _ := st.GetMCPConfig(context.Background())
	if revoked.Epoch == cfg.Epoch || !revoked.Enabled {
		t.Fatal("revocation must invalidate grants without disabling MCP")
	}
	form.Set("mcp_public_url", "http://external.example")
	r = httptest.NewRequest("POST", "https://nori.example/settings", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Origin", "https://nori.example")
	for _, c := range cookies {
		r.AddCookie(c)
	}
	rr = httptest.NewRecorder()
	srv.ServeHTTP(rr, r)
	if rr.Code != 200 || !strings.Contains(rr.Body.String(), "MCP requires HTTPS") {
		t.Fatalf("insecure URL = %d %s", rr.Code, rr.Body)
	}
	after, _ := st.GetMCPConfig(context.Background())
	if after != revoked {
		t.Fatal("invalid settings changed MCP configuration")
	}
}

func TestMCPOAuthLoginReturnAndSecureCookies(t *testing.T) {
	srv, st := mcpSettingsServer(t)
	oldCookies := loginCookies(t, srv)
	if err := st.SetMCPConfig(context.Background(), true, "https://nori.example", false); err != nil {
		t.Fatal(err)
	}
	upgradeRequest := httptest.NewRequest("GET", "http://nori.example/oauth/authorize", nil)
	for _, c := range oldCookies {
		upgradeRequest.AddCookie(c)
	}
	upgrade := httptest.NewRecorder()
	srv.ServeHTTP(upgrade, upgradeRequest)
	if len(upgrade.Result().Cookies()) != 2 {
		t.Fatal("pre-existing session not upgraded for OAuth")
	}
	for _, c := range upgrade.Result().Cookies() {
		if !c.Secure {
			t.Fatal("pre-existing OAuth session cookie not Secure")
		}
	}
	next := "/oauth/authorize?client_id=test&state=a%26b"
	rr := httptest.NewRecorder()
	srv.ServeHTTP(rr, httptest.NewRequest("GET", "https://nori.example"+next, nil))
	location, err := url.Parse(rr.Header().Get("Location"))
	if err != nil || location.Path != "/login" || location.Query().Get("next") != next {
		t.Fatalf("login redirect: %v %v", location, err)
	}
	// Simulate HTTP behind a TLS-terminating proxy with the configured Host.
	r := httptest.NewRequest("POST", "http://nori.example/login", strings.NewReader(url.Values{"password": {"test"}, "next": {next}}.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr = httptest.NewRecorder()
	srv.ServeHTTP(rr, r)
	if rr.Code != http.StatusSeeOther || rr.Header().Get("Location") != next {
		t.Fatalf("login return: %d %s", rr.Code, rr.Header().Get("Location"))
	}
	for _, cookie := range rr.Result().Cookies() {
		if !cookie.Secure {
			t.Errorf("cookie %s not Secure", cookie.Name)
		}
	}
	for _, bad := range []string{"https://evil.example", "//evil.example", "/\\evil.example", "/oauth/authorize#bad", "/%6fauth/authorize"} {
		if safeLoginNext(bad) != "/" {
			t.Errorf("unsafe return %q", bad)
		}
	}
}
