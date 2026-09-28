// Package mcpauth implements the instance's OAuth authorization and resource server.
package mcpauth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"nori/internal/auth"
	"nori/internal/store"
)

const (
	ScopeRead     = "nori:read"
	ScopeWrite    = "nori:write"
	ScopeSecrets  = "nori:secrets"
	defaultScopes = ScopeRead + " " + ScopeWrite

	authorizationCodeLifetime = 5 * time.Minute
	accessTokenLifetime       = 10 * time.Minute
	grantLifetime             = 30 * 24 * time.Hour
	pendingClientLifetime     = 10 * time.Minute
	approvedClientLifetime    = 365 * 24 * time.Hour
)

var scopes = []string{ScopeRead, ScopeWrite, ScopeSecrets}

type Server struct {
	st      *store.Store
	auth    *auth.Auth
	mu      sync.Mutex
	budgets map[string]requestBudget
}

type requestBudget struct {
	window   time.Time
	requests int
}

// Anonymous registration cannot exhaust the budget for existing grants.
// Grant keys enter this bounded map only after the credential is verified.
func (s *Server) allow(w http.ResponseWriter, key string, limit int) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.budgets == nil {
		s.budgets = make(map[string]requestBudget)
	}
	for k, budget := range s.budgets {
		if time.Since(budget.window) >= time.Minute {
			delete(s.budgets, k)
		}
	}
	budget := s.budgets[key]
	if budget.window.IsZero() {
		budget.window = time.Now()
	}
	budget.requests++
	s.budgets[key] = budget
	if budget.requests > limit {
		w.Header().Set("Retry-After", "60")
		failure(w, 429, "slow_down")
		return false
	}
	return true
}

func New(st *store.Store, a *auth.Auth) *Server { return &Server{st: st, auth: a} }

// ListOAuthGrantManagement exposes only Store's browser-safe management
// projection to Settings. It deliberately does not expose generic OAuth rows,
// whose serialized payloads include credentials and protocol-private context.
// Legacy families are reconstructed from live code or refresh records. A
// refresh family may contain narrowed scopes, so all of its live refresh
// records must be considered before rebuilding the management projection.
func (s *Server) ListOAuthGrantManagement(ctx context.Context) ([]store.OAuthRegistration, error) {
	if err := s.bootstrapOAuthGrantManagement(ctx); err != nil {
		return nil, err
	}
	return s.st.ListOAuthGrantManagement(ctx)
}

func (s *Server) bootstrapOAuthGrantManagement(ctx context.Context) error {
	config, err := s.st.GetMCPConfig(ctx)
	if err != nil {
		return err
	}
	if !config.Enabled || config.Epoch == "" || config.PublicURL == "" {
		return nil
	}
	projectedFamilies, err := s.st.ListOAuthManagedGrantFamilies(ctx)
	if err != nil {
		return err
	}
	codes, err := s.st.ListOAuthRecords(ctx, "code")
	if err != nil {
		return err
	}
	bootstrap := func(g grant, approvedAt time.Time, scopes string) error {
		if _, ok := projectedFamilies[g.Family]; ok {
			return nil
		}
		clientRecord, err := s.st.GetOAuth(ctx, digest(g.ClientID), "client")
		if err != nil {
			if errors.Is(err, store.ErrNotFound) {
				return nil
			}
			return err
		}
		var client storedClient
		if json.Unmarshal(clientRecord.Data, &client) != nil || client.Epoch != config.Epoch || clientRecord.Used {
			return nil
		}
		err = s.st.BootstrapOAuthGrant(ctx, store.OAuthGrantBootstrap{
			ClientKey:       digest(g.ClientID),
			ClientName:      client.Client.Name,
			ClientExpiresAt: time.Unix(clientRecord.Expires, 0),
			ApprovedAt:      approvedAt,
			Family:          g.Family,
			FamilyExpiresAt: time.Unix(g.FamilyExpires, 0),
			Scopes:          scopes,
		})
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			return err
		}
		if err == nil {
			projectedFamilies[g.Family] = struct{}{}
		}
		return nil
	}
	now := time.Now().Unix()
	for _, code := range codes {
		var g grant
		if json.Unmarshal(code.Data, &g) != nil || g.ClientID == "" || g.Scope == "" || g.Family == "" || g.Family != code.Family || g.Epoch != config.Epoch || g.Resource != config.PublicURL+"/mcp" || g.FamilyExpires <= now {
			continue
		}
		if err := bootstrap(g, time.Unix(code.Expires, 0).Add(-authorizationCodeLifetime), g.Scope); err != nil {
			return err
		}
	}
	refreshes, err := s.st.ListOAuthRecords(ctx, "refresh")
	if err != nil {
		return err
	}
	type refreshFamily struct {
		grant  grant
		scopes map[string]struct{}
	}
	families := make(map[string]refreshFamily)
	for _, refresh := range refreshes {
		if _, ok := projectedFamilies[refresh.Family]; ok {
			continue
		}
		var g grant
		if json.Unmarshal(refresh.Data, &g) != nil || g.ClientID == "" || g.Scope == "" || g.Family == "" || g.Family != refresh.Family || g.Epoch != config.Epoch || g.Resource != config.PublicURL+"/mcp" || g.FamilyExpires <= now {
			continue
		}
		family := families[g.Family]
		if family.grant.Family == "" {
			family.grant = g
			family.scopes = make(map[string]struct{})
		}
		for _, scope := range strings.Fields(g.Scope) {
			family.scopes[scope] = struct{}{}
		}
		families[g.Family] = family
	}
	familyNames := make([]string, 0, len(families))
	for family := range families {
		familyNames = append(familyNames, family)
	}
	sort.Strings(familyNames)
	for _, familyName := range familyNames {
		family := families[familyName]
		scopes := make([]string, 0, len(family.scopes))
		for scope := range family.scopes {
			scopes = append(scopes, scope)
		}
		sort.Strings(scopes)
		if err := bootstrap(family.grant, time.Unix(family.grant.FamilyExpires, 0).Add(-grantLifetime), strings.Join(scopes, " ")); err != nil {
			return err
		}
	}
	return nil
}

// GetOAuthGrantManagement resolves one opaque management ID to the safe data
// needed for a Settings confirmation page.
func (s *Server) GetOAuthGrantManagement(ctx context.Context, id string) (store.OAuthGrant, error) {
	return s.st.GetOAuthGrantManagement(ctx, id)
}

// RevokeOAuthGrantManagement revokes exactly one active family selected by an
// opaque management ID. The Store owns the transaction and family tombstone.
func (s *Server) RevokeOAuthGrantManagement(ctx context.Context, id string) error {
	return s.st.RevokeOAuthGrant(ctx, id)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
func failure(w http.ResponseWriter, status int, code string) {
	writeJSON(w, status, map[string]string{"error": code})
}
func (s *Server) config(w http.ResponseWriter, r *http.Request) (store.MCPConfig, bool) {
	c, err := s.st.GetMCPConfig(r.Context())
	if err != nil {
		failure(w, 503, "temporarily_unavailable")
		return c, false
	}
	if !c.Enabled || c.PublicURL == "" || c.Epoch == "" {
		http.NotFound(w, r)
		return c, false
	}
	u, err := url.Parse(c.PublicURL)
	if err != nil || u.Host != r.Host {
		failure(w, 403, "invalid_host")
		return c, false
	}
	return c, true
}
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	c, ok := s.config(w, r)
	if !ok {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 32<<10)
	if len(r.URL.RawQuery) > 16384 {
		failure(w, 414, "invalid_request")
		return
	}
	if r.URL.Path != "/oauth/authorize" {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		if r.Method == "OPTIONS" {
			w.WriteHeader(204)
			return
		}
	}
	switch r.URL.Path {
	case "/.well-known/oauth-authorization-server":
		if r.Method != "GET" {
			failure(w, 405, "invalid_request")
			return
		}
		writeJSON(w, 200, map[string]any{"issuer": c.PublicURL, "authorization_endpoint": c.PublicURL + "/oauth/authorize", "token_endpoint": c.PublicURL + "/oauth/token", "registration_endpoint": c.PublicURL + "/oauth/register", "revocation_endpoint": c.PublicURL + "/oauth/revoke", "response_types_supported": []string{"code"}, "grant_types_supported": []string{"authorization_code", "refresh_token"}, "code_challenge_methods_supported": []string{"S256"}, "token_endpoint_auth_methods_supported": []string{"none", "client_secret_basic"}, "revocation_endpoint_auth_methods_supported": []string{"none", "client_secret_basic"}, "scopes_supported": scopes})
	case "/.well-known/oauth-protected-resource", "/.well-known/oauth-protected-resource/mcp":
		if r.Method != "GET" {
			failure(w, 405, "invalid_request")
			return
		}
		writeJSON(w, 200, map[string]any{"resource": c.PublicURL + "/mcp", "authorization_servers": []string{c.PublicURL}, "scopes_supported": scopes, "bearer_methods_supported": []string{"header"}})
	case "/oauth/authorize":
		if r.Method != "GET" && r.Method != "POST" {
			failure(w, 405, "invalid_request")
			return
		}
		// OAuth clients open the consent page from other origins. GET only
		// renders consent; approving or denying it requires a same-origin POST
		// and the session's CSRF token.
		if r.Method == "POST" && r.Header.Get("Origin") != c.PublicURL {
			failure(w, 403, "invalid_origin")
			return
		}
		s.auth.Middleware(s.auth.CSRFMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { s.authorize(w, r, c) }))).ServeHTTP(w, r)
	case "/oauth/register", "/oauth/token", "/oauth/revoke":
		if r.Method != "POST" {
			failure(w, 405, "invalid_request")
			return
		}
		if r.URL.Path == "/oauth/register" {
			if !s.allow(w, "registration", 10) {
				return
			}
			s.register(w, r, c)
			return
		}
		if err := r.ParseForm(); err != nil || !unique(r.PostForm) {
			failure(w, 400, "invalid_request")
			return
		}
		if r.URL.Path == "/oauth/token" {
			s.token(w, r, c)
		} else {
			s.revoke(w, r, c)
		}
	default:
		http.NotFound(w, r)
	}
}
func unique(v url.Values) bool {
	for _, values := range v {
		if len(values) != 1 {
			return false
		}
	}
	return true
}
