package mcpauth

import (
	_ "embed"
	"encoding/json"
	"html/template"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"

	"nori/internal/store"
)

var challengePattern = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)

//go:embed consent.html
var consentHTML string

var consent = template.Must(template.New("consent").Parse(consentHTML))

func normalizeScope(raw string) (string, bool) {
	if raw == "" {
		return defaultScopes, true
	}
	out := []string{}
	for _, v := range strings.Fields(raw) {
		if !slices.Contains(scopes, v) {
			return "", false
		}
		if !slices.Contains(out, v) {
			out = append(out, v)
		}
	}
	return strings.Join(out, " "), len(out) > 0
}

func (s *Server) authorize(w http.ResponseWriter, r *http.Request, c store.MCPConfig) {
	if err := r.ParseForm(); err != nil {
		failure(w, 400, "invalid_request")
		return
	}
	p := r.URL.Query()
	if r.Method == "POST" {
		p = r.PostForm
	}
	if !unique(p) {
		failure(w, 400, "invalid_request")
		return
	}
	cl, err := s.getClient(r.Context(), p.Get("client_id"), c)
	if err != nil || !slices.Contains(cl.Client.Redirects, p.Get("redirect_uri")) {
		failure(w, 400, "invalid_request")
		return
	}
	scope, ok := normalizeScope(p.Get("scope"))
	if !ok {
		failure(w, 400, "invalid_scope")
		return
	}
	if p.Get("response_type") != "code" || p.Get("code_challenge_method") != "S256" || !challengePattern.MatchString(p.Get("code_challenge")) || p.Get("resource") != c.PublicURL+"/mcp" || len(p.Get("state")) > 2048 {
		failure(w, 400, "invalid_request")
		return
	}
	target, _ := url.Parse(p.Get("redirect_uri"))
	if r.Method == "GET" {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		// Browsers also check form-action on the POST's 303 callback redirect.
		// Only allow the validated callback origin, escaping CSP delimiters and
		// wildcards so client metadata cannot broaden the policy.
		callbackOrigin := (&url.URL{Scheme: target.Scheme, Host: target.Host}).String()
		callbackSource := strings.NewReplacer(";", "%3B", ",", "%2C", "*", "%2A").Replace(callbackOrigin)
		w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'self'; form-action 'self' "+callbackSource+"; frame-ancestors 'none'; base-uri 'none'")
		// no-referrer makes browsers send Origin: null on the consent form
		// POST. same-origin preserves that security check while withholding
		// the authorization URL from cross-origin client callbacks.
		w.Header().Set("Referrer-Policy", "same-origin")
		w.Header().Set("X-Frame-Options", "DENY")
		params := url.Values{}
		for _, k := range []string{"client_id", "redirect_uri", "response_type", "code_challenge_method", "code_challenge", "resource", "scope", "state"} {
			params.Set(k, p.Get(k))
		}
		_ = consent.Execute(w, struct {
			Name, ID, Scope, Redirect, CSRF string
			Params                          url.Values
		}{cl.Client.Name, cl.Client.ID, scope, p.Get("redirect_uri"), s.auth.CSRFToken(r), params})
		return
	}
	q := target.Query()
	q.Set("state", p.Get("state"))
	if p.Get("decision") != "allow" {
		q.Set("error", "access_denied")
	} else {
		now := time.Now()
		code := secret()
		g := grant{ClientID: cl.Client.ID, Redirect: p.Get("redirect_uri"), Resource: p.Get("resource"), Scope: scope, Challenge: p.Get("code_challenge"), Epoch: c.Epoch, Family: secret(), FamilyExpires: now.Add(grantLifetime).Unix()}
		data, err := json.Marshal(g)
		if err != nil {
			failure(w, 503, "temporarily_unavailable")
			return
		}
		if _, err := s.st.ApproveOAuthGrant(r.Context(), store.OAuthGrantApproval{
			ClientKey:       digest(cl.Client.ID),
			ClientName:      oauthClientDisplayName(cl.Client.Name),
			ClientExpiresAt: now.Add(approvedClientLifetime),
			ApprovedAt:      now,
			Family:          g.Family,
			FamilyExpiresAt: time.Unix(g.FamilyExpires, 0),
			Scopes:          scope,
			Code: store.OAuthRecord{
				Key:     digest(code),
				Kind:    "code",
				Family:  g.Family,
				Data:    data,
				Expires: now.Add(authorizationCodeLifetime).Unix(),
			},
		}); err != nil {
			failure(w, 503, "temporarily_unavailable")
			return
		}
		q.Set("code", code)
	}
	target.RawQuery = q.Encode()
	http.Redirect(w, r, target.String(), http.StatusSeeOther)
}
