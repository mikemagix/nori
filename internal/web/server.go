package web

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"io/fs"
	"log"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/gorilla/websocket"

	"nori/internal/auth"
	"nori/internal/docker"
	"nori/internal/envfile"
	"nori/internal/executor"
	"nori/internal/launcher"
	"nori/internal/mcpauth"
	"nori/internal/notify"
	"nori/internal/poller"
	"nori/internal/store"
	terminalsession "nori/internal/terminal"
)

type selfEnvironmentStore interface {
	EditableEnvironment() (string, error)
	ReplaceEditableEnvironment(string) error
}

type Server struct {
	store           *store.Store
	oauth           *mcpauth.Server
	docker          docker.Client
	executor        *executor.Executor
	poller          *poller.Poller
	auth            *auth.Auth
	terminal        terminalsession.Attacher
	selfEnvironment selfEnvironmentStore
	channels        Channels
	router          chi.Router
}

func NewServer(st *store.Store, dk docker.Client, ex *executor.Executor, pl *poller.Poller, a *auth.Auth, channels Channels, terminals ...terminalsession.Attacher) *Server {
	term := terminalsession.Attacher(terminalsession.New("nori", "."))
	if len(terminals) > 0 && terminals[0] != nil {
		term = terminals[0]
	}
	s := &Server{
		store: st, docker: dk, executor: ex, poller: pl, auth: a, terminal: term,
		selfEnvironment: launcher.New(),
		channels:        channels,
	}
	r := chi.NewRouter()
	r.Use(s.botNameMiddleware)
	r.Use(s.mcpSecureCookies)
	r.Get("/login", s.handleLoginGet)
	r.Post("/login", s.handleLoginPost)
	r.Post("/logout", s.handleLogout)
	// Intentionally outside the auth group so proxies and uptime monitors can
	// reach it; the response carries no information beyond liveness.
	r.Get("/healthz", s.handleHealthz)
	s.oauth = mcpauth.New(st, a)
	r.Handle("/mcp", s.oauth.Protect(s.newMCPHandler()))
	r.Handle("/oauth/*", s.oauth)
	r.Handle("/.well-known/oauth-authorization-server", s.oauth)
	r.Handle("/.well-known/oauth-protected-resource", s.oauth)
	r.Handle("/.well-known/oauth-protected-resource/mcp", s.oauth)

	r.Group(func(r chi.Router) {
		r.Use(s.auth.Middleware)
		r.Use(s.auth.CSRFMiddleware)

		r.Get("/", s.handleDashboard)
		r.Get("/terminal", s.handleTerminal)
		r.Get("/terminal/ws", s.handleTerminalWebSocket)
		r.Get("/partials/services", s.handleServicesPartial)
		r.Get("/services/new", s.handleServiceNew)
		r.Post("/validate/editor", s.handleEditorValidate)
		r.Post("/services", s.handleServiceCreate)
		r.Get("/services/{name}", s.handleServiceDetail)
		r.Get("/services/{name}/edit", s.handleServiceEdit)
		r.Get("/services/{name}/history/{kind}", s.handleConfigHistory)
		r.Get("/services/{name}/history/{kind}/{version}", s.handleConfigHistory)
		r.Post("/services/{name}", s.handleServiceUpdate)
		r.Post("/services/{name}/delete", s.handleServiceDelete)
		r.Post("/services/{name}/deploy", s.handleDeploy)
		r.Post("/services/{name}/start", s.handleStart)
		r.Post("/services/{name}/stop", s.handleStop)
		r.Get("/services/{name}/logs/stream", s.handleLogsStream)
		r.Get("/deployments/{id}", s.handleDeployment)
		r.Get("/deployments/{id}/stream", s.handleDeploymentStream)
	})

	// Settings reads need a signed administrator session, but no CSRF proof.
	// Keep them outside the mutation chain so its body and origin guarantees are
	// easy to audit independently.
	r.Group(func(r chi.Router) {
		r.Use(s.auth.Middleware)
		r.Get("/settings", s.handleSettingsGet)
		r.Get("/settings/mcp/grants/{id}/revoke", s.handleMCPGrantRevokeConfirm)
	})

	// Every Settings endpoint that can rotate the MCP epoch or invalidate a
	// family passes through this exact order. CSRF parses form bodies, so the
	// cap must come first; the configured origin is intentionally read from
	// persistent Settings rather than any forwarding header.
	r.Group(func(r chi.Router) {
		r.Use(s.auth.Middleware)
		r.Use(s.mcpSettingsBodyLimit)
		r.Use(s.mcpSettingsOrigin)
		r.Use(s.auth.CSRFMiddleware)
		r.Post("/settings", s.handleSettingsPost)
		r.Post("/settings/mcp/revoke", s.handleMCPRevoke)
		r.Post("/settings/mcp/grants/{id}/revoke", s.handleMCPGrantRevoke)
	})

	sub, _ := fs.Sub(staticFS, "static")
	r.Handle("/static/*", http.StripPrefix("/static/", http.FileServer(http.FS(sub))))
	s.router = r
	return s
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) { s.router.ServeHTTP(w, r) }

func (s *Server) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}

func (s *Server) csrf(r *http.Request) string { return s.auth.CSRFToken(r) }

func (s *Server) botNameMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(w, r.WithContext(withBotName(r.Context(), s.store.BotName(r.Context()))))
	})
}

// Trust the administrator's explicit public URL rather than arbitrary forwarded
// headers when TLS terminates at a reverse proxy.
func (s *Server) mcpSecureCookies(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" || r.URL.Path == "/mcp" || strings.HasPrefix(r.URL.Path, "/static/") || strings.HasPrefix(r.URL.Path, "/.well-known/") || (strings.HasPrefix(r.URL.Path, "/oauth/") && r.URL.Path != "/oauth/authorize") {
			next.ServeHTTP(w, r)
			return
		}
		cfg, err := s.store.GetMCPConfig(r.Context())
		if err == nil && cfg.PublicURL != "" {
			u, err := url.Parse(cfg.PublicURL)
			if err == nil && u.Scheme == "https" && sameOriginHost(u, r.Host) {
				r = r.WithContext(auth.WithSecureCookies(r.Context()))
			}
		}
		next.ServeHTTP(w, r)
	})
}

const mcpSettingsBodyLimit int64 = 16 << 10

// mcpSettingsBodyLimit runs before CSRF because auth.CSRFMiddleware obtains
// its form token through FormValue. Content-Length lets us reject a known
// oversized request before any parser work; MaxBytesReader covers streamed
// requests as they are consumed by the next middleware.
func (s *Server) mcpSettingsBodyLimit(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ContentLength > mcpSettingsBodyLimit {
			http.Error(w, "settings request is too large", http.StatusRequestEntityTooLarge)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, mcpSettingsBodyLimit)
		next.ServeHTTP(w, r)
	})
}

// mcpSettingsOrigin authorizes a destructive Settings request against the
// instance's already-saved public origin. It deliberately ignores Forwarded
// and X-Forwarded-* headers: proxy claims are not browser-origin proof. A new
// installation has no persisted public origin, so it can complete first-time
// setup with the existing session + CSRF protections.
func (s *Server) mcpSettingsOrigin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cfg, err := s.store.GetMCPConfig(r.Context())
		if err != nil {
			http.Error(w, "could not verify MCP settings origin", http.StatusInternalServerError)
			return
		}
		if cfg.PublicURL == "" {
			next.ServeHTTP(w, r)
			return
		}
		configured, err := url.Parse(cfg.PublicURL)
		if err != nil || configured.Scheme == "" || configured.Host == "" || !sameOriginHost(configured, r.Host) {
			http.Error(w, "invalid settings origin", http.StatusForbidden)
			return
		}
		origins := r.Header.Values("Origin")
		if len(origins) != 1 || origins[0] == "null" {
			http.Error(w, "invalid settings origin", http.StatusForbidden)
			return
		}
		origin, err := url.Parse(origins[0])
		if err != nil || !sameOriginURL(configured, origin) || origin.User != nil || origin.Path != "" || origin.RawPath != "" || origin.RawQuery != "" || origin.Fragment != "" {
			http.Error(w, "invalid settings origin", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func sameOriginHost(configured *url.URL, requestHost string) bool {
	request, err := url.Parse(configured.Scheme + "://" + requestHost)
	return err == nil && request.User == nil && request.Host != "" && sameOriginURL(configured, request)
}

func sameOriginURL(left, right *url.URL) bool {
	if !strings.EqualFold(left.Scheme, right.Scheme) || !strings.EqualFold(left.Hostname(), right.Hostname()) {
		return false
	}
	return effectivePort(left) == effectivePort(right)
}

func effectivePort(u *url.URL) string {
	if port := u.Port(); port != "" {
		return port
	}
	if strings.EqualFold(u.Scheme, "https") {
		return "443"
	}
	if strings.EqualFold(u.Scheme, "http") {
		return "80"
	}
	return ""
}

type mcpSettingsView struct {
	Registrations        []store.OAuthRegistration
	InventoryUnavailable bool
	GrantRevoked         bool
	GrantError           string
}

func (s *Server) mcpSettingsView(ctx context.Context) mcpSettingsView {
	registrations, err := s.oauth.ListOAuthGrantManagement(ctx)
	if err != nil {
		return mcpSettingsView{InventoryUnavailable: true}
	}
	return mcpSettingsView{Registrations: registrations}
}

func (s *Server) handleSettingsGet(w http.ResponseWriter, r *http.Request) {
	routing := notify.EffectiveRouting(s.store.NotifyRoutingRaw(r.Context()), s.store.NotifyMode(r.Context()))
	cfg, err := s.store.GetMCPConfig(r.Context())
	if err != nil {
		http.Error(w, "could not load MCP settings", http.StatusInternalServerError)
		return
	}
	view := s.mcpSettingsView(r.Context())
	view.GrantRevoked = r.URL.Query().Get("mcp_grant_revoked") == "1"
	_ = SettingsPage(BotName(r.Context()), s.csrf(r), "", r.URL.Query().Get("saved") == "1", cfg, view, s.channels, routing).Render(r.Context(), w)
}

func (s *Server) handleSettingsPost(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	// Parse the routing checkboxes first so an error re-render can preserve
	// what the user toggled.
	routing := parseRoutingForm(s.channels, r.Form)
	name, err := store.NormalizeBotName(r.FormValue("bot_name"))
	if err != nil {
		s.renderSettingsError(w, r, r.FormValue("bot_name"), routing, err.Error())
		return
	}
	if err := s.store.SetMCPConfig(r.Context(), r.FormValue("mcp_enabled") == "1", r.FormValue("mcp_public_url"), false); err != nil {
		s.renderSettingsError(w, r, name, routing, err.Error())
		return
	}
	if err := s.store.SetSetting(r.Context(), store.SettingBotName, name); err != nil {
		s.renderSettingsError(w, r, name, routing, err.Error())
		return
	}
	// parseRoutingForm only produces table entries for configured channels, so
	// an empty table means nothing is configured and the matrix offered no
	// editable choices. Keep the legacy mode as the active fallback then, so
	// an explicit opt-out survives until a channel exists and the matrix can
	// express a real decision.
	if len(routing) > 0 {
		raw, err := notify.MarshalRouting(routing)
		if err != nil {
			s.renderSettingsError(w, r, name, routing, err.Error())
			return
		}
		if err := s.store.SetSetting(r.Context(), store.SettingNotifyRouting, raw); err != nil {
			s.renderSettingsError(w, r, name, routing, err.Error())
			return
		}
		// The legacy mode is superseded by the routing table; clear it so the
		// fallback translation never resurrects an outdated choice.
		if err := s.store.SetSetting(r.Context(), store.SettingNotifyMode, ""); err != nil {
			s.renderSettingsError(w, r, name, routing, err.Error())
			return
		}
	}
	log.Printf("settings: bot name set to %q, notification routing updated", name)
	http.Redirect(w, r, "/settings?saved=1", http.StatusSeeOther)
}

func (s *Server) renderSettingsError(w http.ResponseWriter, r *http.Request, botName string, routing notify.Routing, errMsg string) {
	// Preserve whatever the user typed (not the normalized value) so they can
	// see and fix their input on re-render.
	cfg := store.MCPConfig{Enabled: r.FormValue("mcp_enabled") == "1", PublicURL: r.FormValue("mcp_public_url")}
	_ = SettingsPage(botName, s.csrf(r), errMsg, false, cfg, s.mcpSettingsView(r.Context()), s.channels, routing).Render(r.Context(), w)
}

func (s *Server) handleMCPRevoke(w http.ResponseWriter, r *http.Request) {
	cfg, err := s.store.GetMCPConfig(r.Context())
	if err == nil {
		err = s.store.SetMCPConfig(r.Context(), cfg.Enabled, cfg.PublicURL, true)
	}
	if err != nil {
		http.Error(w, "could not revoke MCP access", http.StatusInternalServerError)
		return
	}
	log.Print("mcp: administrator revoked all agent access")
	http.Redirect(w, r, "/settings?saved=1", http.StatusSeeOther)
}

func (s *Server) handleMCPGrantRevokeConfirm(w http.ResponseWriter, r *http.Request) {
	grant, err := s.oauth.GetOAuthGrantManagement(r.Context(), chi.URLParam(r, "id"))
	if errors.Is(err, store.ErrNotFound) {
		http.Error(w, "that OAuth connection is no longer active", http.StatusNotFound)
		return
	}
	if err != nil {
		http.Error(w, "could not load the OAuth connection", http.StatusInternalServerError)
		return
	}
	_ = MCPGrantRevokeConfirmPage(BotName(r.Context()), s.csrf(r), grant).Render(r.Context(), w)
}

func (s *Server) handleMCPGrantRevoke(w http.ResponseWriter, r *http.Request) {
	decisions := r.Form["decision"]
	if len(decisions) != 1 {
		http.Error(w, "choose whether to revoke this OAuth connection", http.StatusBadRequest)
		return
	}
	switch decisions[0] {
	case "cancel":
		http.Redirect(w, r, "/settings", http.StatusSeeOther)
		return
	case "revoke":
		// Continue below. The Store reloads and claims this single opaque ID in
		// its revocation transaction rather than trusting confirmation state.
	default:
		http.Error(w, "choose whether to revoke this OAuth connection", http.StatusBadRequest)
		return
	}
	if err := s.oauth.RevokeOAuthGrantManagement(r.Context(), chi.URLParam(r, "id")); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			http.Error(w, "that OAuth connection is no longer active", http.StatusConflict)
			return
		}
		// Do not redirect to the normal success view: a storage error does not
		// prove whether a rollback or commit won, so the connection may remain
		// active and the administrator needs an explicit uncertainty warning.
		routing := notify.EffectiveRouting(s.store.NotifyRoutingRaw(r.Context()), s.store.NotifyMode(r.Context()))
		cfg, cfgErr := s.store.GetMCPConfig(r.Context())
		if cfgErr != nil {
			http.Error(w, "could not revoke the OAuth connection; it may still be active", http.StatusInternalServerError)
			return
		}
		view := s.mcpSettingsView(r.Context())
		view.GrantError = "Could not confirm that the connection was revoked. It may still be active."
		w.WriteHeader(http.StatusInternalServerError)
		_ = SettingsPage(BotName(r.Context()), s.csrf(r), "", false, cfg, view, s.channels, routing).Render(r.Context(), w)
		return
	}
	log.Print("mcp: administrator revoked one OAuth connection")
	http.Redirect(w, r, "/settings?mcp_grant_revoked=1", http.StatusSeeOther)
}

func (s *Server) handleTerminal(w http.ResponseWriter, r *http.Request) {
	unavailable := ""
	if err := s.terminal.Available(); err != nil {
		unavailable = err.Error()
	}
	_ = TerminalPage(s.csrf(r), unavailable).Render(r.Context(), w)
}

type terminalClientMessage struct {
	Type string `json:"type"`
	Data string `json:"data,omitempty"`
	Rows uint16 `json:"rows,omitempty"`
	Cols uint16 `json:"cols,omitempty"`
}

var terminalUpgrader = websocket.Upgrader{
	HandshakeTimeout: 5 * time.Second,
	CheckOrigin:      terminalOriginAllowed,
}

func terminalOriginAllowed(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return false
	}
	u, err := url.Parse(origin)
	return err == nil && strings.EqualFold(u.Host, r.Host)
}

func (s *Server) handleTerminalWebSocket(w http.ResponseWriter, r *http.Request) {
	if err := s.terminal.Available(); err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	ws, err := terminalUpgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer ws.Close()
	ws.SetReadLimit(1 << 20)

	client, err := s.terminal.Attach(r.Context(), 24, 80)
	if err != nil {
		log.Printf("terminal: attach failed: %v", err)
		_ = ws.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseInternalServerErr, err.Error()), time.Now().Add(time.Second))
		return
	}
	defer client.Close()
	log.Printf("terminal: session attached from %s", r.RemoteAddr)

	outputDone := make(chan struct{})
	go func() {
		defer close(outputDone)
		buffer := make([]byte, 32<<10)
		for {
			n, readErr := client.Read(buffer)
			if n > 0 {
				if writeErr := ws.WriteMessage(websocket.BinaryMessage, buffer[:n]); writeErr != nil {
					return
				}
			}
			if readErr != nil {
				_ = ws.Close()
				return
			}
		}
	}()

	for {
		_, payload, err := ws.ReadMessage()
		if err != nil {
			break
		}
		var message terminalClientMessage
		if err := json.Unmarshal(payload, &message); err != nil {
			continue
		}
		switch message.Type {
		case "input":
			if message.Data != "" {
				if _, err := client.Write([]byte(message.Data)); err != nil {
					return
				}
			}
		case "resize":
			rows, cols := terminalDimensions(message.Rows, message.Cols)
			_ = client.Resize(rows, cols)
		case "ping":
			// Application-level keepalive. Receiving the frame is sufficient.
		}
	}

	_ = client.Close()
	select {
	case <-outputDone:
	case <-time.After(time.Second):
	}
}

func terminalDimensions(rows, cols uint16) (uint16, uint16) {
	rows = min(max(rows, 2), 500)
	cols = min(max(cols, 2), 500)
	return rows, cols
}

func (s *Server) handleLoginGet(w http.ResponseWriter, r *http.Request) {
	_ = LoginPage("", "", safeLoginNext(r.URL.Query().Get("next"))).Render(r.Context(), w)
}

// Only the OAuth consent endpoint may resume after login. Never accept an
// absolute URL or a path interpreted differently by browsers and net/url.
func safeLoginNext(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.IsAbs() || u.Host != "" || u.Path != "/oauth/authorize" || u.RawPath != "" || u.Fragment != "" || strings.ContainsAny(raw, "\\\r\n") {
		return "/"
	}
	return u.RequestURI()
}

func (s *Server) handleLoginPost(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	remember := r.FormValue("remember") != ""
	if err := s.auth.Login(w, r, r.FormValue("password"), remember); err != nil {
		log.Printf("auth: login failed from %s", r.RemoteAddr)
		_ = LoginPage("", "Invalid credentials", safeLoginNext(r.FormValue("next"))).Render(r.Context(), w)
		return
	}
	log.Printf("auth: login ok from %s", r.RemoteAddr)
	http.Redirect(w, r, safeLoginNext(r.FormValue("next")), http.StatusSeeOther)
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	log.Printf("auth: logout from %s", r.RemoteAddr)
	s.auth.Logout(w)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func (s *Server) loadViews(ctx context.Context) ([]ServiceView, error) {
	svcs, err := s.store.ListServices(ctx)
	if err != nil {
		return nil, err
	}
	views := make([]ServiceView, 0, len(svcs))
	now := time.Now()
	for _, svc := range svcs {
		cs, err := s.docker.ListByService(ctx, svc.Name)
		state := "unknown"
		runningDigest := ""
		if err == nil {
			state = summarizeState(cs)
			runningDigest = watchedDigest(cs, svc.WatchedImage)
		}
		latest := s.poller.CachedDigest(svc.Name)
		deploys, err := s.store.ListDeployments(ctx, svc.ID, 1)
		if err != nil {
			return nil, err
		}
		lastDeploy := "No deployments yet"
		if len(deploys) > 0 {
			lastDeploy = deployedAgo(deploys[0].StartedAt, now)
		}
		v := ServiceView{
			ID:             svc.ID,
			Name:           svc.Name,
			State:          state,
			RunningVersion: shortDigest(runningDigest),
			LatestVersion:  shortDigest(latest),
			RunningFor:     runningFor(cs, now),
			LastDeploy:     lastDeploy,
			RecentLogs:     s.recentLogs(ctx, cs, 6),
			Managed:        svc.IsSelf,
		}
		v.UpdateAvailable = runningDigest != "" && latest != "" && runningDigest != latest
		views = append(views, v)
	}
	return views, nil
}

func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	views, err := s.loadViews(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	_ = Page(views, s.csrf(r)).Render(r.Context(), w)
}

func (s *Server) handleServicesPartial(w http.ResponseWriter, r *http.Request) {
	views, err := s.loadViews(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	_ = ServicesTablePartial(views, s.csrf(r)).Render(r.Context(), w)
}

func (s *Server) handleServiceNew(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	form, ok := s.newServiceForm(w, r)
	if !ok {
		return
	}
	_ = ServiceFormPage(form, s.csrf(r), false, "/services", "").Render(r.Context(), w)
}

func (s *Server) handleServiceCreate(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	form := parseServiceForm(r)
	svc := &store.Service{
		Name:         form.Name,
		WatchedImage: form.WatchedImage,
		Policy:       store.Policy(form.Policy),
		CronExpr:     form.CronExpr,
		DeployScript: form.DeployScript,
		HealthURL:    form.HealthURL,
	}
	if _, err := s.saveOrdinaryService(r.Context(), ordinaryWrite{Service: svc, Environment: &form.EnvFile, EnvironmentMode: dashboardEnvironment}); err != nil {
		var validationErr *ordinaryValidationError
		if errors.As(err, &validationErr) {
			_ = ServiceFormPage(form, s.csrf(r), false, "/services", validationErr.Error()).Render(r.Context(), w)
			return
		}
		if _, lookupErr := s.store.GetServiceByName(r.Context(), svc.Name); lookupErr == nil {
			_ = ServiceFormPage(form, s.csrf(r), false, "/services", "A service with that name already exists.").Render(r.Context(), w)
			return
		}
		_ = ServiceFormPage(form, s.csrf(r), false, "/services", "No changes were saved. Try again.").Render(r.Context(), w)
		return
	}
	log.Printf("service: created %q (image=%s policy=%s)", svc.Name, svc.WatchedImage, svc.Policy)
	http.Redirect(w, r, "/services/"+svc.Name, http.StatusSeeOther)
}

func (s *Server) handleServiceEdit(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	svc, err := s.getServiceByName(w, r)
	if err != nil {
		return
	}
	form, err := s.serviceToEditForm(r.Context(), svc)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	_ = ServiceFormPage(form, s.csrf(r), true, "/services/"+svc.Name, "").Render(r.Context(), w)
}

func (s *Server) handleServiceUpdate(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	svc, err := s.getServiceByName(w, r)
	if err != nil {
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	form := parseServiceForm(r)
	if svc.IsSelf {
		// The launcher owns the self image and handoff command. Policy remains
		// editable, but a POST cannot turn the managed service into an arbitrary
		// privileged Docker script. The submitted environment is intentionally
		// retained: only non-protected launcher values are exposed and accepted.
		form.Name = svc.Name
		form.WatchedImage = svc.WatchedImage
		form.DeployScript = store.SelfDeployScript
		form.IsSelf = true
	}
	previous := *svc
	svc.WatchedImage = form.WatchedImage
	svc.Policy = store.Policy(form.Policy)
	svc.CronExpr = form.CronExpr
	svc.DeployScript = form.DeployScript
	svc.HealthURL = form.HealthURL
	if svc.IsSelf {
		if err := validateServiceForm(r.Context(), form); err != nil {
			_ = ServiceFormPage(form, s.csrf(r), true, "/services/"+svc.Name, err.Error()).Render(r.Context(), w)
			return
		}
		err = s.saveSelfConfig(r.Context(), svc, &previous, form.EnvFile)
	} else {
		expected := &store.Service{ID: svc.ID, Name: svc.Name, ConfigVersion: form.ConfigVersion}
		_, err = s.saveOrdinaryService(r.Context(), ordinaryWrite{Service: svc, Previous: expected, Environment: &form.EnvFile, EnvironmentMode: dashboardEnvironment})
	}
	if err != nil {
		if errors.Is(err, store.ErrServiceConflict) && !svc.IsSelf {
			current, currentErr := s.store.GetService(r.Context(), svc.ID)
			if currentErr == nil {
				conflictForm := serviceForm(current)
				conflictForm.EnvFile, currentErr = s.store.GetEnvFile(r.Context(), current.ID)
				if currentErr != nil {
					http.Error(w, "could not reload service configuration", http.StatusInternalServerError)
					return
				}
				conflictForm.ReloadURL = "/services/" + current.Name + "/edit"
				w.WriteHeader(http.StatusConflict)
				_ = ServiceFormPage(conflictForm, s.csrf(r), true, "/services/"+current.Name, "The configuration changed. Reload it before trying again.").Render(r.Context(), w)
				return
			}
		}
		var validationErr *ordinaryValidationError
		if !svc.IsSelf && errors.As(err, &validationErr) {
			_ = ServiceFormPage(form, s.csrf(r), true, "/services/"+svc.Name, validationErr.Error()).Render(r.Context(), w)
			return
		}
		if !svc.IsSelf {
			retryForm := serviceForm(svc)
			// Preserve the precondition the client actually submitted; upgrading it
			// to the freshly read version could let a retry commit stale fields.
			retryForm.ConfigVersion = form.ConfigVersion
			retryForm.EnvFile, err = s.store.GetEnvFile(r.Context(), svc.ID)
			if err != nil {
				http.Error(w, "could not reload service configuration", http.StatusInternalServerError)
				return
			}
			_ = ServiceFormPage(retryForm, s.csrf(r), true, "/services/"+svc.Name, "No changes were saved. Try again.").Render(r.Context(), w)
			return
		}
		_ = ServiceFormPage(form, s.csrf(r), true, "/services/"+svc.Name, err.Error()).Render(r.Context(), w)
		return
	}
	log.Printf("service: updated %q (image=%s policy=%s)", svc.Name, svc.WatchedImage, svc.Policy)
	http.Redirect(w, r, "/services/"+svc.Name, http.StatusSeeOther)
}

func (s *Server) handleServiceDelete(w http.ResponseWriter, r *http.Request) {
	svc, err := s.getServiceByName(w, r)
	if err != nil {
		return
	}
	if svc.IsSelf {
		http.Error(w, "the managed self-service cannot be deleted", http.StatusForbidden)
		return
	}
	if err := s.store.DeleteService(r.Context(), svc.ID); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	log.Printf("service: deleted %q", svc.Name)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) handleDeploy(w http.ResponseWriter, r *http.Request) {
	svc, err := s.getServiceByName(w, r)
	if err != nil {
		return
	}
	id, err := s.executor.Deploy(r.Context(), svc.ID, store.TriggerManual)
	if err != nil {
		log.Printf("deploy: manual %q failed: %v", svc.Name, err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, fmt.Sprintf("/deployments/%d", id), http.StatusSeeOther)
}

func (s *Server) handleStart(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	if err := s.docker.StartByService(r.Context(), name); err != nil {
		log.Printf("service: start %q failed: %v", name, err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	log.Printf("service: started %q", name)
	http.Redirect(w, r, "/services/"+name, http.StatusSeeOther)
}

func (s *Server) handleStop(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	if err := s.docker.StopByService(r.Context(), name); err != nil {
		log.Printf("service: stop %q failed: %v", name, err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	log.Printf("service: stopped %q", name)
	http.Redirect(w, r, "/services/"+name, http.StatusSeeOther)
}

func (s *Server) handleServiceDetail(w http.ResponseWriter, r *http.Request) {
	svc, err := s.getServiceByName(w, r)
	if err != nil {
		return
	}
	data, err := s.buildDetail(r.Context(), svc)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	_ = ServiceDetailPage(data, s.csrf(r)).Render(r.Context(), w)
}

func (s *Server) handleDeployment(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		http.Error(w, "bad id", http.StatusBadRequest)
		return
	}
	d, err := s.store.GetDeployment(r.Context(), id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	_ = DeploymentPage(d.ID, d.Status, d.Log, s.csrf(r)).Render(r.Context(), w)
}

func (s *Server) handleDeploymentStream(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		http.Error(w, "bad id", http.StatusBadRequest)
		return
	}
	d, err := s.store.GetDeployment(r.Context(), id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, html.EscapeString(d.Log))
	if d.Status == store.DeployRunning || d.Status == store.DeployPending {
		w.Header().Set("HX-Trigger", "continue")
	}
}

// handleLogsStream serves the service detail page's log panel as a fragment:
// a tab row when the service has several containers plus the selected
// container's tail. The container query parameter picks the tab; missing or
// unknown names fall back to the first container so stale tabs from an
// earlier page load still resolve after a redeploy.
func (s *Server) handleLogsStream(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	cs, err := s.docker.ListByService(r.Context(), name)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	names := make([]string, len(cs))
	for i, c := range cs {
		names[i] = c.Name
	}
	selected := r.URL.Query().Get("container")
	if slices.Index(names, selected) < 0 {
		selected = ""
	}
	if selected == "" && len(names) > 0 {
		selected = names[0]
	}
	var logs string
	if selected != "" {
		idx := slices.Index(names, selected)
		logs = s.containerLogs(r.Context(), cs[idx:idx+1], 100)
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = containerLogsFragment(name, names, selected, logs).Render(r.Context(), w)
}

// recentLogs returns a compact, readable tail for dashboard cards. The full
// per-container log output remains available from the service detail page.
func (s *Server) recentLogs(ctx context.Context, cs []docker.Container, lineLimit int) string {
	logs := s.containerLogs(ctx, cs, lineLimit)
	if logs == "" {
		return "No container logs yet."
	}
	lines := strings.Split(logs, "\n")
	if len(lines) > lineLimit {
		logs = strings.Join(lines[len(lines)-lineLimit:], "\n")
	}
	return logs
}

// containerLogs concatenates the given containers' tails. Callers pass a
// single container for the per-container log panel; recentLogs passes a
// service's containers for the mixed dashboard preview.
func (s *Server) containerLogs(ctx context.Context, cs []docker.Container, tail int) string {
	var b strings.Builder
	for _, c := range cs {
		rc, err := s.docker.Logs(ctx, c.ID, tail)
		if err != nil {
			continue
		}
		lines := readLogLines(rc)
		rc.Close()
		for _, line := range lines {
			b.WriteString(line)
			b.WriteByte('\n')
		}
	}
	return strings.TrimSuffix(b.String(), "\n")
}

func readLogLines(rc io.Reader) []string {
	scanner := bufio.NewScanner(rc)
	// Container log lines are user-controlled and can be substantially longer
	// than bufio.Scanner's default token limit.
	scanner.Buffer(make([]byte, 4<<10), 1<<20)
	var lines []string
	for scanner.Scan() {
		line := scanner.Text()
		// Docker's non-TTY log stream prefixes each frame with an eight-byte
		// multiplexing header. Fakes and TTY logs are plain text, so only remove
		// it when it has the expected stream marker and zero padding.
		if len(line) >= 8 && (line[0] == 1 || line[0] == 2) && line[1] == 0 && line[2] == 0 && line[3] == 0 {
			line = line[8:]
		}
		lines = append(lines, formatLogLine(line))
	}
	return lines
}

func (s *Server) getServiceByName(w http.ResponseWriter, r *http.Request) (*store.Service, error) {
	svc, err := s.store.GetServiceByName(r.Context(), chi.URLParam(r, "name"))
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return nil, err
	}
	return svc, nil
}

func (s *Server) buildDetail(ctx context.Context, svc *store.Service) (ServiceDetailData, error) {
	form := serviceForm(svc)
	cs, err := s.docker.ListByService(ctx, svc.Name)
	state := "unknown"
	running := ""
	if err == nil {
		state = summarizeState(cs)
		running = watchedDigest(cs, svc.WatchedImage)
	}
	latest := s.poller.CachedDigest(svc.Name)
	deploys, err := s.store.ListDeployments(ctx, svc.ID, 20)
	if err != nil {
		return ServiceDetailData{}, err
	}
	var dviews []DeploymentView
	for _, d := range deploys {
		dviews = append(dviews, DeploymentView{
			ID: d.ID, Trigger: d.Trigger, TargetDigest: d.TargetDigest,
			Status: d.Status, StartedAt: d.StartedAt.Format(time.RFC3339),
		})
	}
	var cviews []ContainerView
	for _, c := range cs {
		cviews = append(cviews, ContainerView{Name: c.Name, Image: c.Image, State: c.State})
	}
	lastDeploy := "No deployments yet"
	if len(deploys) > 0 {
		lastDeploy = deployedAgo(deploys[0].StartedAt, time.Now())
	}
	return ServiceDetailData{
		Service: form, State: state, Running: shortDigest(running), Latest: shortDigest(latest),
		RunningFor: runningFor(cs, time.Now()), LastDeploy: lastDeploy,
		UpdateAvail: running != "" && latest != "" && running != latest,
		Containers:  cviews, Deployments: dviews,
	}, nil
}

func (s *Server) serviceToEditForm(ctx context.Context, svc *store.Service) (ServiceFormData, error) {
	var (
		content string
		err     error
	)
	if svc.IsSelf {
		content, err = s.selfEnvironment.EditableEnvironment()
	} else {
		content, err = s.store.GetEnvFile(ctx, svc.ID)
	}
	if err != nil {
		return ServiceFormData{}, err
	}
	if err := s.store.RecordEnvRevision(ctx, svc.ID, content); err != nil {
		return ServiceFormData{}, err
	}
	form := serviceForm(svc)
	form.EnvFile = content
	return form, nil
}

func serviceForm(svc *store.Service) ServiceFormData {
	return ServiceFormData{
		Name: svc.Name, WatchedImage: svc.WatchedImage, Policy: string(svc.Policy),
		CronExpr: svc.CronExpr, DeployScript: svc.DeployScript, HealthURL: svc.HealthURL, ConfigVersion: svc.ConfigVersion, IsSelf: svc.IsSelf,
	}
}

func parseServiceForm(r *http.Request) ServiceFormData {
	// Browsers submit <textarea> content with CRLF newlines; normalize to
	// LF so the stored script/env matches what was validated and what Bash
	// can parse.
	configVersion, _ := strconv.ParseInt(r.FormValue("expected_config_version"), 10, 64)
	return ServiceFormData{
		Name: r.FormValue("name"), WatchedImage: r.FormValue("watched_image"),
		Policy: r.FormValue("policy"), CronExpr: r.FormValue("cron_expr"), HealthURL: r.FormValue("health_url"),
		DeployScript:  executor.NormalizeNewlines(r.FormValue("deploy_script")),
		EnvFile:       executor.NormalizeNewlines(r.FormValue("env_file")),
		ConfigVersion: configVersion,
	}
}

func validateServiceForm(ctx context.Context, form ServiceFormData) error {
	if form.HealthURL != "" {
		// basic URL validation: must have scheme http/https and non-empty host
		u, err := url.Parse(form.HealthURL)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return fmt.Errorf("health URL: invalid URL")
		}
	}
	if form.IsSelf {
		if err := launcher.ValidateEditableEnvironment(form.EnvFile); err != nil {
			return fmt.Errorf("environment file: %w", err)
		}
	} else {
		if _, err := envfile.Parse(form.EnvFile); err != nil {
			return fmt.Errorf("environment file: %w", err)
		}
	}
	if err := executor.ValidateScript(ctx, form.DeployScript); err != nil {
		return fmt.Errorf("deploy script: %w", err)
	}
	return nil
}

type editorValidation struct {
	Valid   bool   `json:"valid"`
	Message string `json:"message,omitempty"`
	Line    int    `json:"line,omitempty"`
}

var validationLinePattern = regexp.MustCompile(`(?i)line[ :]+([0-9]+)`)

func (s *Server) handleEditorValidate(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	var err error
	switch r.FormValue("kind") {
	case "bash":
		err = executor.ValidateScript(r.Context(), r.FormValue("content"))
	case "dotenv":
		_, err = envfile.Parse(r.FormValue("content"))
	case "launcher-env":
		err = launcher.ValidateEditableEnvironment(r.FormValue("content"))
	default:
		http.Error(w, "unknown editor kind", http.StatusBadRequest)
		return
	}

	result := editorValidation{Valid: err == nil}
	if err != nil {
		result.Message = err.Error()
		if match := validationLinePattern.FindStringSubmatch(result.Message); len(match) == 2 {
			result.Line, _ = strconv.Atoi(match[1])
		}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(result)
}
