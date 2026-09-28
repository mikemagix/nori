package mcpauth

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"

	"nori/internal/store"
)

type client struct {
	ID        string   `json:"client_id"`
	Name      string   `json:"client_name"`
	Redirects []string `json:"redirect_uris"`
	Method    string   `json:"token_endpoint_auth_method"`
}
type storedClient struct {
	Client            client
	SecretHash, Epoch string
}

func oauthClientDisplayName(name string) string {
	if name == "" {
		return "Unnamed client"
	}
	return name
}

func validRedirect(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || len(raw) > 2048 || u.Host == "" || u.User != nil || u.Fragment != "" || u.RawFragment != "" {
		return false
	}
	return u.Scheme == "https" || u.Scheme == "http" && (u.Hostname() == "localhost" || net.ParseIP(u.Hostname()).IsLoopback())
}
func (s *Server) register(w http.ResponseWriter, r *http.Request, c store.MCPConfig) {
	var req struct {
		Name      string   `json:"client_name"`
		Redirects []string `json:"redirect_uris"`
		Method    string   `json:"token_endpoint_auth_method"`
		Grants    []string `json:"grant_types"`
		Responses []string `json:"response_types"`
	}
	dec := json.NewDecoder(r.Body)
	if err := dec.Decode(&req); err != nil {
		failure(w, 400, "invalid_client_metadata")
		return
	}
	var extra any
	if dec.Decode(&extra) != io.EOF {
		failure(w, 400, "invalid_client_metadata")
		return
	}
	if req.Method == "" {
		req.Method = "client_secret_basic"
	}
	if req.Method != "none" && req.Method != "client_secret_basic" || len(req.Redirects) == 0 || len(req.Redirects) > 10 || len(req.Name) > 200 {
		failure(w, 400, "invalid_client_metadata")
		return
	}
	for _, g := range req.Grants {
		if g != "authorization_code" && g != "refresh_token" {
			failure(w, 400, "invalid_client_metadata")
			return
		}
	}
	for _, v := range req.Responses {
		if v != "code" {
			failure(w, 400, "invalid_client_metadata")
			return
		}
	}
	for _, v := range req.Redirects {
		if !validRedirect(v) {
			failure(w, 400, "invalid_redirect_uri")
			return
		}
	}
	cl := client{ID: secret(), Name: req.Name, Redirects: req.Redirects, Method: req.Method}
	rawSecret := ""
	if cl.Method == "client_secret_basic" {
		rawSecret = secret()
	}
	// Unapproved registrations expire quickly; only explicit administrator
	// consent extends their lifetime, so anonymous clients cannot fill the registry.
	if err := s.put(r.Context(), cl.ID, "client", "", time.Now().Add(pendingClientLifetime), storedClient{Client: cl, SecretHash: digest(rawSecret), Epoch: c.Epoch}); err != nil {
		failure(w, 503, "temporarily_unavailable")
		return
	}
	response := map[string]any{"client_id": cl.ID, "client_name": cl.Name, "redirect_uris": cl.Redirects, "token_endpoint_auth_method": cl.Method, "grant_types": []string{"authorization_code", "refresh_token"}, "response_types": []string{"code"}, "client_id_issued_at": time.Now().Unix()}
	if rawSecret != "" {
		response["client_secret"] = rawSecret
		response["client_secret_expires_at"] = 0
	}
	writeJSON(w, 201, response)
}
func (s *Server) getClient(ctx context.Context, id string, c store.MCPConfig) (storedClient, error) {
	var cl storedClient
	r, err := s.st.GetOAuth(ctx, digest(id), "client")
	if err != nil {
		return cl, err
	}
	err = json.Unmarshal(r.Data, &cl)
	if err == nil && (cl.Epoch != c.Epoch || r.Used) {
		err = errors.New("invalid client")
	}
	return cl, err
}

func (s *Server) authenticateClient(r *http.Request, c store.MCPConfig) (storedClient, error) {
	id := r.PostForm.Get("client_id")
	basicID, password, basic := r.BasicAuth()
	if basic {
		var err error
		basicID, err = url.QueryUnescape(basicID)
		if err != nil {
			return storedClient{}, err
		}
		password, err = url.QueryUnescape(password)
		if err != nil {
			return storedClient{}, err
		}
		if id != "" && id != basicID {
			return storedClient{}, errors.New("conflicting client")
		}
		id = basicID
	}
	cl, err := s.getClient(r.Context(), id, c)
	if err != nil {
		return cl, err
	}
	if cl.Client.Method == "client_secret_basic" {
		if !basic || !equal(digest(password), cl.SecretHash) {
			return cl, errors.New("invalid secret")
		}
	} else if basic || r.Header.Get("Authorization") != "" || r.PostForm.Has("client_secret") {
		return cl, errors.New("unexpected credentials")
	}
	return cl, nil
}
