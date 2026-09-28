package web

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"nori/internal/store"
)

func validHistoryKind(kind string) bool { return kind == "script" || kind == "env" }

func (s *Server) handleConfigHistory(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	svc, err := s.getServiceByName(w, r)
	if err != nil {
		return
	}
	kind := chi.URLParam(r, "kind")
	if !validHistoryKind(kind) {
		http.NotFound(w, r)
		return
	}
	var result any
	if value := chi.URLParam(r, "version"); value != "" {
		version, parseErr := strconv.ParseInt(value, 10, 64)
		if parseErr != nil || version < 1 {
			http.NotFound(w, r)
			return
		}
		result, err = s.store.GetConfigRevision(r.Context(), svc.ID, kind, version)
	} else {
		result, err = s.store.ListConfigRevisions(r.Context(), svc.ID, kind)
	}
	if errors.Is(err, store.ErrNotFound) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		http.Error(w, "Could not load version history", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(result)
}

// Copying only prepares an unsaved form. No secret contents travel in URLs.
func (s *Server) newServiceForm(w http.ResponseWriter, r *http.Request) (ServiceFormData, bool) {
	form := ServiceFormData{Policy: "manual", DeploymentMode: string(store.DeploymentModeCustom)}
	source := r.URL.Query().Get("source")
	if source == "" {
		return form, true
	}
	kind := r.URL.Query().Get("kind")
	version, err := strconv.ParseInt(r.URL.Query().Get("version"), 10, 64)
	if !validHistoryKind(kind) || err != nil || version < 1 {
		http.NotFound(w, r)
		return form, false
	}
	svc, err := s.store.GetServiceByName(r.Context(), source)
	if errors.Is(err, store.ErrNotFound) {
		http.NotFound(w, r)
		return form, false
	}
	if err != nil {
		http.Error(w, "Could not load source service", http.StatusInternalServerError)
		return form, false
	}
	revision, err := s.store.GetConfigRevision(r.Context(), svc.ID, kind, version)
	if errors.Is(err, store.ErrNotFound) {
		http.NotFound(w, r)
		return form, false
	}
	if err != nil {
		http.Error(w, "Could not load source version", http.StatusInternalServerError)
		return form, false
	}
	if kind == "script" {
		form.DeployScript = revision.Content
	} else {
		form.EnvFile = revision.Content
	}
	return form, true
}
