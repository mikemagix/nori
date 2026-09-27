package web

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"nori/internal/launcher"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"nori/internal/store"
)

func TestConfigHistoryAndCopyToNewService(t *testing.T) {
	st, _, srv, cookies, _ := newSelfServiceServer(t)
	ctx := context.Background()
	svc := &store.Service{Name: "history", WatchedImage: "nginx", Policy: store.PolicyManual, DeployScript: "echo original"}
	env := "# preserve formatting\nTOKEN=original-secret\n"
	if err := st.SaveServiceConfig(ctx, svc, &env, nil); err != nil {
		t.Fatal(err)
	}
	before := *svc
	svc.DeployScript = "echo current"
	current := "TOKEN=current-secret\n"
	if err := st.SaveServiceConfig(ctx, svc, &current, &before); err != nil {
		t.Fatal(err)
	}
	base := "/services/history/history/env"
	rr := httptest.NewRecorder()
	srv.ServeHTTP(rr, httptest.NewRequest("GET", base+"/1", nil))
	if rr.Code != http.StatusSeeOther && rr.Code != http.StatusFound {
		t.Fatalf("unauthenticated history: %d", rr.Code)
	}
	body := getAuthed(t, srv, cookies, base)
	if strings.Contains(body, "secret") {
		t.Fatal("metadata exposed content")
	}
	var versions []store.ConfigRevision
	if err := json.Unmarshal([]byte(body), &versions); err != nil || len(versions) != 2 {
		t.Fatalf("history = %s, %v", body, err)
	}
	var revision store.ConfigRevision
	if err := json.Unmarshal([]byte(getAuthed(t, srv, cookies, base+"/1")), &revision); err != nil || revision.Content != env {
		t.Fatalf("preview: %+v %v", revision, err)
	}
	edit := getAuthed(t, srv, cookies, "/services/history/edit")
	if !strings.Contains(edit, `data-history-kind="env"`) || !strings.Contains(edit, `data-history-kind="script"`) {
		t.Fatal("missing history controls")
	}
	copied := getAuthed(t, srv, cookies, "/services/new?source=history&kind=env&version=1")
	if !strings.Contains(copied, "original-secret") || strings.Contains(copied, `name="name" value="history"`) {
		t.Fatal("copy did not prefill a new unnamed service")
	}
	saved, _ := st.GetEnvFile(ctx, svc.ID)
	if saved != current {
		t.Fatal("preview/copy mutated current configuration")
	}
	form := url.Values{"csrf_token": {csrfFromBody(edit)}, "name": {"history"}, "watched_image": {"nginx"}, "policy": {"manual"}, "deploy_script": {"echo current"}, "env_file": {env}, "expected_config_version": {strconv.FormatInt(svc.ConfigVersion, 10)}}
	postAuthed(t, srv, cookies, "/services/history", form.Encode())
	versions, _ = st.ListConfigRevisions(ctx, svc.ID, "env")
	if len(versions) != 3 {
		t.Fatalf("restoring did not append a version: %d", len(versions))
	}
	for _, path := range []string{base + "/999", base + "/bad", "/services/history/history/unknown", "/services/new?source=history&kind=bad&version=1"} {
		req := httptest.NewRequest("GET", path, nil)
		for _, c := range cookies {
			req.AddCookie(c)
		}
		rr := httptest.NewRecorder()
		srv.ServeHTTP(rr, req)
		if rr.Code != http.StatusNotFound {
			t.Errorf("%s: %d, want 404", path, rr.Code)
		}
	}
}

func TestSelfEnvironmentHistory(t *testing.T) {
	st, self, srv, cookies, _ := newSelfServiceServer(t)
	srv.selfEnvironment = &fakeSelfEnvironment{content: "HOST=old.example\n"}
	body := getAuthed(t, srv, cookies, "/services/"+self.Name+"/edit")
	rr := postSelfServiceUpdate(t, srv, cookies, self, csrfFromBody(body), "manual", "HOST=new.example\n")
	if rr.Code != http.StatusSeeOther {
		t.Fatalf("save: %d %s", rr.Code, rr.Body.String())
	}
	versions, err := st.ListConfigRevisions(context.Background(), self.ID, "env")
	if err != nil || len(versions) != 2 {
		t.Fatalf("self history: %+v %v", versions, err)
	}
	old, err := st.GetConfigRevision(context.Background(), self.ID, "env", versions[1].Version)
	if err != nil || old.Content != "HOST=old.example\n" {
		t.Fatal(fmt.Sprint("missing old launcher values: ", err))
	}
}

func TestSelfHistoryFailureRestoresEnvironmentAndPolicy(t *testing.T) {
	st, self, srv, cookies, path := newSelfServiceServer(t)
	environment := &fakeSelfEnvironment{content: "HOST=original\n"}
	srv.selfEnvironment = environment
	body := getAuthed(t, srv, cookies, "/services/"+self.Name+"/edit")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`CREATE TRIGGER fail_history BEFORE INSERT ON config_revision WHEN NEW.kind='env' BEGIN SELECT RAISE(ABORT, 'history failed'); END`); err != nil {
		t.Fatal(err)
	}
	rr := postSelfServiceUpdate(t, srv, cookies, self, csrfFromBody(body), "immediate", "HOST=changed\n")
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), "history failed") {
		t.Fatalf("save response: %d %s", rr.Code, rr.Body.String())
	}
	if len(environment.replacements) != 2 || environment.replacements[1] != "HOST=original\n" {
		t.Fatalf("environment not restored: %+v", environment.replacements)
	}
	saved, err := st.GetService(context.Background(), self.ID)
	if err != nil || saved.Policy != store.PolicyManual {
		t.Fatal("policy not restored")
	}
	versions, err := st.ListConfigRevisions(context.Background(), self.ID, "env")
	if err != nil || len(versions) != 1 {
		t.Fatalf("failed save left history: %+v %v", versions, err)
	}
}

func TestSelfHistoryUsesPersistedLauncherContent(t *testing.T) {
	st, self, srv, cookies, _ := newSelfServiceServer(t)
	configDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(configDir, launcher.EnvFilename), []byte("NORI_KEY=protected-secret\nA=old\nZ=old\n"), 0600); err != nil {
		t.Fatal(err)
	}
	srv.selfEnvironment = &launcher.Launcher{ConfigDir: configDir}
	body := getAuthed(t, srv, cookies, "/services/"+self.Name+"/edit")
	for _, content := range []string{"# note\nZ=new\nA=new", "Z=new\nA=new\n"} {
		rr := postSelfServiceUpdate(t, srv, cookies, self, csrfFromBody(body), "manual", content)
		if rr.Code != http.StatusSeeOther {
			t.Fatalf("save: %d %s", rr.Code, rr.Body.String())
		}
		body = getAuthed(t, srv, cookies, "/services/"+self.Name+"/edit")
	}
	versions, err := st.ListConfigRevisions(context.Background(), self.ID, "env")
	if err != nil || len(versions) != 2 {
		t.Fatalf("format-only changes created extra versions: %+v %v", versions, err)
	}
	latest, err := st.GetConfigRevision(context.Background(), self.ID, "env", 2)
	if err != nil || latest.Content != "A=new\nZ=new\n" {
		t.Fatalf("snapshot not canonical or contains protected values: %+v %v", latest, err)
	}
}

func TestLegacyEnvironmentHistoryStartsWhenEditorOpens(t *testing.T) {
	st, _, srv, cookies, path := newSelfServiceServer(t)
	ctx := context.Background()
	svc := &store.Service{Name: "legacy", WatchedImage: "image", Policy: store.PolicyManual, DeployScript: "echo ok"}
	if err := st.CreateService(ctx, svc); err != nil {
		t.Fatal(err)
	}
	if err := st.SetEnvVar(ctx, &store.EnvVar{ServiceID: svc.ID, Key: "TOKEN", Value: "legacy-value", IsSecret: true}); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`DELETE FROM config_revision WHERE service_id=? AND kind='env'`, svc.ID); err != nil {
		t.Fatal(err)
	}
	getAuthed(t, srv, cookies, "/services/legacy/edit")
	first, err := st.GetConfigRevision(ctx, svc.ID, "env", 1)
	if err != nil || !strings.Contains(first.Content, "legacy-value") {
		t.Fatalf("legacy baseline unavailable in editor: %+v %v", first, err)
	}
	getAuthed(t, srv, cookies, "/services/legacy/edit")
	versions, err := st.ListConfigRevisions(ctx, svc.ID, "env")
	if err != nil || len(versions) != 1 {
		t.Fatalf("reopening created duplicate baseline: %+v %v", versions, err)
	}
}
