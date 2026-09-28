package web

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"nori/internal/notify"
	"nori/internal/store"
)

func TestParseServiceFormReadsCompleteEnvFile(t *testing.T) {
	body := "name=app&watched_image=ghcr.io%2Fme%2Fapp%3Alatest&policy=manual&deploy_script=echo+ok&env_file=PORT%3D8080%0ASECRET%3D%22hello+world%22%0A"
	req := httptest.NewRequest("POST", "/services", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if err := req.ParseForm(); err != nil {
		t.Fatal(err)
	}
	form := parseServiceForm(req)
	if form.EnvFile != "PORT=8080\nSECRET=\"hello world\"\n" {
		t.Fatalf("EnvFile = %q", form.EnvFile)
	}
}

func TestParseServiceFormReadsHealthURL(t *testing.T) {
	body := "name=app&watched_image=ghcr.io%2Fme%2Fapp%3Alatest&policy=manual&deploy_script=echo+ok&env_file=PORT%3D8080%0ASECRET%3D%22hello+world%22%0A&health_url=http%3A%2F%2Fexample.com%2Fhealth"
	req := httptest.NewRequest("POST", "/services", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if err := req.ParseForm(); err != nil {
		t.Fatal(err)
	}
	form := parseServiceForm(req)
	if form.HealthURL != "http://example.com/health" {
		t.Fatalf("HealthURL = %q", form.HealthURL)
	}
}

func TestParseServiceFormNormalizesCRLFDeployScript(t *testing.T) {
	// Browsers submit <textarea> content with CRLF newlines; the server
	// must store LF so Bash can parse the script.
	body := "name=app&watched_image=img&policy=manual&deploy_script=echo+ok%0D%0Afor+i+in+1+2%3B+do%0D%0A++echo+%24i%0D%0Adone&env_file=PORT%3D8080%0D%0A"
	req := httptest.NewRequest("POST", "/services", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if err := req.ParseForm(); err != nil {
		t.Fatal(err)
	}
	form := parseServiceForm(req)
	if strings.Contains(form.DeployScript, "\r") {
		t.Fatalf("DeployScript still contains CR: %q", form.DeployScript)
	}
	if form.DeployScript != "echo ok\nfor i in 1 2; do\n  echo $i\ndone" {
		t.Fatalf("DeployScript = %q", form.DeployScript)
	}
	if strings.Contains(form.EnvFile, "\r") {
		t.Fatalf("EnvFile still contains CR: %q", form.EnvFile)
	}
}

func TestValidateServiceFormRejectsInvalidBash(t *testing.T) {
	form := ServiceFormData{EnvFile: "PORT=8080\n", DeployScript: "if true; then\n  echo broken"}
	err := validateServiceForm(context.Background(), form)
	if err == nil || !strings.Contains(err.Error(), "deploy script") {
		t.Fatalf("expected deploy script validation error, got %v", err)
	}
}

func TestValidateServiceFormRejectsInvalidDotenv(t *testing.T) {
	form := ServiceFormData{EnvFile: "NOT VALID", DeployScript: "echo ok"}
	err := validateServiceForm(context.Background(), form)
	if err == nil || !strings.Contains(err.Error(), "environment file") {
		t.Fatalf("expected environment file validation error, got %v", err)
	}
}

func TestValidateServiceFormRejectsInvalidHealthURL(t *testing.T) {
	form := ServiceFormData{EnvFile: "PORT=8080\n", DeployScript: "echo ok", HealthURL: "ftp://bad"}
	err := validateServiceForm(context.Background(), form)
	if err == nil || !strings.Contains(err.Error(), "health URL") {
		t.Fatalf("expected health URL validation error, got %v", err)
	}
}

func TestTemplateServiceFormUsesStructuredConfigWithoutRequiringBash(t *testing.T) {
	values := url.Values{
		"name":            {"api"},
		"watched_image":   {"ghcr.io/acme/api:latest"},
		"policy":          {"manual"},
		"deployment_mode": {"single_container"},
		"template_config": {`{"version":1,"internal_port":8080,"restart_policy":"always","health":{"command":"true","timeout_seconds":5}}`},
		"env_file":        {"PORT=8080\n"},
	}
	req := httptest.NewRequest("POST", "/services", strings.NewReader(values.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if err := req.ParseForm(); err != nil {
		t.Fatal(err)
	}
	form := parseServiceForm(req)
	if form.DeploymentMode != "single_container" {
		t.Fatalf("DeploymentMode = %q", form.DeploymentMode)
	}
	if err := validateServiceForm(context.Background(), form); err != nil {
		t.Fatalf("template form validation: %v", err)
	}
}

func TestValidateServiceFormRejectsInvalidTemplateServiceName(t *testing.T) {
	form := ServiceFormData{
		Name:           strings.Repeat("a", 64),
		EnvFile:        "PORT=8080\n",
		DeploymentMode: "single_container",
		TemplateConfig: `{"version":1,"internal_port":8080,"restart_policy":"always","health":{"command":"true","timeout_seconds":5}}`,
	}
	if err := validateServiceForm(context.Background(), form); err == nil || !strings.Contains(err.Error(), "template service name") {
		t.Fatalf("expected template service name validation error, got %v", err)
	}
}

func TestTemplateServiceFormRejectsInvalidConfigBeforeSaving(t *testing.T) {
	form := ServiceFormData{
		EnvFile:        "PORT=8080\n",
		DeploymentMode: "postgres",
		TemplateConfig: `{"version":1,"internal_port":8080,"restart_policy":"always","health":{"command":"true","timeout_seconds":5},"postgres":{"image":"postgres:latest"}}`,
	}
	err := validateServiceForm(context.Background(), form)
	if err == nil || !strings.Contains(err.Error(), "template configuration") {
		t.Fatalf("expected template configuration validation error, got %v", err)
	}
}

func TestRenderTemplateAsCustomScriptKeepsSecretsOutOfTheGeneratedScript(t *testing.T) {
	svc := &store.Service{
		ID: 1, Name: "api", WatchedImage: "ghcr.io/acme/api:latest",
		DeploymentMode: store.DeploymentModeSingleContainer,
		TemplateConfig: `{"version":1,"internal_port":8080,"restart_policy":"always","health":{"command":"true","timeout_seconds":5}}`,
	}
	script, err := renderTemplateAsCustomScript(svc)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(script, "$ENV_FILE") || strings.Contains(script, "s3cret") {
		t.Fatalf("generated script must use the secret-safe env-file boundary: %q", script)
	}
}

func TestDashboardCreatesTemplateServiceWithValidatedStructuredConfiguration(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "dashboard-template.db"), make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	values := url.Values{
		"name":                   {"api"},
		"watched_image":          {"ghcr.io/acme/api:latest"},
		"policy":                 {"manual"},
		"deployment_mode":        {"single_container"},
		"template_config_single": {`{"version":1,"internal_port":8080,"restart_policy":"always","health":{"command":"true","timeout_seconds":5}}`},
		"env_file":               {"PORT=8080\n"},
	}
	req := httptest.NewRequest(http.MethodPost, "/services", strings.NewReader(values.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response := httptest.NewRecorder()
	(&Server{store: st}).handleServiceCreate(response, req)
	if response.Code != http.StatusSeeOther {
		t.Fatalf("create status = %d, body = %q", response.Code, response.Body.String())
	}
	svc, err := st.GetServiceByName(context.Background(), "api")
	if err != nil {
		t.Fatal(err)
	}
	if svc.DeploymentMode != store.DeploymentModeSingleContainer || !strings.Contains(svc.TemplateConfig, `"restart_policy":"always"`) {
		t.Fatalf("dashboard did not persist the validated template contract: %+v", svc)
	}
}

func TestEditorValidationEndpointReturnsBashDiagnostic(t *testing.T) {
	body := "kind=bash&content=if+true%3B+then%0A++echo+broken"
	req := httptest.NewRequest("POST", "/validate/editor", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	(&Server{}).handleEditorValidate(rr, req)

	var result editorValidation
	if err := json.NewDecoder(rr.Body).Decode(&result); err != nil {
		t.Fatal(err)
	}
	if result.Valid || result.Line == 0 || !strings.Contains(result.Message, "bash syntax") {
		t.Fatalf("unexpected validation result: %+v", result)
	}
}

func TestParseRoutingFormReadsConfiguredChannels(t *testing.T) {
	form := url.Values{
		"notify_twilio_down":            {"1"},
		"notify_telegram_deploy_failed": {"1"},
		"notify_telegram_success":       {"1"},
	}
	routing := parseRoutingForm(Channels{Twilio: true, Telegram: true}, form)
	if !routing.Allowed(notify.ChannelTwilio, notify.KindDown) {
		t.Error("twilio/down must be on")
	}
	if routing.Allowed(notify.ChannelTwilio, notify.KindRecovered) {
		t.Error("absent twilio/recovered checkbox means off")
	}
	if routing.Allowed(notify.ChannelTelegram, notify.KindDown) {
		t.Error("absent telegram/down checkbox means off")
	}
	if !routing.Allowed(notify.ChannelTelegram, notify.KindDeployFailed) {
		t.Error("telegram/deploy_failed must be on independently of down")
	}
	if !routing.Allowed(notify.ChannelTelegram, notify.KindSuccess) {
		t.Error("telegram/success must be on")
	}
}

func TestParseRoutingFormOmitsUnconfiguredChannels(t *testing.T) {
	form := url.Values{"notify_telegram_down": {"1"}}
	routing := parseRoutingForm(Channels{Twilio: false, Telegram: true}, form)
	if _, ok := routing[notify.ChannelTwilio]; ok {
		t.Error("unconfigured channels must get no table entry, so they default on once configured")
	}
	if !routing.Allowed(notify.ChannelTelegram, notify.KindDown) {
		t.Error("configured channel checkbox must be read")
	}
}

func TestParseRoutingFormEmptyMeansAllOff(t *testing.T) {
	routing := parseRoutingForm(Channels{Twilio: true, Telegram: false}, url.Values{})
	for _, kind := range notify.Kinds {
		if routing.Allowed(notify.ChannelTwilio, kind) {
			t.Errorf("empty form must leave %s off", kind)
		}
	}
}
