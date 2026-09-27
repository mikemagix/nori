// Package deploytemplate defines Nori's typed, non-secret deployment
// templates. It has no Docker SDK dependency so one plan powers execution,
// previews, and conversion to Custom.
package deploytemplate

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"path"
	"regexp"
	"strconv"
	"strings"
)

type Mode string

const (
	ModeCustom          Mode = "custom"
	ModeSingleContainer Mode = "single_container"
	ModePostgres        Mode = "postgres"
)

type RestartPolicy string

const (
	RestartNo            RestartPolicy = "no"
	RestartAlways        RestartPolicy = "always"
	RestartUnlessStopped RestartPolicy = "unless-stopped"
	RestartOnFailure     RestartPolicy = "on-failure"
)

var (
	resourceNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,62}$`)
	environmentKey      = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
	databaseIdentifier  = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,62}$`)
)

// Config is the persisted template contract. Environment values deliberately
// stay in Nori's encrypted dotenv store rather than this value-free struct.
type Config struct {
	Mode           Mode            `json:"-"`
	Version        int             `json:"version"`
	InternalPort   int             `json:"internal_port,omitempty"`
	RestartPolicy  RestartPolicy   `json:"restart_policy,omitempty"`
	ServingNetwork string          `json:"serving_network,omitempty"`
	Proxy          *ProxyConfig    `json:"proxy,omitempty"`
	Volumes        []VolumeMount   `json:"volumes,omitempty"`
	Health         HealthCheck     `json:"health,omitempty"`
	Postgres       *PostgresConfig `json:"postgres,omitempty"`
}

// ProxyConfig describes an operator-owned, attach-only proxy network.
type ProxyConfig struct {
	Network string `json:"network"`
	Domain  string `json:"domain"`
	Port    int    `json:"port"`
}

type VolumeMount struct {
	// Name is logical. The actual Docker volume derives from the service ID.
	Name   string `json:"name"`
	Target string `json:"target"`
}

type HealthCheck struct {
	URL            string `json:"url,omitempty"`
	Command        string `json:"command,omitempty"`
	TimeoutSeconds int    `json:"timeout_seconds,omitempty"`
}

type PostgresConfig struct {
	Image               string `json:"image"`
	Database            string `json:"database"`
	User                string `json:"user"`
	PasswordEnv         string `json:"password_env"`
	ConnectionURLEnv    string `json:"connection_url_env"`
	ReadyTimeoutSeconds int    `json:"ready_timeout_seconds"`
}

type Input struct {
	ServiceID   int64
	ServiceName string
	TargetImage string
	Config      Config
}

// Resource is safe to show publicly: it contains no environment values or
// Docker SDK values.
type Resource struct {
	Kind          string
	Name          string
	Role          string
	Image         string
	Labels        map[string]string
	Networks      []string
	Mounts        []VolumeMount
	RestartPolicy RestartPolicy
	EnvKeys       []string
}

type Action struct {
	Phase       string
	Description string
}

type Plan struct {
	Mode            Mode
	ServiceID       int64
	ServiceName     string
	TargetImage     string
	AppCurrent      Resource
	AppCandidate    Resource
	AppRollback     Resource
	Database        *Resource
	Postgres        *PostgresConfig
	InternalNetwork *Resource
	Volumes         []Resource
	ExternalNetwork string
	Proxy           *ProxyConfig
	Health          HealthCheck
	Actions         []Action
}

func ParseConfig(mode Mode, raw string) (Config, error) {
	if raw == "" {
		raw = "{}"
	}
	decoder := json.NewDecoder(strings.NewReader(raw))
	decoder.DisallowUnknownFields()
	var config Config
	if err := decoder.Decode(&config); err != nil {
		return Config{}, fmt.Errorf("decode template config: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return Config{}, errors.New("decode template config: multiple JSON values")
	}
	config.Mode = mode
	if err := config.Validate(); err != nil {
		return Config{}, err
	}
	return config, nil
}

func (c Config) Validate() error {
	switch c.Mode {
	case ModeCustom:
		return nil
	case ModeSingleContainer, ModePostgres:
	default:
		return fmt.Errorf("unsupported deployment mode %q", c.Mode)
	}
	if c.Version != 1 {
		return errors.New("template config version must be 1")
	}
	if c.InternalPort < 1 || c.InternalPort > 65535 {
		return errors.New("internal port must be 1..65535")
	}
	switch c.RestartPolicy {
	case RestartNo, RestartAlways, RestartUnlessStopped, RestartOnFailure:
	default:
		return fmt.Errorf("unsupported restart policy %q", c.RestartPolicy)
	}
	if c.ServingNetwork != "" && !validResourceName(c.ServingNetwork) {
		return fmt.Errorf("invalid serving network %q", c.ServingNetwork)
	}
	if err := c.Proxy.validate(c.ServingNetwork, c.InternalPort); err != nil {
		return err
	}
	seenNames := map[string]bool{}
	seenTargets := map[string]bool{}
	for _, mount := range c.Volumes {
		if !validResourceName(mount.Name) || seenNames[mount.Name] {
			return fmt.Errorf("invalid or duplicate volume name %q", mount.Name)
		}
		seenNames[mount.Name] = true
		if !validMountTarget(mount.Target) || seenTargets[mount.Target] {
			return fmt.Errorf("unsafe or duplicate volume target %q", mount.Target)
		}
		seenTargets[mount.Target] = true
	}
	if c.Mode == ModePostgres {
		if c.Postgres == nil {
			return errors.New("postgres settings are required")
		}
		// Validate this first: a mutable dependency must never reach the
		// runtime regardless of any other invalid setting.
		if err := c.Postgres.validate(); err != nil {
			return err
		}
	} else if c.Postgres != nil {
		return errors.New("postgres settings require postgres mode")
	}
	return c.Health.validate("application")
}

func (p *ProxyConfig) validate(servingNetwork string, internalPort int) error {
	if p == nil {
		return nil
	}
	if p.Network == "" || p.Domain == "" || p.Port < 1 || p.Port > 65535 {
		return errors.New("proxy requires network, domain, and port")
	}
	if !validResourceName(p.Network) {
		return fmt.Errorf("invalid proxy network %q", p.Network)
	}
	if servingNetwork != "" && servingNetwork != p.Network {
		return errors.New("serving network and proxy network must match")
	}
	if p.Port != internalPort {
		return errors.New("proxy port must match the internal application port")
	}
	if strings.ContainsAny(p.Domain, "/:@") {
		return fmt.Errorf("invalid proxy domain %q", p.Domain)
	}
	return nil
}

func (h HealthCheck) validate(subject string) error {
	if (h.URL == "") == (h.Command == "") {
		return fmt.Errorf("%s health check requires exactly one URL or command", subject)
	}
	if h.TimeoutSeconds < 5 || h.TimeoutSeconds > 300 {
		return fmt.Errorf("%s health timeout must be 5..300 seconds", subject)
	}
	if h.URL != "" {
		u, err := url.Parse(h.URL)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil {
			return fmt.Errorf("invalid health URL %q", h.URL)
		}
	}
	if strings.ContainsRune(h.Command, '\x00') {
		return errors.New("health command contains a NUL byte")
	}
	return nil
}

func (p PostgresConfig) validate() error {
	if !explicitPostgresImage(p.Image) {
		return fmt.Errorf("postgres image must use an explicit non-latest tag: %q", p.Image)
	}
	if !databaseIdentifier.MatchString(p.Database) {
		return fmt.Errorf("invalid postgres database %q", p.Database)
	}
	if !databaseIdentifier.MatchString(p.User) {
		return fmt.Errorf("invalid postgres user %q", p.User)
	}
	for _, item := range []struct{ label, key string }{
		{"password environment key", p.PasswordEnv},
		{"connection URL environment key", p.ConnectionURLEnv},
	} {
		if !environmentKey.MatchString(item.key) {
			return fmt.Errorf("invalid postgres %s %q", item.label, item.key)
		}
	}
	if p.PasswordEnv == p.ConnectionURLEnv {
		return errors.New("postgres password and connection URL environment keys must differ")
	}
	if p.ReadyTimeoutSeconds < 5 || p.ReadyTimeoutSeconds > 300 {
		return errors.New("postgres readiness timeout must be 5..300 seconds")
	}
	return nil
}

func explicitPostgresImage(image string) bool {
	if image == "" || strings.Contains(image, "@") {
		return false
	}
	slash := strings.LastIndex(image, "/")
	colon := strings.LastIndex(image, ":")
	return colon > slash && colon < len(image)-1 && image[colon+1:] != "latest"
}

func validResourceName(name string) bool { return resourceNamePattern.MatchString(name) }

func validMountTarget(target string) bool {
	return strings.HasPrefix(target, "/") && target != "/" && path.Clean(target) == target && !strings.Contains(target, "..")
}

func BuildPlan(in Input) (Plan, error) {
	if in.ServiceID <= 0 {
		return Plan{}, errors.New("service ID must be positive")
	}
	if !validResourceName(in.ServiceName) {
		return Plan{}, fmt.Errorf("invalid service name %q", in.ServiceName)
	}
	if !strings.Contains(in.TargetImage, "@sha256:") {
		return Plan{}, errors.New("target image must be digest-pinned")
	}
	if err := in.Config.Validate(); err != nil {
		return Plan{}, err
	}
	plan := Plan{Mode: in.Config.Mode, ServiceID: in.ServiceID, ServiceName: in.ServiceName, TargetImage: in.TargetImage, Health: in.Config.Health}
	if in.Config.Proxy != nil {
		proxy := *in.Config.Proxy
		plan.Proxy = &proxy
	}
	if in.Config.Mode == ModeCustom {
		plan.Actions = []Action{{Phase: "custom", Description: "Run the operator-managed Custom deployment script"}}
		return plan, nil
	}
	base := fmt.Sprintf("nori-%d", in.ServiceID)
	plan.ExternalNetwork = in.Config.ServingNetwork
	if in.Config.Proxy != nil {
		plan.ExternalNetwork = in.Config.Proxy.Network
	}
	plan.AppCurrent = makeResource(in, "container", base+"-app", "app")
	plan.AppRollback = makeResource(in, "container", base+"-app-rollback", "app")
	plan.AppCandidate = makeResource(in, "container", base+"-app-candidate", "candidate")
	plan.AppCandidate.Image = in.TargetImage
	plan.AppCandidate.RestartPolicy = in.Config.RestartPolicy
	plan.AppCandidate.Mounts = append([]VolumeMount(nil), in.Config.Volumes...)
	if plan.ExternalNetwork != "" {
		plan.AppCandidate.Networks = append(plan.AppCandidate.Networks, plan.ExternalNetwork)
	}
	for _, mount := range in.Config.Volumes {
		plan.Volumes = append(plan.Volumes, makeResource(in, "volume", base+"-volume-"+mount.Name, "data-volume"))
	}
	plan.Actions = append(plan.Actions, Action{Phase: "preflight", Description: "Pull " + in.TargetImage})
	if plan.ExternalNetwork != "" {
		plan.Actions = append(plan.Actions, Action{Phase: "preflight", Description: "Verify external serving network " + plan.ExternalNetwork})
	}
	for _, volume := range plan.Volumes {
		plan.Actions = append(plan.Actions, Action{Phase: "preflight", Description: "Verify ownership and ensure volume " + volume.Name})
	}
	if in.Config.Mode == ModePostgres {
		internal := makeResource(in, "network", base+"-db-internal", "internal-network")
		plan.InternalNetwork = &internal
		plan.AppCandidate.Networks = append(plan.AppCandidate.Networks, internal.Name)
		dbVolume := makeResource(in, "volume", base+"-volume-postgres-data", "data-volume")
		plan.Volumes = append(plan.Volumes, dbVolume)
		db := makeResource(in, "container", base+"-postgres", "db")
		db.Image = in.Config.Postgres.Image
		db.Networks = []string{internal.Name}
		db.EnvKeys = []string{"POSTGRES_DB", "POSTGRES_USER", in.Config.Postgres.PasswordEnv}
		plan.Database = &db
		postgres := *in.Config.Postgres
		plan.Postgres = &postgres
		plan.Actions = append(plan.Actions,
			Action{Phase: "preflight", Description: "Pull " + db.Image},
			Action{Phase: "preflight", Description: "Verify ownership and ensure private network " + internal.Name},
			Action{Phase: "preflight", Description: "Verify ownership and ensure volume " + dbVolume.Name},
			Action{Phase: "database", Description: "Create or reuse PostgreSQL " + db.Name},
			Action{Phase: "database", Description: "Run authenticated PostgreSQL readiness probe across " + internal.Name},
		)
	}
	plan.Actions = append(plan.Actions,
		Action{Phase: "preflight", Description: "Verify ownership of " + plan.AppCurrent.Name + ", " + plan.AppCandidate.Name + ", and " + plan.AppRollback.Name},
		Action{Phase: "candidate", Description: "Create and start candidate " + plan.AppCandidate.Name},
		Action{Phase: "health", Description: fmt.Sprintf("Wait up to %d seconds for application health", in.Config.Health.TimeoutSeconds)},
		Action{Phase: "promotion", Description: "Promote healthy candidate and retain rollback until replacement succeeds"},
		Action{Phase: "rollback", Description: "On failure remove the candidate and retain the previous application and data"},
	)
	return plan, nil
}

func makeResource(in Input, kind, name, role string) Resource {
	return Resource{
		Kind: kind, Name: name, Role: role,
		Labels: map[string]string{
			"nori.service": in.ServiceName, "nori.template": "1",
			"nori.service-id": strconv.FormatInt(in.ServiceID, 10), "nori.role": role,
		},
	}
}

// Preview is value-free by construction; actions contain resource names,
// images, and phase descriptions but never dotenv values.
func (p Plan) Preview() string {
	lines := make([]string, 0, len(p.Actions))
	for _, action := range p.Actions {
		lines = append(lines, action.Description)
	}
	return strings.Join(lines, "\n")
}

// RenderCustomScript emits an inspectable one-way Custom handoff. It refers
// only to the established runtime variables and never interpolates dotenv data.
func (p Plan) RenderCustomScript() (string, error) {
	if p.Mode == ModeCustom {
		return "", errors.New("custom services already have an operator-managed script")
	}
	if p.AppCandidate.Name == "" || p.TargetImage == "" {
		return "", errors.New("incomplete deployment plan")
	}
	var script bytes.Buffer
	script.WriteString("# Generated by Nori from a structured deployment template.\nset -euo pipefail\n\n")
	script.WriteString("docker pull \"$TARGET_IMAGE\"\n")
	for _, volume := range p.Volumes {
		script.WriteString(fmt.Sprintf("docker volume inspect %q >/dev/null 2>&1 || docker volume create --label nori.service=\"$SERVICE\" --label nori.template=1 --label nori.service-id=%d --label nori.role=data-volume %q\n", volume.Name, p.ServiceID, volume.Name))
	}
	if p.ExternalNetwork != "" {
		script.WriteString(fmt.Sprintf("docker network inspect %q >/dev/null\n", p.ExternalNetwork))
	}
	if p.InternalNetwork != nil {
		script.WriteString(fmt.Sprintf("docker network inspect %q >/dev/null 2>&1 || docker network create --label nori.service=\"$SERVICE\" --label nori.template=1 --label nori.service-id=%d --label nori.role=internal-network %q\n", p.InternalNetwork.Name, p.ServiceID, p.InternalNetwork.Name))
	}
	if p.Database != nil {
		script.WriteString(fmt.Sprintf("docker pull %q\n", p.Database.Image))
		passwordKey := p.Database.EnvKeys[len(p.Database.EnvKeys)-1]
		script.WriteString(fmt.Sprintf("grep -q '^%s=' \"$ENV_FILE\"\n", passwordKey))
		script.WriteString(fmt.Sprintf("if ! docker container inspect %q >/dev/null 2>&1; then docker run -d --name %q --label nori.service=\"$SERVICE\" --label nori.template=1 --label nori.service-id=%d --label nori.role=db --network %q --mount type=volume,src=%q,dst=/var/lib/postgresql/data --env-file \"$ENV_FILE\" %q; else docker start %q >/dev/null; fi\n", p.Database.Name, p.Database.Name, p.ServiceID, p.InternalNetwork.Name, fmt.Sprintf("nori-%d-volume-postgres-data", p.ServiceID), p.Database.Image, p.Database.Name))
		script.WriteString("# PostgreSQL uses the existing $ENV_FILE boundary before application promotion.\n")
	}
	script.WriteString(fmt.Sprintf("docker rm -f %q >/dev/null 2>&1 || true\n", p.AppCandidate.Name))
	script.WriteString(fmt.Sprintf("docker run -d --name %q --label nori.service=\"$SERVICE\" --label nori.template=1 --label nori.service-id=%d --label nori.role=candidate --restart %q --env-file \"$ENV_FILE\"", p.AppCandidate.Name, p.ServiceID, p.AppCandidate.RestartPolicy))
	for _, mount := range p.AppCandidate.Mounts {
		script.WriteString(fmt.Sprintf(" --mount type=volume,src=%q,dst=%q", fmt.Sprintf("nori-%d-volume-%s", p.ServiceID, mount.Name), mount.Target))
	}
	for _, network := range p.AppCandidate.Networks {
		script.WriteString(fmt.Sprintf(" --network %q", network))
	}
	script.WriteString(" \"$TARGET_IMAGE\"\n")
	script.WriteString(fmt.Sprintf("# Wait no longer than %d seconds for health before promotion.\n", p.Health.TimeoutSeconds))
	script.WriteString(fmt.Sprintf("docker rm -f %q >/dev/null 2>&1 || true\n", p.AppRollback.Name))
	script.WriteString(fmt.Sprintf("if docker container inspect %q >/dev/null 2>&1; then docker rename %q %q; fi\n", p.AppCurrent.Name, p.AppCurrent.Name, p.AppRollback.Name))
	script.WriteString(fmt.Sprintf("docker rename %q %q\n", p.AppCandidate.Name, p.AppCurrent.Name))
	return script.String(), nil
}
