package store

import "time"

type Policy string

const (
	PolicyImmediate Policy = "immediate"
	PolicyManual    Policy = "manual"
	PolicyScheduled Policy = "scheduled"
)

type DeploymentMode string

const (
	DeploymentModeCustom          DeploymentMode = "custom"
	DeploymentModeSingleContainer DeploymentMode = "single_container"
	DeploymentModePostgres        DeploymentMode = "postgres"
)

type Service struct {
	ID             int64
	Name           string
	WatchedImage   string
	Policy         Policy
	CronExpr       string
	DeployScript   string
	IsSelf         bool
	HealthURL      string
	DeploymentMode DeploymentMode
	TemplateConfig string
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

type EnvVar struct {
	ID        int64
	ServiceID int64
	Key       string
	Value     string
	IsSecret  bool
}

// TemplateState records non-secret state that must survive managed template
// deployments. The database identity fingerprint is created only after a
// database has initialized successfully; it is never an environment secret.
type TemplateState struct {
	ServiceID                   int64
	DatabaseIdentityFingerprint string
	UpdatedAt                   time.Time
}

type Deployment struct {
	ID           int64
	ServiceID    int64
	Trigger      string
	TargetDigest string
	Status       string
	StartedAt    time.Time
	FinishedAt   *time.Time
	Log          string
}
