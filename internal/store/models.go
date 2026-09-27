package store

import "time"

type Policy string

const (
	PolicyImmediate Policy = "immediate"
	PolicyManual    Policy = "manual"
	PolicyScheduled Policy = "scheduled"
)

type Service struct {
	ID            int64
	Name          string
	WatchedImage  string
	Policy        Policy
	CronExpr      string
	DeployScript  string
	IsSelf        bool
	HealthURL     string
	ConfigVersion int64 `json:"config_version"`
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

type EnvVar struct {
	ID        int64
	ServiceID int64
	Key       string
	Value     string
	IsSecret  bool
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
