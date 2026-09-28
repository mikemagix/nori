package web

import (
	"net/url"
	"strconv"

	"nori/internal/notify"
)

func strconvItoa(i int) string {
	return strconv.Itoa(i)
}

// Channels reports which notification channels are configured for this
// process via environment variables. Configuration happens at startup, so
// the settings page treats it as read-only status.
type Channels struct {
	Twilio   bool
	Telegram bool
}

// has reports whether the named notify.Channel is configured.
func (c Channels) has(channel string) bool {
	switch channel {
	case notify.ChannelTwilio:
		return c.Twilio
	case notify.ChannelTelegram:
		return c.Telegram
	}
	return false
}

// parseRoutingForm reads the notification checkboxes for the configured
// channels. Unchecked checkboxes do not submit values, so an absent value
// means off. Only configured channels get a table entry, so a channel that
// is configured via environment later on starts with every event enabled
// (see notify.Routing.Allowed).
func parseRoutingForm(channels Channels, form url.Values) notify.Routing {
	routing := notify.Routing{}
	for _, ch := range notify.Channels {
		if !channels.has(ch) {
			continue
		}
		entry := make(map[notify.EventKind]bool, len(notify.Kinds))
		for _, kind := range notify.Kinds {
			entry[kind] = form.Get("notify_"+ch+"_"+string(kind)) == "1"
		}
		routing[ch] = entry
	}
	return routing
}

type ServiceFormData struct {
	Name            string
	WatchedImage    string
	Policy          string
	CronExpr        string
	DeployScript    string
	EnvFile         string
	HealthURL       string
	ConfigVersion   int64
	ReloadURL       string
	IsSelf          bool
	DeploymentMode  string
	TemplateConfig  string
	TemplatePreview string
}

type ServiceDetailData struct {
	Service     ServiceFormData
	State       string
	Running     string
	Latest      string
	RunningFor  string
	LastDeploy  string
	UpdateAvail bool
	Containers  []ContainerView
	Deployments []DeploymentView
}

type ContainerView struct {
	Name  string
	Image string
	State string
}

type DeploymentView struct {
	ID           int64
	Trigger      string
	TargetDigest string
	Status       string
	StartedAt    string
}
