package web

import (
	"encoding/json"
	"fmt"
	"strings"

	"nori/internal/deploytemplate"
	"nori/internal/store"
)

func normalizedTemplateConfig(rawMode, rawConfig string) (store.DeploymentMode, string, error) {
	mode := store.DeploymentMode(strings.TrimSpace(rawMode))
	if mode == "" {
		mode = store.DeploymentModeCustom
	}
	switch mode {
	case store.DeploymentModeCustom:
		return mode, "{}", nil
	case store.DeploymentModeSingleContainer, store.DeploymentModePostgres:
	default:
		return "", "", fmt.Errorf("unsupported deployment mode %q", rawMode)
	}
	config, err := deploytemplate.ParseConfig(deploytemplate.Mode(mode), rawConfig)
	if err != nil {
		return "", "", err
	}
	encoded, err := json.Marshal(config)
	if err != nil {
		return "", "", fmt.Errorf("encode template configuration: %w", err)
	}
	return mode, string(encoded), nil
}

func templatePreview(svc *store.Service) (string, error) {
	plan, err := templatePlan(svc)
	if err != nil {
		return "", err
	}
	if plan == nil {
		return "", nil
	}
	return plan.Preview(), nil
}

func renderTemplateAsCustomScript(svc *store.Service) (string, error) {
	plan, err := templatePlan(svc)
	if err != nil {
		return "", err
	}
	if plan == nil {
		return "", fmt.Errorf("service already uses a Custom deployment script")
	}
	return plan.RenderCustomScript()
}

func templatePlan(svc *store.Service) (*deploytemplate.Plan, error) {
	mode, config, err := normalizedTemplateConfig(string(svc.DeploymentMode), svc.TemplateConfig)
	if err != nil {
		return nil, err
	}
	if mode == store.DeploymentModeCustom {
		return nil, nil
	}
	parsed, err := deploytemplate.ParseConfig(deploytemplate.Mode(mode), config)
	if err != nil {
		return nil, err
	}
	targetImage := svc.WatchedImage
	if !strings.Contains(targetImage, "@sha256:") {
		targetImage += "@sha256:preview"
	}
	plan, err := deploytemplate.BuildPlan(deploytemplate.Input{
		ServiceID: svc.ID, ServiceName: svc.Name,
		TargetImage: targetImage, Config: parsed,
	})
	if err != nil {
		return nil, err
	}
	return &plan, nil
}
