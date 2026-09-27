package store

import (
	"context"
	"errors"
	"time"

	"nori/internal/envfile"
)

var ErrServiceConflict = errors.New("service configuration changed; read it again and retry")

// SaveServiceConfig atomically saves service configuration and, when supplied,
// its encrypted environment. Existing names and managed status are immutable;
// updates require the previous configuration to detect concurrent edits.
func (s *Store) SaveServiceConfig(ctx context.Context, svc *Service, env *string, previous *Service) error {
	return s.saveServiceConfig(ctx, svc, env, previous, false)
}

// SaveServiceConfigTemplate resolves placeholders inside the same transaction
// as the service save, so a stale template cannot restore older secret values.
func (s *Store) SaveServiceConfigTemplate(ctx context.Context, svc *Service, env *string, previous *Service) error {
	return s.saveServiceConfig(ctx, svc, env, previous, true)
}

func (s *Store) saveServiceConfig(ctx context.Context, svc *Service, env *string, previous *Service, template bool) error {
	normalizeDeploymentConfig(svc)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var content string
	if env != nil {
		content = *env
		if template {
			current, err := s.getEnvFile(ctx, tx, svc.ID)
			if err != nil {
				return err
			}
			content, err = envfile.ResolveTemplate(current, content)
			if err != nil {
				return err
			}
		}
	}

	now := time.Now().UTC()
	id := svc.ID
	if id == 0 {
		res, err := tx.ExecContext(ctx, `INSERT INTO service (name,watched_image,policy,cron_expr,deploy_script,health_url,is_self,deployment_mode,template_config,created_at,updated_at) VALUES (?,?,?,?,?,?,0,?,?,?,?)`, svc.Name, svc.WatchedImage, svc.Policy, svc.CronExpr, svc.DeployScript, svc.HealthURL, svc.DeploymentMode, svc.TemplateConfig, now.Unix(), now.Unix())
		if err != nil {
			return err
		}
		id, err = res.LastInsertId()
		if err != nil {
			return err
		}
	} else {
		if previous == nil {
			return errors.New("previous service configuration is required for updates")
		}
		expected := *previous
		normalizeDeploymentConfig(&expected)
		res, err := tx.ExecContext(ctx, `UPDATE service SET watched_image=?,policy=?,cron_expr=?,deploy_script=?,health_url=?,deployment_mode=?,template_config=?,updated_at=? WHERE id=? AND name=? AND is_self=0 AND watched_image=? AND policy=? AND cron_expr=? AND deploy_script=? AND health_url=? AND deployment_mode=? AND template_config=?`, svc.WatchedImage, svc.Policy, svc.CronExpr, svc.DeployScript, svc.HealthURL, svc.DeploymentMode, svc.TemplateConfig, now.Unix(), id, svc.Name, expected.WatchedImage, expected.Policy, expected.CronExpr, expected.DeployScript, expected.HealthURL, expected.DeploymentMode, expected.TemplateConfig)
		if err != nil {
			return err
		}
		n, err := res.RowsAffected()
		if err != nil {
			return err
		}
		if n != 1 {
			return ErrServiceConflict
		}
	}
	if env != nil {
		if err := s.writeEnvFile(ctx, tx, id, content); err != nil {
			return err
		}
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	if svc.ID == 0 {
		svc.CreatedAt = now
	}
	svc.ID, svc.UpdatedAt = id, now
	return nil
}
