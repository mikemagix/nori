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
		res, err := tx.ExecContext(ctx, `INSERT INTO service (name,watched_image,policy,cron_expr,deploy_script,health_url,is_self,created_at,updated_at) VALUES (?,?,?,?,?,?,0,?,?)`, svc.Name, svc.WatchedImage, svc.Policy, svc.CronExpr, svc.DeployScript, svc.HealthURL, now.Unix(), now.Unix())
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
		res, err := tx.ExecContext(ctx, `UPDATE service SET watched_image=?,policy=?,cron_expr=?,deploy_script=?,health_url=?,updated_at=?,config_version=config_version+1 WHERE id=? AND name=? AND is_self=0 AND config_version=?`, svc.WatchedImage, svc.Policy, svc.CronExpr, svc.DeployScript, svc.HealthURL, now.Unix(), id, svc.Name, previous.ConfigVersion)
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
	if previous == nil {
		svc.ConfigVersion = 1
	} else {
		svc.ConfigVersion = previous.ConfigVersion + 1
	}
	return nil
}
