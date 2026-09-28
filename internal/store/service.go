package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

var ErrNotFound = errors.New("not found")

var ErrTemplateDatabaseMigrationRequired = errors.New("template database identity changed; migrate data before redeploying")

const (
	SelfServiceName  = "nori"
	SelfDeployScript = `docker run --rm -d \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v "$NORI_CONFIG_VOLUME:/config" \
  "$NORI_SELF_IMAGE@$TARGET_DIGEST" \
  update --target-digest "$TARGET_DIGEST"`
)

func (s *Store) CreateService(ctx context.Context, svc *Service) error {
	normalizeDeploymentConfig(svc)
	now := time.Now().UTC()
	svc.CreatedAt, svc.UpdatedAt = now, now
	res, err := s.db.ExecContext(ctx,
		`INSERT INTO service (name, watched_image, policy, cron_expr, deploy_script, health_url, is_self, deployment_mode, template_config, created_at, updated_at)
		 VALUES (?,?,?,?,?,?,?,?,?,?,?)`,
		svc.Name, svc.WatchedImage, string(svc.Policy), svc.CronExpr, svc.DeployScript, svc.HealthURL,
		boolToInt(svc.IsSelf), svc.DeploymentMode, svc.TemplateConfig, svc.CreatedAt.Unix(), svc.UpdatedAt.Unix())
	if err != nil {
		return err
	}
	svc.ID, err = res.LastInsertId()
	svc.ConfigVersion = 1
	return err
}

func (s *Store) GetService(ctx context.Context, id int64) (*Service, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT id,name,watched_image,policy,cron_expr,deploy_script,health_url,is_self,deployment_mode,template_config,created_at,updated_at
		 FROM service WHERE id=?`, id)
	return scanService(row)
}

func (s *Store) GetServiceByName(ctx context.Context, name string) (*Service, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT id,name,watched_image,policy,cron_expr,deploy_script,health_url,is_self,deployment_mode,template_config,created_at,updated_at
		 FROM service WHERE name=?`, name)
	return scanService(row)
}

func (s *Store) UpdateService(ctx context.Context, svc *Service) error {
	normalizeDeploymentConfig(svc)
	svc.UpdatedAt = time.Now().UTC()
	_, err := s.db.ExecContext(ctx,
		`UPDATE service SET name=?, watched_image=?, policy=?, cron_expr=?, deploy_script=?, health_url=?, is_self=?, deployment_mode=?, template_config=?, updated_at=?
		 WHERE id=?`,
		svc.Name, svc.WatchedImage, string(svc.Policy), svc.CronExpr, svc.DeployScript, svc.HealthURL,
		boolToInt(svc.IsSelf), svc.DeploymentMode, svc.TemplateConfig, svc.UpdatedAt.Unix(), svc.ID)
	return err
}

func (s *Store) DeleteService(ctx context.Context, id int64) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM service WHERE id=?`, id)
	return err
}

// GetTemplateState returns the non-secret managed-template state for a
// service. A service has no state until its managed database initialized.
func (s *Store) GetTemplateState(ctx context.Context, serviceID int64) (*TemplateState, error) {
	var state TemplateState
	var updated int64
	err := s.db.QueryRowContext(ctx, `SELECT service_id,database_identity_fingerprint,updated_at FROM template_state WHERE service_id=?`, serviceID).Scan(&state.ServiceID, &state.DatabaseIdentityFingerprint, &updated)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	state.UpdatedAt = time.Unix(updated, 0).UTC()
	return &state, nil
}

// RecordTemplateDatabaseIdentity records the non-secret identity after the
// managed database is ready. Once recorded it cannot change implicitly: a
// different identity requires an explicit data migration outside this path.
func (s *Store) RecordTemplateDatabaseIdentity(ctx context.Context, serviceID int64, fingerprint string) error {
	if fingerprint == "" {
		return errors.New("template database identity fingerprint is required")
	}
	result, err := s.db.ExecContext(ctx, `INSERT INTO template_state (service_id,database_identity_fingerprint,updated_at)
		VALUES (?,?,?)
		ON CONFLICT(service_id) DO UPDATE SET updated_at=excluded.updated_at
		WHERE template_state.database_identity_fingerprint=excluded.database_identity_fingerprint`, serviceID, fingerprint, time.Now().UTC().Unix())
	if err != nil {
		return err
	}
	updated, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if updated != 1 {
		return ErrTemplateDatabaseMigrationRequired
	}
	return nil
}

func (s *Store) ListServices(ctx context.Context) ([]*Service, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id,name,watched_image,policy,cron_expr,deploy_script,health_url,is_self,deployment_mode,template_config,created_at,updated_at
		 FROM service ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Service
	for rows.Next() {
		svc, err := scanService(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, svc)
	}
	return out, rows.Err()
}

type rowScanner interface{ Scan(...any) error }

func normalizeDeploymentConfig(svc *Service) {
	if svc.DeploymentMode == "" {
		svc.DeploymentMode = DeploymentModeCustom
	}
	if svc.TemplateConfig == "" {
		svc.TemplateConfig = "{}"
	}
}

func scanService(sc rowScanner) (*Service, error) {
	var svc Service
	var policy string
	var created, updated int64
	var isSelf int
	var healthURL string
	var deploymentMode string
	var templateConfig string
	err := sc.Scan(&svc.ID, &svc.Name, &svc.WatchedImage, &policy,
		&svc.CronExpr, &svc.DeployScript, &healthURL, &isSelf, &deploymentMode, &templateConfig, &created, &updated)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	svc.Policy = Policy(policy)
	svc.IsSelf = isSelf != 0
	svc.HealthURL = healthURL
	svc.DeploymentMode = DeploymentMode(deploymentMode)
	svc.TemplateConfig = templateConfig
	svc.CreatedAt = time.Unix(created, 0).UTC()
	svc.UpdatedAt = time.Unix(updated, 0).UTC()
	return &svc, nil
}

// GetSelfService returns the launcher-managed service, if this installation
// has one.
func (s *Store) GetSelfService(ctx context.Context) (*Service, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT id,name,watched_image,policy,cron_expr,deploy_script,health_url,is_self,deployment_mode,template_config,created_at,updated_at
		 FROM service WHERE is_self=1`)
	return scanService(row)
}

// EnsureSelfService seeds the single managed self-service. Its deployment
// policy remains user-editable; the image and handoff script remain owned by
// the launcher so they cannot drift from the actual bot configuration.
func (s *Store) EnsureSelfService(ctx context.Context, image string) (*Service, error) {
	svc, err := s.GetSelfService(ctx)
	if err == nil {
		svc.Name = SelfServiceName
		svc.WatchedImage = image
		svc.DeployScript = SelfDeployScript
		svc.IsSelf = true
		if err := s.UpdateService(ctx, svc); err != nil {
			return nil, err
		}
		return svc, nil
	}
	if !errors.Is(err, ErrNotFound) {
		return nil, err
	}
	if existing, err := s.GetServiceByName(ctx, SelfServiceName); err == nil {
		return nil, fmt.Errorf("service name %q is reserved for self-update (existing service id %d)", SelfServiceName, existing.ID)
	} else if !errors.Is(err, ErrNotFound) {
		return nil, err
	}
	svc = &Service{
		Name:         SelfServiceName,
		WatchedImage: image,
		Policy:       PolicyManual,
		DeployScript: SelfDeployScript,
		IsSelf:       true,
	}
	if err := s.CreateService(ctx, svc); err != nil {
		return nil, err
	}
	return svc, nil
}
