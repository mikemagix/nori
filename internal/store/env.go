package store

import (
	"context"
	"database/sql"
	"strings"
	"time"

	"github.com/joho/godotenv"
	"nori/internal/crypto"
	"nori/internal/envfile"
)

// SetEnvFile stores one complete dotenv document. The entire file is encrypted
// because dotenv files commonly contain a mixture of public and secret values.
func (s *Store) SetEnvFile(ctx context.Context, serviceID int64, content string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := s.writeEnvFile(ctx, tx, serviceID, content); err != nil {
		return err
	}
	if err := advanceConfigVersion(ctx, tx, serviceID); err != nil {
		return err
	}
	return tx.Commit()
}

// SetEnvTemplate changes declared keys without accepting or returning values.
func (s *Store) SetEnvTemplate(ctx context.Context, serviceID int64, template string) error {
	return s.updateEnvFile(ctx, serviceID, func(current string) (string, error) {
		return envfile.ResolveTemplate(current, template)
	})
}

// SetEnvTemplateAtVersion changes declared keys only when the client still
// holds the current service configuration generation.
func (s *Store) SetEnvTemplateAtVersion(ctx context.Context, serviceID, expectedVersion int64, template string) (int64, error) {
	return s.updateEnvFileAtVersion(ctx, serviceID, expectedVersion, func(current string) (string, error) {
		return envfile.ResolveTemplate(current, template)
	})
}

// SetEnvSecret is write-only and cannot introduce an undeclared variable.
func (s *Store) SetEnvSecret(ctx context.Context, serviceID int64, key, value string) error {
	return s.updateEnvFile(ctx, serviceID, func(current string) (string, error) {
		return envfile.SetValue(current, key, value)
	})
}

// SetEnvSecretAtVersion is write-only and refuses a stale client snapshot.
func (s *Store) SetEnvSecretAtVersion(ctx context.Context, serviceID, expectedVersion int64, key, value string) (int64, error) {
	return s.updateEnvFileAtVersion(ctx, serviceID, expectedVersion, func(current string) (string, error) {
		return envfile.SetValue(current, key, value)
	})
}

func (s *Store) updateEnvFile(ctx context.Context, serviceID int64, update func(string) (string, error)) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	current, err := s.getEnvFile(ctx, tx, serviceID)
	if err != nil {
		return err
	}
	content, err := update(current)
	if err != nil {
		return err
	}
	if err := s.writeEnvFile(ctx, tx, serviceID, content); err != nil {
		return err
	}
	if err := advanceConfigVersion(ctx, tx, serviceID); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) updateEnvFileAtVersion(ctx context.Context, serviceID, expectedVersion int64, update func(string) (string, error)) (int64, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	if err := advanceConfigVersionAt(ctx, tx, serviceID, expectedVersion); err != nil {
		return 0, err
	}
	current, err := s.getEnvFile(ctx, tx, serviceID)
	if err != nil {
		return 0, err
	}
	content, err := update(current)
	if err != nil {
		return 0, err
	}
	if err := s.writeEnvFile(ctx, tx, serviceID, content); err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return expectedVersion + 1, nil
}

func (s *Store) writeEnvFile(ctx context.Context, tx *sql.Tx, serviceID int64, content string) error {
	current, err := s.getEnvFile(ctx, tx, serviceID)
	if err != nil {
		return err
	}
	if current != "" {
		if err := s.recordEnvRevision(ctx, tx, serviceID, current); err != nil {
			return err
		}
	}
	if err := s.recordEnvRevision(ctx, tx, serviceID, content); err != nil {
		return err
	}
	stored, err := crypto.Encrypt(s.key, []byte(content))
	if err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx,
		`INSERT INTO service_env (service_id, content) VALUES (?, ?)
		 ON CONFLICT(service_id) DO UPDATE SET content=excluded.content`,
		serviceID, stored); err != nil {
		return err
	}
	// Once the complete file exists, the legacy per-variable representation is
	// obsolete and must not retain values that were removed from the file.
	if _, err = tx.ExecContext(ctx, `DELETE FROM env_var WHERE service_id=?`, serviceID); err != nil {
		return err
	}
	return nil
}

// GetEnvFile returns the complete dotenv document. Per-variable rows created
// by older versions are represented as a dotenv document for compatibility.
func (s *Store) GetEnvFile(ctx context.Context, serviceID int64) (string, error) {
	return s.getEnvFile(ctx, s.db, serviceID)
}

type envQuerier interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}

func (s *Store) getEnvFile(ctx context.Context, q envQuerier, serviceID int64) (string, error) {
	var raw []byte
	err := q.QueryRowContext(ctx,
		`SELECT content FROM service_env WHERE service_id=?`, serviceID).Scan(&raw)
	if err == nil {
		plain, err := crypto.Decrypt(s.key, raw)
		if err != nil {
			return "", err
		}
		return string(plain), nil
	}
	if err != sql.ErrNoRows {
		return "", err
	}

	legacy, err := s.listEnvVars(ctx, q, serviceID)
	if err != nil || len(legacy) == 0 {
		return "", err
	}
	values := make(map[string]string, len(legacy))
	for _, item := range legacy {
		values[item.Key] = item.Value
	}
	content, err := godotenv.Marshal(values)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(content) + "\n", nil
}

func (s *Store) SetEnvVar(ctx context.Context, ev *EnvVar) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	current, err := s.getEnvFile(ctx, tx, ev.ServiceID)
	if err != nil {
		return err
	}
	if current != "" {
		if err := s.recordEnvRevision(ctx, tx, ev.ServiceID, current); err != nil {
			return err
		}
	}
	stored := []byte(ev.Value)
	if ev.IsSecret {
		enc, err := crypto.Encrypt(s.key, []byte(ev.Value))
		if err != nil {
			return err
		}
		stored = enc
	}
	_, err = tx.ExecContext(ctx,
		`INSERT INTO env_var (service_id, key, value, is_secret) VALUES (?,?,?,?)
		 ON CONFLICT(service_id, key) DO UPDATE SET value=excluded.value, is_secret=excluded.is_secret`,
		ev.ServiceID, ev.Key, stored, boolToInt(ev.IsSecret))
	if err != nil {
		return err
	}
	content, err := s.getEnvFile(ctx, tx, ev.ServiceID)
	if err != nil {
		return err
	}
	if err := s.recordEnvRevision(ctx, tx, ev.ServiceID, content); err != nil {
		return err
	}
	if err := advanceConfigVersion(ctx, tx, ev.ServiceID); err != nil {
		return err
	}
	return tx.Commit()
}

func advanceConfigVersion(ctx context.Context, tx *sql.Tx, serviceID int64) error {
	res, err := tx.ExecContext(ctx, `UPDATE service SET config_version=config_version+1, updated_at=? WHERE id=?`, time.Now().UTC().Unix(), serviceID)
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
	return nil
}

func advanceConfigVersionAt(ctx context.Context, tx *sql.Tx, serviceID, expectedVersion int64) error {
	res, err := tx.ExecContext(ctx, `UPDATE service SET config_version=config_version+1, updated_at=? WHERE id=? AND config_version=?`, time.Now().UTC().Unix(), serviceID, expectedVersion)
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
	return nil
}

func (s *Store) ListEnvVars(ctx context.Context, serviceID int64) ([]*EnvVar, error) {
	return s.listEnvVars(ctx, s.db, serviceID)
}

func (s *Store) listEnvVars(ctx context.Context, q envQuerier, serviceID int64) ([]*EnvVar, error) {
	rows, err := q.QueryContext(ctx,
		`SELECT id, service_id, key, value, is_secret FROM env_var WHERE service_id=? ORDER BY key`, serviceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*EnvVar
	for rows.Next() {
		var ev EnvVar
		var raw []byte
		var isSecret int
		if err := rows.Scan(&ev.ID, &ev.ServiceID, &ev.Key, &raw, &isSecret); err != nil {
			return nil, err
		}
		ev.IsSecret = isSecret != 0
		if ev.IsSecret {
			dec, err := crypto.Decrypt(s.key, raw)
			if err != nil {
				return nil, err
			}
			ev.Value = string(dec)
		} else {
			ev.Value = string(raw)
		}
		out = append(out, &ev)
	}
	return out, rows.Err()
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
