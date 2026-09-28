package store

import (
	"context"
	"database/sql"
	"net/url"

	_ "modernc.org/sqlite"
)

// dsn builds a SQLite URI carrying the connection PRAGMAs. They have to travel
// on the DSN rather than run as `db.Exec("PRAGMA ...")` after opening: sql.Open
// returns a pool, so such a statement configures only whichever connection
// served it. Every later connection would keep the SQLite defaults —
// busy_timeout=0, which turns concurrent writes into instant SQLITE_BUSY, and
// foreign_keys=OFF, which silently skips ON DELETE CASCADE.
// The path is carried as an opaque URI part so it never grows a "//" authority,
// which would make SQLite read a relative path like "nori.db" as a hostname.
func dsn(path string) string {
	u := url.URL{
		Scheme:   "file",
		Opaque:   (&url.URL{Path: path}).EscapedPath(),
		RawQuery: url.Values{"_pragma": {"busy_timeout(5000)", "foreign_keys(1)"}, "_txlock": {"immediate"}}.Encode(),
	}
	return u.String()
}

type Store struct {
	db  *sql.DB
	key []byte
}

const schema = `
CREATE TABLE IF NOT EXISTS service (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	name TEXT NOT NULL UNIQUE,
	watched_image TEXT NOT NULL,
	policy TEXT NOT NULL,
	cron_expr TEXT NOT NULL DEFAULT '',
	deploy_script TEXT NOT NULL DEFAULT '',
	health_url TEXT NOT NULL DEFAULT '',
	is_self INTEGER NOT NULL DEFAULT 0,
	deployment_mode TEXT NOT NULL DEFAULT 'custom',
	template_config TEXT NOT NULL DEFAULT '{}',
	config_version INTEGER NOT NULL DEFAULT 1,
	created_at INTEGER NOT NULL,
	updated_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS env_var (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	service_id INTEGER NOT NULL REFERENCES service(id) ON DELETE CASCADE,
	key TEXT NOT NULL,
	value BLOB NOT NULL,
	is_secret INTEGER NOT NULL DEFAULT 0,
	UNIQUE(service_id, key)
);
CREATE TABLE IF NOT EXISTS service_env (
	service_id INTEGER PRIMARY KEY REFERENCES service(id) ON DELETE CASCADE,
	content BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS template_state (
	service_id INTEGER PRIMARY KEY REFERENCES service(id) ON DELETE CASCADE,
	database_identity_fingerprint TEXT NOT NULL,
	updated_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS deployment (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	service_id INTEGER NOT NULL REFERENCES service(id) ON DELETE CASCADE,
	trigger TEXT NOT NULL,
	target_digest TEXT NOT NULL DEFAULT '',
	status TEXT NOT NULL,
	started_at INTEGER NOT NULL,
	finished_at INTEGER,
	log TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS setting (
	key TEXT PRIMARY KEY,
	value TEXT NOT NULL
);
`

func Open(path string, key []byte) (*Store, error) {
	db, err := sql.Open("sqlite", dsn(path))
	if err != nil {
		return nil, err
	}
	if _, err := db.Exec(schema + oauthSchema); err != nil {
		db.Close()
		return nil, err
	}
	if err := migrate(db); err != nil {
		db.Close()
		return nil, err
	}
	if _, err := db.Exec(revisionSchema); err != nil {
		db.Close()
		return nil, err
	}
	st := &Store{db: db, key: key}
	if err := st.backfillEnvRevisions(context.Background()); err != nil {
		db.Close()
		return nil, err
	}
	return st, nil
}

func (s *Store) Close() error { return s.db.Close() }

func migrate(db *sql.DB) error {
	rows, err := db.Query(`PRAGMA table_info(service)`)
	if err != nil {
		return err
	}
	defer rows.Close()
	hasSelf := false
	hasHealth := false
	hasDeploymentMode := false
	hasTemplateConfig := false
	hasConfigVersion := false
	for rows.Next() {
		var cid int
		var name, typ string
		var notNull, pk int
		var defaultValue any
		if err := rows.Scan(&cid, &name, &typ, &notNull, &defaultValue, &pk); err != nil {
			return err
		}
		if name == "is_self" {
			hasSelf = true
		}
		if name == "health_url" {
			hasHealth = true
		}
		if name == "deployment_mode" {
			hasDeploymentMode = true
		}
		if name == "template_config" {
			hasTemplateConfig = true
		}
		if name == "config_version" {
			hasConfigVersion = true
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if !hasSelf {
		if _, err := db.Exec(`ALTER TABLE service ADD COLUMN is_self INTEGER NOT NULL DEFAULT 0`); err != nil {
			return err
		}
	}
	if !hasHealth {
		if _, err := db.Exec(`ALTER TABLE service ADD COLUMN health_url TEXT NOT NULL DEFAULT ''`); err != nil {
			return err
		}
	}
	if !hasDeploymentMode {
		if _, err := db.Exec(`ALTER TABLE service ADD COLUMN deployment_mode TEXT NOT NULL DEFAULT 'custom'`); err != nil {
			return err
		}
	}
	if !hasTemplateConfig {
		if _, err := db.Exec(`ALTER TABLE service ADD COLUMN template_config TEXT NOT NULL DEFAULT '{}'`); err != nil {
			return err
		}
	}
	if !hasConfigVersion {
		if _, err := db.Exec(`ALTER TABLE service ADD COLUMN config_version INTEGER NOT NULL DEFAULT 1`); err != nil {
			return err
		}
	}
	_, err = db.Exec(`CREATE UNIQUE INDEX IF NOT EXISTS service_one_self ON service(is_self) WHERE is_self=1`)
	return err
}
