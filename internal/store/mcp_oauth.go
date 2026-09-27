package store

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"
	"time"
)

const oauthSchema = `CREATE TABLE IF NOT EXISTS mcp_oauth (
 key TEXT PRIMARY KEY, kind TEXT NOT NULL, data BLOB NOT NULL, expires INTEGER NOT NULL,
 family TEXT NOT NULL DEFAULT '', used INTEGER NOT NULL DEFAULT 0);
 CREATE INDEX IF NOT EXISTS mcp_oauth_family ON mcp_oauth(family);
 CREATE INDEX IF NOT EXISTS mcp_oauth_expiry ON mcp_oauth(expires);`

const (
	oauthRecordLimit             = 20000
	oauthClientLimit             = 1000
	oauthFamilyTombstoneLifetime = 31 * 24 * time.Hour
	oauthManagedRegistrationKind = "oauth_managed_registration"
	oauthManagedGrantKind        = "oauth_managed_grant"
	oauthRevokedKind             = "revoked"
)

type OAuthRecord struct {
	Key, Kind, Family string
	Data              []byte
	Expires           int64
	Used              bool
}

// OAuthGrantStatus is deliberately limited to the lifecycle state suitable
// for an administrator-facing connection inventory.
type OAuthGrantStatus string

const (
	OAuthGrantActive  OAuthGrantStatus = "active"
	OAuthGrantExpired OAuthGrantStatus = "expired"
	OAuthGrantRevoked OAuthGrantStatus = "revoked"
)

// OAuthGrant is the safe, browser-facing projection of one approved OAuth
// grant. It intentionally has no OAuth client ID, secret, redirect URL,
// credential digest, code, token, or family value.
type OAuthGrant struct {
	ManagementID string
	ClientName   string
	Scopes       string
	ApprovedAt   time.Time
	ExpiresAt    time.Time
	Status       OAuthGrantStatus
}

// OAuthRegistration groups safe OAuth grants under one approved client label.
// The label is supplied by the OAuth layer only after administrator consent.
type OAuthRegistration struct {
	ClientName string
	ApprovedAt time.Time
	ExpiresAt  time.Time
	Grants     []OAuthGrant
}

// OAuthGrantApproval is the Store-owned input to the atomic consent
// persistence operation. OAuthRecord remains generic so Store does not import
// protocol-private OAuth structs or decode credential-bearing payloads.
type OAuthGrantApproval struct {
	ClientKey       string
	ClientName      string
	ClientExpiresAt time.Time
	ApprovedAt      time.Time
	Family          string
	FamilyExpiresAt time.Time
	Scopes          string
	Code            OAuthRecord
}

type oauthManagedRegistration struct {
	ClientName string `json:"client_name"`
	ApprovedAt int64  `json:"approved_at"`
	ExpiresAt  int64  `json:"expires_at"`
}

type oauthManagedGrant struct {
	ManagementID    string `json:"management_id"`
	RegistrationKey string `json:"registration_key"`
	ClientName      string `json:"client_name"`
	Scopes          string `json:"scopes"`
	ApprovedAt      int64  `json:"approved_at"`
	GrantExpiresAt  int64  `json:"grant_expires_at"`
}

func oauthManagementKey(namespace, value string) string {
	sum := sha256.Sum256([]byte(namespace + ":" + value))
	return namespace + ":" + hex.EncodeToString(sum[:])
}

func newOAuthManagementID() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}

// PutOAuth stores only digests of credentials; the caller supplies serialized metadata.
// The atomic INSERT bounds persistent storage even under simultaneous registration.
func (s *Store) PutOAuth(ctx context.Context, r OAuthRecord) error {
	if _, err := s.db.ExecContext(ctx, `DELETE FROM mcp_oauth WHERE expires <= ?`, time.Now().Unix()); err != nil {
		return err
	}
	result, err := s.db.ExecContext(ctx, `INSERT INTO mcp_oauth(key,kind,data,expires,family) SELECT ?,?,?,?,? WHERE NOT EXISTS (SELECT 1 FROM mcp_oauth WHERE kind=? AND family=?) AND (SELECT count(*) FROM mcp_oauth)<? AND (? != 'client' OR (SELECT count(*) FROM mcp_oauth WHERE kind='client')<?)`, r.Key, r.Kind, r.Data, r.Expires, r.Family, oauthRevokedKind, r.Family, oauthRecordLimit, r.Kind, oauthClientLimit)
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err == nil && n == 0 {
		return errors.New("OAuth storage capacity reached")
	}
	return err
}

func (s *Store) GetOAuth(ctx context.Context, key, kind string) (OAuthRecord, error) {
	r := OAuthRecord{Key: key, Kind: kind}
	err := s.db.QueryRowContext(ctx, `SELECT data,expires,family,used FROM mcp_oauth WHERE key=? AND kind=? AND expires>?`, key, kind, time.Now().Unix()).Scan(&r.Data, &r.Expires, &r.Family, &r.Used)
	return r, err
}

func (s *Store) ConsumeOAuth(ctx context.Context, key string) (bool, error) {
	r, err := s.db.ExecContext(ctx, `UPDATE mcp_oauth SET used=1 WHERE key=? AND used=0 AND expires>?`, key, time.Now().Unix())
	if err != nil {
		return false, err
	}
	n, err := r.RowsAffected()
	return n == 1, err
}

func (s *Store) ExtendOAuthClient(ctx context.Context, key string, expires time.Time) error {
	res, err := s.db.ExecContext(ctx, `UPDATE mcp_oauth SET expires=? WHERE key=? AND kind='client' AND used=0 AND expires>?`, expires.Unix(), key, time.Now().Unix())
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err == nil && n != 1 {
		return ErrNotFound
	}
	return err
}

// ApproveOAuthGrant extends a live registered client and writes the safe
// registration, safe grant, and authorization-code record in one transaction.
// It returns the opaque management ID needed by the Settings confirmation flow.
func (s *Store) ApproveOAuthGrant(ctx context.Context, a OAuthGrantApproval) (OAuthGrant, error) {
	now := time.Now()
	if a.ClientKey == "" || a.ClientName == "" || a.Family == "" || a.Scopes == "" || a.Code.Key == "" || a.Code.Kind != "code" || a.Code.Family != a.Family || a.Code.Used || !a.ClientExpiresAt.After(now) || !a.FamilyExpiresAt.After(now) || a.Code.Expires <= now.Unix() {
		return OAuthGrant{}, errors.New("invalid OAuth grant approval")
	}
	if a.ApprovedAt.IsZero() {
		a.ApprovedAt = now
	}
	id, err := newOAuthManagementID()
	if err != nil {
		return OAuthGrant{}, err
	}
	registrationKey := oauthManagementKey("oauth-managed-registration", a.ClientKey)
	registration := oauthManagedRegistration{ClientName: a.ClientName, ApprovedAt: a.ApprovedAt.Unix(), ExpiresAt: a.ClientExpiresAt.Unix()}
	grantData, err := json.Marshal(oauthManagedGrant{ManagementID: id, RegistrationKey: registrationKey, ClientName: a.ClientName, Scopes: a.Scopes, ApprovedAt: a.ApprovedAt.Unix(), GrantExpiresAt: a.FamilyExpiresAt.Unix()})
	if err != nil {
		return OAuthGrant{}, err
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return OAuthGrant{}, err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `DELETE FROM mcp_oauth WHERE expires <= ?`, now.Unix()); err != nil {
		return OAuthGrant{}, err
	}
	client, err := tx.ExecContext(ctx, `UPDATE mcp_oauth SET expires=? WHERE key=? AND kind='client' AND used=0 AND expires>?`, a.ClientExpiresAt.Unix(), a.ClientKey, now.Unix())
	if err != nil {
		return OAuthGrant{}, err
	}
	if n, err := client.RowsAffected(); err != nil {
		return OAuthGrant{}, err
	} else if n != 1 {
		return OAuthGrant{}, ErrNotFound
	}
	if err := upsertOAuthManagedRegistrationTx(ctx, tx, registrationKey, registration); err != nil {
		return OAuthGrant{}, err
	}
	grantRecord := OAuthRecord{Key: oauthManagementKey("oauth-managed-grant", id), Kind: oauthManagedGrantKind, Data: grantData, Family: a.Family, Expires: a.FamilyExpiresAt.Add(oauthFamilyTombstoneLifetime).Unix()}
	if err := insertOAuthTx(ctx, tx, grantRecord); err != nil {
		return OAuthGrant{}, err
	}
	if err := insertOAuthTx(ctx, tx, a.Code); err != nil {
		return OAuthGrant{}, err
	}
	if err := tx.Commit(); err != nil {
		return OAuthGrant{}, err
	}
	return OAuthGrant{ManagementID: id, ClientName: a.ClientName, Scopes: a.Scopes, ApprovedAt: time.Unix(a.ApprovedAt.Unix(), 0), ExpiresAt: time.Unix(a.FamilyExpiresAt.Unix(), 0), Status: OAuthGrantActive}, nil
}

func upsertOAuthManagedRegistrationTx(ctx context.Context, tx *sql.Tx, key string, registration oauthManagedRegistration) error {
	var existingData []byte
	err := tx.QueryRowContext(ctx, `SELECT data FROM mcp_oauth WHERE key=? AND kind=?`, key, oauthManagedRegistrationKind).Scan(&existingData)
	if err == nil {
		existing, err := decodeOAuthManagedRegistration(existingData)
		if err != nil {
			return err
		}
		registration.ApprovedAt = existing.ApprovedAt
	} else if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	data, err := json.Marshal(registration)
	if err != nil {
		return err
	}
	result, err := tx.ExecContext(ctx, `INSERT INTO mcp_oauth(key,kind,data,expires,family,used) SELECT ?,?,?,?,'',0 WHERE EXISTS (SELECT 1 FROM mcp_oauth WHERE key=?) OR (SELECT count(*) FROM mcp_oauth)<? ON CONFLICT(key) DO UPDATE SET data=excluded.data, expires=excluded.expires, used=0`, key, oauthManagedRegistrationKind, data, registration.ExpiresAt, key, oauthRecordLimit)
	if err != nil {
		return err
	}
	if n, err := result.RowsAffected(); err != nil {
		return err
	} else if n == 0 {
		return errors.New("OAuth storage capacity reached")
	}
	return nil
}

func insertOAuthTx(ctx context.Context, tx *sql.Tx, r OAuthRecord) error {
	result, err := tx.ExecContext(ctx, `INSERT INTO mcp_oauth(key,kind,data,expires,family,used) SELECT ?,?,?,?,?,? WHERE NOT EXISTS (SELECT 1 FROM mcp_oauth WHERE kind=? AND family=?) AND (SELECT count(*) FROM mcp_oauth)<? AND (? != 'client' OR (SELECT count(*) FROM mcp_oauth WHERE kind='client')<?)`, r.Key, r.Kind, r.Data, r.Expires, r.Family, boolToInt(r.Used), oauthRevokedKind, r.Family, oauthRecordLimit, r.Kind, oauthClientLimit)
	if err != nil {
		return err
	}
	if n, err := result.RowsAffected(); err != nil {
		return err
	} else if n == 0 {
		return errors.New("OAuth storage capacity reached")
	}
	return nil
}

// ListOAuthGrantManagement returns a deterministic safe projection. It never
// returns a generic OAuthRecord, so callers cannot accidentally render
// credential-bearing OAuth payloads.
func (s *Store) ListOAuthGrantManagement(ctx context.Context) ([]OAuthRegistration, error) {
	now := time.Now().Unix()
	if _, err := s.db.ExecContext(ctx, `DELETE FROM mcp_oauth WHERE expires <= ?`, now); err != nil {
		return nil, err
	}
	registrations, byKey, err := s.listOAuthManagedRegistrations(ctx, now)
	if err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT data,used FROM mcp_oauth WHERE kind=? AND expires>?`, oauthManagedGrantKind, now)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var data []byte
		var used bool
		if err := rows.Scan(&data, &used); err != nil {
			return nil, err
		}
		projection, err := decodeOAuthManagedGrant(data)
		if err != nil {
			return nil, err
		}
		registration, ok := byKey[projection.RegistrationKey]
		if !ok {
			continue
		}
		registration.Grants = append(registration.Grants, oauthGrantView(projection, used, now))
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for i := range registrations {
		sort.Slice(registrations[i].Grants, func(a, b int) bool {
			left, right := registrations[i].Grants[a], registrations[i].Grants[b]
		if left.ApprovedAt.Equal(right.ApprovedAt) {
			return left.ManagementID < right.ManagementID
		}
		return left.ApprovedAt.After(right.ApprovedAt)
		})
	}
	return registrations, nil
}

func (s *Store) listOAuthManagedRegistrations(ctx context.Context, now int64) ([]OAuthRegistration, map[string]*OAuthRegistration, error) {
	type record struct {
		key        string
		projection oauthManagedRegistration
	}
	rows, err := s.db.QueryContext(ctx, `SELECT key,data FROM mcp_oauth WHERE kind=? AND used=0 AND expires>?`, oauthManagedRegistrationKind, now)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	data := []record{}
	for rows.Next() {
		var item record
		var raw []byte
		if err := rows.Scan(&item.key, &raw); err != nil {
			return nil, nil, err
		}
		projection, err := decodeOAuthManagedRegistration(raw)
		if err != nil {
			return nil, nil, err
		}
		item.projection = projection
		data = append(data, item)
	}
	if err := rows.Err(); err != nil {
		return nil, nil, err
	}
	sort.Slice(data, func(a, b int) bool {
		if data[a].projection.ApprovedAt == data[b].projection.ApprovedAt {
			return data[a].key < data[b].key
		}
		return data[a].projection.ApprovedAt < data[b].projection.ApprovedAt
	})
	registrations := make([]OAuthRegistration, 0, len(data))
	byKey := make(map[string]*OAuthRegistration, len(data))
	for _, item := range data {
		registrations = append(registrations, OAuthRegistration{ClientName: item.projection.ClientName, ApprovedAt: time.Unix(item.projection.ApprovedAt, 0), ExpiresAt: time.Unix(item.projection.ExpiresAt, 0)})
		byKey[item.key] = &registrations[len(registrations)-1]
	}
	return registrations, byKey, nil
}

func decodeOAuthManagedRegistration(data []byte) (oauthManagedRegistration, error) {
	var projection oauthManagedRegistration
	if err := json.Unmarshal(data, &projection); err != nil {
		return projection, err
	}
	if projection.ClientName == "" || projection.ApprovedAt <= 0 || projection.ExpiresAt <= 0 {
		return projection, errors.New("invalid OAuth managed registration")
	}
	return projection, nil
}

func decodeOAuthManagedGrant(data []byte) (oauthManagedGrant, error) {
	var projection oauthManagedGrant
	if err := json.Unmarshal(data, &projection); err != nil {
		return projection, err
	}
	if projection.ManagementID == "" || projection.RegistrationKey == "" || projection.ClientName == "" || projection.Scopes == "" || projection.ApprovedAt <= 0 || projection.GrantExpiresAt <= 0 {
		return projection, errors.New("invalid OAuth managed grant")
	}
	return projection, nil
}

func oauthGrantView(projection oauthManagedGrant, used bool, now int64) OAuthGrant {
	status := OAuthGrantActive
	if used {
		status = OAuthGrantRevoked
	} else if projection.GrantExpiresAt <= now {
		status = OAuthGrantExpired
	}
	return OAuthGrant{ManagementID: projection.ManagementID, ClientName: projection.ClientName, Scopes: projection.Scopes, ApprovedAt: time.Unix(projection.ApprovedAt, 0), ExpiresAt: time.Unix(projection.GrantExpiresAt, 0), Status: status}
}

// GetOAuthGrantManagement resolves exactly one opaque management ID and only
// returns an active grant suitable for a destructive confirmation flow.
func (s *Store) GetOAuthGrantManagement(ctx context.Context, id string) (OAuthGrant, error) {
	if id == "" {
		return OAuthGrant{}, ErrNotFound
	}
	row, err := s.getOAuthManagedGrant(ctx, id)
	if err != nil {
		return OAuthGrant{}, err
	}
	now := time.Now().Unix()
	if row.used || row.projection.GrantExpiresAt <= now {
		return OAuthGrant{}, ErrNotFound
	}
	return oauthGrantView(row.projection, false, now), nil
}

type oauthManagedGrantRow struct {
	projection oauthManagedGrant
	family     string
	used       bool
}

func (s *Store) getOAuthManagedGrant(ctx context.Context, id string) (oauthManagedGrantRow, error) {
	var row oauthManagedGrantRow
	var data []byte
	err := s.db.QueryRowContext(ctx, `SELECT data,family,used FROM mcp_oauth WHERE key=? AND kind=? AND expires>?`, oauthManagementKey("oauth-managed-grant", id), oauthManagedGrantKind, time.Now().Unix()).Scan(&data, &row.family, &row.used)
	if errors.Is(err, sql.ErrNoRows) {
		return row, ErrNotFound
	}
	if err != nil {
		return row, err
	}
	row.projection, err = decodeOAuthManagedGrant(data)
	if err != nil {
		return row, err
	}
	if row.projection.ManagementID != id || row.family == "" {
		return row, ErrNotFound
	}
	return row, nil
}

// RevokeOAuthGrant resolves and claims one currently active management record,
// then uses the same family tombstone transaction as every other OAuth revoke.
func (s *Store) RevokeOAuthGrant(ctx context.Context, id string) error {
	if id == "" {
		return ErrNotFound
	}
	row, err := s.getOAuthManagedGrant(ctx, id)
	if err != nil {
		return err
	}
	now := time.Now()
	if row.used || row.projection.GrantExpiresAt <= now.Unix() {
		return ErrNotFound
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	key := oauthManagementKey("oauth-managed-grant", id)
	tombstoneExpires := now.Add(oauthFamilyTombstoneLifetime).Unix()
	// Claim the selected row with the write that acquires SQLite's writer lock.
	// Reading inside a deferred transaction first would make a simultaneous
	// token exchange hit SQLITE_BUSY while upgrading that read transaction.
	claimed, err := tx.ExecContext(ctx, `UPDATE mcp_oauth SET used=1, expires=? WHERE key=? AND kind=? AND used=0 AND expires>? AND NOT EXISTS (SELECT 1 FROM mcp_oauth WHERE kind=? AND family=?)`, tombstoneExpires, key, oauthManagedGrantKind, now.Unix(), oauthRevokedKind, row.family)
	if err != nil {
		return err
	}
	if n, err := claimed.RowsAffected(); err != nil {
		return err
	} else if n != 1 {
		return ErrNotFound
	}
	if err := revokeOAuthFamilyTx(ctx, tx, row.family, now); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) RevokeOAuthFamily(ctx context.Context, family string) error {
	if family == "" {
		return errors.New("empty OAuth family")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := revokeOAuthFamilyTx(ctx, tx, family, time.Now()); err != nil {
		return err
	}
	return tx.Commit()
}

// revokeOAuthFamilyTx is the single family invalidation primitive. The caller
// must hold the transaction until no credential can be inserted after the
// tombstone or remain live in the selected family.
func revokeOAuthFamilyTx(ctx context.Context, tx *sql.Tx, family string, now time.Time) error {
	if family == "" {
		return errors.New("empty OAuth family")
	}
	tombstoneExpires := now.Add(oauthFamilyTombstoneLifetime).Unix()
	if _, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO mcp_oauth(key,kind,data,expires,family,used) VALUES (?, ?, '{}', ?, ?, 1)`, "revoked:"+family, oauthRevokedKind, tombstoneExpires, family); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE mcp_oauth SET used=1, expires=CASE WHEN kind=? THEN ? ELSE expires END WHERE family=?`, oauthManagedGrantKind, tombstoneExpires, family); err != nil {
		return err
	}
	return nil
}
