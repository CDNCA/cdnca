// Package acmecacredentials holds the installation's External Account
// Binding credentials for ACME CAs that require them (RFC 8555 §7.3.4:
// ZeroSSL, Google Trust Services).
//
// The HMAC key is sealed with the DNS credential keyring (the same KEK and
// rotation as DNS API credentials) and is never returned: a read shows the
// key ID, whether a key is set and the first 8 hex digits of its SHA-256.
// A CA's directory is fixed per CA; only the credentials are configured.
package acmecacredentials

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// CAs that need External Account Binding, with their production ACME
// directories.
const (
	CAZeroSSL     = "zerossl"
	CAGoogleTrust = "google_trust"
)

var directories = map[string]string{
	CAZeroSSL:     "https://acme.zerossl.com/v2/DV90",
	CAGoogleTrust: "https://dv.acme-v02.api.pki.goog/directory",
}

// Directory is the ACME directory of an EAB CA ("" for unknown).
func Directory(ca string) string { return directories[ca] }

var (
	ErrInvalidInput     = errors.New("acme_ca_credentials_invalid")
	ErrPermissionDenied = errors.New("acme_ca_credentials_permission_denied")
	ErrRevisionConflict = errors.New("acme_ca_credentials_revision_conflict")
	ErrNotConfigured    = errors.New("acme_ca_credentials_not_configured")
	ErrUnavailable      = errors.New("acme_ca_credentials_unavailable")
)

const (
	permissionRead   = "system_configuration.read"
	permissionManage = "system_configuration.manage"
	auditAction      = "acme.ca_credential.update"
	maxHMACKeyBytes  = 512
)

var keyIDPattern = regexp.MustCompile(`^[A-Za-z0-9._:/+=-]{1,256}$`)

// Cipher seals the HMAC key (dnsacme.AESGCMCredentialCipher).
type Cipher interface {
	Encrypt([]byte) (keyID string, ciphertext []byte, err error)
	Decrypt(keyID string, ciphertext []byte) ([]byte, error)
}

type Actor struct {
	UserID, ScopeID uuid.UUID
	ScopeKind       string
}

// View is what a read returns for one CA: never the HMAC key.
type View struct {
	CA            string     `json:"ca"`
	DirectoryURL  string     `json:"directory_url"`
	Configured    bool       `json:"configured"`
	KeyID         string     `json:"eab_key_id,omitempty"`
	HMACKeyPrefix string     `json:"eab_hmac_sha256_prefix,omitempty"`
	Revision      int64      `json:"revision"`
	UpdatedAt     *time.Time `json:"updated_at,omitempty"`
	UpdatedByUser *uuid.UUID `json:"updated_by_user_id,omitempty"`
}

// SaveRequest sets (KeyID and HMACKey) or clears (Clear) a CA's credentials.
// HMACKey is the base64url key the CA shows (padding optional).
type SaveRequest struct {
	CA               string
	ExpectedRevision int64
	KeyID            string
	HMACKey          string
	Clear            bool
	RequestID        string
}

// EAB is a CA's credential as the ACME worker uses it.
type EAB struct {
	KeyID string
	Key   []byte
}

type Store struct {
	pool    *pgxpool.Pool
	cipher  Cipher
	auditor *audit.Log
	now     func() time.Time
}

func NewStore(pool *pgxpool.Pool, cipher Cipher, auditor *audit.Log, now func() time.Time) (*Store, error) {
	if pool == nil || cipher == nil || auditor == nil || now == nil {
		return nil, ErrUnavailable
	}
	return &Store{pool: pool, cipher: cipher, auditor: auditor, now: now}, nil
}

// List returns both EAB CAs, configured or not.
func (s *Store) List(ctx context.Context, actor Actor) ([]View, error) {
	var result []View
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if err := authorize(ctx, tx, actor, permissionRead); err != nil {
			return err
		}
		for _, ca := range []string{CAZeroSSL, CAGoogleTrust} {
			view, err := readView(ctx, tx, actor.ScopeID, ca)
			if err != nil {
				return err
			}
			result = append(result, view)
		}
		return nil
	})
	return result, err
}

func readView(ctx context.Context, tx pgx.Tx, platform uuid.UUID, ca string) (View, error) {
	view := View{CA: ca, DirectoryURL: directories[ca]}
	var updatedAt time.Time
	var updatedBy uuid.UUID
	err := tx.QueryRow(ctx, `SELECT eab_key_id,eab_hmac_sha256_prefix,revision,updated_at,updated_by_user_id
		FROM acme_ca_credentials WHERE platform_scope_id=$1 AND ca=$2`, platform, ca).
		Scan(&view.KeyID, &view.HMACKeyPrefix, &view.Revision, &updatedAt, &updatedBy)
	if errors.Is(err, pgx.ErrNoRows) {
		return view, nil
	}
	if err != nil {
		return View{}, fmt.Errorf("read ACME CA credentials: %w", err)
	}
	view.Configured, view.UpdatedAt, view.UpdatedByUser = true, &updatedAt, &updatedBy
	return view, nil
}

// Save sets or clears one CA's credentials at ExpectedRevision (0 when none
// is stored) and audits it (the key ID and digest prefix, never the key).
func (s *Store) Save(ctx context.Context, actor Actor, request SaveRequest) (View, error) {
	key, err := validateSave(request)
	if err != nil {
		return View{}, err
	}
	defer clear(key)
	var result View
	err = pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if err := authorize(ctx, tx, actor, permissionManage); err != nil {
			return err
		}
		before, err := readView(ctx, tx, actor.ScopeID, request.CA)
		if err != nil {
			return err
		}
		if before.Revision != request.ExpectedRevision {
			return ErrRevisionConflict
		}
		now := s.now().UTC().Truncate(time.Microsecond)
		if request.Clear {
			if _, err := tx.Exec(ctx, `DELETE FROM acme_ca_credentials WHERE platform_scope_id=$1 AND ca=$2`,
				actor.ScopeID, request.CA); err != nil {
				return err
			}
			result = View{CA: request.CA, DirectoryURL: directories[request.CA]}
		} else {
			keyID, ciphertext, err := s.cipher.Encrypt(key)
			if err != nil {
				return fmt.Errorf("%w: seal EAB key", ErrUnavailable)
			}
			sum := sha256.Sum256(key)
			prefix := hex.EncodeToString(sum[:4])
			if _, err := tx.Exec(ctx, `INSERT INTO acme_ca_credentials(platform_scope_id,ca,directory_url,eab_key_id,
				eab_hmac_key_id,eab_hmac_ciphertext,eab_hmac_sha256_prefix,revision,updated_by_user_id,updated_at)
				VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
				ON CONFLICT (platform_scope_id,ca) DO UPDATE SET directory_url=EXCLUDED.directory_url,
				  eab_key_id=EXCLUDED.eab_key_id,eab_hmac_key_id=EXCLUDED.eab_hmac_key_id,
				  eab_hmac_ciphertext=EXCLUDED.eab_hmac_ciphertext,eab_hmac_sha256_prefix=EXCLUDED.eab_hmac_sha256_prefix,
				  revision=EXCLUDED.revision,updated_by_user_id=EXCLUDED.updated_by_user_id,updated_at=EXCLUDED.updated_at`,
				actor.ScopeID, request.CA, directories[request.CA], request.KeyID, keyID, ciphertext, prefix,
				before.Revision+1, actor.UserID, now); err != nil {
				return err
			}
			result = View{CA: request.CA, DirectoryURL: directories[request.CA], Configured: true, KeyID: request.KeyID,
				HMACKeyPrefix: prefix, Revision: before.Revision + 1, UpdatedAt: &now, UpdatedByUser: &actor.UserID}
		}
		return s.auditor.Append(ctx, tx, audit.Event{
			ScopeID: actor.ScopeID, ActorUserID: &actor.UserID, Action: auditAction,
			ResourceType: "acme_ca_credential", ResourceID: request.CA, RequestID: request.RequestID, Result: "success",
			Payload: map[string]any{"ca": request.CA, "changes": map[string]any{
				"eab_key_id":             map[string]any{"from": before.KeyID, "to": result.KeyID},
				"eab_hmac_sha256_prefix": map[string]any{"from": before.HMACKeyPrefix, "to": result.HMACKeyPrefix},
			}},
		})
	})
	if err != nil {
		return View{}, err
	}
	return result, nil
}

func validateSave(request SaveRequest) ([]byte, error) {
	if directories[request.CA] == "" || request.ExpectedRevision < 0 || request.RequestID == "" || len(request.RequestID) > 128 {
		return nil, ErrInvalidInput
	}
	if request.Clear {
		if request.KeyID != "" || request.HMACKey != "" {
			return nil, ErrInvalidInput
		}
		return nil, nil
	}
	if !keyIDPattern.MatchString(request.KeyID) {
		return nil, ErrInvalidInput
	}
	encoded := strings.TrimRight(strings.TrimSpace(request.HMACKey), "=")
	key, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		key, err = base64.RawStdEncoding.DecodeString(encoded)
	}
	if err != nil || len(key) < 16 || len(key) > maxHMACKeyBytes {
		clear(key)
		return nil, ErrInvalidInput
	}
	return key, nil
}

func authorize(ctx context.Context, tx pgx.Tx, actor Actor, permission string) error {
	if actor.UserID == uuid.Nil || actor.ScopeID == uuid.Nil || actor.ScopeKind != "platform" {
		return ErrPermissionDenied
	}
	var allowed bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS (
		SELECT 1 FROM access_scopes scope
		JOIN memberships membership ON membership.scope_id=scope.id AND membership.user_id=$2 AND membership.status='active'
		JOIN role_assignments assignment ON assignment.scope_id=scope.id AND assignment.user_id=$2
		JOIN role_permissions grant_row ON grant_row.role_id=assignment.role_id
		 AND grant_row.permission_name IN ($3,'platform.admin')
		WHERE scope.id=$1 AND scope.kind='platform' AND scope.tenant_id IS NULL)`,
		actor.ScopeID, actor.UserID, permission).Scan(&allowed); err != nil {
		return fmt.Errorf("authorize ACME CA credentials: %w", err)
	}
	if !allowed {
		return ErrPermissionDenied
	}
	return nil
}

// Resolver gives the ACME worker a directory's EAB (acmeworker.EABSource).
type Resolver struct {
	pool   *pgxpool.Pool
	cipher Cipher
}

func NewResolver(pool *pgxpool.Pool, cipher Cipher) (*Resolver, error) {
	if pool == nil || cipher == nil {
		return nil, ErrUnavailable
	}
	return &Resolver{pool: pool, cipher: cipher}, nil
}

// ExternalAccountBinding is the EAB of directoryURL, or found=false when the
// directory is not an EAB CA's or has no credentials.
func (r *Resolver) ExternalAccountBinding(ctx context.Context, directoryURL string) (string, []byte, bool, error) {
	var keyID, sealedKeyID string
	var ciphertext []byte
	err := r.pool.QueryRow(ctx, `SELECT credential.eab_key_id,credential.eab_hmac_key_id,credential.eab_hmac_ciphertext
		FROM acme_ca_credentials credential
		JOIN access_scopes scope ON scope.id=credential.platform_scope_id AND scope.kind='platform' AND scope.tenant_id IS NULL
		WHERE credential.directory_url=$1`, directoryURL).Scan(&keyID, &sealedKeyID, &ciphertext)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", nil, false, nil
	}
	if err != nil {
		return "", nil, false, fmt.Errorf("read ACME EAB: %w", err)
	}
	key, err := r.cipher.Decrypt(sealedKeyID, ciphertext)
	if err != nil {
		return "", nil, false, fmt.Errorf("%w: open EAB key", ErrUnavailable)
	}
	return keyID, key, true, nil
}

// DirectoryForIssuer is the directory new orders use for the configured
// issuer: the installation's own directory for lets_encrypt, the CA's for an
// EAB CA (which must have credentials).
func (r *Resolver) DirectoryForIssuer(ctx context.Context, tx pgx.Tx, issuer, defaultDirectory string) (string, error) {
	directory := directories[issuer]
	if directory == "" {
		return defaultDirectory, nil
	}
	configured, err := Configured(ctx, tx, issuer)
	if err != nil {
		return "", err
	}
	if !configured {
		return "", ErrNotConfigured
	}
	return directory, nil
}

// Querier is the read side of a pgx transaction or pool.
type Querier interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// Configured reports whether the platform holds EAB credentials for the CA
// (an issuer without its own directory, lets_encrypt, needs none).
func Configured(ctx context.Context, query Querier, issuer string) (bool, error) {
	if directories[issuer] == "" {
		return true, nil
	}
	var configured bool
	if err := query.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM acme_ca_credentials credential
		JOIN access_scopes scope ON scope.id=credential.platform_scope_id AND scope.kind='platform' AND scope.tenant_id IS NULL
		WHERE credential.ca=$1)`, issuer).Scan(&configured); err != nil {
		return false, fmt.Errorf("read ACME CA credentials: %w", err)
	}
	return configured, nil
}
