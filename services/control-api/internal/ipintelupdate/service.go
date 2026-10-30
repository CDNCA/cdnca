package ipintelupdate

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"strings"
	"time"

	"github.com/cdnca/cdnca/libs/entitlement/artifactcatalog"
	"github.com/cdnca/cdnca/libs/entitlement/ipintel/builder"
	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// SecretCipher is the control-api credential keyring
// (dnsacme.AESGCMCredentialCipher).
type SecretCipher interface {
	Encrypt([]byte) (keyID string, ciphertext []byte, err error)
	Decrypt(keyID string, ciphertext []byte) ([]byte, error)
}

// FeatureReader is entitlementguard.Guard.ReadValidFeatures (read-only:
// the worker checks the module before each pull).
type FeatureReader interface {
	ReadValidFeatures(ctx context.Context, tx pgx.Tx) (map[string]bool, error)
}

// Publisher stores a built library (artifactsync.Store).
type Publisher interface {
	LatestLocalRevision(ctx context.Context) (uint64, error)
	StoreLocalBuildTx(ctx context.Context, tx pgx.Tx, entry artifactcatalog.Entry, content []byte, payload map[string]any) error
}

// Config wires the service. Probe / Fetch hosts are whatever the operator
// configures; tests point them at an httptest server.
type Config struct {
	Pool      *pgxpool.Pool
	Cipher    SecretCipher
	Features  FeatureReader
	Publisher Publisher
	// OnPublished wakes the node artifact set distributor.
	OnPublished func()
	// MaxBytes bounds the compressed snapshot (0: builder default).
	MaxBytes int64
	Now      func() time.Time
	Logger   *slog.Logger
}

type Service struct {
	config  Config
	auditor *audit.Log
	wake    chan struct{}
}

func New(config Config) (*Service, error) {
	if config.Pool == nil || config.Cipher == nil || config.Features == nil || config.Publisher == nil {
		return nil, ErrInvalidInput
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	if config.Logger == nil {
		config.Logger = slog.Default()
	}
	return &Service{config: config, auditor: audit.NewWithClock(config.Pool, config.Now), wake: make(chan struct{}, 1)}, nil
}

func (service *Service) now() time.Time { return service.config.Now().UTC().Truncate(time.Second) }

// --- secrets ---

func secretDigest(secret string) string {
	sum := sha256.Sum256([]byte(secretDomain + "fingerprint\x00" + secret))
	return hex.EncodeToString(sum[:])
}

func (service *Service) seal(secret string) (string, []byte, error) {
	plaintext := []byte(secretDomain + secret)
	defer clear(plaintext)
	keyID, ciphertext, err := service.config.Cipher.Encrypt(plaintext)
	if err != nil {
		return "", nil, ErrSecretUnavailable
	}
	return keyID, ciphertext, nil
}

func (service *Service) open(keyID string, ciphertext []byte) (string, error) {
	plaintext, err := service.config.Cipher.Decrypt(keyID, ciphertext)
	if err != nil {
		return "", ErrSecretUnavailable
	}
	defer clear(plaintext)
	secret, ok := strings.CutPrefix(string(plaintext), secretDomain)
	if !ok || secret == "" {
		return "", ErrSecretUnavailable
	}
	return secret, nil
}

// --- stored settings ---

type stored struct {
	Enabled         bool
	URL             string
	APIKey          string
	KeyID           *string
	Ciphertext      []byte
	Fingerprint     string
	IntervalMinutes int
	AnchorMinute    int
	TimeZone        string
	Revision        int64
	UpdatedAt       time.Time
}

type queryRower interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

func readSettings(ctx context.Context, db queryRower, lock bool) (stored, error) {
	statement := `SELECT enabled,url,api_key,secret_key_id,secret_ciphertext,secret_fingerprint,interval_minutes,anchor_minute,
		time_zone,revision,updated_at FROM ip_intel_update_settings WHERE singleton`
	if lock {
		statement += " FOR UPDATE"
	}
	var value stored
	if err := db.QueryRow(ctx, statement).Scan(&value.Enabled, &value.URL, &value.APIKey, &value.KeyID, &value.Ciphertext,
		&value.Fingerprint, &value.IntervalMinutes, &value.AnchorMinute, &value.TimeZone, &value.Revision, &value.UpdatedAt); err != nil {
		return stored{}, fmt.Errorf("read ip intel update settings: %w", err)
	}
	return value, nil
}

// sameOrigin: a stored secret is only sent again to the URL origin and API
// key it was entered for.
func sameOrigin(value stored, rawURL, apiKey string) bool {
	if value.APIKey == "" || value.APIKey != apiKey {
		return false
	}
	before, errBefore := url.Parse(value.URL)
	after, errAfter := url.Parse(rawURL)
	return errBefore == nil && errAfter == nil && strings.EqualFold(before.Scheme, after.Scheme) &&
		strings.EqualFold(before.Host, after.Host)
}

func normalize(input *SettingsInput, schedule bool) error {
	input.URL, input.APIKey, input.TimeZone = strings.TrimSpace(input.URL), strings.TrimSpace(input.APIKey), strings.TrimSpace(input.TimeZone)
	if input.APISecret != nil {
		trimmed := strings.TrimSpace(*input.APISecret)
		input.APISecret = &trimmed
	}
	if len(input.URL) > maxURL {
		return ErrInvalidInput
	}
	if input.URL != "" {
		parsed, err := builder.ValidHTTPSourceURL(input.URL)
		if err != nil || parsed.RawQuery != "" {
			return ErrInvalidInput
		}
		input.URL = parsed.String()
	}
	if input.APIKey != "" && !builder.ValidHTTPSourceCredential(input.APIKey, 8) {
		return ErrInvalidInput
	}
	if input.APISecret != nil && *input.APISecret != "" && !builder.ValidHTTPSourceCredential(*input.APISecret, 16) {
		return ErrInvalidInput
	}
	if schedule {
		if _, ok := validSchedule(input.IntervalMinutes, input.AnchorMinute, input.TimeZone); !ok {
			return ErrInvalidInput
		}
	}
	return nil
}

// --- authentication, idempotency ---

// authenticate rechecks the session and permission inside tx.
func authenticate(ctx context.Context, tx pgx.Tx, actor Actor, now time.Time) error {
	if actor.UserID == uuid.Nil || actor.ScopeID == uuid.Nil || actor.SessionID == uuid.Nil {
		return ErrUnauthenticated
	}
	var authenticated, permitted bool
	err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM auth_sessions session
		JOIN users account ON account.id=session.user_id AND account.status='active'
		JOIN memberships membership ON membership.scope_id=session.scope_id AND membership.user_id=session.user_id AND membership.status='active'
		JOIN access_scopes scope ON scope.id=session.scope_id AND scope.kind='platform'
		WHERE session.id=$1 AND session.scope_id=$2 AND session.user_id=$3 AND session.revoked_at IS NULL
		AND session.replaced_by_id IS NULL AND session.expires_at>$4),
		EXISTS(SELECT 1 FROM role_assignments assignment JOIN role_permissions grant_row ON grant_row.role_id=assignment.role_id
		WHERE assignment.scope_id=$2 AND assignment.user_id=$3 AND grant_row.permission_name IN ($5,'platform.admin'))`,
		actor.SessionID, actor.ScopeID, actor.UserID, now, PermissionManage).Scan(&authenticated, &permitted)
	if err != nil {
		return err
	}
	if !authenticated {
		return ErrUnauthenticated
	}
	if !permitted {
		return ErrPermissionDenied
	}
	return nil
}

func requestDigest(parts ...any) [32]byte {
	encoded, _ := json.Marshal(parts)
	return sha256.Sum256(encoded)
}

func replay(ctx context.Context, tx pgx.Tx, actor Actor, key string, digest [32]byte) ([]byte, bool, error) {
	var storedDigest, body []byte
	err := tx.QueryRow(ctx, `SELECT request_digest_sha256,response_body FROM ip_intel_update_write_requests
		WHERE actor_session_id=$1 AND idempotency_key=$2`, actor.SessionID, key).Scan(&storedDigest, &body)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	if !bytes.Equal(storedDigest, digest[:]) {
		return nil, false, ErrIdempotency
	}
	return body, true, nil
}

func recordWrite(ctx context.Context, tx pgx.Tx, actor Actor, key, operation string, digest [32]byte, body []byte, now time.Time) error {
	_, err := tx.Exec(ctx, `INSERT INTO ip_intel_update_write_requests(actor_session_id,idempotency_key,operation,
		request_digest_sha256,response_body,created_at) VALUES($1,$2,$3,$4,$5,$6)`,
		actor.SessionID, key, operation, digest[:], body, now)
	return err
}

func (service *Service) licensed(ctx context.Context, tx pgx.Tx) (bool, error) {
	features, err := service.config.Features.ReadValidFeatures(ctx, tx)
	if err != nil {
		return false, fmt.Errorf("read lease features: %w", err)
	}
	return features[Feature], nil
}

// platformScope is the platform audit stream.
func platformScope(ctx context.Context, db queryRower) (uuid.UUID, error) {
	var scope uuid.UUID
	err := db.QueryRow(ctx, `SELECT id FROM access_scopes WHERE kind='platform' AND tenant_id IS NULL ORDER BY id LIMIT 1`).Scan(&scope)
	return scope, err
}

func (service *Service) appendAudit(ctx context.Context, tx pgx.Tx, actor *Actor, action, result string, payload map[string]any) error {
	scope := uuid.Nil
	var user *uuid.UUID
	if actor != nil {
		scope, user = actor.ScopeID, &actor.UserID
		payload["ip"] = actor.IP
	} else {
		var err error
		if scope, err = platformScope(ctx, tx); errors.Is(err, pgx.ErrNoRows) {
			return nil
		} else if err != nil {
			return err
		}
		payload["actor"], payload["ip"] = "system", ""
	}
	return service.auditor.Append(ctx, tx, audit.Event{ScopeID: scope, ActorUserID: user, Action: action,
		ResourceType: "ip_intel_update", ResourceID: "ip_intel_update", RequestID: action + "." + uuid.NewString(),
		Result: result, Payload: payload})
}

// recordFailure audits a refused operator write in its own transaction.
func (service *Service) recordFailure(ctx context.Context, actor Actor, action string, err error, payload map[string]any) {
	if errors.Is(err, ErrUnauthenticated) || actor.ScopeID == uuid.Nil {
		return
	}
	payload["reason_code"] = reasonCode(err)
	ctx = context.WithoutCancel(ctx)
	if auditErr := pgx.BeginFunc(ctx, service.config.Pool, func(tx pgx.Tx) error {
		return service.appendAudit(ctx, tx, &actor, action, "failure", payload)
	}); auditErr != nil {
		service.config.Logger.Warn("ip intel update audit failed", "action", action, "error", auditErr)
	}
}

func reasonCode(err error) string {
	switch {
	case errors.Is(err, ErrPermissionDenied):
		return "permission_denied"
	case errors.Is(err, ErrFeatureDenied):
		return "feature_not_licensed"
	case errors.Is(err, ErrIdempotency):
		return "idempotency_conflict"
	case errors.Is(err, ErrSecretRequired):
		return "secret_required"
	case errors.Is(err, ErrSecretUnavailable):
		return "credential_unavailable"
	case errors.Is(err, ErrInvalidInput):
		return "invalid_input"
	case errors.Is(err, ErrDisabled):
		return "disabled"
	default:
		return "internal_error"
	}
}

// Wake asks the worker to look now (settings changed, "check now").
func (service *Service) Wake() {
	select {
	case service.wake <- struct{}{}:
	default:
	}
}
