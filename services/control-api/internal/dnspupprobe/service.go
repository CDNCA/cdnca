package dnspupprobe

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/notification"
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

// FeatureReader is entitlementguard.Guard.ReadValidFeatures.
type FeatureReader interface {
	ReadValidFeatures(ctx context.Context, tx pgx.Tx) (map[string]bool, error)
}

// AlertEnqueuer is notification.Store's transactional enqueue.
type AlertEnqueuer interface {
	EnqueueTx(context.Context, pgx.Tx, notification.EnqueueRequest) (notification.EnqueueResult, error)
}

type Config struct {
	Pool     *pgxpool.Pool
	Cipher   SecretCipher
	Features FeatureReader
	Alerts   AlertEnqueuer // nil: degrade is recorded, not notified
	// Transport is the dnspup HTTP transport (nil: default; tests: fake).
	Transport http.RoundTripper
	Now       func() time.Time
	Logger    *slog.Logger
}

// Service is the plugin: settings page, connection test, and the probe
// source the origin failover and aggregated edge runners ask.
type Service struct {
	config  Config
	auditor *audit.Log

	mu     sync.Mutex
	prober *Prober
	loaded int64 // settings revision the prober was built for (-1: none)
}

func New(config Config) (*Service, error) {
	if config.Pool == nil || config.Cipher == nil || config.Features == nil {
		return nil, ErrInvalidInput
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	if config.Logger == nil {
		config.Logger = slog.Default()
	}
	return &Service{config: config, auditor: audit.NewWithClock(config.Pool, config.Now), loaded: -1}, nil
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
	Enabled                    bool
	BaseURL, APIKey            string
	KeyID                      *string
	Ciphertext                 []byte
	Fingerprint, SourceDomain  string
	OriginSources, EdgeSources []string
	Revision                   int64
	UpdatedAt                  time.Time
}

type queryRower interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

func readSettings(ctx context.Context, db queryRower, lock bool) (stored, error) {
	statement := `SELECT enabled,base_url,api_key,secret_key_id,secret_ciphertext,secret_fingerprint,source_domain,
		origin_sources,edge_sources,revision,updated_at FROM probe_dnspup_settings WHERE singleton`
	if lock {
		statement += " FOR UPDATE"
	}
	var value stored
	err := db.QueryRow(ctx, statement).Scan(&value.Enabled, &value.BaseURL, &value.APIKey, &value.KeyID, &value.Ciphertext,
		&value.Fingerprint, &value.SourceDomain, &value.OriginSources, &value.EdgeSources, &value.Revision, &value.UpdatedAt)
	return value, err
}

// sameEndpoint: a stored secret is only sent again to the base URL host and
// API key it was entered for.
func sameEndpoint(value stored, baseURL, apiKey string) bool {
	if value.APIKey == "" || value.APIKey != apiKey {
		return false
	}
	before, errBefore := ValidBaseURL(value.BaseURL)
	after, errAfter := ValidBaseURL(baseURL)
	return errBefore == nil && errAfter == nil && strings.EqualFold(before.Scheme, after.Scheme) &&
		strings.EqualFold(before.Host, after.Host)
}

// validSources: a non-empty ordered subset of allowed without repeats.
func validSources(values, allowed []string) bool {
	if len(values) == 0 || len(values) > len(allowed) {
		return false
	}
	seen := map[string]bool{}
	for _, value := range values {
		if !slices.Contains(allowed, value) || seen[value] {
			return false
		}
		seen[value] = true
	}
	return true
}

func normalize(input *SettingsInput) error {
	input.BaseURL, input.APIKey = strings.TrimSpace(input.BaseURL), strings.TrimSpace(input.APIKey)
	input.SourceDomain = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(input.SourceDomain), "."))
	if input.BaseURL == "" {
		input.BaseURL = DefaultBaseURL
	}
	parsed, err := ValidBaseURL(input.BaseURL)
	if err != nil {
		return ErrInvalidInput
	}
	input.BaseURL = parsed.String()
	if input.APISecret != nil {
		trimmed := strings.TrimSpace(*input.APISecret)
		input.APISecret = &trimmed
	}
	if input.APIKey != "" && !ValidCredential(input.APIKey, 8) ||
		input.APISecret != nil && *input.APISecret != "" && !ValidCredential(*input.APISecret, 16) {
		return ErrInvalidInput
	}
	if len(input.SourceDomain) > 253 || input.SourceDomain != "" && (!strings.Contains(input.SourceDomain, ".") ||
		strings.IndexFunc(input.SourceDomain, func(r rune) bool {
			return !(r == '.' || r == '-' || r >= 'a' && r <= 'z' || r >= '0' && r <= '9')
		}) >= 0) {
		return ErrInvalidInput
	}
	if input.OriginSources == nil {
		input.OriginSources = DefaultOriginSources
	}
	if input.EdgeSources == nil {
		input.EdgeSources = DefaultEdgeSources
	}
	if !validSources(input.OriginSources, DefaultOriginSources) || !validSources(input.EdgeSources, DefaultEdgeSources) {
		return ErrInvalidInput
	}
	return nil
}

// --- authentication, idempotency ---

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
	err := tx.QueryRow(ctx, `SELECT request_digest_sha256,response_body FROM probe_dnspup_write_requests
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
	_, err := tx.Exec(ctx, `INSERT INTO probe_dnspup_write_requests(actor_session_id,idempotency_key,operation,
		request_digest_sha256,response_body,created_at) VALUES($1,$2,$3,$4,$5,$6)`,
		actor.SessionID, key, operation, digest[:], body, now)
	return err
}

func validKey(key string) bool {
	if key == "" || len(key) > 128 {
		return false
	}
	for index, r := range key {
		alnum := r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z' || r >= '0' && r <= '9'
		if !alnum && (index == 0 || r != '.' && r != '_' && r != '-') {
			return false
		}
	}
	return true
}

func (service *Service) licensed(ctx context.Context, tx pgx.Tx) (bool, error) {
	features, err := service.config.Features.ReadValidFeatures(ctx, tx)
	if err != nil {
		return false, err
	}
	return features[Feature], nil
}

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
		ResourceType: "probe_dnspup", ResourceID: "probe_dnspup", RequestID: action + "." + uuid.NewString(),
		Result: result, Payload: payload})
}

func (service *Service) recordFailure(ctx context.Context, actor Actor, action string, err error, payload map[string]any) {
	if errors.Is(err, ErrUnauthenticated) || actor.ScopeID == uuid.Nil {
		return
	}
	payload["reason_code"] = reasonCode(err)
	ctx = context.WithoutCancel(ctx)
	if auditErr := pgx.BeginFunc(ctx, service.config.Pool, func(tx pgx.Tx) error {
		return service.appendAudit(ctx, tx, &actor, action, "failure", payload)
	}); auditErr != nil {
		service.config.Logger.Warn("dnspup probe audit failed", "action", action, "error", auditErr)
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
	default:
		return "internal_error"
	}
}
