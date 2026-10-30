package apikeycredential

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/systemothersettings"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

const digestDomain = "cdnca-control-api/api-key/digest/v1\x00"

var (
	ErrInvalidConfig     = errors.New("API key credential verifier configuration invalid")
	ErrInvalidCredential = errors.New("API key credential invalid")
	ErrProtocolRequired  = errors.New("IAM global lock protocol required")
	ErrUnavailable       = errors.New("API key credential verifier unavailable")
	keyIDPattern         = regexp.MustCompile(`^cfk_[A-Za-z0-9_-]{22}$`)
	permissionPattern    = regexp.MustCompile(`^[a-z][a-z0-9_.-]{0,127}$`)
)

type Clock func() time.Time

type Verifier struct {
	keyring     PepperKeyring
	dummyDigest [32]byte
	now         Clock
	denials     DenialRecorder
}

// Credential is a sealed result of secret verification and locked PostgreSQL fact checks.
type Credential struct {
	id        uuid.UUID
	userID    uuid.UUID
	scopeID   uuid.UUID
	tenantID  uuid.UUID
	revision  int64
	createdAt time.Time
	expiresAt time.Time
	scopes    []string
}

func NewVerifier(pepper []byte, now Clock) (*Verifier, error) {
	return NewVerifierWithDenials(pepper, now, nil)
}

func NewVerifierWithDenials(pepper []byte, now Clock, denials DenialRecorder) (*Verifier, error) {
	keyring, err := NewPepperKeyring(PepperKeyringConfig{
		ActiveVersion: LegacyPepperVersion,
		Active:        pepper,
	})
	if err != nil {
		return nil, err
	}
	return NewVerifierWithKeyring(keyring, now, denials)
}

func NewVerifierWithKeyring(keyring PepperKeyring, now Clock, denials DenialRecorder) (*Verifier, error) {
	if !keyring.Configured() || now == nil {
		return nil, ErrInvalidConfig
	}
	verifier := &Verifier{keyring: keyring, now: now, denials: denials}
	_, verifier.dummyDigest, _ = keyring.SignActive(
		digestDomain, []byte("cfk_AAAAAAAAAAAAAAAAAAAAAA"), []byte{0}, []byte("invalid-placeholder-secret"),
	)
	return verifier, nil
}

// Configured reports whether NewVerifier initialized the verifier's in-memory dependencies.
// It does not check dependency health.
func (verifier *Verifier) Configured() bool {
	return verifier != nil && verifier.keyring.Configured() && verifier.now != nil
}

func (verifier *Verifier) VerifyTx(
	ctx context.Context,
	tx pgx.Tx,
	rawCredential string,
	targetScopeID uuid.UUID,
	lockedScopes []uuid.UUID,
) (Credential, error) {
	if verifier == nil || !verifier.keyring.Configured() || verifier.now == nil || tx == nil ||
		targetScopeID == uuid.Nil || !containsScope(lockedScopes, targetScopeID) {
		return Credential{}, ErrInvalidCredential
	}
	keyID, secret, ok := parseCredential(rawCredential)
	if !ok {
		return Credential{}, ErrInvalidCredential
	}
	if _, err := tx.Exec(ctx, `SELECT iam_assert_scope_locks_v1($1::uuid[])`, lockedScopes); err != nil {
		return Credential{}, fmt.Errorf("%w: assert API key credential locks", ErrProtocolRequired)
	}
	enabled, err := systemothersettings.APIKeyEnabled(ctx, tx)
	if err != nil {
		return Credential{}, fmt.Errorf("%w: read platform API key status", ErrUnavailable)
	}
	if !enabled {
		return Credential{}, ErrInvalidCredential
	}

	var keyIDUUID, userID, scopeID, tenantID uuid.UUID
	err = tx.QueryRow(ctx, `SELECT id,user_id,scope_id,tenant_id FROM api_keys WHERE key_id=$1`, keyID).Scan(
		&keyIDUUID, &userID, &scopeID, &tenantID)
	if errors.Is(err, pgx.ErrNoRows) {
		_, dummy, _ := verifier.keyring.SignActive(digestDomain, []byte(keyID), []byte{0}, []byte(secret))
		_ = hmac.Equal(dummy[:], verifier.dummyDigest[:])
		return Credential{}, ErrInvalidCredential
	}
	if err != nil {
		return Credential{}, fmt.Errorf("%w: locate API key credential", ErrUnavailable)
	}
	if scopeID != targetScopeID || tenantID == uuid.Nil || userID == uuid.Nil || keyIDUUID == uuid.Nil {
		return Credential{}, ErrInvalidCredential
	}

	var scopeKind string
	var scopeTenantID *uuid.UUID
	if err := tx.QueryRow(ctx, `SELECT kind,tenant_id FROM access_scopes
		WHERE id=$1 FOR KEY SHARE`, scopeID).Scan(&scopeKind, &scopeTenantID); err != nil {
		return Credential{}, credentialFactError(err)
	}
	if scopeKind != "tenant" || scopeTenantID == nil || *scopeTenantID != tenantID {
		return Credential{}, ErrInvalidCredential
	}
	var tenantStatus, userStatus, membershipStatus string
	if err := tx.QueryRow(ctx, `SELECT status FROM tenants WHERE id=$1 FOR SHARE`, tenantID).Scan(&tenantStatus); err != nil {
		return Credential{}, credentialFactError(err)
	}
	if err := tx.QueryRow(ctx, `SELECT status FROM users WHERE id=$1 FOR SHARE`, userID).Scan(&userStatus); err != nil {
		return Credential{}, credentialFactError(err)
	}
	if err := tx.QueryRow(ctx, `SELECT status FROM memberships
		WHERE scope_id=$1 AND user_id=$2 FOR SHARE`, scopeID, userID).Scan(&membershipStatus); err != nil {
		return Credential{}, credentialFactError(err)
	}

	var status, pepperVersion string
	var expiresAt *time.Time
	var storedDigest []byte
	var scopes []string
	var ipAllowlist []string
	var revision int64
	var createdAt time.Time
	if err := tx.QueryRow(ctx, `SELECT status,expires_at,secret_digest,pepper_version,scopes,ip_allowlist,revision,created_at
		FROM api_keys
		WHERE id=$1 AND key_id=$2 AND user_id=$3 AND scope_id=$4 AND tenant_id=$5
		FOR SHARE`, keyIDUUID, keyID, userID, scopeID, tenantID).Scan(
		&status, &expiresAt, &storedDigest, &pepperVersion, &scopes, &ipAllowlist, &revision, &createdAt); err != nil {
		return Credential{}, credentialFactError(err)
	}
	computed, ok := verifier.keyring.Sign(
		pepperVersion, digestDomain, []byte(keyID), []byte{0}, []byte(secret),
	)
	if !ok {
		_, fallback, _ := verifier.keyring.SignActive(digestDomain, []byte(keyID), []byte{0}, []byte(secret))
		_ = hmac.Equal(fallback[:], storedDigest)
		return Credential{}, ErrInvalidCredential
	}
	if !hmac.Equal(computed[:], storedDigest) {
		return Credential{}, ErrInvalidCredential
	}
	now := verifier.now().UTC()
	if status != "active" || tenantStatus != "active" || userStatus != "active" ||
		membershipStatus != "active" || revision < 1 || createdAt.IsZero() ||
		expiresAt != nil && !now.Before(*expiresAt) {
		return Credential{}, ErrInvalidCredential
	}
	canonicalScopes, ok := canonicalPermissions(scopes)
	if !ok {
		return Credential{}, ErrInvalidCredential
	}
	clientIP, reasonCode := enforceIPAllowlist(ctx, ipAllowlist)
	if reasonCode != "" {
		fact, _ := clientIPFactFromContext(ctx)
		if verifier.denials != nil {
			_ = verifier.denials.Record(ctx, Denial{
				ScopeID: scopeID, ActorUserID: userID, KeyID: keyIDUUID,
				RequestID: fact.requestID, ClientIP: clientIP,
				IPAllowlist: append([]string(nil), ipAllowlist...), ReasonCode: reasonCode,
			})
		}
		return Credential{}, ErrInvalidCredential
	}
	credential := Credential{
		id: keyIDUUID, userID: userID, scopeID: scopeID, tenantID: tenantID,
		revision: revision, createdAt: createdAt.UTC(), scopes: canonicalScopes,
	}
	if expiresAt != nil {
		credential.expiresAt = expiresAt.UTC()
	}
	if !credential.Valid() {
		return Credential{}, ErrInvalidCredential
	}
	return credential, nil
}

func (credential Credential) ID() uuid.UUID        { return credential.id }
func (credential Credential) UserID() uuid.UUID    { return credential.userID }
func (credential Credential) ScopeID() uuid.UUID   { return credential.scopeID }
func (credential Credential) TenantID() uuid.UUID  { return credential.tenantID }
func (credential Credential) Revision() int64      { return credential.revision }
func (credential Credential) CreatedAt() time.Time { return credential.createdAt }
func (credential Credential) ExpiresAt() time.Time { return credential.expiresAt }
func (credential Credential) Scopes() []string     { return append([]string(nil), credential.scopes...) }

func (credential Credential) Allows(permission string) bool {
	index := sort.SearchStrings(credential.scopes, permission)
	return index < len(credential.scopes) && credential.scopes[index] == permission
}

func (credential Credential) Valid() bool {
	return credential.id != uuid.Nil && credential.userID != uuid.Nil && credential.scopeID != uuid.Nil &&
		credential.tenantID != uuid.Nil && credential.revision >= 1 && !credential.createdAt.IsZero() &&
		len(credential.scopes) > 0 && (credential.expiresAt.IsZero() || credential.createdAt.Before(credential.expiresAt))
}

func (Credential) String() string   { return "apikeycredential.Credential{redacted}" }
func (Credential) GoString() string { return "apikeycredential.Credential{redacted}" }

func (Credential) MarshalJSON() ([]byte, error) {
	return nil, errors.New("API key credential serialization forbidden")
}

func parseCredential(raw string) (string, string, bool) {
	if raw == "" || len(raw) > 256 || raw != strings.TrimSpace(raw) {
		return "", "", false
	}
	keyID, secret, found := strings.Cut(raw, ".")
	if !found || strings.Contains(secret, ".") || !keyIDPattern.MatchString(keyID) {
		return "", "", false
	}
	decoded, err := base64.RawURLEncoding.DecodeString(secret)
	if err != nil || len(decoded) != sha256.Size {
		return "", "", false
	}
	return keyID, secret, true
}

func canonicalPermissions(values []string) ([]string, bool) {
	// 与 api_keys.scopes CHECK（迁移 574）一致。
	if len(values) < 1 || len(values) > 128 {
		return nil, false
	}
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		if !permissionPattern.MatchString(value) {
			return nil, false
		}
		if _, exists := seen[value]; exists {
			return nil, false
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	sort.Strings(result)
	return result, true
}

func credentialFactError(err error) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrInvalidCredential
	}
	return fmt.Errorf("%w: read API key credential facts", ErrUnavailable)
}

func containsScope(scopes []uuid.UUID, wanted uuid.UUID) bool {
	for _, scopeID := range scopes {
		if scopeID == wanted {
			return true
		}
	}
	return false
}

var _ json.Marshaler = Credential{}
