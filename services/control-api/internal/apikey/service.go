package apikey

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/cdnca/cdnca/services/control-api/internal/apikeycredential"
	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/iamlock/protocol"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/systemothersettings"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	LegacyPepperVersion = apikeycredential.LegacyPepperVersion
	secretDomain        = "cdnca-control-api/api-key/secret/v1\x00"
	digestDomain        = "cdnca-control-api/api-key/digest/v1\x00"
	requestDomain       = "cdnca-control-api/api-key/request/v1\x00"
	listCursorV1Domain  = "cdnca-control-api/api-key/list-cursor/v1\x00"
	listCursorV2Domain  = "cdnca-control-api/api-key/list-cursor/v2\x00"
	defaultPendingTTL   = 7 * 24 * time.Hour
	maxPendingTTL       = 30 * 24 * time.Hour
	maxCredentialTTL    = 366 * 24 * time.Hour
	listCursorTTL       = 15 * time.Minute
	defaultListLimit    = 50
	maxListLimit        = 100

	// maxKeyScopes 与 api_keys.scopes CHECK（迁移 574）一致：简单版"全部权限"密钥要能装下租户全部安全权限。
	maxKeyScopes = 128
)

var (
	keyIDPattern       = regexp.MustCompile(`^cfk_[A-Za-z0-9_-]{22}$`)
	scopePattern       = regexp.MustCompile(`^[a-z][a-z0-9_.-]{0,127}$`)
	idempotencyPattern = regexp.MustCompile(`^[A-Za-z0-9._-]{1,128}$`)
)

type Service struct {
	pool                *pgxpool.Pool
	auditor             *audit.Log
	pepper              apikeycredential.PepperKeyring
	dummyDigest         [32]byte
	now                 func() time.Time
	denials             apikeycredential.DenialRecorder
	pageList            func(context.Context, apiKeyPageStoreRequest) ([]Key, error)
	pageCount           func(context.Context, apiKeyPageStoreRequest) (int, error)
	pageTargetPrincipal func(context.Context, uuid.UUID, uuid.UUID) (identity.Principal, error)
}

type apiKeyPageStoreRequest struct {
	ScopeID        uuid.UUID
	UserID         uuid.UUID
	SnapshotAt     time.Time
	HasAfter       bool
	AfterCreatedAt time.Time
	AfterID        uuid.UUID
	Limit          int
	Offset         int
	Status         string
	Name           string
	KeyID          string
}

type apiKeyListCursor struct {
	Version        int       `json:"v"`
	Audience       string    `json:"aud"`
	ScopeID        uuid.UUID `json:"scope_id"`
	UserID         uuid.UUID `json:"user_id"`
	IssuedAt       time.Time `json:"issued_at"`
	ExpiresAt      time.Time `json:"expires_at"`
	SnapshotAt     time.Time `json:"snapshot_at"`
	AfterCreatedAt time.Time `json:"after_created_at"`
	AfterID        uuid.UUID `json:"after_id"`
	Limit          int       `json:"limit"`
	Status         string    `json:"status"`
	Name           string    `json:"name"`
	KeyID          string    `json:"key_id"`
}

type apiKeyListCursorV1 struct {
	Version        int       `json:"v"`
	Audience       string    `json:"aud"`
	ScopeID        uuid.UUID `json:"scope_id"`
	UserID         uuid.UUID `json:"user_id"`
	SnapshotAt     time.Time `json:"snapshot_at"`
	AfterCreatedAt time.Time `json:"after_created_at"`
	AfterID        uuid.UUID `json:"after_id"`
	Limit          int       `json:"limit"`
	Status         string    `json:"status"`
	Name           string    `json:"name"`
	KeyID          string    `json:"key_id"`
}

func NewService(pool *pgxpool.Pool, pepper []byte, now func() time.Time) *Service {
	keyring, _ := apikeycredential.NewPepperKeyring(apikeycredential.PepperKeyringConfig{
		ActiveVersion: LegacyPepperVersion,
		Active:        pepper,
	})
	return NewServiceWithPepperKeyring(pool, keyring, now)
}

func NewServiceWithPepperKeyring(
	pool *pgxpool.Pool,
	pepper apikeycredential.PepperKeyring,
	now func() time.Time,
) *Service {
	if now == nil {
		now = time.Now
	}
	service := &Service{pool: pool, pepper: pepper, now: now}
	if pool != nil {
		service.auditor = audit.New(pool)
		service.denials = apikeycredential.NewPostgresDenialRecorder(pool, now)
		service.pageList = service.readPage
		service.pageCount = service.countPage
		service.pageTargetPrincipal = service.targetPrincipal
	}
	_, service.dummyDigest, _ = pepper.SignActive(
		digestDomain, []byte("cfk_AAAAAAAAAAAAAAAAAAAAAA"), []byte{0}, []byte("invalid-placeholder-secret"),
	)
	return service
}

func requireAPIKeyEnabled(ctx context.Context, query systemothersettings.RowQuerier) error {
	enabled, err := systemothersettings.APIKeyEnabled(ctx, query)
	if err != nil {
		return ErrUnavailable
	}
	if !enabled {
		return ErrDisabled
	}
	return nil
}

func (s *Service) ListSelf(ctx context.Context, principal identity.Principal) ([]Key, error) {
	if err := requireSelf(principal); err != nil {
		return nil, err
	}
	target, err := s.resolvePageTarget(ctx, principal.ScopeID, principal.UserID)
	if err != nil {
		return nil, err
	}
	if !sameTenantPrincipal(principal, target) {
		return nil, ErrPermissionDenied
	}
	return s.listAllPages(ctx, "self", target.ScopeID, target.UserID)
}

func (s *Service) ListSelfPage(
	ctx context.Context,
	principal identity.Principal,
	input APIKeyListInput,
) (APIKeyListPage, error) {
	if err := requireSelf(principal); err != nil {
		return APIKeyListPage{}, err
	}
	normalized, err := normalizeAPIKeyListInput(input)
	if err != nil {
		return APIKeyListPage{}, err
	}
	target, err := s.resolvePageTarget(ctx, principal.ScopeID, principal.UserID)
	if err != nil {
		return APIKeyListPage{}, err
	}
	if !sameTenantPrincipal(principal, target) {
		return APIKeyListPage{}, ErrPermissionDenied
	}
	return s.listPage(ctx, "self", target.ScopeID, target.UserID, normalized)
}

func (s *Service) GetSelf(ctx context.Context, principal identity.Principal, id uuid.UUID) (Key, error) {
	if err := requireSelf(principal); err != nil {
		return Key{}, err
	}
	if id == uuid.Nil {
		return Key{}, ErrInvalidInput
	}
	return s.get(ctx, principal.ScopeID, principal.UserID, id)
}

func (s *Service) CreateSelf(ctx context.Context, principal identity.Principal, input CreateInput) (IssuedKey, error) {
	if err := requireSelf(principal); err != nil {
		return IssuedKey{}, err
	}
	now := s.now().UTC()
	if err := normalizeCreate(&input, now, principal.Permissions); err != nil || !s.available() {
		if !s.available() {
			return IssuedKey{}, ErrUnavailable
		}
		return IssuedKey{}, err
	}
	digest := s.requestDigest("self.create", struct {
		Name        string     `json:"name"`
		Scopes      []string   `json:"scopes"`
		IPAllowlist []string   `json:"ip_allowlist"`
		ExpiresAt   *time.Time `json:"expires_at"`
	}{input.Name, input.Scopes, input.IPAllowlist, input.ExpiresAt})
	return s.createActive(ctx, principal, principal.ScopeID, *principal.TenantID, principal.UserID, input, digest)
}

func (s *Service) UpdateSelf(ctx context.Context, principal identity.Principal, input UpdateInput) (Key, error) {
	if err := requireSelf(principal); err != nil {
		return Key{}, err
	}
	now := s.now().UTC()
	if input.ID == uuid.Nil || input.ExpectedRevision < 1 ||
		!validWriteMetadata(input.IdempotencyKey, input.RequestID) {
		return Key{}, ErrInvalidInput
	}
	create := CreateInput{
		Name: input.Name, Scopes: input.Scopes, IPAllowlist: input.IPAllowlist, ExpiresAt: input.ExpiresAt,
		IdempotencyKey: input.IdempotencyKey, RequestID: input.RequestID,
	}
	if err := normalizeCreate(&create, now, principal.Permissions); err != nil {
		return Key{}, err
	}
	input.Name, input.Scopes, input.IPAllowlist, input.ExpiresAt =
		create.Name, create.Scopes, create.IPAllowlist, create.ExpiresAt
	digest := s.requestDigest("self.update", struct {
		ID          uuid.UUID  `json:"id"`
		Revision    int64      `json:"revision"`
		Name        string     `json:"name"`
		Scopes      []string   `json:"scopes"`
		IPAllowlist []string   `json:"ip_allowlist"`
		ExpiresAt   *time.Time `json:"expires_at"`
	}{input.ID, input.ExpectedRevision, input.Name, input.Scopes, input.IPAllowlist, input.ExpiresAt})
	var result Key
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if _, err := protocol.BeginAuthorityMutation(
			ctx, tx, protocol.OperationAPIKeySelfUpdate, []uuid.UUID{principal.ScopeID},
		); err != nil {
			return err
		}
		writeID, replay, err := reserveWrite(ctx, tx, principal, principal.ScopeID, principal.UserID,
			"api_key.self.update", input.IdempotencyKey, digest)
		_ = writeID
		if err != nil {
			return err
		}
		if replay != nil {
			return json.Unmarshal(replay, &result)
		}
		err = scanKey(tx.QueryRow(ctx, `
			UPDATE api_keys
			SET name=$5, scopes=$6, ip_allowlist=$7, expires_at=$8, revision=revision+1, updated_at=$9
			WHERE id=$1 AND scope_id=$2 AND user_id=$3 AND revision=$4 AND status = 'active'
			RETURNING `+keyColumns,
			input.ID, principal.ScopeID, principal.UserID, input.ExpectedRevision,
			input.Name, input.Scopes, input.IPAllowlist, input.ExpiresAt, now), &result)
		if errors.Is(err, pgx.ErrNoRows) {
			return classifyKeyMiss(ctx, tx, principal.ScopeID, principal.UserID, input.ID, StatusActive)
		}
		if err != nil {
			return err
		}
		if err := s.appendAudit(ctx, tx, principal, principal.ScopeID, input.RequestID,
			"api_key.self.update", result, map[string]any{
				"scopes": result.Scopes, "ip_allowlist": result.IPAllowlist, "revision": result.Revision,
			}); err != nil {
			return err
		}
		return completeWrite(ctx, tx, principal, "api_key.self.update", input.IdempotencyKey, result.ID, result)
	})
	return result, err
}

func (s *Service) ActivateSelf(ctx context.Context, principal identity.Principal, input MutationInput) (IssuedKey, error) {
	return s.issueForSelf(ctx, principal, input, "api_key.self.activate", StatusPendingActivation)
}

func (s *Service) RotateSelf(ctx context.Context, principal identity.Principal, input MutationInput) (IssuedKey, error) {
	return s.issueForSelf(ctx, principal, input, "api_key.self.rotate", StatusActive)
}

func (s *Service) RevokeSelf(ctx context.Context, principal identity.Principal, input MutationInput) (Key, error) {
	if err := requireSelf(principal); err != nil {
		return Key{}, err
	}
	return s.revoke(ctx, principal, principal.ScopeID, principal.UserID, input, "api_key.self.revoke")
}

func (s *Service) AdminList(
	ctx context.Context,
	principal identity.Principal,
	targetScopeID, targetUserID uuid.UUID,
) ([]Key, error) {
	if err := requireAdmin(principal); err != nil || targetScopeID == uuid.Nil || targetUserID == uuid.Nil {
		return nil, ErrPermissionDenied
	}
	target, err := s.resolvePageTarget(ctx, targetScopeID, targetUserID)
	if err != nil {
		return nil, err
	}
	if target.ScopeID != targetScopeID {
		return nil, ErrPermissionDenied
	}
	return s.listAllPages(ctx, "admin", target.ScopeID, target.UserID)
}

func (s *Service) AdminListPage(
	ctx context.Context,
	principal identity.Principal,
	targetScopeID, targetUserID uuid.UUID,
	input APIKeyListInput,
) (APIKeyListPage, error) {
	if err := requireAdmin(principal); err != nil || targetScopeID == uuid.Nil || targetUserID == uuid.Nil {
		return APIKeyListPage{}, ErrPermissionDenied
	}
	normalized, err := normalizeAPIKeyListInput(input)
	if err != nil {
		return APIKeyListPage{}, err
	}
	target, err := s.resolvePageTarget(ctx, targetScopeID, targetUserID)
	if err != nil {
		return APIKeyListPage{}, err
	}
	if target.ScopeID != targetScopeID {
		return APIKeyListPage{}, ErrPermissionDenied
	}
	return s.listPage(ctx, "admin", target.ScopeID, target.UserID, normalized)
}

func (s *Service) AdminCreatePending(ctx context.Context, principal identity.Principal, input AdminCreateInput) (Key, error) {
	if err := requireAdmin(principal); err != nil {
		return Key{}, err
	}
	if input.TargetScopeID == uuid.Nil || input.TargetUserID == uuid.Nil {
		return Key{}, ErrPermissionDenied
	}
	if !s.available() {
		return Key{}, ErrUnavailable
	}
	target, err := s.targetPrincipal(ctx, input.TargetScopeID, input.TargetUserID)
	if err != nil {
		return Key{}, err
	}
	if target.ScopeID != input.TargetScopeID {
		return Key{}, ErrPermissionDenied
	}
	now := s.now().UTC()
	create := CreateInput{Name: input.Name, Scopes: input.Scopes, IPAllowlist: input.IPAllowlist, ExpiresAt: input.ExpiresAt,
		IdempotencyKey: input.IdempotencyKey, RequestID: input.RequestID}
	if err := normalizeCreate(&create, now, target.Permissions); err != nil {
		return Key{}, err
	}
	input.Name, input.Scopes, input.IPAllowlist, input.ExpiresAt =
		create.Name, create.Scopes, create.IPAllowlist, create.ExpiresAt
	if input.PendingTTL == 0 {
		input.PendingTTL = defaultPendingTTL
	}
	if input.PendingTTL < time.Hour || input.PendingTTL > maxPendingTTL {
		return Key{}, ErrInvalidInput
	}
	digest := s.requestDigest("admin.create_pending", struct {
		TargetScopeID uuid.UUID     `json:"target_scope_id"`
		TargetUserID  uuid.UUID     `json:"target_user_id"`
		Name          string        `json:"name"`
		Scopes        []string      `json:"scopes"`
		IPAllowlist   []string      `json:"ip_allowlist"`
		ExpiresAt     *time.Time    `json:"expires_at"`
		PendingTTL    time.Duration `json:"pending_ttl"`
	}{input.TargetScopeID, input.TargetUserID, input.Name, input.Scopes, input.IPAllowlist, input.ExpiresAt, input.PendingTTL})
	var result Key
	err = pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if _, err := protocol.BeginAuthorityMutation(
			ctx, tx, protocol.OperationAPIKeyAdminCreate, []uuid.UUID{principal.ScopeID, target.ScopeID},
		); err != nil {
			return err
		}
		_, replay, err := reserveWrite(ctx, tx, principal, target.ScopeID, target.UserID,
			"api_key.admin.create_pending", input.IdempotencyKey, digest)
		if err != nil {
			return err
		}
		if replay != nil {
			return json.Unmarshal(replay, &result)
		}
		if err := requireAPIKeyEnabled(ctx, tx); err != nil {
			return err
		}
		id, err := uuid.NewV7()
		if err != nil {
			return err
		}
		keyID, err := randomKeyID()
		if err != nil {
			return err
		}
		pendingExpires := now.Add(input.PendingTTL)
		err = scanKey(tx.QueryRow(ctx, `
			INSERT INTO api_keys (
				id, key_id, key_prefix, scope_id, tenant_id, user_id, name, scopes, ip_allowlist,
				status, pending_expires_at, expires_at, created_by_user_id, created_at, updated_at
			) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,'pending_activation',$10,$11,$12,$13,$13)
			RETURNING `+keyColumns,
			id, keyID, keyID+".", target.ScopeID, *target.TenantID, target.UserID,
			input.Name, input.Scopes, input.IPAllowlist, pendingExpires, input.ExpiresAt, principal.UserID, now), &result)
		if err != nil {
			return err
		}
		if err := s.appendAudit(ctx, tx, principal, target.ScopeID, input.RequestID,
			"api_key.admin.create_pending", result, map[string]any{
				"target_user_id": target.UserID, "scopes": result.Scopes,
				"ip_allowlist":       result.IPAllowlist,
				"pending_expires_at": pendingExpires,
			}); err != nil {
			return err
		}
		return completeWrite(ctx, tx, principal, "api_key.admin.create_pending", input.IdempotencyKey, result.ID, result)
	})
	return result, err
}

func (s *Service) AdminRevoke(ctx context.Context, principal identity.Principal, input AdminRevokeInput) (Key, error) {
	if err := requireAdmin(principal); err != nil || input.TargetScopeID == uuid.Nil || input.TargetUserID == uuid.Nil {
		return Key{}, ErrPermissionDenied
	}
	target, err := s.targetPrincipal(ctx, input.TargetScopeID, input.TargetUserID)
	if err != nil {
		return Key{}, err
	}
	if target.ScopeID != input.TargetScopeID {
		return Key{}, ErrPermissionDenied
	}
	return s.revoke(ctx, principal, target.ScopeID, target.UserID, MutationInput{
		ID: input.ID, ExpectedRevision: input.ExpectedRevision,
		IPAllowlist:    input.IPAllowlist,
		IdempotencyKey: input.IdempotencyKey, RequestID: input.RequestID,
	}, "api_key.admin.revoke")
}

func (s *Service) Authenticate(ctx context.Context, raw string) (identity.Principal, error) {
	principal, _, _, err := s.AuthenticateWithKeyID(ctx, raw)
	return principal, err
}

func (s *Service) AuthenticateWithKeyID(
	ctx context.Context,
	raw string,
) (identity.Principal, uuid.UUID, time.Time, error) {
	if !s.available() {
		return identity.Principal{}, uuid.Nil, time.Time{}, ErrInvalidCredential
	}
	keyID, secret, ok := parseCredential(raw)
	if !ok {
		return identity.Principal{}, uuid.Nil, time.Time{}, ErrInvalidCredential
	}
	if err := requireAPIKeyEnabled(ctx, s.pool); err != nil {
		if errors.Is(err, ErrDisabled) {
			return identity.Principal{}, uuid.Nil, time.Time{}, ErrInvalidCredential
		}
		return identity.Principal{}, uuid.Nil, time.Time{}, err
	}
	type credentialRecord struct {
		id               uuid.UUID
		status           string
		expiresAt        *time.Time
		pendingExpiresAt *time.Time
		digest           []byte
		pepperVersion    string
		principal        identity.Principal
		keyScopes        []string
		ipAllowlist      []string
		tenantStatus     string
		userStatus       string
		membershipStatus string
	}
	record := credentialRecord{principal: identity.Principal{Roles: []string{}, Permissions: []string{}}}
	err := s.pool.QueryRow(ctx, `
		SELECT k.id, k.status, k.expires_at, k.pending_expires_at, k.secret_digest, k.pepper_version,
		       k.user_id, k.scope_id, scope.kind, scope.tenant_id, u.username, u.display_name,
		       k.scopes, k.ip_allowlist, tenant.status, u.status, m.status,
		       COALESCE(array_agg(DISTINCT roles.name) FILTER (WHERE roles.name IS NOT NULL), '{}'::text[]),
		       COALESCE(array_agg(DISTINCT rp.permission_name) FILTER (WHERE rp.permission_name IS NOT NULL), '{}'::text[])
		FROM api_keys k
		JOIN access_scopes scope ON scope.id=k.scope_id
		JOIN tenants tenant ON tenant.id=scope.tenant_id
		JOIN users u ON u.id=k.user_id
		JOIN memberships m ON m.scope_id=k.scope_id AND m.user_id=k.user_id
		LEFT JOIN role_assignments ra ON ra.scope_id=k.scope_id AND ra.user_id=k.user_id
		LEFT JOIN roles ON roles.id=ra.role_id
		LEFT JOIN role_permissions rp ON rp.role_id=roles.id
		WHERE k.key_id=$1
		GROUP BY k.id, scope.kind, scope.tenant_id, tenant.status, u.username, u.display_name, u.status, m.status`, keyID,
	).Scan(
		&record.id, &record.status, &record.expiresAt, &record.pendingExpiresAt, &record.digest, &record.pepperVersion,
		&record.principal.UserID, &record.principal.ScopeID, &record.principal.ScopeKind,
		&record.principal.TenantID, &record.principal.Username, &record.principal.DisplayName,
		&record.keyScopes, &record.ipAllowlist, &record.tenantStatus, &record.userStatus, &record.membershipStatus,
		&record.principal.Roles, &record.principal.Permissions,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		_, computed, _ := s.pepper.SignActive(digestDomain, []byte(keyID), []byte{0}, []byte(secret))
		_ = hmac.Equal(computed[:], s.dummyDigest[:])
		return identity.Principal{}, uuid.Nil, time.Time{}, ErrInvalidCredential
	}
	if err != nil {
		return identity.Principal{}, uuid.Nil, time.Time{}, fmt.Errorf("load API key credential: %w", err)
	}
	computed, knownVersion := s.pepper.Sign(
		record.pepperVersion, digestDomain, []byte(keyID), []byte{0}, []byte(secret),
	)
	if !knownVersion {
		_, computed, _ = s.pepper.SignActive(digestDomain, []byte(keyID), []byte{0}, []byte(secret))
	}
	if !hmac.Equal(computed[:], record.digest) || !knownVersion {
		return identity.Principal{}, uuid.Nil, time.Time{}, ErrInvalidCredential
	}
	authenticatedAt := s.now().UTC()
	if record.status != StatusActive || record.principal.ScopeKind != "tenant" || record.tenantStatus != "active" ||
		record.userStatus != "active" || record.membershipStatus != "active" ||
		(record.expiresAt != nil && !authenticatedAt.Before(*record.expiresAt)) {
		return identity.Principal{}, uuid.Nil, time.Time{}, ErrInvalidCredential
	}
	current := make(map[string]struct{}, len(record.principal.Permissions))
	for _, permission := range record.principal.Permissions {
		current[permission] = struct{}{}
	}
	effective := make([]string, 0, len(record.keyScopes))
	for _, permission := range record.keyScopes {
		if _, exists := current[permission]; exists {
			effective = append(effective, permission)
		}
	}
	if len(effective) == 0 {
		return identity.Principal{}, uuid.Nil, time.Time{}, ErrInvalidCredential
	}
	clientIP, reasonCode := apikeycredential.EnforceIPAllowlist(ctx, record.ipAllowlist)
	if reasonCode != "" {
		if s.denials != nil {
			_ = s.denials.Record(ctx, apikeycredential.Denial{
				ScopeID: record.principal.ScopeID, ActorUserID: record.principal.UserID, KeyID: record.id,
				RequestID: apikeycredential.ClientIPRequestID(ctx), ClientIP: clientIP,
				IPAllowlist: append([]string(nil), record.ipAllowlist...), ReasonCode: reasonCode,
			})
		}
		return identity.Principal{}, uuid.Nil, time.Time{}, ErrInvalidCredential
	}
	record.principal.Permissions = effective
	return record.principal, record.id, authenticatedAt, nil
}

func (s *Service) createActive(
	ctx context.Context,
	principal identity.Principal,
	targetScopeID uuid.UUID,
	tenantID uuid.UUID,
	targetUserID uuid.UUID,
	input CreateInput,
	digest versionedRequestDigest,
) (IssuedKey, error) {
	var result IssuedKey
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if _, err := protocol.BeginAuthorityMutation(
			ctx, tx, protocol.OperationAPIKeySelfCreate, []uuid.UUID{targetScopeID},
		); err != nil {
			return err
		}
		writeID, replay, err := reserveWrite(ctx, tx, principal, targetScopeID, targetUserID,
			"api_key.self.create", input.IdempotencyKey, digest)
		if err != nil {
			return err
		}
		if replay != nil {
			if err := json.Unmarshal(replay, &result.Key); err != nil {
				return err
			}
			result.Secret, err = s.replaySecret(ctx, tx, writeID, result.Key)
			return err
		}
		if err := requireAPIKeyEnabled(ctx, tx); err != nil {
			return err
		}
		id, err := uuid.NewV7()
		if err != nil {
			return err
		}
		keyID, err := randomKeyID()
		if err != nil {
			return err
		}
		pepperVersion, secret, secretDigest, ok := s.deriveActiveSecret(writeID, keyID)
		if !ok {
			return ErrUnavailable
		}
		result.Secret = secret
		now := s.now().UTC()
		err = scanKey(tx.QueryRow(ctx, `
			INSERT INTO api_keys (
				id, key_id, key_prefix, scope_id, tenant_id, user_id, name, scopes, ip_allowlist,
				secret_digest, pepper_version, status, expires_at, activated_at, created_by_user_id, created_at, updated_at
			) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,'active',$12,$13,$14,$13,$13)
			RETURNING `+keyColumns,
			id, keyID, keyID+".", targetScopeID, tenantID, targetUserID, input.Name,
			input.Scopes, input.IPAllowlist, secretDigest[:], pepperVersion, input.ExpiresAt, now, principal.UserID), &result.Key)
		if err != nil {
			return err
		}
		if err := s.appendAudit(ctx, tx, principal, targetScopeID, input.RequestID,
			"api_key.self.create", result.Key, map[string]any{
				"scopes": result.Key.Scopes, "ip_allowlist": result.Key.IPAllowlist,
			}); err != nil {
			return err
		}
		return completeWrite(ctx, tx, principal, "api_key.self.create", input.IdempotencyKey, result.Key.ID, result.Key)
	})
	return result, err
}

func (s *Service) issueForSelf(
	ctx context.Context,
	principal identity.Principal,
	input MutationInput,
	operation string,
	requiredStatus string,
) (IssuedKey, error) {
	if err := requireSelf(principal); err != nil {
		return IssuedKey{}, err
	}
	if !s.available() {
		return IssuedKey{}, ErrUnavailable
	}
	if input.ID == uuid.Nil || input.ExpectedRevision < 1 || !validWriteMetadata(input.IdempotencyKey, input.RequestID) {
		return IssuedKey{}, ErrInvalidInput
	}
	allowlist, err := normalizeIPAllowlist(input.IPAllowlist)
	if err != nil {
		return IssuedKey{}, err
	}
	input.IPAllowlist = allowlist
	refreshedScopes, err := issuanceScopes(operation, input.GrantAllScopes, principal.Permissions)
	if err != nil {
		return IssuedKey{}, err
	}
	// grant_all_scopes 只在为 true 时进摘要，原有请求的幂等摘要不变。
	digest := s.requestDigest(operation, struct {
		ID             uuid.UUID `json:"id"`
		Revision       int64     `json:"revision"`
		IPAllowlist    []string  `json:"ip_allowlist"`
		GrantAllScopes bool      `json:"grant_all_scopes,omitempty"`
	}{input.ID, input.ExpectedRevision, input.IPAllowlist, input.GrantAllScopes})
	var result IssuedKey
	err = pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if _, err := protocol.BeginAuthorityMutation(
			ctx, tx, protocol.Operation(operation), []uuid.UUID{principal.ScopeID},
		); err != nil {
			return err
		}
		writeID, replay, err := reserveWrite(ctx, tx, principal, principal.ScopeID, principal.UserID,
			operation, input.IdempotencyKey, digest)
		if err != nil {
			return err
		}
		if replay != nil {
			if err := json.Unmarshal(replay, &result.Key); err != nil {
				return err
			}
			result.Secret, err = s.replaySecret(ctx, tx, writeID, result.Key)
			return err
		}
		if err := requireAPIKeyEnabled(ctx, tx); err != nil {
			return err
		}
		var current Key
		var pendingExpires *time.Time
		err = scanKey(tx.QueryRow(ctx, `SELECT `+keyColumns+` FROM api_keys
			WHERE id=$1 AND scope_id=$2 AND user_id=$3 FOR UPDATE`,
			input.ID, principal.ScopeID, principal.UserID), &current)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		pendingExpires = current.PendingExpiresAt
		if current.Revision != input.ExpectedRevision {
			return ErrRevisionConflict
		}
		now := s.now().UTC()
		if current.Status != requiredStatus ||
			(requiredStatus == StatusPendingActivation && (pendingExpires == nil || !now.Before(*pendingExpires))) ||
			(current.ExpiresAt != nil && !now.Before(*current.ExpiresAt)) {
			return ErrInvalidTransition
		}
		previousScopes := current.Scopes
		if refreshedScopes == nil {
			if err := validateScopes(current.Scopes, principal.Permissions); err != nil {
				return ErrPermissionDenied
			}
		}
		if !equalStrings(current.IPAllowlist, input.IPAllowlist) {
			return ErrRevisionConflict
		}
		pepperVersion, secret, secretDigest, ok := s.deriveActiveSecret(writeID, current.KeyID)
		if !ok {
			return ErrUnavailable
		}
		result.Secret = secret
		err = scanKey(tx.QueryRow(ctx, `
			UPDATE api_keys
			SET secret_digest=$5, pepper_version=$6, status='active', pending_expires_at=NULL,
			    activated_at=COALESCE(activated_at,$7), scopes=COALESCE($9::text[], scopes),
			    revision=revision+1, updated_at=$7
			WHERE id=$1 AND scope_id=$2 AND user_id=$3 AND revision=$4 AND ip_allowlist=$8
			RETURNING `+keyColumns,
			input.ID, principal.ScopeID, principal.UserID, input.ExpectedRevision,
			secretDigest[:], pepperVersion, now, input.IPAllowlist, refreshedScopes), &result.Key)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrRevisionConflict
		}
		if err != nil {
			return err
		}
		payload := map[string]any{"ip_allowlist": result.Key.IPAllowlist, "revision": result.Key.Revision}
		if refreshedScopes != nil {
			payload["scopes"] = result.Key.Scopes
			payload["changes"] = map[string]any{"scopes": map[string]any{"from": previousScopes, "to": result.Key.Scopes}}
		}
		if err := s.appendAudit(ctx, tx, principal, principal.ScopeID, input.RequestID,
			operation, result.Key, payload); err != nil {
			return err
		}
		return completeWrite(ctx, tx, principal, operation, input.IdempotencyKey, result.Key.ID, result.Key)
	})
	return result, err
}

func (s *Service) revoke(
	ctx context.Context,
	principal identity.Principal,
	targetScopeID uuid.UUID,
	targetUserID uuid.UUID,
	input MutationInput,
	operation string,
) (Key, error) {
	if input.ID == uuid.Nil || input.ExpectedRevision < 1 || !validWriteMetadata(input.IdempotencyKey, input.RequestID) {
		return Key{}, ErrInvalidInput
	}
	allowlist, err := normalizeIPAllowlist(input.IPAllowlist)
	if err != nil {
		return Key{}, err
	}
	input.IPAllowlist = allowlist
	digest := s.requestDigest(operation, struct {
		ID            uuid.UUID `json:"id"`
		TargetScopeID uuid.UUID `json:"target_scope_id"`
		TargetUserID  uuid.UUID `json:"target_user_id"`
		Revision      int64     `json:"revision"`
		IPAllowlist   []string  `json:"ip_allowlist"`
	}{input.ID, targetScopeID, targetUserID, input.ExpectedRevision, input.IPAllowlist})
	var result Key
	err = pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if _, err := protocol.BeginAuthorityMutation(
			ctx, tx, protocol.Operation(operation), []uuid.UUID{principal.ScopeID, targetScopeID},
		); err != nil {
			return err
		}
		_, replay, err := reserveWrite(ctx, tx, principal, targetScopeID, targetUserID,
			operation, input.IdempotencyKey, digest)
		if err != nil {
			return err
		}
		if replay != nil {
			return json.Unmarshal(replay, &result)
		}
		now := s.now().UTC()
		err = scanKey(tx.QueryRow(ctx, `
			UPDATE api_keys
			SET status='revoked', pending_expires_at=NULL, revoked_at=$6, revoked_by_user_id=$5,
			    revision=revision+1, updated_at=$6
			WHERE id=$1 AND scope_id=$2 AND user_id=$3 AND revision=$4
			  AND status <> 'revoked' AND ip_allowlist=$7
			RETURNING `+keyColumns,
			input.ID, targetScopeID, targetUserID, input.ExpectedRevision,
			principal.UserID, now, input.IPAllowlist), &result)
		if errors.Is(err, pgx.ErrNoRows) {
			return classifyKeyMiss(
				ctx, tx, targetScopeID, targetUserID, input.ID, StatusPendingActivation, StatusActive,
			)
		}
		if err != nil {
			return err
		}
		if err := s.appendAudit(ctx, tx, principal, targetScopeID, input.RequestID,
			operation, result, map[string]any{
				"target_user_id": targetUserID, "ip_allowlist": result.IPAllowlist,
				"revision": result.Revision,
			}); err != nil {
			return err
		}
		return completeWrite(ctx, tx, principal, operation, input.IdempotencyKey, result.ID, result)
	})
	return result, err
}

const keyColumns = `id, key_id, key_prefix, scope_id, tenant_id, user_id, name, scopes, ip_allowlist,
	status, pending_expires_at, expires_at, last_used_at, activated_at, revoked_at,
	revision, created_at, updated_at`

func (s *Service) listAllPages(ctx context.Context, audience string, scopeID, userID uuid.UUID) ([]Key, error) {
	input := APIKeyListInput{Limit: maxListLimit}
	items := make([]Key, 0)
	for {
		page, err := s.listPage(ctx, audience, scopeID, userID, input)
		if err != nil {
			return nil, err
		}
		items = append(items, page.Items...)
		if page.NextCursor == "" {
			return items, nil
		}
		input.Cursor = page.NextCursor
	}
}

func (s *Service) listPage(
	ctx context.Context,
	audience string,
	scopeID, userID uuid.UUID,
	input APIKeyListInput,
) (APIKeyListPage, error) {
	if s.pageList == nil || !s.pepper.Configured() {
		return APIKeyListPage{}, ErrUnavailable
	}
	now := s.now().UTC()
	request := apiKeyPageStoreRequest{
		ScopeID: scopeID, UserID: userID, SnapshotAt: now, Limit: input.Limit + 1, Offset: input.Offset,
		Status: input.Status, Name: input.Name, KeyID: input.KeyID,
	}
	issuedAt, expiresAt := now, now.Add(listCursorTTL)
	if input.Cursor != "" {
		cursor, err := s.decodeListCursor(input.Cursor, now)
		if err != nil || cursor.Audience != audience || cursor.ScopeID != scopeID || cursor.UserID != userID ||
			cursor.Limit != input.Limit || cursor.Status != input.Status || cursor.Name != input.Name || cursor.KeyID != input.KeyID {
			return APIKeyListPage{}, ErrInvalidInput
		}
		issuedAt, expiresAt = cursor.IssuedAt, cursor.ExpiresAt
		request.SnapshotAt = cursor.SnapshotAt
		request.HasAfter = true
		request.AfterCreatedAt = cursor.AfterCreatedAt
		request.AfterID = cursor.AfterID
	}
	items, err := s.pageList(ctx, request)
	if err != nil {
		return APIKeyListPage{}, err
	}
	if !validPageRows(request, items) {
		return APIKeyListPage{}, ErrUnavailable
	}
	page := APIKeyListPage{Items: append([]Key(nil), items...), SnapshotAt: request.SnapshotAt}
	// Total only on first/offset pages: one indexed count over a single
	// user's keys at the same snapshot, so the cost stays bounded.
	if input.Cursor == "" && s.pageCount != nil {
		total, err := s.pageCount(ctx, request)
		if err != nil {
			return APIKeyListPage{}, err
		}
		// Count and page are separate reads; a concurrent removal can make
		// the count lag the rows already returned, so never report fewer.
		if seen := input.Offset + min(len(items), input.Limit); len(items) > 0 && total < seen {
			total = seen
		}
		page.Total = &total
	}
	if len(page.Items) <= input.Limit {
		return page, nil
	}
	page.Items = page.Items[:input.Limit]
	last := page.Items[len(page.Items)-1]
	page.NextCursor, err = s.encodeListCursor(apiKeyListCursor{
		Version: 2, Audience: audience, ScopeID: scopeID, UserID: userID,
		IssuedAt: issuedAt, ExpiresAt: expiresAt,
		SnapshotAt: request.SnapshotAt, AfterCreatedAt: last.CreatedAt, AfterID: last.ID,
		Limit: input.Limit, Status: input.Status, Name: input.Name, KeyID: input.KeyID,
	})
	if err != nil {
		return APIKeyListPage{}, err
	}
	return page, nil
}

func (s *Service) readPage(ctx context.Context, request apiKeyPageStoreRequest) ([]Key, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+keyColumns+` FROM api_keys
		WHERE scope_id=$1 AND user_id=$2 AND created_at <= $3
		  AND (NOT $4 OR (created_at, id) < ($5, $6))
		  AND ($7 = '' OR status=$7)
		  AND ($8 = '' OR lower(name)=$8)
		  AND ($9 = '' OR key_id=$9)
		ORDER BY created_at DESC, id DESC LIMIT $10 OFFSET $11`,
		request.ScopeID, request.UserID, request.SnapshotAt,
		request.HasAfter, request.AfterCreatedAt, request.AfterID,
		request.Status, request.Name, request.KeyID, request.Limit, request.Offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]Key, 0, request.Limit)
	for rows.Next() {
		var item Key
		if err := scanKey(rows, &item); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *Service) countPage(ctx context.Context, request apiKeyPageStoreRequest) (int, error) {
	var total int
	err := s.pool.QueryRow(ctx, `SELECT count(*) FROM api_keys
		WHERE scope_id=$1 AND user_id=$2 AND created_at <= $3
		  AND ($4 = '' OR status=$4)
		  AND ($5 = '' OR lower(name)=$5)
		  AND ($6 = '' OR key_id=$6)`,
		request.ScopeID, request.UserID, request.SnapshotAt,
		request.Status, request.Name, request.KeyID).Scan(&total)
	return total, err
}

func (s *Service) resolvePageTarget(ctx context.Context, scopeID, userID uuid.UUID) (identity.Principal, error) {
	if s.pageTargetPrincipal == nil {
		return identity.Principal{}, ErrUnavailable
	}
	return s.pageTargetPrincipal(ctx, scopeID, userID)
}

func sameTenantPrincipal(left, right identity.Principal) bool {
	return left.UserID == right.UserID && left.ScopeID == right.ScopeID && left.ScopeKind == "tenant" &&
		right.ScopeKind == "tenant" && left.TenantID != nil && right.TenantID != nil && *left.TenantID == *right.TenantID
}

func normalizeAPIKeyListInput(input APIKeyListInput) (APIKeyListInput, error) {
	if input.Limit == 0 {
		input.Limit = defaultListLimit
	}
	if input.Limit < 1 || input.Limit > maxListLimit || len(input.Cursor) > 4096 ||
		input.Offset < 0 || input.Offset > MaxListOffset || input.Offset > 0 && input.Cursor != "" {
		return APIKeyListInput{}, ErrInvalidInput
	}
	input.Status = strings.ToLower(strings.TrimSpace(input.Status))
	if input.Status != "" && input.Status != StatusPendingActivation && input.Status != StatusActive && input.Status != StatusRevoked {
		return APIKeyListInput{}, ErrInvalidInput
	}
	rawName := input.Name
	input.Name = strings.ToLower(strings.TrimSpace(input.Name))
	if rawName != "" && input.Name == "" || !utf8.ValidString(input.Name) || utf8.RuneCountInString(input.Name) > 128 {
		return APIKeyListInput{}, ErrInvalidInput
	}
	input.KeyID = strings.TrimSpace(input.KeyID)
	if input.KeyID != "" && !keyIDPattern.MatchString(input.KeyID) {
		return APIKeyListInput{}, ErrInvalidInput
	}
	return input, nil
}

func validPageRows(request apiKeyPageStoreRequest, items []Key) bool {
	if len(items) > request.Limit {
		return false
	}
	for index := range items {
		item := items[index]
		if item.ScopeID != request.ScopeID || item.UserID != request.UserID || item.CreatedAt.After(request.SnapshotAt) ||
			request.Status != "" && item.Status != request.Status ||
			request.Name != "" && strings.ToLower(item.Name) != request.Name ||
			request.KeyID != "" && item.KeyID != request.KeyID {
			return false
		}
		if request.HasAfter && (item.CreatedAt.After(request.AfterCreatedAt) ||
			(item.CreatedAt.Equal(request.AfterCreatedAt) && bytes.Compare(item.ID[:], request.AfterID[:]) >= 0)) {
			return false
		}
		if index > 0 {
			previous := items[index-1]
			if item.CreatedAt.After(previous.CreatedAt) ||
				(item.CreatedAt.Equal(previous.CreatedAt) && bytes.Compare(item.ID[:], previous.ID[:]) >= 0) {
				return false
			}
		}
	}
	return true
}

func (s *Service) encodeListCursor(cursor apiKeyListCursor) (string, error) {
	payload, err := json.Marshal(cursor)
	if err != nil {
		return "", err
	}
	_, signature, ok := s.pepper.SignActive(listCursorV2Domain, payload)
	if !ok {
		return "", ErrUnavailable
	}
	return base64.RawURLEncoding.EncodeToString(payload) + "." +
		base64.RawURLEncoding.EncodeToString(signature[:]), nil
}

func (s *Service) decodeListCursor(value string, now time.Time) (apiKeyListCursor, error) {
	payloadText, signatureText, ok := strings.Cut(value, ".")
	if !ok || payloadText == "" || signatureText == "" || strings.Contains(signatureText, ".") {
		return apiKeyListCursor{}, ErrInvalidInput
	}
	payload, err := base64.RawURLEncoding.DecodeString(payloadText)
	if err != nil || base64.RawURLEncoding.EncodeToString(payload) != payloadText {
		return apiKeyListCursor{}, ErrInvalidInput
	}
	signature, err := base64.RawURLEncoding.DecodeString(signatureText)
	if err != nil || len(signature) != sha256.Size || base64.RawURLEncoding.EncodeToString(signature) != signatureText {
		return apiKeyListCursor{}, ErrInvalidInput
	}
	var version struct {
		Version int `json:"v"`
	}
	if json.Unmarshal(payload, &version) != nil {
		return apiKeyListCursor{}, ErrInvalidInput
	}
	domain := listCursorV2Domain
	if version.Version == 1 {
		domain = listCursorV1Domain
	} else if version.Version != 2 {
		return apiKeyListCursor{}, ErrInvalidInput
	}
	if !s.pepper.VerifyAny(signature, domain, payload) {
		return apiKeyListCursor{}, ErrInvalidInput
	}
	now = now.UTC()
	if version.Version == 1 {
		return decodeListCursorV1(payload, now)
	}
	var cursor apiKeyListCursor
	if json.Unmarshal(payload, &cursor) != nil || !validListCursorCore(
		cursor.Audience, cursor.ScopeID, cursor.UserID, cursor.SnapshotAt, cursor.AfterCreatedAt, cursor.AfterID,
	) || !canonicalCursorTime(cursor.IssuedAt) || !canonicalCursorTime(cursor.ExpiresAt) ||
		cursor.IssuedAt.After(cursor.SnapshotAt) || cursor.SnapshotAt.After(now) || !now.Before(cursor.ExpiresAt) ||
		cursor.ExpiresAt.Sub(cursor.IssuedAt) != listCursorTTL {
		return apiKeyListCursor{}, ErrInvalidInput
	}
	canonical, err := json.Marshal(cursor)
	if err != nil || !bytes.Equal(canonical, payload) {
		return apiKeyListCursor{}, ErrInvalidInput
	}
	return cursor, nil
}

func decodeListCursorV1(payload []byte, now time.Time) (apiKeyListCursor, error) {
	var legacy apiKeyListCursorV1
	if json.Unmarshal(payload, &legacy) != nil || !validListCursorCore(
		legacy.Audience, legacy.ScopeID, legacy.UserID, legacy.SnapshotAt, legacy.AfterCreatedAt, legacy.AfterID,
	) || legacy.SnapshotAt.After(now) || !now.Before(legacy.SnapshotAt.Add(listCursorTTL)) {
		return apiKeyListCursor{}, ErrInvalidInput
	}
	canonical, err := json.Marshal(legacy)
	if err != nil || !bytes.Equal(canonical, payload) {
		return apiKeyListCursor{}, ErrInvalidInput
	}
	return apiKeyListCursor{
		Version: 2, Audience: legacy.Audience, ScopeID: legacy.ScopeID, UserID: legacy.UserID,
		IssuedAt: legacy.SnapshotAt, ExpiresAt: legacy.SnapshotAt.Add(listCursorTTL),
		SnapshotAt: legacy.SnapshotAt, AfterCreatedAt: legacy.AfterCreatedAt, AfterID: legacy.AfterID,
		Limit: legacy.Limit, Status: legacy.Status, Name: legacy.Name, KeyID: legacy.KeyID,
	}, nil
}

func validListCursorCore(
	audience string,
	scopeID, userID uuid.UUID,
	snapshotAt, afterCreatedAt time.Time,
	afterID uuid.UUID,
) bool {
	return audience != "" && scopeID != uuid.Nil && userID != uuid.Nil && afterID != uuid.Nil &&
		canonicalCursorTime(snapshotAt) && canonicalCursorTime(afterCreatedAt) && !afterCreatedAt.After(snapshotAt)
}

func canonicalCursorTime(value time.Time) bool {
	return !value.IsZero() && value.Location() == time.UTC
}

func (s *Service) get(ctx context.Context, scopeID, userID, id uuid.UUID) (Key, error) {
	var item Key
	err := scanKey(s.pool.QueryRow(ctx, `SELECT `+keyColumns+` FROM api_keys
		WHERE id=$1 AND scope_id=$2 AND user_id=$3`, id, scopeID, userID), &item)
	if errors.Is(err, pgx.ErrNoRows) {
		return Key{}, ErrNotFound
	}
	return item, err
}

func (s *Service) targetPrincipal(ctx context.Context, scopeID, userID uuid.UUID) (identity.Principal, error) {
	principal := identity.Principal{UserID: userID, Roles: []string{}, Permissions: []string{}}
	err := s.pool.QueryRow(ctx, `
		SELECT scope.id, scope.kind, scope.tenant_id, u.username, u.display_name,
		       COALESCE(array_agg(DISTINCT roles.name) FILTER (WHERE roles.name IS NOT NULL), '{}'::text[]),
		       COALESCE(array_agg(DISTINCT rp.permission_name) FILTER (WHERE rp.permission_name IS NOT NULL), '{}'::text[])
		FROM users u
		JOIN memberships m ON m.user_id=u.id AND m.status='active'
		JOIN access_scopes scope ON scope.id=m.scope_id AND scope.kind='tenant'
		JOIN tenants tenant ON tenant.id=scope.tenant_id AND tenant.status='active'
		LEFT JOIN role_assignments ra ON ra.scope_id=scope.id AND ra.user_id=u.id
		LEFT JOIN roles ON roles.id=ra.role_id
		LEFT JOIN role_permissions rp ON rp.role_id=roles.id
		WHERE u.id=$1 AND scope.id=$2 AND u.status='active'
		GROUP BY scope.id, scope.kind, scope.tenant_id, u.username, u.display_name
		ORDER BY scope.id`, userID, scopeID,
	).Scan(&principal.ScopeID, &principal.ScopeKind, &principal.TenantID, &principal.Username,
		&principal.DisplayName, &principal.Roles, &principal.Permissions)
	if errors.Is(err, pgx.ErrNoRows) {
		return identity.Principal{}, ErrNotFound
	}
	return principal, err
}

func requireSelf(principal identity.Principal) error {
	if principal.UserID == uuid.Nil || principal.ScopeID == uuid.Nil || principal.ScopeKind != "tenant" || principal.TenantID == nil {
		return ErrPermissionDenied
	}
	if err := identity.Authorize(principal, "api_keys.self.manage"); err != nil {
		return ErrPermissionDenied
	}
	return nil
}

func requireAdmin(principal identity.Principal) error {
	if principal.UserID == uuid.Nil || principal.ScopeID == uuid.Nil || principal.ScopeKind != "platform" {
		return ErrPermissionDenied
	}
	if err := identity.Authorize(principal, "api_keys.admin.manage"); err != nil {
		return ErrPermissionDenied
	}
	return nil
}

func normalizeCreate(input *CreateInput, now time.Time, permissions []string) error {
	input.Name = strings.TrimSpace(input.Name)
	if utf8.RuneCountInString(input.Name) < 1 || utf8.RuneCountInString(input.Name) > 128 ||
		!validWriteMetadata(input.IdempotencyKey, input.RequestID) {
		return ErrInvalidInput
	}
	if input.ExpiresAt != nil {
		value := input.ExpiresAt.UTC()
		input.ExpiresAt = &value
		if !value.After(now) || value.After(now.Add(maxCredentialTTL)) {
			return ErrInvalidInput
		}
	}
	if err := validateScopes(input.Scopes, permissions); err != nil {
		return err
	}
	allowlist, err := normalizeIPAllowlist(input.IPAllowlist)
	if err != nil {
		return err
	}
	input.IPAllowlist = allowlist
	return nil
}

func normalizeIPAllowlist(values []string) ([]string, error) {
	if len(values) > 32 {
		return nil, ErrInvalidInput
	}
	prefixes := make([]netip.Prefix, 0, len(values))
	normalized := make([]string, 0, len(values))
	for _, value := range values {
		prefix, err := netip.ParsePrefix(value)
		if err != nil || prefix != prefix.Masked() || value != prefix.String() || prefix.Addr().Is4In6() {
			return nil, ErrInvalidInput
		}
		for _, existing := range prefixes {
			if existing.Contains(prefix.Addr()) || prefix.Contains(existing.Addr()) {
				return nil, ErrInvalidInput
			}
		}
		prefixes = append(prefixes, prefix)
		normalized = append(normalized, value)
	}
	sort.Strings(normalized)
	return normalized, nil
}

func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func validateScopes(requested []string, permissions []string) error {
	if len(requested) < 1 || len(requested) > maxKeyScopes || len(requested) >= len(permissions) {
		return ErrInvalidInput
	}
	allowed := make(map[string]struct{}, len(permissions))
	for _, permission := range permissions {
		allowed[permission] = struct{}{}
	}
	seen := make(map[string]struct{}, len(requested))
	for _, scope := range requested {
		if !scopePattern.MatchString(scope) || scope == "platform.admin" || strings.HasPrefix(scope, "identity.") || strings.HasPrefix(scope, "api_keys.") {
			return ErrInvalidInput
		}
		if _, exists := allowed[scope]; !exists {
			return ErrPermissionDenied
		}
		if _, duplicate := seen[scope]; duplicate {
			return ErrInvalidInput
		}
		seen[scope] = struct{}{}
	}
	sort.Strings(requested)
	return nil
}

// issuanceScopes 返回签发时要写入的新权限；nil 表示保持密钥原权限。只有轮换可以要求刷新为全部可授予权限。
func issuanceScopes(operation string, grantAll bool, permissions []string) ([]string, error) {
	if !grantAll {
		return nil, nil
	}
	if operation != "api_key.self.rotate" {
		return nil, ErrInvalidInput
	}
	scopes := grantableScopes(permissions)
	if err := validateScopes(scopes, permissions); err != nil {
		return nil, ErrPermissionDenied
	}
	return scopes, nil
}

// grantableScopes 是简单版"全部权限"：会话权限里允许授予 API 密钥的全部（去重、排序），与前端 safeScope 同一规则。
func grantableScopes(permissions []string) []string {
	seen := make(map[string]struct{}, len(permissions))
	scopes := make([]string, 0, len(permissions))
	for _, permission := range permissions {
		if !scopePattern.MatchString(permission) || permission == "platform.admin" ||
			strings.HasPrefix(permission, "identity.") || strings.HasPrefix(permission, "api_keys.") {
			continue
		}
		if _, duplicate := seen[permission]; duplicate {
			continue
		}
		seen[permission] = struct{}{}
		scopes = append(scopes, permission)
	}
	sort.Strings(scopes)
	return scopes
}

func validWriteMetadata(key, requestID string) bool {
	return idempotencyPattern.MatchString(key) && strings.TrimSpace(requestID) != ""
}

func randomKeyID() (string, error) {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("generate API key ID: %w", err)
	}
	return "cfk_" + base64.RawURLEncoding.EncodeToString(raw), nil
}

func parseCredential(raw string) (string, string, bool) {
	if raw != strings.TrimSpace(raw) {
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

func (s *Service) available() bool {
	return s.pool != nil && s.pepper.Configured()
}

func (s *Service) Ready(ctx context.Context) error {
	if !s.available() || ctx == nil {
		return ErrUnavailable
	}
	var ready bool
	if err := s.pool.QueryRow(ctx, `SELECT EXISTS (
		SELECT 1 FROM information_schema.columns
		WHERE table_schema=current_schema() AND table_name='api_keys' AND column_name='pepper_version'
	) AND EXISTS (
		SELECT 1 FROM information_schema.columns
		WHERE table_schema=current_schema() AND table_name='api_key_write_requests' AND column_name='pepper_version'
	)`).Scan(&ready); err != nil || !ready {
		return ErrUnavailable
	}
	return nil
}

func (s *Service) deriveActiveSecret(writeID uuid.UUID, keyID string) (string, string, [32]byte, bool) {
	version := s.pepper.ActiveVersion()
	secret, ok := s.deriveSecret(version, writeID, keyID)
	if !ok {
		return "", "", [32]byte{}, false
	}
	digest, ok := s.pepper.Sign(version, digestDomain, []byte(keyID), []byte{0}, []byte(secret))
	return version, secret, digest, ok
}

func (s *Service) deriveSecret(version string, writeID uuid.UUID, keyID string) (string, bool) {
	digest, ok := s.pepper.Sign(version, secretDomain, writeID[:], []byte(keyID))
	if !ok {
		return "", false
	}
	return base64.RawURLEncoding.EncodeToString(digest[:]), true
}

func (s *Service) replaySecret(ctx context.Context, tx pgx.Tx, writeID uuid.UUID, key Key) (string, error) {
	var version string
	if err := tx.QueryRow(ctx, `SELECT pepper_version FROM api_keys WHERE id=$1`, key.ID).Scan(&version); err != nil {
		return "", err
	}
	secret, ok := s.deriveSecret(version, writeID, key.KeyID)
	if !ok {
		return "", ErrInvalidCredential
	}
	return secret, nil
}

type versionedRequestDigest struct {
	keyring   apikeycredential.PepperKeyring
	operation string
	payload   []byte
}

func (digest versionedRequestDigest) active() (string, [32]byte, bool) {
	return digest.keyring.SignActive(requestDomain, []byte(digest.operation), []byte{0}, digest.payload)
}

func (digest versionedRequestDigest) forVersion(version string) ([32]byte, bool) {
	return digest.keyring.Sign(version, requestDomain, []byte(digest.operation), []byte{0}, digest.payload)
}

func (s *Service) requestDigest(operation string, value any) versionedRequestDigest {
	encoded, _ := json.Marshal(value)
	return versionedRequestDigest{keyring: s.pepper, operation: operation, payload: encoded}
}

func reserveWrite(
	ctx context.Context,
	tx pgx.Tx,
	actor identity.Principal,
	targetScopeID uuid.UUID,
	targetUserID uuid.UUID,
	operation string,
	key string,
	digest versionedRequestDigest,
) (uuid.UUID, []byte, error) {
	id, err := uuid.NewV7()
	if err != nil {
		return uuid.Nil, nil, err
	}
	pepperVersion, activeDigest, ok := digest.active()
	if !ok {
		return uuid.Nil, nil, ErrUnavailable
	}
	result, err := tx.Exec(ctx, `
		INSERT INTO api_key_write_requests (
			id, actor_user_id, actor_scope_id, target_scope_id, target_user_id,
			operation, idempotency_key, request_digest, pepper_version
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
		ON CONFLICT (actor_user_id, operation, idempotency_key) DO NOTHING`,
		id, actor.UserID, actor.ScopeID, targetScopeID, targetUserID, operation, key, activeDigest[:], pepperVersion)
	if err != nil {
		return uuid.Nil, nil, err
	}
	if result.RowsAffected() == 1 {
		return id, nil, nil
	}
	var storedDigest, response []byte
	var storedPepperVersion string
	err = tx.QueryRow(ctx, `
		SELECT id, request_digest, pepper_version, response_body::text::bytea
		FROM api_key_write_requests
		WHERE actor_user_id=$1 AND operation=$2 AND idempotency_key=$3
		FOR UPDATE`, actor.UserID, operation, key).Scan(&id, &storedDigest, &storedPepperVersion, &response)
	if err != nil {
		return uuid.Nil, nil, err
	}
	expected, knownVersion := digest.forVersion(storedPepperVersion)
	if !knownVersion || !bytes.Equal(storedDigest, expected[:]) {
		return uuid.Nil, nil, ErrIdempotencyConflict
	}
	if len(response) == 0 {
		return uuid.Nil, nil, fmt.Errorf("incomplete API key idempotent request")
	}
	return id, response, nil
}

func completeWrite(
	ctx context.Context,
	tx pgx.Tx,
	actor identity.Principal,
	operation string,
	key string,
	resourceID uuid.UUID,
	response any,
) error {
	encoded, err := json.Marshal(response)
	if err != nil {
		return err
	}
	result, err := tx.Exec(ctx, `
		UPDATE api_key_write_requests
		SET resource_id=$4, response_body=$5, completed_at=now()
		WHERE actor_user_id=$1 AND operation=$2 AND idempotency_key=$3 AND completed_at IS NULL`,
		actor.UserID, operation, key, resourceID, encoded)
	if err != nil {
		return err
	}
	if result.RowsAffected() != 1 {
		return ErrIdempotencyConflict
	}
	return nil
}

func (s *Service) appendAudit(
	ctx context.Context,
	tx pgx.Tx,
	actor identity.Principal,
	targetScopeID uuid.UUID,
	requestID string,
	action string,
	key Key,
	payload map[string]any,
) error {
	payload["key_id"] = key.KeyID
	payload["status"] = key.Status
	actorID := actor.UserID
	return s.auditor.Append(ctx, tx, audit.Event{
		ScopeID: targetScopeID, ActorUserID: &actorID, Action: action,
		ResourceType: "api_key", ResourceID: key.ID.String(), RequestID: requestID,
		Result: "success", Payload: payload,
	})
}

func classifyKeyMiss(
	ctx context.Context,
	tx pgx.Tx,
	scopeID, userID, id uuid.UUID,
	allowedStatuses ...string,
) error {
	var revision int64
	var status string
	err := tx.QueryRow(ctx, `SELECT revision, status FROM api_keys
		WHERE id=$1 AND scope_id=$2 AND user_id=$3`, id, scopeID, userID).Scan(&revision, &status)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	for _, allowed := range allowedStatuses {
		if status == allowed {
			return ErrRevisionConflict
		}
	}
	return ErrInvalidTransition
}

type rowScanner interface{ Scan(...any) error }

func scanKey(row rowScanner, key *Key) error {
	return row.Scan(
		&key.ID, &key.KeyID, &key.KeyPrefix, &key.ScopeID, &key.TenantID, &key.UserID,
		&key.Name, &key.Scopes, &key.IPAllowlist, &key.Status, &key.PendingExpiresAt, &key.ExpiresAt,
		&key.LastUsedAt, &key.ActivatedAt, &key.RevokedAt, &key.Revision,
		&key.CreatedAt, &key.UpdatedAt,
	)
}
