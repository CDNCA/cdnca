package dnsacme

import (
	"bytes"
	"context"
	"crypto/md5"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/acmecacredentials"
	"github.com/cdnca/cdnca/services/control-api/internal/acmeworker"
	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/domaintrust"
	"github.com/cdnca/cdnca/services/control-api/internal/entitlementguard"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Store struct {
	pool    *pgxpool.Pool
	auditor *audit.Log
	guard   orderEntitlementChecker
}

type orderEntitlementChecker interface {
	CheckFeature(context.Context, pgx.Tx, entitlementguard.FeatureCheck) (entitlementguard.FeatureDecision, error)
}

type providerVerificationTarget struct {
	Provider
	TenantID             uuid.UUID
	CredentialKeyID      string
	CredentialCiphertext []byte
	CredentialVersion    int64
	CredentialRevoked    bool
}

type providerCredentialTarget struct {
	Provider
	TenantID uuid.UUID
}

func (target providerCredentialTarget) binding() CredentialBinding {
	return CredentialBinding{TenantID: target.TenantID, ScopeID: target.ScopeID, ProviderID: target.ID}
}

type providerVerificationWriteResponse struct {
	Provider  *Provider `json:"provider,omitempty"`
	ErrorCode string    `json:"error_code,omitempty"`
}

const certificateOrderProjection = `id, scope_id, dns_provider_id, domains, challenge_type, status,
	auto_renew, renewal_of_order_id, not_after, failure_code, failure_reason,
	issued_asset_id, issued_asset_version_id, issued_at,
	leaf_fingerprint_sha256, leaf_spki_sha256,
	acme_directory_url, acme_account_key_ref, certificate_key_ref,
	external_order_url, authorization_urls_sha256, certificate_url,
	revision, created_at, updated_at, issuer, name, remark`

const (
	renewalJitterMaximum        = 24 * time.Hour
	renewalRetryBaseMaximum     = time.Minute
	renewalRetryExponentMaximum = int64(20)
)

func renewalJitterSeed(certificateID uuid.UUID, notAfter time.Time) uint32 {
	digest := md5.Sum([]byte(certificateID.String() + ":" + strconv.FormatInt(notAfter.UnixMicro(), 10)))
	return binary.BigEndian.Uint32(digest[:4])
}

func renewalJitterOffset(certificateID uuid.UUID, notAfter time.Time, renewBefore time.Duration) time.Duration {
	maximumMilliseconds := renewBefore.Milliseconds() / 4
	if capMilliseconds := renewalJitterMaximum.Milliseconds(); maximumMilliseconds > capMilliseconds {
		maximumMilliseconds = capMilliseconds
	}
	if maximumMilliseconds <= 0 {
		return 0
	}
	offsetMilliseconds := uint64(renewalJitterSeed(certificateID, notAfter)) % uint64(maximumMilliseconds+1)
	return time.Duration(offsetMilliseconds) * time.Millisecond
}

func renewalInitialDue(certificateID uuid.UUID, notAfter time.Time, renewBefore time.Duration) time.Time {
	return notAfter.Add(-time.Duration(renewBefore.Milliseconds())*time.Millisecond +
		renewalJitterOffset(certificateID, notAfter, renewBefore))
}

func renewalRetryDelay(
	failureCount int64,
	notAfter time.Time,
	latestFailureAt time.Time,
	retryMaximum time.Duration,
) time.Duration {
	maximumMilliseconds := retryMaximum.Milliseconds()
	if failureCount <= 0 || maximumMilliseconds <= 0 {
		return 0
	}
	baseMilliseconds := min(renewalRetryBaseMaximum.Milliseconds(), maximumMilliseconds)
	exponent := min(failureCount-1, renewalRetryExponentMaximum)
	delayMilliseconds := baseMilliseconds
	for i := int64(0); i < exponent; i++ {
		if delayMilliseconds >= maximumMilliseconds || delayMilliseconds > maximumMilliseconds/2 {
			delayMilliseconds = maximumMilliseconds
			break
		}
		delayMilliseconds *= 2
	}
	delayMilliseconds = min(delayMilliseconds, maximumMilliseconds)
	remainingMilliseconds := max(int64(0), notAfter.Sub(latestFailureAt).Milliseconds())
	expiryCapMilliseconds := max(baseMilliseconds, remainingMilliseconds/4)
	return time.Duration(min(delayMilliseconds, expiryCapMilliseconds)) * time.Millisecond
}

func NewStore(pool *pgxpool.Pool) *Store {
	return NewStoreWithEntitlement(pool, time.Now, nil)
}

func NewStoreWithEntitlement(
	pool *pgxpool.Pool,
	now func() time.Time,
	trust *entitlementguard.TrustStore,
) *Store {
	return &Store{
		pool: pool, auditor: audit.New(pool), guard: entitlementguard.NewGuard(pool, now, trust),
	}
}

func (s *Store) CreateProvider(
	ctx context.Context,
	actor Actor,
	request CreateProviderRequest,
	binding CredentialBinding,
	keyID string,
	ciphertext []byte,
	digest [32]byte,
) (Provider, error) {
	var result Provider
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		replay, err := reserveWrite(ctx, tx, actor, request.TargetScopeID, "dns.provider.create", request.IdempotencyKey, digest)
		if err != nil {
			return err
		}
		if replay != nil {
			return json.Unmarshal(replay, &result)
		}
		err = scanProvider(tx.QueryRow(ctx, `
			INSERT INTO dns_providers (
				id, scope_id, name, provider_type, credential_key_id, credential_ciphertext,
				created_by_user_id, updated_by_user_id, remark
			) SELECT $1,scope.id,$3,$4,$5,$6,$7,$7,$9
			  FROM access_scopes AS scope
			 WHERE scope.id=$2 AND scope.kind='tenant' AND scope.tenant_id=$8
			RETURNING id, scope_id, name, remark, provider_type, credentials_configured, status, managed_by,
			          revision, created_at, updated_at`,
			binding.ProviderID, request.TargetScopeID, request.Name, request.ProviderType, keyID, ciphertext,
			actor.UserID, binding.TenantID, request.Remark,
		), &result)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return mapWriteError(err)
		}
		if err := s.appendAudit(ctx, tx, actor, request.TargetScopeID, request.RequestID,
			"dns.provider.create", "dns_provider", result.ID, map[string]any{
				"name": result.Name, "remark": result.Remark, "provider_type": result.ProviderType, "credentials_configured": true,
			}); err != nil {
			return err
		}
		return completeWrite(ctx, tx, actor, "dns.provider.create", request.IdempotencyKey, result.ID, result)
	})
	return result, err
}

func (s *Store) UpdateProvider(
	ctx context.Context,
	actor Actor,
	request UpdateProviderRequest,
	binding CredentialBinding,
	keyID string,
	ciphertext []byte,
	digest [32]byte,
) (Provider, error) {
	var result Provider
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		scopeID, err := resourceScope(ctx, tx, "dns_providers", actor, request.ID)
		if err != nil {
			return err
		}
		var tenantID uuid.UUID
		if err := tx.QueryRow(ctx, `SELECT tenant_id FROM access_scopes
			WHERE id=$1 AND kind='tenant'`, scopeID).Scan(&tenantID); err != nil ||
			scopeID != binding.ScopeID || tenantID != binding.TenantID || request.ID != binding.ProviderID {
			return ErrNotFound
		}
		replay, err := reserveWrite(ctx, tx, actor, scopeID, "dns.provider.update", request.IdempotencyKey, digest)
		if err != nil {
			return err
		}
		if replay != nil {
			return json.Unmarshal(replay, &result)
		}
		if ciphertext == nil && request.Status != ProviderStatusDisabled {
			// DNS-UX-20261027-02: a revoked credential (the account was
			// disabled) cannot verify again; enabling it needs new credentials.
			var revoked bool
			if err := tx.QueryRow(ctx, `SELECT credential_revoked FROM dns_providers WHERE id=$1 FOR UPDATE`,
				request.ID).Scan(&revoked); err != nil {
				return err
			}
			if revoked {
				return ErrProviderReauthorizationRequired
			}
		}
		if ciphertext == nil {
			// DNS-01: without new credentials the verification still holds, so
			// "enabled" (unverified on the wire) keeps a verified account
			// verified; only disabling or new credentials change it.
			err = scanProvider(tx.QueryRow(ctx, `
				UPDATE dns_providers SET name=$3,
				    status=CASE WHEN $4='unverified' AND status='verified' THEN 'verified' ELSE $4 END,
				    revision=revision+1,
				    updated_by_user_id=$5, updated_at=now(), remark=COALESCE($6, remark)
				WHERE id=$1 AND revision=$2
				RETURNING id, scope_id, name, remark, provider_type, credentials_configured, status, managed_by,
				          revision, created_at, updated_at`,
				request.ID, request.ExpectedRevision, request.Name, request.Status, actor.UserID, request.Remark,
			), &result)
		} else {
			err = scanProvider(tx.QueryRow(ctx, `
				UPDATE dns_providers SET name=$3, status=$4, credential_key_id=$5,
				    credential_ciphertext=$6, revision=revision+1,
				    updated_by_user_id=$7, updated_at=now(), remark=COALESCE($8, remark)
				WHERE id=$1 AND revision=$2
				RETURNING id, scope_id, name, remark, provider_type, credentials_configured, status, managed_by,
				          revision, created_at, updated_at`,
				request.ID, request.ExpectedRevision, request.Name, request.Status,
				keyID, ciphertext, actor.UserID, request.Remark,
			), &result)
		}
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrRevisionConflict
		}
		if err != nil {
			return mapWriteError(err)
		}
		if err := s.appendAudit(ctx, tx, actor, scopeID, request.RequestID,
			"dns.provider.update", "dns_provider", result.ID, map[string]any{
				"name": result.Name, "remark": result.Remark, "status": result.Status, "credentials_replaced": ciphertext != nil,
			}); err != nil {
			return err
		}
		return completeWrite(ctx, tx, actor, "dns.provider.update", request.IdempotencyKey, result.ID, result)
	})
	return result, err
}

func (s *Store) providerForUpdate(ctx context.Context, actor Actor, id uuid.UUID) (providerCredentialTarget, error) {
	var result providerCredentialTarget
	err := s.pool.QueryRow(ctx, `
			SELECT provider.id, provider.scope_id, provider.name, provider.provider_type,
			       provider.credentials_configured, provider.status, provider.managed_by, provider.revision,
			       provider.created_at, provider.updated_at, scope.tenant_id
			FROM dns_providers AS provider
			JOIN access_scopes AS scope ON scope.id=provider.scope_id AND scope.kind='tenant'
			JOIN tenants AS tenant ON tenant.id=scope.tenant_id AND tenant.status='active'
			WHERE provider.id=$1 AND ($2='platform' OR provider.scope_id=$3)`,
		id, actor.ScopeKind, actor.ScopeID).Scan(
		&result.ID, &result.ScopeID, &result.Name, &result.ProviderType,
		&result.CredentialsConfigured, &result.Status, &result.ManagedBy, &result.Revision,
		&result.CreatedAt, &result.UpdatedAt, &result.TenantID,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return providerCredentialTarget{}, ErrNotFound
	}
	return result, err
}

func (s *Store) prepareProviderCredentialCreate(
	ctx context.Context,
	actor Actor,
	scopeID uuid.UUID,
) (CredentialBinding, error) {
	if s == nil || s.pool == nil || !validActor(actor) || scopeID == uuid.Nil {
		return CredentialBinding{}, ErrInvalidInput
	}
	providerID, err := uuid.NewV7()
	if err != nil {
		return CredentialBinding{}, err
	}
	var tenantID uuid.UUID
	err = s.pool.QueryRow(ctx, `SELECT scope.tenant_id
		FROM access_scopes AS scope
		JOIN tenants AS tenant ON tenant.id=scope.tenant_id AND tenant.status='active'
		WHERE scope.id=$1 AND scope.kind='tenant' AND ($2='platform' OR scope.id=$3)`,
		scopeID, actor.ScopeKind, actor.ScopeID).Scan(&tenantID)
	if errors.Is(err, pgx.ErrNoRows) {
		return CredentialBinding{}, ErrNotFound
	}
	if err != nil {
		return CredentialBinding{}, err
	}
	return CredentialBinding{TenantID: tenantID, ScopeID: scopeID, ProviderID: providerID}, nil
}

func (s *Store) ListProviders(ctx context.Context, actor Actor, limit int, after *providerPageCursor) ([]Provider, error) {
	var afterCreatedAt *time.Time
	afterID := uuid.Nil
	if after != nil {
		afterCreatedAt = &after.CreatedAt
		afterID = after.ID
	}
	rows, err := s.pool.Query(ctx, `
		SELECT id, scope_id, name, remark, provider_type, credentials_configured, status, managed_by,
		       revision, created_at, updated_at
		FROM dns_providers
		WHERE ($1 = 'platform' OR scope_id = $2)
		  AND ($3::timestamptz IS NULL OR created_at < $3 OR (created_at = $3 AND id < $4))
		ORDER BY created_at DESC, id DESC
		LIMIT $5`, actor.ScopeKind, actor.ScopeID, afterCreatedAt, afterID, limit)
	if err != nil {
		return nil, fmt.Errorf("list DNS providers: %w", err)
	}
	defer rows.Close()
	items := make([]Provider, 0)
	for rows.Next() {
		var item Provider
		if err := scanProvider(rows, &item); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *Store) PrepareProviderVerification(
	ctx context.Context,
	actor Actor,
	request VerifyProviderRequest,
	digest [32]byte,
) (providerVerificationTarget, *providerVerificationWriteResponse, error) {
	replay, found, err := s.findProviderVerificationReplay(ctx, actor, request.IdempotencyKey, digest)
	if err != nil || found {
		return providerVerificationTarget{}, replay, err
	}
	var target providerVerificationTarget
	err = s.pool.QueryRow(ctx, `
		SELECT provider.id, provider.scope_id, provider.name, provider.provider_type,
		       provider.credentials_configured, provider.status, provider.managed_by,
		       provider.revision, provider.created_at, provider.updated_at,
		       provider.credential_key_id, provider.credential_ciphertext,
		       provider.credential_version, provider.credential_revoked, scope.tenant_id
		FROM dns_providers AS provider
		JOIN access_scopes AS scope ON scope.id=provider.scope_id AND scope.kind='tenant'
		JOIN tenants AS tenant ON tenant.id=scope.tenant_id AND tenant.status='active'
		WHERE provider.id=$1 AND ($2='platform' OR provider.scope_id=$3)`,
		request.ID, actor.ScopeKind, actor.ScopeID,
	).Scan(
		&target.ID, &target.ScopeID, &target.Name, &target.ProviderType,
		&target.CredentialsConfigured, &target.Status, &target.ManagedBy, &target.Revision,
		&target.CreatedAt, &target.UpdatedAt, &target.CredentialKeyID,
		&target.CredentialCiphertext, &target.CredentialVersion, &target.CredentialRevoked, &target.TenantID,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return providerVerificationTarget{}, nil, ErrNotFound
	}
	if err != nil {
		return providerVerificationTarget{}, nil, err
	}
	if IsPlatformManagedProvider(target.ManagedBy, target.ScopeID, target.ID) {
		clear(target.CredentialCiphertext)
		return providerVerificationTarget{}, nil, ErrPlatformManagedProvider
	}
	if target.Revision != request.ExpectedRevision {
		clear(target.CredentialCiphertext)
		return providerVerificationTarget{}, nil, ErrRevisionConflict
	}
	if target.CredentialRevoked || target.CredentialVersion <= 0 {
		clear(target.CredentialCiphertext)
		return providerVerificationTarget{}, nil, ErrProviderDisabled
	}
	return target, nil, nil
}

func (s *Store) CompleteProviderVerification(
	ctx context.Context,
	actor Actor,
	request VerifyProviderRequest,
	digest [32]byte,
	verificationErr error,
) (Provider, error) {
	var outcome providerVerificationWriteResponse
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		scopeID, err := resourceScope(ctx, tx, "dns_providers", actor, request.ID)
		if err != nil {
			return err
		}
		replay, err := reserveWrite(ctx, tx, actor, scopeID, "dns.provider.verify", request.IdempotencyKey, digest)
		if err != nil {
			return err
		}
		if replay != nil {
			return json.Unmarshal(replay, &outcome)
		}

		var current Provider
		err = scanProvider(tx.QueryRow(ctx, `
			SELECT id, scope_id, name, remark, provider_type, credentials_configured, status, managed_by,
			       revision, created_at, updated_at
			FROM dns_providers WHERE id=$1 FOR UPDATE`, request.ID), &current)
		if err != nil {
			return err
		}
		if current.Revision != request.ExpectedRevision {
			return ErrRevisionConflict
		}

		if verificationErr == nil {
			err = scanProvider(tx.QueryRow(ctx, `
				UPDATE dns_providers
				SET status='verified', revision=revision+1,
				    updated_by_user_id=$3, updated_at=now()
				WHERE id=$1 AND revision=$2
				RETURNING id, scope_id, name, remark, provider_type, credentials_configured, status, managed_by,
				          revision, created_at, updated_at`,
				request.ID, request.ExpectedRevision, actor.UserID,
			), &current)
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrRevisionConflict
			}
			if err != nil {
				return err
			}
			outcome.Provider = &current
			if err := s.appendVerificationAudit(ctx, tx, actor, scopeID, request, current.ProviderType, "success", "active"); err != nil {
				return err
			}
		} else {
			code, ok := providerVerificationErrorCode(verificationErr)
			if !ok {
				return verificationErr
			}
			if credentialRollbackEligible(verificationErr) {
				if _, err := s.rollbackRejectedProviderCredential(
					ctx, tx, actor, scopeID, request, current, code,
				); err != nil {
					return err
				}
			}
			outcome.ErrorCode = code
			if err := s.appendVerificationAudit(ctx, tx, actor, scopeID, request, current.ProviderType, "denied", code); err != nil {
				return err
			}
		}
		return completeWrite(ctx, tx, actor, "dns.provider.verify", request.IdempotencyKey, request.ID, outcome)
	})
	if err != nil {
		return Provider{}, err
	}
	return outcome.result()
}

func credentialRollbackEligible(err error) bool {
	return errors.Is(err, ErrProviderCredentialsInvalid) ||
		errors.Is(err, ErrProviderTokenInactive) ||
		errors.Is(err, ErrProviderCredentialsRejected)
}

func (s *Store) rollbackRejectedProviderCredential(
	ctx context.Context,
	tx pgx.Tx,
	actor Actor,
	scopeID uuid.UUID,
	request VerifyProviderRequest,
	current Provider,
	reasonCode string,
) (bool, error) {
	var currentVersion, restoredVersion int64
	var restoredKeyID string
	var restoredCiphertext []byte
	err := tx.QueryRow(ctx, `
		SELECT provider.credential_version, prior.credential_version,
		       prior.credential_key_id, prior.credential_ciphertext
		FROM dns_providers AS provider
		JOIN dns_provider_credential_history AS active
		  ON active.provider_id=provider.id
		 AND active.credential_version=provider.credential_version
		JOIN LATERAL (
		    SELECT candidate.credential_version,candidate.credential_key_id,candidate.credential_ciphertext
		    FROM dns_provider_credential_history AS candidate
		    WHERE candidate.provider_id=provider.id
		      AND candidate.credential_version<provider.credential_version
		      AND candidate.provider_status='verified' AND NOT candidate.credential_revoked
		      AND candidate.credential_version>COALESCE((
		          SELECT max(revoked.credential_version)
		          FROM dns_provider_credential_history AS revoked
		          WHERE revoked.provider_id=provider.id AND revoked.credential_revoked
		      ),0)
		    ORDER BY candidate.credential_version DESC
		    LIMIT 1
		) AS prior ON true
		WHERE provider.id=$1 AND provider.scope_id=$2 AND provider.revision=$3
		  AND provider.status='unverified' AND NOT provider.credential_revoked
		  AND active.credential_event='rotation'`,
		request.ID, scopeID, request.ExpectedRevision,
	).Scan(&currentVersion, &restoredVersion, &restoredKeyID, &restoredCiphertext)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	defer clear(restoredCiphertext)
	var newVersion int64
	err = tx.QueryRow(ctx, `
		UPDATE dns_providers
		SET credential_key_id=$4, credential_ciphertext=$5, status='verified',
		    revision=revision+1, updated_by_user_id=$6, updated_at=now()
		WHERE id=$1 AND scope_id=$2 AND revision=$3
		  AND credential_version=$7 AND NOT credential_revoked
		RETURNING credential_version`,
		request.ID, scopeID, request.ExpectedRevision, restoredKeyID, restoredCiphertext,
		actor.UserID, currentVersion,
	).Scan(&newVersion)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, ErrRevisionConflict
	}
	if err != nil {
		return false, err
	}
	if newVersion <= currentVersion {
		return false, ErrRevisionConflict
	}
	actorID := actor.UserID
	err = s.auditor.Append(ctx, tx, audit.Event{
		ScopeID: scopeID, ActorUserID: &actorID, Action: "dns.provider.credential.rollback",
		ResourceType: "dns_provider", ResourceID: current.ID.String(),
		RequestID: request.RequestID, Result: "success",
		Payload: map[string]any{
			"from_version": currentVersion, "restored_from_version": restoredVersion,
			"new_version": newVersion, "reason_code": reasonCode,
		},
	})
	return err == nil, err
}

func (s *Store) findProviderVerificationReplay(
	ctx context.Context,
	actor Actor,
	key string,
	digest [32]byte,
) (*providerVerificationWriteResponse, bool, error) {
	var storedDigest, response []byte
	err := s.pool.QueryRow(ctx, `
		SELECT request_digest, response_body::text::bytea
		FROM dns_acme_write_requests
		WHERE actor_user_id=$1 AND operation='dns.provider.verify' AND idempotency_key=$2`,
		actor.UserID, key,
	).Scan(&storedDigest, &response)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	if !bytes.Equal(storedDigest, digest[:]) {
		return nil, false, ErrIdempotencyConflict
	}
	if len(response) == 0 {
		return nil, false, fmt.Errorf("incomplete provider verification request")
	}
	var replay providerVerificationWriteResponse
	if err := json.Unmarshal(response, &replay); err != nil {
		return nil, false, err
	}
	return &replay, true, nil
}

func (s *Store) appendVerificationAudit(
	ctx context.Context,
	tx pgx.Tx,
	actor Actor,
	scopeID uuid.UUID,
	request VerifyProviderRequest,
	providerType string,
	result string,
	reasonCode string,
) error {
	actorID := actor.UserID
	return s.auditor.Append(ctx, tx, audit.Event{
		ScopeID: scopeID, ActorUserID: &actorID, Action: "dns.provider.verify",
		ResourceType: "dns_provider", ResourceID: request.ID.String(),
		RequestID: request.RequestID, Result: result,
		Payload: map[string]any{"provider_type": providerType, "reason_code": reasonCode},
	})
}

func (r providerVerificationWriteResponse) result() (Provider, error) {
	if r.Provider != nil && r.ErrorCode == "" {
		return *r.Provider, nil
	}
	if err := providerVerificationError(r.ErrorCode); err != nil {
		return Provider{}, err
	}
	return Provider{}, fmt.Errorf("invalid provider verification replay")
}

func providerVerificationErrorCode(err error) (string, bool) {
	switch {
	case errors.Is(err, ErrProviderVerificationUnsupported):
		return "provider_verification_unsupported", true
	case errors.Is(err, ErrProviderDisabled):
		return "provider_disabled", true
	case errors.Is(err, ErrProviderCredentialsInvalid):
		return "provider_credentials_invalid", true
	case errors.Is(err, ErrProviderTokenInactive):
		return "provider_token_inactive", true
	case errors.Is(err, ErrProviderCredentialsRejected):
		return "provider_credentials_rejected", true
	default:
		return "", false
	}
}

func providerVerificationError(code string) error {
	switch code {
	case "provider_verification_unsupported":
		return ErrProviderVerificationUnsupported
	case "provider_disabled":
		return ErrProviderDisabled
	case "provider_credentials_invalid":
		return ErrProviderCredentialsInvalid
	case "provider_token_inactive":
		return ErrProviderTokenInactive
	case "provider_credentials_rejected":
		return ErrProviderCredentialsRejected
	default:
		return nil
	}
}

func (s *Store) DeleteProvider(ctx context.Context, actor Actor, request DeleteRequest, digest [32]byte) error {
	return s.deleteResource(ctx, actor, request, digest, "dns_providers", "dns.provider.delete", "dns_provider")
}

func (s *Store) CreateZone(ctx context.Context, actor Actor, request CreateZoneRequest, digest [32]byte) (Zone, error) {
	var result Zone
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		replay, err := reserveWrite(ctx, tx, actor, request.TargetScopeID, "dns.zone.create", request.IdempotencyKey, digest)
		if err != nil {
			return err
		}
		if replay != nil {
			return json.Unmarshal(replay, &result)
		}
		id, err := uuid.NewV7()
		if err != nil {
			return err
		}
		// The first zone of a scope becomes its default CNAME allocation zone,
		// so the single DNS configuration form yields a usable allocator without
		// a separate "default zone" step. The transaction lock serialises the
		// check with the partial unique index on (scope_id) WHERE is_default.
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('dns_zones.default:' || $1::text, 0))`,
			request.TargetScopeID); err != nil {
			return err
		}
		err = scanZone(tx.QueryRow(ctx, `
			INSERT INTO dns_zones (id, scope_id, provider_id, name, created_by_user_id, updated_by_user_id, is_default,
			    provider_zone_apex)
			VALUES ($1,$2,$3,$4,$5,$5,NOT EXISTS (SELECT 1 FROM dns_zones WHERE scope_id=$2 AND is_default),NULLIF($6,''))
			RETURNING id, scope_id, provider_id, name, status, revision, created_at, updated_at`,
			id, request.TargetScopeID, request.ProviderID, request.Name, actor.UserID, request.ProviderZoneApex,
		), &result)
		if err != nil {
			return mapWriteError(err)
		}
		if err := s.appendAudit(ctx, tx, actor, request.TargetScopeID, request.RequestID,
			"dns.zone.create", "dns_zone", result.ID, map[string]any{"name": result.Name, "provider_id": result.ProviderID}); err != nil {
			return err
		}
		if _, err := RequeueCNAMEConfigFailures(ctx, tx, request.TargetScopeID, "dns_zone_create", time.Now().UTC()); err != nil {
			return err
		}
		return completeWrite(ctx, tx, actor, "dns.zone.create", request.IdempotencyKey, result.ID, result)
	})
	return result, err
}

// zoneProviderCredentials decrypts the credentials of the provider a new
// zone is saved under. An unknown provider yields nil credentials; the
// insert then reports it as before.
func (s *Store) zoneProviderCredentials(ctx context.Context, cipher CredentialCipher, scopeID, providerID uuid.UUID) (
	string, map[string]string, error) {
	var (
		providerType, keyID string
		ciphertext          []byte
		tenantID            uuid.UUID
	)
	err := s.pool.QueryRow(ctx, `SELECT provider.provider_type, provider.credential_key_id,
		       provider.credential_ciphertext, scope.tenant_id
		FROM dns_providers provider
		JOIN access_scopes scope ON scope.id=provider.scope_id AND scope.kind='tenant'
		WHERE provider.id=$1 AND provider.scope_id=$2`, providerID, scopeID).Scan(
		&providerType, &keyID, &ciphertext, &tenantID)
	defer clear(ciphertext)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", nil, nil
	}
	if err != nil {
		return "", nil, err
	}
	boundCipher, ok := cipher.(BoundCredentialCipher)
	if !ok {
		return "", nil, ErrCredentialUnavailable
	}
	plaintext, err := boundCipher.DecryptCredential(CredentialBinding{TenantID: tenantID, ScopeID: scopeID,
		ProviderID: providerID}, keyID, ciphertext)
	defer clear(plaintext)
	if err != nil {
		return "", nil, ErrCredentialUnavailable
	}
	credentials, err := parseProviderCredentials(plaintext)
	if err != nil {
		return "", nil, ErrProviderCredentialsInvalid
	}
	return providerType, credentials, nil
}

func (s *Store) ListZones(ctx context.Context, actor Actor) ([]Zone, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, scope_id, provider_id, name, status, revision, created_at, updated_at
		FROM dns_zones WHERE $1 = 'platform' OR scope_id = $2
		ORDER BY created_at DESC, id DESC`, actor.ScopeKind, actor.ScopeID)
	if err != nil {
		return nil, fmt.Errorf("list DNS zones: %w", err)
	}
	defer rows.Close()
	items := make([]Zone, 0)
	for rows.Next() {
		var item Zone
		if err := scanZone(rows, &item); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *Store) DeleteZone(ctx context.Context, actor Actor, request DeleteRequest, digest [32]byte) error {
	return s.deleteResource(ctx, actor, request, digest, "dns_zones", "dns.zone.delete", "dns_zone")
}

func (s *Store) CreateRecord(ctx context.Context, actor Actor, request CreateRecordRequest, digest [32]byte) (Record, error) {
	var result Record
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		replay, err := reserveWrite(ctx, tx, actor, request.TargetScopeID, "dns.record.create", request.IdempotencyKey, digest)
		if err != nil {
			return err
		}
		if replay != nil {
			return json.Unmarshal(replay, &result)
		}
		id, err := uuid.NewV7()
		if err != nil {
			return err
		}
		err = scanRecord(tx.QueryRow(ctx, `
			INSERT INTO dns_records (
				id, scope_id, zone_id, name, record_type, content, ttl,
				created_by_user_id, updated_by_user_id
			) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$8)
			RETURNING id, scope_id, zone_id, name, record_type, content, ttl,
			          status, revision, created_at, updated_at`,
			id, request.TargetScopeID, request.ZoneID, request.Name, request.Type,
			request.Content, request.TTL, actor.UserID,
		), &result)
		if err != nil {
			return mapWriteError(err)
		}
		if err := s.appendAudit(ctx, tx, actor, request.TargetScopeID, request.RequestID,
			"dns.record.create", "dns_record", result.ID, map[string]any{
				"zone_id": result.ZoneID, "name": result.Name, "type": result.Type, "ttl": result.TTL,
			}); err != nil {
			return err
		}
		return completeWrite(ctx, tx, actor, "dns.record.create", request.IdempotencyKey, result.ID, result)
	})
	return result, err
}

func (s *Store) UpdateRecord(ctx context.Context, actor Actor, request UpdateRecordRequest, digest [32]byte) (Record, error) {
	var result Record
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		scopeID, err := resourceScope(ctx, tx, "dns_records", actor, request.ID)
		if err != nil {
			return err
		}
		replay, err := reserveWrite(ctx, tx, actor, scopeID, "dns.record.update", request.IdempotencyKey, digest)
		if err != nil {
			return err
		}
		if replay != nil {
			return json.Unmarshal(replay, &result)
		}
		err = scanRecord(tx.QueryRow(ctx, `
			UPDATE dns_records SET name=$3, record_type=$4, content=$5, ttl=$6,
			    status='draft', revision=revision+1, updated_by_user_id=$7, updated_at=now()
			WHERE id=$1 AND revision=$2
			RETURNING id, scope_id, zone_id, name, record_type, content, ttl,
			          status, revision, created_at, updated_at`,
			request.ID, request.ExpectedRevision, request.Name, request.Type,
			request.Content, request.TTL, actor.UserID,
		), &result)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrRevisionConflict
		}
		if err != nil {
			return mapWriteError(err)
		}
		if err := s.appendAudit(ctx, tx, actor, scopeID, request.RequestID,
			"dns.record.update", "dns_record", result.ID, map[string]any{
				"name": result.Name, "type": result.Type, "ttl": result.TTL,
			}); err != nil {
			return err
		}
		return completeWrite(ctx, tx, actor, "dns.record.update", request.IdempotencyKey, result.ID, result)
	})
	return result, err
}

func (s *Store) ListRecords(ctx context.Context, actor Actor, zoneID uuid.UUID) ([]Record, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, scope_id, zone_id, name, record_type, content, ttl,
		       status, revision, created_at, updated_at
		FROM dns_records
		WHERE zone_id=$1 AND ($2 = 'platform' OR scope_id=$3)
		ORDER BY created_at DESC, id DESC`, zoneID, actor.ScopeKind, actor.ScopeID)
	if err != nil {
		return nil, fmt.Errorf("list DNS records: %w", err)
	}
	defer rows.Close()
	items := make([]Record, 0)
	for rows.Next() {
		var item Record
		if err := scanRecord(rows, &item); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *Store) DeleteRecord(ctx context.Context, actor Actor, request DeleteRequest, digest [32]byte) error {
	return s.deleteResource(ctx, actor, request, digest, "dns_records", "dns.record.delete", "dns_record")
}

func (s *Store) CreateOrder(
	ctx context.Context,
	actor Actor,
	request CreateOrderRequest,
	renewalOf *uuid.UUID,
	digest [32]byte,
) (CertificateOrder, error) {
	var result CertificateOrder
	id, err := uuid.NewV7()
	if err != nil {
		return CertificateOrder{}, err
	}
	var denial error
	err = pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		// The platform domain blocklist (#11) covers certificates too: no ACME
		// order is placed for a blocked name, whoever asks.
		if domain, blocked, err := domaintrust.BlockedDomain(ctx, tx, request.Domains); err != nil {
			return err
		} else if blocked {
			return &domaintrust.DomainError{Err: domaintrust.ErrDomainBlocked, Domain: domain}
		}
		// DNS-SEC-20261027-01: a tenant cannot order DNS-01 through the
		// platform DNS copy (the worker checks the order creator again).
		if request.DNSProviderID != nil {
			if err := refusePlatformManagedUse(ctx, tx, actor, request.TargetScopeID, *request.DNSProviderID); err != nil {
				return err
			}
		}
		if err := s.checkCreateOrderEntitlement(ctx, tx, actor, request, id); err != nil {
			if entitlementguard.IsDenial(err) {
				denial = err
				return nil
			}
			return err
		}
		replay, err := reserveWrite(ctx, tx, actor, request.TargetScopeID, "certificate.order.create", request.IdempotencyKey, digest)
		if err != nil {
			return err
		}
		if replay != nil {
			return json.Unmarshal(replay, &result)
		}
		if err := refuseOrderInFlight(ctx, tx, request.TargetScopeID, request.Domains); err != nil {
			return err
		}
		issuer, err := s.resolveOrderIssuer(ctx, tx, actor, request.TargetScopeID, request.Issuer)
		if err != nil {
			return err
		}
		err = scanOrder(tx.QueryRow(ctx, `
			INSERT INTO certificate_orders (
				id, scope_id, dns_provider_id, domains, challenge_type, auto_renew,
				renewal_of_order_id, created_by_user_id, updated_by_user_id, issuer, name, remark
			) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$8,$9,$10,$11)
			RETURNING `+certificateOrderProjection,
			id, request.TargetScopeID, request.DNSProviderID, request.Domains,
			request.ChallengeType, request.AutoRenew, renewalOf, actor.UserID, issuer, request.Name, request.Remark,
		), &result)
		if err != nil {
			return mapWriteError(err)
		}
		auditPayload := map[string]any{
			"domains": result.Domains, "challenge_type": result.ChallengeType,
			"dns_provider_id": result.DNSProviderID, "renewal_of_order_id": renewalOf,
			"issuer": result.Issuer,
		}
		if actor.ScopeKind == "platform" && actor.ScopeID != request.TargetScopeID {
			// A platform member ordering for a tenant (migration 531).
			auditPayload["on_behalf_of"] = "tenant"
			auditPayload["actor_scope_id"] = actor.ScopeID
		}
		if err := s.appendAudit(ctx, tx, actor, request.TargetScopeID, request.RequestID,
			"certificate.order.create", "certificate_order", result.ID, auditPayload); err != nil {
			return err
		}
		if err := enqueueCertificateOrder(ctx, tx, result); err != nil {
			return err
		}
		return completeWrite(ctx, tx, actor, "certificate.order.create", request.IdempotencyKey, result.ID, result)
	})
	if err == nil && denial != nil {
		err = denial
	}
	return result, err
}

// refuseOrderInFlight: ErrOrderInFlight when the scope has a pending,
// validating or issuing order for exactly this domain set (set equality: an
// order's domains are unique). The advisory lock (on the sorted set
// normalizeDomains leaves) serializes two concurrent orders for one set.
func refuseOrderInFlight(ctx context.Context, tx pgx.Tx, scopeID uuid.UUID, domains []string) error {
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('certificate_orders.in_flight:' || $1::text || ':' || array_to_string($2::text[], ','), 0))`,
		scopeID, domains); err != nil {
		return err
	}
	var inFlight bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM certificate_orders
		WHERE scope_id=$1 AND status IN ('pending','validating','issuing')
		  AND domains @> $2::text[] AND domains <@ $2::text[])`, scopeID, domains).Scan(&inFlight); err != nil {
		return err
	}
	if inFlight {
		return ErrOrderInFlight
	}
	return nil
}

// resolveOrderIssuer is the order's frozen CA: the explicit one, else the
// creating user's default issuer (证书默认设置). nil leaves the order on the
// platform default issuer, read when the order is first dispatched (as before
// 515). A CA without platform EAB credentials is refused.
func (s *Store) resolveOrderIssuer(ctx context.Context, tx pgx.Tx, actor Actor, scopeID uuid.UUID, explicit string) (*string, error) {
	issuer := explicit
	if issuer == "" {
		var stored *string
		err := tx.QueryRow(ctx, `SELECT issuer FROM certificate_user_defaults
			WHERE scope_id=$1 AND user_id=$2 AND certificate_type='acme'`, scopeID, actor.UserID).Scan(&stored)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return nil, err
		}
		if stored == nil {
			return nil, nil
		}
		issuer = *stored
	}
	configured, err := acmecacredentials.Configured(ctx, tx, issuer)
	if err != nil {
		return nil, err
	}
	if !configured {
		return nil, ErrIssuerUnavailable
	}
	return &issuer, nil
}

func (s *Store) checkCreateOrderEntitlement(
	ctx context.Context,
	tx pgx.Tx,
	actor Actor,
	request CreateOrderRequest,
	orderID uuid.UUID,
) error {
	if s.guard == nil {
		return entitlementguard.ErrUnavailable
	}
	_, err := s.guard.CheckFeature(ctx, tx, entitlementguard.FeatureCheck{
		TargetScopeID: request.TargetScopeID,
		ActorScopeID:  actor.ScopeID,
		ActorUserID:   actor.UserID,
		ResourceType:  "certificate_order",
		ResourceID:    orderID,
		RequestID:     request.RequestID,
		Operation:     "certificate.order.create",
		Feature:       entitlementguard.FeatureCertificatesIssue,
	})
	return err
}

// renewalBlockedPredicate is true when the platform domain blocklist covers
// any of source.domains, with the domaintrust.BlockedDomain rules (root:
// the name or a parent, wildcard by its base; exact: that host name only).
// Blocked certificates are not renewed.
const renewalBlockedPredicate = `EXISTS (
				SELECT 1 FROM unnest(source.domains) name
				JOIN platform_domain_blocklist entry ON
				     (entry.match_type='exact' AND name NOT LIKE '*.%' AND entry.pattern=name) OR
				     (entry.match_type='root' AND (regexp_replace(name,'^\*\.','')=entry.pattern OR
				      regexp_replace(name,'^\*\.','') LIKE '%.' || entry.pattern)))`

func (s *Store) ScheduleDueRenewal(
	ctx context.Context,
	renewBefore time.Duration,
	leaseDuration time.Duration,
) (bool, error) {
	outcome, err := s.scheduleDueRenewal(ctx, nil, renewBefore, leaseDuration, 0)
	return outcome.Scheduled, err
}

func (s *Store) ScheduleDueRenewalDetailed(
	ctx context.Context,
	renewBefore time.Duration,
	leaseDuration time.Duration,
	retryMaximum time.Duration,
) (acmeworker.RenewalScheduleOutcome, error) {
	return s.scheduleDueRenewal(ctx, nil, renewBefore, leaseDuration, retryMaximum)
}

func (s *Store) ScheduleDueRenewalAt(
	ctx context.Context,
	asOf time.Time,
	renewBefore time.Duration,
	leaseDuration time.Duration,
) (bool, error) {
	outcome, err := s.scheduleDueRenewal(ctx, &asOf, renewBefore, leaseDuration, 0)
	return outcome.Scheduled, err
}

func (s *Store) ScheduleDueRenewalDetailedAt(
	ctx context.Context,
	asOf time.Time,
	renewBefore time.Duration,
	leaseDuration time.Duration,
	retryMaximum time.Duration,
) (acmeworker.RenewalScheduleOutcome, error) {
	return s.scheduleDueRenewal(ctx, &asOf, renewBefore, leaseDuration, retryMaximum)
}

func (s *Store) scheduleDueRenewal(
	ctx context.Context,
	asOf *time.Time,
	renewBefore time.Duration,
	leaseDuration time.Duration,
	retryMaximum time.Duration,
) (acmeworker.RenewalScheduleOutcome, error) {
	if s == nil || s.pool == nil || s.auditor == nil || (asOf != nil && asOf.IsZero()) || renewBefore <= 0 ||
		renewBefore > 365*24*time.Hour || leaseDuration <= 0 || leaseDuration > 24*time.Hour ||
		retryMaximum < 0 || retryMaximum > 24*time.Hour {
		return acmeworker.RenewalScheduleOutcome{}, ErrInvalidInput
	}
	if asOf != nil {
		fixed := asOf.UTC().Truncate(time.Microsecond)
		asOf = &fixed
	}
	outcome := acmeworker.RenewalScheduleOutcome{}
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		var source CertificateOrder
		var actorID uuid.UUID
		var latestRevision *int64
		var latestStatus *string
		var latestChildID *uuid.UUID
		var latestChildStatus *string
		var latestChildUpdatedAt *time.Time
		var claimAt time.Time
		err := tx.QueryRow(ctx, `SELECT
			source.id,source.scope_id,source.dns_provider_id,source.domains,source.challenge_type,source.status,
			source.auto_renew,source.renewal_of_order_id,source.not_after,source.failure_code,
			source.issued_asset_id,source.issued_asset_version_id,source.issued_at,
			source.leaf_fingerprint_sha256,source.leaf_spki_sha256,
			source.acme_directory_url,source.acme_account_key_ref,source.certificate_key_ref,
			source.external_order_url,source.authorization_urls_sha256,source.certificate_url,
			source.revision,source.created_at,source.updated_at,source.issuer,source.name,source.remark,
			source.created_by_user_id,latest.revision,latest.status,latest.renewal_order_id,
			latest_child.status,latest_child.updated_at,
			COALESCE($6::timestamptz,statement_timestamp())
			FROM certificate_orders source
			JOIN users actor ON actor.id=source.created_by_user_id
			 AND acme_runtime_actor_is_active_048(source.scope_id,source.created_by_user_id)
			LEFT JOIN LATERAL (
				SELECT revision,status,event_type,lease_expires_at,next_attempt_at,renewal_order_id
				FROM acme_renewal_claim_facts claim
				WHERE claim.tenant_scope_id=source.scope_id AND claim.source_order_id=source.id
				ORDER BY revision DESC LIMIT 1
			) latest ON true
			LEFT JOIN certificate_orders latest_child
			  ON latest_child.scope_id=source.scope_id AND latest_child.id=latest.renewal_order_id
			LEFT JOIN LATERAL (
				SELECT COUNT(DISTINCT completed.renewal_order_id)::bigint AS failed_attempts,
				       MAX(child.updated_at) AS latest_failure_at
				FROM acme_renewal_claim_facts completed
				JOIN certificate_orders child
				  ON child.id=completed.renewal_order_id
				 AND child.scope_id=source.scope_id AND child.renewal_of_order_id=source.id
				 AND child.created_by_user_id=source.created_by_user_id AND child.status='failed'
				WHERE completed.tenant_scope_id=source.scope_id AND completed.source_order_id=source.id
				  AND completed.status='completed' AND completed.event_type='completed'
			) failure_history ON true
			CROSS JOIN LATERAL (
				SELECT source.not_after-($1 * interval '1 millisecond')+
					((('x' || substring(
						md5(source.id::text || ':' ||
							floor(extract(epoch from source.not_after) * 1000000)::bigint::text)
						from 1 for 8))::bit(32)::bigint %
						(LEAST(($1::bigint / 4), $3::bigint) + 1)) * interval '1 millisecond') AS initial_due
			) initial_schedule
			CROSS JOIN LATERAL (
				SELECT CASE WHEN $2 > 0 AND failure_history.failed_attempts > 0 THEN LEAST(
					$2::bigint,
					(LEAST($4::bigint, $2::bigint) * power(2::numeric,
						LEAST(GREATEST(failure_history.failed_attempts - 1, 0), $5::bigint)))::bigint,
					GREATEST(
						LEAST($4::bigint, $2::bigint),
						GREATEST(0, floor(extract(epoch from
							(source.not_after - failure_history.latest_failure_at)) * 1000)::bigint) / 4
					)
				) END AS retry_delay_ms
			) retry_schedule
			CROSS JOIN LATERAL (
				SELECT CASE
					WHEN latest.status='active' THEN latest.lease_expires_at
					WHEN latest.status='retry_wait' THEN latest.next_attempt_at
					WHEN latest.status='completed' AND $2 > 0
						THEN failure_history.latest_failure_at+
							retry_schedule.retry_delay_ms * interval '1 millisecond'
					ELSE initial_schedule.initial_due
				END AS effective_due
			) due
			WHERE certificate_asset_auto_renew_537(source.scope_id,source.issued_asset_id)
			  AND source.status IN ('active','renewal_due')
			  AND NOT `+renewalBlockedPredicate+`
			  AND NOT EXISTS (
				SELECT 1 FROM certificate_orders child
				WHERE child.scope_id=source.scope_id AND child.renewal_of_order_id=source.id
				  AND child.status NOT IN ('failed','revoked')
			  )
			  AND (
				latest.revision IS NULL
				OR latest.status='active'
				OR latest.status='retry_wait'
				OR (latest.status='completed' AND $2 > 0
					AND latest.event_type='completed'
					AND latest_child.status='failed'
					AND latest_child.renewal_of_order_id=source.id
					AND latest_child.created_by_user_id=source.created_by_user_id
					AND failure_history.failed_attempts > 0)
			  )
			  AND CASE WHEN $6::timestamptz IS NULL
				THEN due.effective_due <= statement_timestamp()
				ELSE due.effective_due <= $6
			  END
			ORDER BY due.effective_due,source.not_after,source.id
			FOR UPDATE OF source SKIP LOCKED LIMIT 1`,
			renewBefore.Milliseconds(), retryMaximum.Milliseconds(), renewalJitterMaximum.Milliseconds(),
			renewalRetryBaseMaximum.Milliseconds(), renewalRetryExponentMaximum, asOf).Scan(
			&source.ID, &source.ScopeID, &source.DNSProviderID, &source.Domains,
			&source.ChallengeType, &source.Status, &source.AutoRenew, &source.RenewalOfOrderID,
			&source.NotAfter, &source.FailureCode, &source.IssuedAssetID, &source.IssuedVersionID,
			&source.IssuedAt, &source.LeafFingerprint, &source.LeafSPKIDigest,
			&source.acmeDirectoryURL, &source.acmeAccountKeyRef, &source.certificateKeyRef,
			&source.externalOrderURL, &source.authorizationURLDigest, &source.certificateURL,
			&source.Revision, &source.CreatedAt, &source.UpdatedAt, &source.Issuer, &source.Name, &source.Remark,
			&actorID, &latestRevision, &latestStatus, &latestChildID, &latestChildStatus,
			&latestChildUpdatedAt, &claimAt,
		)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("select due certificate renewal: %w", err)
		}
		// Under READ COMMITTED a contender whose statement started before the
		// winner committed, but locked the source row after it, rechecks only
		// that row (EvalPlanQual); the claim history and children it joined
		// are still from its statement snapshot. A fresh statement sees the
		// winner's committed claim: then this scheduler did not win.
		var currentRevision *int64
		if err := tx.QueryRow(ctx, `SELECT max(revision) FROM acme_renewal_claim_facts
			WHERE tenant_scope_id=$1 AND source_order_id=$2`, source.ScopeID, source.ID).Scan(&currentRevision); err != nil {
			return fmt.Errorf("recheck certificate renewal claim: %w", err)
		}
		if (currentRevision == nil) != (latestRevision == nil) ||
			currentRevision != nil && *currentRevision != *latestRevision {
			return nil
		}

		token, err := uuid.NewV7()
		if err != nil {
			return err
		}
		claimRevision := int64(1)
		claimEvent := "claim_created"
		reopened := false
		if latestRevision != nil {
			claimRevision = *latestRevision + 1
			claimEvent = "lease_taken_over"
		}
		if latestStatus != nil && *latestStatus == "completed" {
			if latestChildID == nil {
				return ErrConflict
			}
			claimEvent = "claim_reopened"
			reopened = true
		} else if latestStatus != nil && *latestStatus != "active" && *latestStatus != "retry_wait" {
			return ErrConflict
		}
		if _, err := tx.Exec(ctx, `INSERT INTO acme_renewal_claim_facts(
			tenant_scope_id,source_order_id,revision,actor_user_id,event_type,status,
			fence_token,lease_token,lease_expires_at,reopened_from_order_id,occurred_at
		) VALUES($1,$2,$3,$4,$5,'active',$6,$6,$7,$8,$9)`, source.ScopeID, source.ID,
			claimRevision, actorID, claimEvent, token, claimAt.Add(leaseDuration), latestChildID, claimAt); err != nil {
			return fmt.Errorf("claim due certificate renewal: %w", err)
		}
		if source.Status == OrderActive {
			result, err := tx.Exec(ctx, `UPDATE certificate_orders SET
				status='renewal_due',revision=revision+1,updated_at=statement_timestamp()
				WHERE scope_id=$1 AND id=$2 AND status='active' AND revision=$3`,
				source.ScopeID, source.ID, source.Revision)
			if err != nil {
				return fmt.Errorf("mark certificate renewal due: %w", err)
			}
			if result.RowsAffected() != 1 {
				return ErrConflict
			}
		}

		childID, err := uuid.NewV7()
		if err != nil {
			return err
		}
		var child CertificateOrder
		// A renewal keeps its source's CA, name and remark (CERT-04). It is
		// scheduled only while the certificate auto-renews (asset level,
		// migration 540), so the child order auto-renews too.
		err = scanOrder(tx.QueryRow(ctx, `INSERT INTO certificate_orders(
			id,scope_id,dns_provider_id,domains,challenge_type,auto_renew,
			renewal_of_order_id,created_by_user_id,updated_by_user_id,issuer,name,remark
		) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$8,$9,$10,$11) RETURNING `+certificateOrderProjection,
			childID, source.ScopeID, source.DNSProviderID, source.Domains, source.ChallengeType,
			true, source.ID, actorID, source.Issuer, source.Name, source.Remark), &child)
		if err != nil {
			return fmt.Errorf("create certificate renewal order: %w", err)
		}
		requestID := "acme-renewal:" + child.ID.String()
		reason := "renewal_window_elapsed"
		auditPayload := map[string]any{"operation": "schedule_renewal", "reason": reason, "source_order_id": source.ID}
		if reopened {
			auditPayload["reason"] = "failed_renewal_retry"
			auditPayload["previous_child_order_id"] = latestChildID
		}
		if err := s.appendAudit(ctx, tx, Actor{UserID: actorID, ScopeID: source.ScopeID, ScopeKind: "tenant"},
			source.ScopeID, requestID, "certificate.order.renew", "certificate_order", child.ID,
			auditPayload); err != nil {
			return err
		}
		if err := enqueueCertificateOrder(ctx, tx, child); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO acme_renewal_claim_facts(
			tenant_scope_id,source_order_id,revision,actor_user_id,event_type,status,
			fence_token,renewal_order_id,occurred_at
		) VALUES($1,$2,$3,$4,'completed','completed',$5,$6,$7)`, source.ScopeID,
			source.ID, claimRevision+1, actorID, token, child.ID, claimAt); err != nil {
			return fmt.Errorf("complete certificate renewal claim: %w", err)
		}
		outcome.Scheduled = true
		outcome.Reopened = reopened
		return nil
	})
	return outcome, err
}

func (s *Store) ListOrders(ctx context.Context, actor Actor) ([]CertificateOrder, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT `+certificateOrderProjection+`,
			retry.last_error_code, retry.last_error_reason
		FROM certificate_orders
		LEFT JOIN LATERAL (SELECT outbox.last_error_code, outbox.last_error_reason FROM dns_acme_outbox outbox
			WHERE certificate_orders.status IN ('pending','validating','issuing')
			  AND outbox.scope_id=certificate_orders.scope_id AND outbox.aggregate_id=certificate_orders.id
			  AND outbox.status='failed' ORDER BY outbox.updated_at DESC LIMIT 1) retry ON true
		WHERE $1 = 'platform' OR certificate_orders.scope_id=$2
		ORDER BY certificate_orders.created_at DESC, certificate_orders.id DESC`, actor.ScopeKind, actor.ScopeID)
	if err != nil {
		return nil, fmt.Errorf("list certificate orders: %w", err)
	}
	defer rows.Close()
	items := make([]CertificateOrder, 0)
	for rows.Next() {
		var item CertificateOrder
		if err := scanOrderWithRetry(rows, &item); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

// TransitionOrder is retained only to fail closed for direct legacy Store callers.
func (s *Store) TransitionOrder(context.Context, Actor, TransitionOrderRequest, [32]byte) (CertificateOrder, error) {
	return CertificateOrder{}, ErrPermissionDenied
}

// CreateRenewal is retained only to fail closed for direct legacy Store callers.
func (s *Store) CreateRenewal(context.Context, Actor, CreateRenewalRequest, [32]byte) (CertificateOrder, error) {
	return CertificateOrder{}, ErrPermissionDenied
}

func (s *Store) deleteResource(
	ctx context.Context,
	actor Actor,
	request DeleteRequest,
	digest [32]byte,
	table string,
	operation string,
	resourceType string,
) error {
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		replay, err := findCompletedWrite(ctx, tx, actor, operation, request.IdempotencyKey, digest)
		if err != nil {
			return err
		}
		if replay {
			return nil
		}
		scopeID, err := resourceScope(ctx, tx, table, actor, request.ID)
		if errors.Is(err, ErrNotFound) {
			replay, replayErr := findCompletedWrite(ctx, tx, actor, operation, request.IdempotencyKey, digest)
			if replayErr != nil {
				return replayErr
			}
			if replay {
				return nil
			}
		}
		if err != nil {
			return err
		}
		response, err := reserveWrite(ctx, tx, actor, scopeID, operation, request.IdempotencyKey, digest)
		if err != nil {
			return err
		}
		if response != nil {
			return nil
		}
		command := fmt.Sprintf("DELETE FROM %s WHERE id=$1 AND revision=$2", table)
		result, err := tx.Exec(ctx, command, request.ID, request.ExpectedRevision)
		if err != nil {
			var pgErr *pgconn.PgError
			if errors.As(err, &pgErr) && pgErr.Code == "23503" {
				return ErrConflict
			}
			return mapWriteError(err)
		}
		if result.RowsAffected() != 1 {
			return ErrRevisionConflict
		}
		if err := s.appendAudit(ctx, tx, actor, scopeID, request.RequestID,
			operation, resourceType, request.ID, map[string]any{"version": request.ExpectedRevision}); err != nil {
			return err
		}
		return completeWrite(ctx, tx, actor, operation, request.IdempotencyKey, request.ID, map[string]bool{"deleted": true})
	})
}

func findCompletedWrite(
	ctx context.Context,
	tx pgx.Tx,
	actor Actor,
	operation string,
	key string,
	digest [32]byte,
) (bool, error) {
	var storedDigest []byte
	var completed bool
	err := tx.QueryRow(ctx, `
		SELECT request_digest, completed_at IS NOT NULL
		FROM dns_acme_write_requests
		WHERE actor_user_id=$1 AND operation=$2 AND idempotency_key=$3`,
		actor.UserID, operation, key,
	).Scan(&storedDigest, &completed)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if !bytes.Equal(storedDigest, digest[:]) {
		return false, ErrIdempotencyConflict
	}
	if !completed {
		return false, fmt.Errorf("incomplete idempotent request")
	}
	return true, nil
}

func enqueueCertificateOrder(ctx context.Context, tx pgx.Tx, order CertificateOrder) error {
	id, err := uuid.NewV7()
	if err != nil {
		return err
	}
	payload, err := json.Marshal(map[string]any{
		"order_id": order.ID, "challenge_type": order.ChallengeType,
		"domains": order.Domains, "dns_provider_id": order.DNSProviderID,
	})
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `
		INSERT INTO dns_acme_outbox (
			id, scope_id, aggregate_type, aggregate_id, event_type, payload
		) VALUES ($1,$2,'certificate_order',$3,'certificate.order.requested',$4)`,
		id, order.ScopeID, order.ID, payload)
	if err != nil {
		return fmt.Errorf("enqueue certificate order: %w", err)
	}
	return nil
}

func resourceScope(ctx context.Context, tx pgx.Tx, table string, actor Actor, id uuid.UUID) (uuid.UUID, error) {
	allowed := map[string]bool{
		"dns_providers": true, "dns_zones": true, "dns_records": true, "certificate_orders": true,
	}
	if !allowed[table] {
		return uuid.Nil, ErrInvalidInput
	}
	query := fmt.Sprintf("SELECT scope_id FROM %s WHERE id=$1 AND ($2='platform' OR scope_id=$3) FOR UPDATE", table)
	var scopeID uuid.UUID
	err := tx.QueryRow(ctx, query, id, actor.ScopeKind, actor.ScopeID).Scan(&scopeID)
	if errors.Is(err, pgx.ErrNoRows) {
		return uuid.Nil, ErrNotFound
	}
	if err != nil {
		return uuid.Nil, err
	}
	return scopeID, nil
}

func reserveWrite(
	ctx context.Context,
	tx pgx.Tx,
	actor Actor,
	scopeID uuid.UUID,
	operation string,
	key string,
	digest [32]byte,
) ([]byte, error) {
	id, err := uuid.NewV7()
	if err != nil {
		return nil, err
	}
	result, err := tx.Exec(ctx, `
		INSERT INTO dns_acme_write_requests (
			id, actor_user_id, target_scope_id, operation, idempotency_key, request_digest
		) VALUES ($1,$2,$3,$4,$5,$6)
		ON CONFLICT (actor_user_id, operation, idempotency_key) DO NOTHING`,
		id, actor.UserID, scopeID, operation, key, digest[:])
	if err != nil {
		return nil, err
	}
	if result.RowsAffected() == 1 {
		return nil, nil
	}
	var storedDigest, response []byte
	err = tx.QueryRow(ctx, `
		SELECT request_digest, response_body::text::bytea
		FROM dns_acme_write_requests
		WHERE actor_user_id=$1 AND operation=$2 AND idempotency_key=$3
		FOR UPDATE`, actor.UserID, operation, key).Scan(&storedDigest, &response)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(storedDigest, digest[:]) {
		return nil, ErrIdempotencyConflict
	}
	if len(response) == 0 {
		return nil, fmt.Errorf("incomplete idempotent request")
	}
	return response, nil
}

func completeWrite(
	ctx context.Context,
	tx pgx.Tx,
	actor Actor,
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
		UPDATE dns_acme_write_requests
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

func (s *Store) appendAudit(
	ctx context.Context,
	tx pgx.Tx,
	actor Actor,
	scopeID uuid.UUID,
	requestID string,
	action string,
	resourceType string,
	resourceID uuid.UUID,
	payload map[string]any,
) error {
	actorID := actor.UserID
	return s.auditor.Append(ctx, tx, audit.Event{
		ScopeID: scopeID, ActorUserID: &actorID, Action: action, ResourceType: resourceType,
		ResourceID: resourceID.String(), RequestID: requestID, Result: "success", Payload: payload,
	})
}

type rowScanner interface {
	Scan(...any) error
}

func scanProvider(row rowScanner, item *Provider) error {
	return row.Scan(&item.ID, &item.ScopeID, &item.Name, &item.Remark, &item.ProviderType,
		&item.CredentialsConfigured, &item.Status, &item.ManagedBy, &item.Revision, &item.CreatedAt, &item.UpdatedAt)
}

func scanZone(row rowScanner, item *Zone) error {
	return row.Scan(&item.ID, &item.ScopeID, &item.ProviderID, &item.Name,
		&item.Status, &item.Revision, &item.CreatedAt, &item.UpdatedAt)
}

func scanRecord(row rowScanner, item *Record) error {
	return row.Scan(&item.ID, &item.ScopeID, &item.ZoneID, &item.Name, &item.Type,
		&item.Content, &item.TTL, &item.Status, &item.Revision, &item.CreatedAt, &item.UpdatedAt)
}

func scanOrder(row rowScanner, item *CertificateOrder) error {
	return row.Scan(&item.ID, &item.ScopeID, &item.DNSProviderID, &item.Domains,
		&item.ChallengeType, &item.Status, &item.AutoRenew, &item.RenewalOfOrderID,
		&item.NotAfter, &item.FailureCode, &item.FailureReason, &item.IssuedAssetID, &item.IssuedVersionID,
		&item.IssuedAt, &item.LeafFingerprint, &item.LeafSPKIDigest,
		&item.acmeDirectoryURL, &item.acmeAccountKeyRef, &item.certificateKeyRef,
		&item.externalOrderURL, &item.authorizationURLDigest, &item.certificateURL,
		&item.Revision, &item.CreatedAt, &item.UpdatedAt, &item.Issuer, &item.Name, &item.Remark)
}

func scanOrderWithRetry(row rowScanner, item *CertificateOrder) error {
	return row.Scan(&item.ID, &item.ScopeID, &item.DNSProviderID, &item.Domains,
		&item.ChallengeType, &item.Status, &item.AutoRenew, &item.RenewalOfOrderID,
		&item.NotAfter, &item.FailureCode, &item.FailureReason, &item.IssuedAssetID, &item.IssuedVersionID,
		&item.IssuedAt, &item.LeafFingerprint, &item.LeafSPKIDigest,
		&item.acmeDirectoryURL, &item.acmeAccountKeyRef, &item.certificateKeyRef,
		&item.externalOrderURL, &item.authorizationURLDigest, &item.certificateURL,
		&item.Revision, &item.CreatedAt, &item.UpdatedAt, &item.Issuer, &item.Name, &item.Remark, &item.RetryErrorCode,
		&item.RetryErrorReason)
}

func mapWriteError(err error) error {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		switch pgErr.Code {
		case "23503":
			return ErrNotFound
		case "23505":
			return ErrConflict
		case "P8903":
			return ErrRevisionConflict
		case "23514", "22P02":
			return ErrInvalidInput
		}
	}
	if strings.Contains(err.Error(), "violates check constraint") {
		return ErrInvalidInput
	}
	return err
}
