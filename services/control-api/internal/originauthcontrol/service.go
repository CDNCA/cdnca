package originauthcontrol

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/entitlementguard"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

type AuditAppender interface {
	Append(context.Context, pgx.Tx, audit.Event) error
}

type txAuthorizer interface {
	Authorize(context.Context, pgx.Tx, Actor, uuid.UUID, string) error
}

type denyTxAuthorizer struct{}

func (denyTxAuthorizer) Authorize(context.Context, pgx.Tx, Actor, uuid.UUID, string) error {
	return ErrPermissionDenied
}

type Config struct {
	Clock          func() time.Time
	Verifier       CredentialVerifier
	Auditor        AuditAppender
	Entitlement    EntitlementGate
	TrustStore     *entitlementguard.TrustStore
	EgressPolicies map[string][]string
	// Published runs in the publication's transaction after a new origin auth
	// publication of the scope is stored (the edge publication service's
	// site object republication); nil: nothing.
	Published func(ctx context.Context, tx pgx.Tx, scopeID uuid.UUID) error
}

type Service struct {
	pool           *pgxpool.Pool
	keyring        *Keyring
	verifier       CredentialVerifier
	auditor        AuditAppender
	entitlement    EntitlementGate
	authorizer     txAuthorizer
	now            func() time.Time
	egressPolicies map[string]map[string]struct{}
	published      func(ctx context.Context, tx pgx.Tx, scopeID uuid.UUID) error
}

type entitlementAdapter struct {
	guard *entitlementguard.Guard
}

func (adapter entitlementAdapter) Check(ctx context.Context, tx pgx.Tx, check EntitlementCheck) error {
	return adapter.guard.CheckSiteChange(ctx, tx, entitlementguard.SiteCheck{
		AuditScopeID: check.AuditScopeID,
		ActorUserID:  check.ActorUserID,
		ResourceID:   check.ResourceID,
		RequestID:    check.RequestID,
		Operation:    check.Operation,
		Delta:        0,
	})
}

func NewService(pool *pgxpool.Pool, keyring *Keyring, config Config) (*Service, error) {
	return newService(pool, keyring, config, denyTxAuthorizer{})
}

func newService(pool *pgxpool.Pool, keyring *Keyring, config Config, authorizer txAuthorizer) (*Service, error) {
	if pool == nil || keyring == nil || isNilDependency(authorizer) ||
		config.Verifier != nil && isNilDependency(config.Verifier) ||
		config.Auditor != nil && isNilDependency(config.Auditor) ||
		config.Entitlement != nil && isNilDependency(config.Entitlement) {
		return nil, ErrInvalidInput
	}
	if config.Clock == nil {
		config.Clock = time.Now
	}
	if config.Auditor == nil {
		config.Auditor = audit.New(pool)
	}
	if config.Entitlement == nil {
		config.Entitlement = entitlementAdapter{
			guard: entitlementguard.NewGuard(pool, config.Clock, config.TrustStore),
		}
	}
	policies, err := normalizeEgressPolicies(config.EgressPolicies)
	if err != nil {
		return nil, err
	}
	return &Service{
		pool: pool, keyring: keyring, verifier: config.Verifier, auditor: config.Auditor,
		entitlement: config.Entitlement, authorizer: authorizer, now: config.Clock, egressPolicies: policies,
		published: config.Published,
	}, nil
}

type storedWrite struct {
	found        bool
	responseBody []byte
	status       int
}

type storedCredential struct {
	Credential
	tenantID     uuid.UUID
	keyID        string
	ciphertext   []byte
	cipherDigest []byte
}

type secretDocument struct {
	SchemaVersion   string    `json:"schema_version"`
	Provider        string    `json:"provider"`
	AccessKeyID     string    `json:"access_key_id"`
	SecretAccessKey string    `json:"secret_access_key"`
	SessionToken    string    `json:"session_token"`
	NotBefore       time.Time `json:"not_before"`
	ExpiresAt       time.Time `json:"expires_at"`
}

func (service *Service) authorizeTarget(
	ctx context.Context,
	tx pgx.Tx,
	actor Actor,
	targetScopeID uuid.UUID,
	permission string,
) (uuid.UUID, error) {
	if err := validateTarget(actor, targetScopeID); err != nil {
		return uuid.Nil, err
	}
	crossTenant := actor.ScopeKind == "tenant" && actor.ScopeID != targetScopeID
	if service.authorizer == nil || tx == nil {
		return uuid.Nil, ErrPermissionDenied
	}
	if err := service.authorizer.Authorize(ctx, tx, actor, targetScopeID, permission); err != nil {
		if crossTenant && errors.Is(err, ErrPermissionDenied) {
			return uuid.Nil, ErrNotFound
		}
		return uuid.Nil, err
	}
	if crossTenant {
		return uuid.Nil, ErrNotFound
	}
	var tenantID uuid.UUID
	err := tx.QueryRow(ctx, `
		SELECT target.tenant_id
		FROM access_scopes target
		JOIN tenants tenant ON tenant.id=target.tenant_id AND tenant.status='active'
		WHERE target.id=$1 AND target.kind='tenant'
		  AND EXISTS (
		      SELECT 1 FROM access_scopes actor_scope
		      JOIN memberships membership
		        ON membership.scope_id=actor_scope.id AND membership.user_id=$3
		       AND membership.status='active'
		      JOIN users account ON account.id=membership.user_id AND account.status='active'
		      WHERE actor_scope.id=$2 AND actor_scope.kind=$4
		  )`, targetScopeID, actor.ScopeID, actor.UserID, actor.ScopeKind).Scan(&tenantID)
	if errors.Is(err, pgx.ErrNoRows) {
		return uuid.Nil, ErrNotFound
	}
	if err != nil {
		return uuid.Nil, err
	}
	return tenantID, nil
}

func (service *Service) authorizedRead(
	ctx context.Context,
	actor Actor,
	targetScopeID uuid.UUID,
	permission string,
	read func(pgx.Tx) error,
) error {
	if read == nil {
		return ErrInvalidInput
	}
	return pgx.BeginFunc(ctx, service.pool, func(tx pgx.Tx) error {
		if _, err := service.authorizeTarget(ctx, tx, actor, targetScopeID, permission); err != nil {
			return err
		}
		return read(tx)
	})
}

func (service *Service) checkEntitlement(
	ctx context.Context,
	tx pgx.Tx,
	actor Actor,
	targetScopeID, resourceID uuid.UUID,
	metadata WriteMetadata,
	operation string,
) error {
	if service.entitlement == nil {
		return ErrEntitlementUnavailable
	}
	err := service.entitlement.Check(ctx, tx, EntitlementCheck{
		AuditScopeID: targetScopeID, ActorUserID: actor.UserID, ResourceID: resourceID,
		RequestID: metadata.RequestID, Operation: operation,
	})
	switch {
	case err == nil:
		return nil
	case errors.Is(err, entitlementguard.ErrUnavailable), errors.Is(err, entitlementguard.ErrInvalid):
		return ErrEntitlementUnavailable
	case entitlementguard.IsDenial(err):
		return ErrEntitlementDenied
	default:
		return err
	}
}

func (service *Service) claimWrite(
	ctx context.Context,
	tx pgx.Tx,
	actor Actor,
	targetScopeID uuid.UUID,
	operation string,
	metadata WriteMetadata,
	digest [32]byte,
) (storedWrite, error) {
	requestID, err := uuid.NewV7()
	if err != nil {
		return storedWrite{}, err
	}
	now := storeTime(service.now())
	command, err := tx.Exec(ctx, `INSERT INTO origin_auth_write_requests(
		id,actor_scope_id,actor_user_id,target_scope_id,operation,idempotency_key,request_digest,
		request_id,trace_id,created_at)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
		ON CONFLICT(actor_scope_id,actor_user_id,operation,idempotency_key) DO NOTHING`,
		requestID, actor.ScopeID, actor.UserID, targetScopeID, operation, metadata.IdempotencyKey,
		digest[:], metadata.RequestID, metadata.TraceID, now)
	if err != nil {
		return storedWrite{}, err
	}
	if command.RowsAffected() == 1 {
		return storedWrite{}, nil
	}
	var existingTarget uuid.UUID
	var existingDigest []byte
	var body []byte
	var status *int
	var completedAt *time.Time
	err = tx.QueryRow(ctx, `SELECT target_scope_id,request_digest,response_body,response_status,completed_at
		FROM origin_auth_write_requests
		WHERE actor_scope_id=$1 AND actor_user_id=$2 AND operation=$3 AND idempotency_key=$4
		FOR UPDATE`, actor.ScopeID, actor.UserID, operation, metadata.IdempotencyKey).Scan(
		&existingTarget, &existingDigest, &body, &status, &completedAt)
	if err != nil {
		return storedWrite{}, err
	}
	if existingTarget != targetScopeID || !bytes.Equal(existingDigest, digest[:]) || status == nil || completedAt == nil {
		return storedWrite{}, ErrIdempotencyConflict
	}
	return storedWrite{found: true, responseBody: body, status: *status}, nil
}

func (service *Service) completeWrite(
	ctx context.Context,
	tx pgx.Tx,
	actor Actor,
	operation, idempotencyKey string,
	resourceID uuid.UUID,
	status int,
	response any,
) error {
	encoded, err := encodeJSON(response)
	if err != nil || len(encoded) > maximumJSONBytes {
		return ErrUnavailable
	}
	command, err := tx.Exec(ctx, `UPDATE origin_auth_write_requests SET
		resource_id=$5,response_status=$6,response_body=$7,completed_at=$8
		WHERE actor_scope_id=$1 AND actor_user_id=$2 AND operation=$3 AND idempotency_key=$4
		  AND completed_at IS NULL`, actor.ScopeID, actor.UserID, operation, idempotencyKey,
		resourceID, status, encoded, storeTime(service.now()))
	if err != nil {
		return err
	}
	if command.RowsAffected() != 1 {
		return ErrIdempotencyConflict
	}
	return nil
}

func (service *Service) appendAudit(
	ctx context.Context,
	tx pgx.Tx,
	actor Actor,
	targetScopeID, resourceID uuid.UUID,
	metadata WriteMetadata,
	action, resourceType string,
	payload map[string]any,
) error {
	if payload == nil {
		payload = map[string]any{}
	}
	payload["trace_id"] = metadata.TraceID
	return service.auditor.Append(ctx, tx, audit.Event{
		ScopeID: targetScopeID, ActorUserID: &actor.UserID, Action: action,
		ResourceType: resourceType, ResourceID: resourceID.String(), RequestID: metadata.RequestID,
		Result: "success", Payload: payload,
	})
}

// sealedRevisionColumn is the revision a credential revision's ciphertext
// was sealed under (its AAD): verify/disable/delete copy the ciphertext of
// the create or replace revision before them.
const sealedRevisionColumn = `(SELECT max(sealed.revision) FROM origin_auth_credential_revisions sealed
		WHERE sealed.credential_id=revision.credential_id AND sealed.revision<=revision.revision
		  AND sealed.operation IN ('create','replace'))`

func credentialAAD(id uuid.UUID, revision int64, provider string) []byte {
	return []byte(fmt.Sprintf("credential=%s\x00provider=%s\x00revision=%d", id, provider, revision))
}

func encodeSecret(provider string, secret CredentialSecret) ([]byte, error) {
	document := secretDocument{
		SchemaVersion: "cdnca.control.originauth.credential/v1", Provider: provider,
		AccessKeyID: secret.AccessKeyID, SecretAccessKey: secret.SecretAccessKey,
		SessionToken: secret.SessionToken, NotBefore: storeTime(secret.NotBefore), ExpiresAt: storeTime(secret.ExpiresAt),
	}
	return json.Marshal(document)
}

func decodeSecret(raw []byte, provider string) (CredentialSecret, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var document secretDocument
	if err := decoder.Decode(&document); err != nil || document.SchemaVersion != "cdnca.control.originauth.credential/v1" ||
		document.Provider != provider {
		return CredentialSecret{}, ErrEncryptionUnavailable
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return CredentialSecret{}, ErrEncryptionUnavailable
	}
	return CredentialSecret{
		AccessKeyID: document.AccessKeyID, SecretAccessKey: document.SecretAccessKey,
		SessionToken: document.SessionToken, NotBefore: document.NotBefore, ExpiresAt: document.ExpiresAt,
	}, nil
}

func (service *Service) decryptCredential(stored storedCredential) (CredentialSecret, error) {
	plaintext, err := service.keyring.open(stored.keyID, stored.ciphertext,
		credentialAAD(stored.ID, stored.Revision, stored.Provider))
	if err != nil {
		return CredentialSecret{}, ErrEncryptionUnavailable
	}
	defer clearBytes(plaintext)
	secret, err := decodeSecret(plaintext, stored.Provider)
	if err != nil {
		clearSecret(&secret)
		return CredentialSecret{}, ErrEncryptionUnavailable
	}
	return secret, nil
}

func normalizeServiceError(err error) error {
	if err == nil {
		return nil
	}
	known := []error{
		ErrUnauthenticated, ErrInvalidInput, ErrValidation, ErrPermissionDenied, ErrNotFound, ErrConflict, ErrSiteLocked,
		ErrRevisionConflict, ErrIdempotencyConflict, ErrCredentialUnverified,
		ErrVerificationRejected, ErrVerifierUnavailable, ErrEncryptionUnavailable,
		ErrEntitlementDenied, ErrEntitlementUnavailable, context.Canceled, context.DeadlineExceeded,
	}
	for _, candidate := range known {
		if errors.Is(err, candidate) {
			return candidate
		}
	}
	var databaseError *pgconn.PgError
	if errors.As(err, &databaseError) {
		switch databaseError.Code {
		case "23505", "23514", "P0001":
			return ErrConflict
		case "23503":
			return ErrNotFound
		}
	}
	return ErrUnavailable
}

func digestCiphertext(value []byte) [32]byte {
	return sha256.Sum256(value)
}

func isNilDependency(value any) bool {
	if value == nil {
		return true
	}
	kind := reflect.ValueOf(value).Kind()
	return (kind == reflect.Chan || kind == reflect.Func || kind == reflect.Interface ||
		kind == reflect.Map || kind == reflect.Pointer || kind == reflect.Slice) && reflect.ValueOf(value).IsNil()
}
