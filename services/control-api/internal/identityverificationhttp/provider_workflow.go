package identityverificationhttp

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/identityverification"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	defaultProviderSessionTTL      = 30 * time.Minute
	defaultProviderUploadTTL       = 15 * time.Minute
	defaultProviderRetention       = 30 * 24 * time.Hour
	defaultProviderCallbackMaxAge  = 5 * time.Minute
	defaultProviderCallbackSkew    = 30 * time.Second
	defaultProviderEraseLease      = time.Minute
	defaultProviderEraseRetry      = 5 * time.Minute
	providerTokenDomain            = "cdnca.identity-verification.provider-token.v1\x00"
	providerRequestDigestDomain    = "cdnca.identity-verification.provider-session.v1\x00"
	providerUploadDigestDomain     = "cdnca.identity-verification.provider-upload.v1\x00"
	providerNormalizedDigestDomain = "cdnca.identity-verification.provider-settlement.v1\x00"
)

type ProviderWorkflow struct {
	pool               *pgxpool.Pool
	auditor            identityverification.AuditAppender
	authorizer         providerWriteAuthorizer
	objects            PrivateObjectStore
	provider           KYCProvider
	now                identityverification.Clock
	newID              identityverification.IDGenerator
	tokenKey           []byte
	resolverName       string
	encryptionKeyID    string
	sessionTTL         time.Duration
	uploadTTL          time.Duration
	retentionPeriod    time.Duration
	callbackMaxAge     time.Duration
	callbackFutureSkew time.Duration
	eraseLease         time.Duration
	eraseRetry         time.Duration
}

type providerSessionRecord struct {
	ID                uuid.UUID
	TenantScopeID     uuid.UUID
	ActorUserID       uuid.UUID
	ActorSessionID    uuid.UUID
	Kind              string
	Provider          string
	ProviderRequestID string
	ExternalSessionID *string
	RequestDigest     []byte
	State             string
	Revision          int64
	AttemptCount      int64
	ExpiresAt         time.Time
	UpdatedAt         time.Time
}

type providerUploadRecord struct {
	ID              uuid.UUID
	SessionID       uuid.UUID
	TenantScopeID   uuid.UUID
	ActorUserID     uuid.UUID
	MaterialKind    string
	ObjectKey       string
	ObjectVersion   *string
	ObjectSHA256    []byte
	SizeBytes       int64
	ContentType     string
	EncryptionKeyID string
	IdempotencyKey  string
	State           string
	Revision        int64
	ExpiresAt       time.Time
	UpdatedAt       time.Time
}

type eraseClaim struct {
	ID            uuid.UUID
	UploadID      uuid.UUID
	SessionID     uuid.UUID
	TenantScopeID uuid.UUID
	ActorUserID   uuid.UUID
	ObjectKey     string
	ObjectVersion string
	LeaseToken    uuid.UUID
	Revision      int64
	AttemptCount  int64
}

func NewProviderWorkflow(pool *pgxpool.Pool, auditor identityverification.AuditAppender,
	authorizer providerWriteAuthorizer, objects PrivateObjectStore, provider KYCProvider,
	config ProviderWorkflowConfig,
) (*ProviderWorkflow, error) {
	if pool == nil || isNilDependency(auditor) || isNilProviderAuthorizer(authorizer) ||
		!configuredPrivateObjectStore(objects) || !configuredKYCProvider(provider) {
		return nil, ErrInvalidService
	}
	if config.Clock == nil {
		config.Clock = time.Now
	}
	if config.NewID == nil {
		config.NewID = uuid.NewV7
	}
	if config.SessionTTL == 0 {
		config.SessionTTL = defaultProviderSessionTTL
	}
	if config.UploadTTL == 0 {
		config.UploadTTL = defaultProviderUploadTTL
	}
	if config.RetentionPeriod == 0 {
		config.RetentionPeriod = defaultProviderRetention
	}
	if config.CallbackMaxAge == 0 {
		config.CallbackMaxAge = defaultProviderCallbackMaxAge
	}
	if config.CallbackFutureSkew == 0 {
		config.CallbackFutureSkew = defaultProviderCallbackSkew
	}
	if config.EraseLeaseDuration == 0 {
		config.EraseLeaseDuration = defaultProviderEraseLease
	}
	if config.EraseRetryDelay == 0 {
		config.EraseRetryDelay = defaultProviderEraseRetry
	}
	if len(config.TokenKey) < 32 || len(config.TokenKey) > 128 ||
		!resolverNamePattern.MatchString(config.ResolverName) ||
		!evidenceKeyIDPattern.MatchString(config.EncryptionKeyID) ||
		config.SessionTTL < time.Minute || config.SessionTTL > 24*time.Hour ||
		config.UploadTTL < time.Minute || config.UploadTTL > config.SessionTTL ||
		config.RetentionPeriod <= 0 || config.CallbackMaxAge <= 0 || config.CallbackFutureSkew < 0 ||
		config.EraseLeaseDuration <= 0 || config.EraseRetryDelay <= 0 {
		return nil, ErrInvalidService
	}
	return &ProviderWorkflow{pool: pool, auditor: auditor, authorizer: authorizer,
		objects: objects, provider: provider, now: config.Clock, newID: config.NewID,
		tokenKey: bytes.Clone(config.TokenKey), resolverName: config.ResolverName,
		encryptionKeyID: config.EncryptionKeyID, sessionTTL: config.SessionTTL,
		uploadTTL: config.UploadTTL, retentionPeriod: config.RetentionPeriod,
		callbackMaxAge: config.CallbackMaxAge, callbackFutureSkew: config.CallbackFutureSkew,
		eraseLease: config.EraseLeaseDuration, eraseRetry: config.EraseRetryDelay}, nil
}

func (workflow *ProviderWorkflow) Configured() bool {
	return workflow != nil && workflow.pool != nil && workflow.now != nil && workflow.newID != nil &&
		len(workflow.tokenKey) >= 32 && configuredPrivateObjectStore(workflow.objects) &&
		configuredKYCProvider(workflow.provider)
}

func (workflow *ProviderWorkflow) Ready(ctx context.Context) error {
	if !workflow.Configured() || ctx == nil {
		return ErrProviderUnavailable
	}
	var ready bool
	err := workflow.pool.QueryRow(ctx, `SELECT
		EXISTS(SELECT 1 FROM schema_migrations WHERE version=169 AND migration_id='169_identity_verification_provider_sessions') AND
		to_regclass('identity_verification_provider_sessions_v1') IS NOT NULL AND
		to_regclass('identity_verification_provider_uploads_v1') IS NOT NULL AND
		to_regclass('identity_verification_provider_callbacks_v1') IS NOT NULL AND
		to_regclass('identity_verification_erase_requests_v1') IS NOT NULL`).Scan(&ready)
	if err != nil || !ready {
		return ErrProviderUnavailable
	}
	return nil
}

func (workflow *ProviderWorkflow) Close() {
	if workflow == nil {
		return
	}
	clear(workflow.tokenKey)
	workflow.tokenKey = nil
	if !isNilDependency(workflow.provider) {
		workflow.provider.Close()
	}
}

func (workflow *ProviderWorkflow) StartSession(ctx context.Context, actor identityverification.Actor,
	request StartProviderSessionRequest,
) (ProviderSessionView, error) {
	if !workflow.Configured() || ctx == nil || validateStartProviderSession(actor, request) != nil ||
		request.Provider != workflow.provider.Name() {
		return ProviderSessionView{}, ErrProviderInvalid
	}
	digest := providerSessionRequestDigest(request)
	now := workflow.now().UTC().Truncate(time.Microsecond)
	if now.IsZero() {
		return ProviderSessionView{}, ErrProviderUnavailable
	}
	var record providerSessionRecord
	replayed := false
	err := pgx.BeginFunc(ctx, workflow.pool, func(tx pgx.Tx) error {
		if err := workflow.authorizer.AuthorizeProviderWrite(ctx, tx, actor); err != nil {
			return err
		}
		found, err := scanProviderSession(tx.QueryRow(ctx, providerSessionSelect+`
			WHERE actor_session_id=$1 AND idempotency_key=$2 FOR UPDATE`, actor.SessionID(), request.IdempotencyKey))
		if err == nil {
			if found.TenantScopeID != actor.ScopeID || found.ActorUserID != actor.UserID ||
				found.Kind != request.Kind || found.Provider != request.Provider ||
				!bytes.Equal(found.RequestDigest, digest[:]) {
				return ErrProviderConflict
			}
			record, replayed = found, true
			return nil
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		id, err := workflow.newID()
		if err != nil || id == uuid.Nil {
			return ErrProviderUnavailable
		}
		expiresAt := now.Add(workflow.sessionTTL)
		providerRequestID := "kyc-" + id.String()
		tokenDigest := sha256.Sum256([]byte(workflow.evidenceToken(id)))
		_, err = tx.Exec(ctx, `INSERT INTO identity_verification_provider_sessions_v1(
			id,tenant_scope_id,actor_user_id,actor_session_id,kind,provider,provider_request_id,
			evidence_token_digest,idempotency_key,request_id,request_digest_sha256,state,revision,
			attempt_count,created_at,updated_at,expires_at,retention_until
		) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,'creating',1,0,$12,$12,$13,$14)`,
			id, actor.ScopeID, actor.UserID, actor.SessionID(), request.Kind, request.Provider, providerRequestID,
			tokenDigest[:], request.IdempotencyKey, request.RequestID, digest[:], now, expiresAt,
			expiresAt.Add(workflow.retentionPeriod))
		if err != nil {
			return err
		}
		record = providerSessionRecord{ID: id, TenantScopeID: actor.ScopeID, ActorUserID: actor.UserID,
			ActorSessionID: actor.SessionID(), Kind: request.Kind, Provider: request.Provider,
			ProviderRequestID: providerRequestID, RequestDigest: digest[:], State: ProviderSessionCreating,
			Revision: 1, ExpiresAt: expiresAt, UpdatedAt: now}
		return workflow.appendAudit(ctx, tx, actor.ScopeID, &actor.UserID, id,
			"identity_verification.provider_session.created", request.RequestID,
			map[string]any{"kind": request.Kind, "provider": request.Provider, "state": ProviderSessionCreating, "revision": 1})
	})
	if err != nil {
		return ProviderSessionView{}, mapProviderWorkflowError(ctx, err)
	}
	if record.State != ProviderSessionCreating && record.State != ProviderSessionUnknown {
		return workflow.sessionView(record, replayed), nil
	}
	startedAt := workflow.now().UTC().Truncate(time.Microsecond)
	created, providerErr := workflow.provider.CreateSession(ctx, ProviderSessionCreate{
		LocalSessionID: record.ID, TenantScopeID: record.TenantScopeID, ActorUserID: record.ActorUserID,
		Kind: record.Kind, ProviderRequestID: record.ProviderRequestID, ExpiresAt: record.ExpiresAt})
	finishedAt := workflow.now().UTC().Truncate(time.Microsecond)
	if finishedAt.Before(startedAt) {
		finishedAt = startedAt
	}
	err = pgx.BeginFunc(ctx, workflow.pool, func(tx pgx.Tx) error {
		if err := workflow.authorizer.AuthorizeProviderWrite(ctx, tx, actor); err != nil {
			return err
		}
		locked, err := scanProviderSession(tx.QueryRow(ctx, providerSessionSelect+` WHERE id=$1 FOR UPDATE`, record.ID))
		if err != nil {
			return err
		}
		if locked.TenantScopeID != actor.ScopeID || locked.ActorUserID != actor.UserID ||
			locked.ActorSessionID != actor.SessionID() || locked.ProviderRequestID != record.ProviderRequestID {
			return ErrProviderConflict
		}
		if locked.State != ProviderSessionCreating && locked.State != ProviderSessionUnknown {
			record = locked
			return nil
		}
		state, failureCode := ProviderSessionPending, ""
		var external any = created.ExternalSessionID
		if providerErr != nil {
			state, external = ProviderSessionUnknown, nil
		}
		if providerErr == nil && (created.State != ProviderSessionPending || !providerExternalIDPattern.MatchString(created.ExternalSessionID)) {
			state, failureCode, external = ProviderSessionFailed, "INVALID_PROVIDER_RESPONSE", nil
			providerErr = ErrProviderUnavailable
		}
		attemptID, idErr := workflow.newID()
		if idErr != nil {
			return ErrProviderUnavailable
		}
		attempt := locked.AttemptCount + 1
		_, err = tx.Exec(ctx, `INSERT INTO identity_verification_provider_attempts_v1(
			id,session_id,tenant_scope_id,actor_user_id,attempt_number,provider_request_id,outcome,
			response_sha256,signature_sha256,verification_key_id,failure_code,started_at,finished_at
		) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`, attemptID, locked.ID,
			locked.TenantScopeID, locked.ActorUserID, attempt, locked.ProviderRequestID, state,
			nullDigest(created.ResponseSHA256), nullDigest(created.SignatureSHA256), nullString(created.VerificationKeyID),
			nullString(failureCode), startedAt, finishedAt)
		if err != nil {
			return err
		}
		terminal := any(nil)
		if state == ProviderSessionFailed {
			terminal = finishedAt
		}
		_, err = tx.Exec(ctx, `UPDATE identity_verification_provider_sessions_v1 SET
			external_session_id=$2,state=$3,failure_code=$4,revision=revision+1,attempt_count=$5,
			updated_at=$6,terminal_at=$7 WHERE id=$1 AND revision=$8`, locked.ID, external, state,
			nullString(failureCode), attempt, finishedAt, terminal, locked.Revision)
		if err != nil {
			return err
		}
		locked.ExternalSessionID = nil
		if created.ExternalSessionID != "" && external != nil {
			locked.ExternalSessionID = &created.ExternalSessionID
		}
		locked.State, locked.Revision, locked.AttemptCount, locked.UpdatedAt = state, locked.Revision+1, attempt, finishedAt
		record = locked
		return workflow.appendAudit(ctx, tx, actor.ScopeID, &actor.UserID, locked.ID,
			"identity_verification.provider_session."+state, request.RequestID,
			map[string]any{"state": state, "revision": locked.Revision, "attempt_count": attempt})
	})
	if err != nil {
		return ProviderSessionView{}, mapProviderWorkflowError(ctx, err)
	}
	view := workflow.sessionView(record, replayed)
	if providerErr != nil {
		return view, ErrProviderUnavailable
	}
	return view, nil
}

func (workflow *ProviderWorkflow) CreateUpload(ctx context.Context, actor identityverification.Actor,
	request CreateProviderUploadRequest,
) (ProviderUploadView, error) {
	if !workflow.Configured() || ctx == nil || validateCreateProviderUpload(actor, request) != nil {
		return ProviderUploadView{}, ErrProviderInvalid
	}
	now := workflow.now().UTC().Truncate(time.Microsecond)
	var record providerUploadRecord
	replayed := false
	err := pgx.BeginFunc(ctx, workflow.pool, func(tx pgx.Tx) error {
		if err := workflow.authorizer.AuthorizeProviderWrite(ctx, tx, actor); err != nil {
			return err
		}
		session, err := scanProviderSession(tx.QueryRow(ctx, providerSessionSelect+` WHERE id=$1 FOR UPDATE`, request.SessionID))
		if err != nil {
			return err
		}
		if session.TenantScopeID != actor.ScopeID || session.ActorUserID != actor.UserID ||
			session.ActorSessionID != actor.SessionID() {
			return identityverification.ErrNotFound
		}
		if session.State != ProviderSessionPending && session.State != ProviderSessionProcessing {
			return ErrProviderConflict
		}
		found, err := scanProviderUpload(tx.QueryRow(ctx, providerUploadSelect+`
			WHERE session_id=$1 AND idempotency_key=$2 FOR UPDATE`, session.ID, request.IdempotencyKey))
		if err == nil {
			if found.MaterialKind != request.MaterialKind || found.ContentType != request.ContentType ||
				found.SizeBytes != request.SizeBytes || !bytes.Equal(found.ObjectSHA256, request.SHA256[:]) {
				return ErrProviderConflict
			}
			record, replayed = found, true
			return nil
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		id, err := workflow.newID()
		if err != nil {
			return ErrProviderUnavailable
		}
		key, err := privateProviderObjectKey(actor, session.ID, id)
		if err != nil {
			return err
		}
		expiresAt := now.Add(workflow.uploadTTL)
		if expiresAt.After(session.ExpiresAt) {
			expiresAt = session.ExpiresAt
		}
		_, err = tx.Exec(ctx, `INSERT INTO identity_verification_provider_uploads_v1(
			id,session_id,tenant_scope_id,actor_user_id,material_kind,object_key,object_sha256,size_bytes,
			content_type,encryption_key_id,idempotency_key,request_id,state,revision,created_at,updated_at,expires_at
		) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,'issued',1,$13,$13,$14)`, id, session.ID,
			actor.ScopeID, actor.UserID, request.MaterialKind, key, request.SHA256[:], request.SizeBytes,
			request.ContentType, workflow.encryptionKeyID, request.IdempotencyKey, request.RequestID, now, expiresAt)
		if err != nil {
			return err
		}
		record = providerUploadRecord{ID: id, SessionID: session.ID, TenantScopeID: actor.ScopeID, ActorUserID: actor.UserID,
			MaterialKind: request.MaterialKind, ObjectKey: key, ObjectSHA256: request.SHA256[:], SizeBytes: request.SizeBytes,
			ContentType: request.ContentType, EncryptionKeyID: workflow.encryptionKeyID, IdempotencyKey: request.IdempotencyKey,
			State: ProviderUploadIssued, Revision: 1, ExpiresAt: expiresAt, UpdatedAt: now}
		return workflow.appendAudit(ctx, tx, actor.ScopeID, &actor.UserID, id,
			"identity_verification.provider_upload.issued", request.RequestID,
			map[string]any{"session_id": session.ID.String(), "material_kind": request.MaterialKind, "state": ProviderUploadIssued, "revision": 1})
	})
	if err != nil {
		return ProviderUploadView{}, mapProviderWorkflowError(ctx, err)
	}
	presigned, err := workflow.objects.PresignPut(ctx, PrivateObjectPresignRequest{ObjectKey: record.ObjectKey,
		SHA256: bytesToDigest(record.ObjectSHA256), SizeBytes: record.SizeBytes, ContentType: record.ContentType,
		EncryptionKeyID: record.EncryptionKeyID, ExpiresAt: record.ExpiresAt})
	if err != nil {
		return ProviderUploadView{}, ErrProviderObjectUnavailable
	}
	if presigned.URL == "" || len(presigned.RequiredHeaders) == 0 {
		return ProviderUploadView{}, ErrProviderObjectUnavailable
	}
	return ProviderUploadView{ID: record.ID, SessionID: record.SessionID, MaterialKind: record.MaterialKind,
		State: record.State, Revision: record.Revision, UploadURL: presigned.URL,
		RequiredHeaders: cloneStringMap(presigned.RequiredHeaders), ExpiresAt: record.ExpiresAt, Replayed: replayed}, nil
}

func (workflow *ProviderWorkflow) FinalizeUpload(ctx context.Context, actor identityverification.Actor,
	request FinalizeProviderUploadRequest,
) (ProviderUploadView, error) {
	if !workflow.Configured() || ctx == nil || !actor.Valid() || request.SessionID == uuid.Nil || request.UploadID == uuid.Nil ||
		request.ExpectedRevision < 1 || !validMetadata(WriteMetadata{IdempotencyKey: request.IdempotencyKey, RequestID: request.RequestID}) {
		return ProviderUploadView{}, ErrProviderInvalid
	}
	var record providerUploadRecord
	err := pgx.BeginFunc(ctx, workflow.pool, func(tx pgx.Tx) error {
		if err := workflow.authorizer.AuthorizeProviderWrite(ctx, tx, actor); err != nil {
			return err
		}
		found, err := scanProviderUpload(tx.QueryRow(ctx, providerUploadSelect+` WHERE id=$1 AND session_id=$2`, request.UploadID, request.SessionID))
		if err != nil {
			return err
		}
		if found.TenantScopeID != actor.ScopeID || found.ActorUserID != actor.UserID {
			return identityverification.ErrNotFound
		}
		record = found
		return nil
	})
	if err != nil {
		return ProviderUploadView{}, mapProviderWorkflowError(ctx, err)
	}
	facts, err := workflow.objects.Stat(ctx, record.ObjectKey)
	if err != nil {
		return ProviderUploadView{}, ErrProviderObjectUnavailable
	}
	if !equalPrivateObjectFacts(record, facts) {
		return ProviderUploadView{}, ErrProviderObjectMismatch
	}
	now := workflow.now().UTC().Truncate(time.Microsecond)
	replayed := false
	err = pgx.BeginFunc(ctx, workflow.pool, func(tx pgx.Tx) error {
		if err := workflow.authorizer.AuthorizeProviderWrite(ctx, tx, actor); err != nil {
			return err
		}
		locked, err := scanProviderUpload(tx.QueryRow(ctx, providerUploadSelect+` WHERE id=$1 AND session_id=$2 FOR UPDATE`, request.UploadID, request.SessionID))
		if err != nil {
			return err
		}
		if locked.TenantScopeID != actor.ScopeID || locked.ActorUserID != actor.UserID {
			return identityverification.ErrNotFound
		}
		if locked.State == ProviderUploadFinalized {
			if locked.ObjectVersion == nil || *locked.ObjectVersion != facts.ObjectVersion {
				return ErrProviderConflict
			}
			record, replayed = locked, true
			return nil
		}
		if locked.State != ProviderUploadIssued || locked.Revision != request.ExpectedRevision {
			return identityverification.ErrRevisionConflict
		}
		command, err := tx.Exec(ctx, `UPDATE identity_verification_provider_uploads_v1 SET object_version=$2,
			state='finalized',revision=revision+1,updated_at=$3,finalized_at=$3
			WHERE id=$1 AND state='issued' AND revision=$4`, locked.ID, facts.ObjectVersion, now, locked.Revision)
		if err != nil {
			return err
		}
		if command.RowsAffected() != 1 {
			return identityverification.ErrRevisionConflict
		}
		locked.ObjectVersion = &facts.ObjectVersion
		locked.State = ProviderUploadFinalized
		locked.Revision++
		locked.UpdatedAt = now
		record = locked
		return workflow.appendAudit(ctx, tx, actor.ScopeID, &actor.UserID, locked.ID,
			"identity_verification.provider_upload.finalized", request.RequestID,
			map[string]any{"session_id": locked.SessionID.String(), "state": ProviderUploadFinalized, "revision": locked.Revision})
	})
	if err != nil {
		return ProviderUploadView{}, mapProviderWorkflowError(ctx, err)
	}
	return ProviderUploadView{ID: record.ID, SessionID: record.SessionID, MaterialKind: record.MaterialKind,
		State: record.State, Revision: record.Revision, ExpiresAt: record.ExpiresAt, Replayed: replayed}, nil
}

func (workflow *ProviderWorkflow) ApplyCallback(ctx context.Context, envelope ProviderCallbackEnvelope) (ProviderCallbackResult, error) {
	if !workflow.Configured() || ctx == nil || envelope.Provider != workflow.provider.Name() {
		return ProviderCallbackResult{}, ErrProviderCallbackAuth
	}
	verified, err := workflow.provider.VerifyCallback(ctx, envelope)
	if err != nil {
		return ProviderCallbackResult{}, ErrProviderCallbackAuth
	}
	now := workflow.now().UTC().Truncate(time.Microsecond)
	if err := validateVerifiedProviderCallback(verified, now, workflow.callbackMaxAge, workflow.callbackFutureSkew); err != nil {
		return ProviderCallbackResult{}, err
	}
	var result ProviderCallbackResult
	err = pgx.BeginFunc(ctx, workflow.pool, func(tx pgx.Tx) error {
		session, err := scanProviderSession(tx.QueryRow(ctx, providerSessionSelect+` WHERE id=$1 FOR UPDATE`, verified.SessionID))
		if err != nil {
			return err
		}
		if session.Provider != verified.Provider || session.ExternalSessionID == nil || *session.ExternalSessionID != verified.ExternalSessionID {
			return ErrProviderConflict
		}
		if session.Kind != identityverification.KindEnterprise && (verified.OrganizationName != "" ||
			verified.LegalPersonFingerprint != ([sha256.Size]byte{}) || verified.AgentFingerprint != ([sha256.Size]byte{}) ||
			verified.AgentRelationship != "") {
			return ErrProviderCallbackAuth
		}
		var existingPayload []byte
		var existingSession uuid.UUID
		err = tx.QueryRow(ctx, `SELECT session_id,payload_sha256 FROM identity_verification_provider_callbacks_v1
			WHERE provider=$1 AND (event_id=$2 OR nonce=$3) LIMIT 1`, verified.Provider, verified.EventID, verified.Nonce).Scan(&existingSession, &existingPayload)
		if err == nil {
			if existingSession != session.ID || !bytes.Equal(existingPayload, verified.PayloadSHA256[:]) {
				return ErrProviderCallbackReplay
			}
			result = ProviderCallbackResult{SessionID: session.ID, State: session.State, Revision: session.Revision, Replayed: true}
			return nil
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		next, applied, err := advanceProviderSessionState(session.State, verified.State)
		if err != nil {
			return err
		}
		callbackID, idErr := workflow.newID()
		if idErr != nil {
			return ErrProviderUnavailable
		}
		normalizedDigest := [sha256.Size]byte{}
		if verified.State == ProviderSessionSucceeded {
			if verified.SubjectFingerprint == ([sha256.Size]byte{}) {
				return ErrProviderMaterialsIncomplete
			}
			normalizedDigest, err = workflow.validateSettledMaterials(ctx, tx, session, verified)
			if err != nil {
				return err
			}
		}
		_, err = tx.Exec(ctx, `INSERT INTO identity_verification_provider_callbacks_v1(
			id,session_id,tenant_scope_id,actor_user_id,provider,external_session_id,event_id,nonce,
			incoming_state,applied,payload_sha256,signature_sha256,verification_key_id,subject_fingerprint,
			normalized_evidence_sha256,occurred_at,received_at
		) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)`, callbackID, session.ID,
			session.TenantScopeID, session.ActorUserID, verified.Provider, verified.ExternalSessionID, verified.EventID,
			verified.Nonce, verified.State, applied, verified.PayloadSHA256[:], verified.SignatureSHA256[:],
			verified.VerificationKeyID, nullDigest(verified.SubjectFingerprint), nullDigest(normalizedDigest),
			verified.OccurredAt, verified.ReceivedAt)
		if err != nil {
			if isUniqueViolation(err) {
				return ErrProviderCallbackReplay
			}
			return err
		}
		if applied {
			failureCode := verified.FailureCode
			if next == ProviderSessionFailed && failureCode == "" {
				failureCode = "PROVIDER_REJECTED"
			}
			if next == ProviderSessionCanceled && failureCode == "" {
				failureCode = "PROVIDER_CANCELED"
			}
			if next == ProviderSessionExpired && failureCode == "" {
				failureCode = "PROVIDER_EXPIRED"
			}
			terminal := any(nil)
			if providerSessionTerminal(next) {
				terminal = verified.ReceivedAt
			}
			_, err = tx.Exec(ctx, `UPDATE identity_verification_provider_sessions_v1 SET state=$2,failure_code=$3,
				revision=revision+1,updated_at=$4,terminal_at=$5 WHERE id=$1 AND revision=$6`, session.ID, next,
				nullString(failureCode), verified.ReceivedAt, terminal, session.Revision)
			if err != nil {
				return err
			}
			session.State = next
			session.Revision++
			session.UpdatedAt = verified.ReceivedAt
			if next == ProviderSessionSucceeded {
				settlementID, idErr := workflow.newID()
				if idErr != nil {
					return ErrProviderUnavailable
				}
				_, err = tx.Exec(ctx, `INSERT INTO identity_verification_provider_settlements_v1(
						id,session_id,tenant_scope_id,actor_user_id,kind,subject_fingerprint,organization_name,
						legal_person_fingerprint,agent_fingerprint,agent_relationship,normalized_evidence_sha256,
						provider_callback_id,settled_at,retention_until
					) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`, settlementID, session.ID,
					session.TenantScopeID, session.ActorUserID, session.Kind, verified.SubjectFingerprint[:],
					nullString(verified.OrganizationName), nullDigest(verified.LegalPersonFingerprint),
					nullDigest(verified.AgentFingerprint), nullString(verified.AgentRelationship), normalizedDigest[:], callbackID,
					verified.ReceivedAt, session.ExpiresAt.Add(workflow.retentionPeriod))
				if err != nil {
					return err
				}
			}
		}
		result = ProviderCallbackResult{SessionID: session.ID, State: session.State, Revision: session.Revision, Applied: applied}
		return workflow.appendAudit(ctx, tx, session.TenantScopeID, nil, session.ID,
			"identity_verification.provider_callback.accepted", "provider-callback-"+callbackID.String(),
			map[string]any{"provider": verified.Provider, "state": verified.State, "applied": applied, "revision": session.Revision})
	})
	if err != nil {
		return ProviderCallbackResult{}, mapProviderWorkflowError(ctx, err)
	}
	return result, nil
}

func (workflow *ProviderWorkflow) RunCleanupOnce(ctx context.Context) (bool, error) {
	if !workflow.Configured() || ctx == nil {
		return false, ErrProviderUnavailable
	}
	var expired int64
	err := pgx.BeginFunc(ctx, workflow.pool, func(tx pgx.Tx) error {
		command, err := tx.Exec(ctx, `UPDATE identity_verification_provider_sessions_v1 SET state='expired',
			failure_code='PROVIDER_EXPIRED',revision=revision+1,updated_at=clock_timestamp(),terminal_at=clock_timestamp()
			WHERE id IN (SELECT id FROM identity_verification_provider_sessions_v1
				WHERE state IN ('creating','pending','processing','unknown') AND expires_at<=clock_timestamp()
				ORDER BY expires_at,id FOR UPDATE SKIP LOCKED LIMIT 100)`)
		if err != nil {
			return err
		}
		expired = command.RowsAffected()
		_, err = tx.Exec(ctx, `SELECT enqueue_identity_verification_erase_requests_169(100)`)
		return err
	})
	if err != nil {
		return false, mapProviderWorkflowError(ctx, err)
	}
	claim, found, err := workflow.claimErase(ctx)
	if err != nil {
		return false, err
	}
	if !found {
		return expired > 0, nil
	}
	receipt, deleteErr := workflow.objects.Delete(ctx, PrivateObjectReference{ObjectKey: claim.ObjectKey, ObjectVersion: claim.ObjectVersion})
	if err := workflow.finishErase(ctx, claim, receipt, deleteErr); err != nil {
		return true, err
	}
	return true, nil
}

func (workflow *ProviderWorkflow) claimErase(ctx context.Context) (eraseClaim, bool, error) {
	now := workflow.now().UTC().Truncate(time.Microsecond)
	token, err := workflow.newID()
	if err != nil {
		return eraseClaim{}, false, ErrProviderUnavailable
	}
	var claim eraseClaim
	err = pgx.BeginFunc(ctx, workflow.pool, func(tx pgx.Tx) error {
		row := tx.QueryRow(ctx, `SELECT id,upload_id,session_id,tenant_scope_id,actor_user_id,object_key,object_version,
			revision,attempt_count FROM identity_verification_erase_requests_v1 WHERE id=(
			SELECT id FROM identity_verification_erase_requests_v1 WHERE state IN ('pending','retry_wait')
			AND available_at<=clock_timestamp() ORDER BY available_at,id FOR UPDATE SKIP LOCKED LIMIT 1) FOR UPDATE`)
		if err := row.Scan(&claim.ID, &claim.UploadID, &claim.SessionID, &claim.TenantScopeID, &claim.ActorUserID,
			&claim.ObjectKey, &claim.ObjectVersion, &claim.Revision, &claim.AttemptCount); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `UPDATE identity_verification_erase_requests_v1 SET state='leased',revision=revision+1,
			attempt_count=attempt_count+1,lease_token=$2,lease_expires_at=$3,updated_at=$4,failure_code=NULL
			WHERE id=$1 AND revision=$5`, claim.ID, token, now.Add(workflow.eraseLease), now, claim.Revision)
		if err == nil {
			claim.LeaseToken = token
			claim.Revision++
			claim.AttemptCount++
		}
		return err
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return eraseClaim{}, false, nil
	}
	if err != nil {
		return eraseClaim{}, false, mapProviderWorkflowError(ctx, err)
	}
	return claim, true, nil
}

func (workflow *ProviderWorkflow) finishErase(ctx context.Context, claim eraseClaim, receipt PrivateObjectDeleteReceipt, deleteErr error) error {
	now := workflow.now().UTC().Truncate(time.Microsecond)
	return mapProviderWorkflowError(ctx, pgx.BeginFunc(ctx, workflow.pool, func(tx pgx.Tx) error {
		var state string
		var revision int64
		var lease uuid.UUID
		if err := tx.QueryRow(ctx, `SELECT state,revision,lease_token FROM identity_verification_erase_requests_v1
			WHERE id=$1 FOR UPDATE`, claim.ID).Scan(&state, &revision, &lease); err != nil {
			return err
		}
		if state != "leased" || revision != claim.Revision || lease != claim.LeaseToken {
			return ErrProviderConflict
		}
		if deleteErr != nil || receipt.ReceiptSHA256 == ([sha256.Size]byte{}) {
			_, err := tx.Exec(ctx, `UPDATE identity_verification_erase_requests_v1 SET state='retry_wait',
				revision=revision+1,lease_token=NULL,lease_expires_at=NULL,failure_code='OBJECT_DELETE_UNAVAILABLE',
				available_at=$2,updated_at=$3 WHERE id=$1`, claim.ID, now.Add(workflow.eraseRetry), now)
			return err
		}
		receiptID, err := workflow.newID()
		if err != nil {
			return ErrProviderUnavailable
		}
		keyDigest := sha256.Sum256([]byte(claim.ObjectKey))
		versionDigest := sha256.Sum256([]byte(claim.ObjectVersion))
		_, err = tx.Exec(ctx, `INSERT INTO identity_verification_erase_receipts_v1(
			id,erase_request_id,upload_id,object_key_sha256,object_version_sha256,provider_receipt_sha256,erased_at
		) VALUES($1,$2,$3,$4,$5,$6,$7)`, receiptID, claim.ID, claim.UploadID, keyDigest[:], versionDigest[:], receipt.ReceiptSHA256[:], now)
		if err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `UPDATE identity_verification_erase_requests_v1 SET state='erased',revision=revision+1,
			lease_token=NULL,lease_expires_at=NULL,failure_code=NULL,updated_at=$2,erased_at=$2 WHERE id=$1`, claim.ID, now)
		if err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `UPDATE identity_verification_provider_uploads_v1 SET state='erased',revision=revision+1,
			updated_at=$2 WHERE id=$1 AND state='erase_pending'`, claim.UploadID, now)
		if err != nil {
			return err
		}
		return workflow.appendAudit(ctx, tx, claim.TenantScopeID, nil, claim.SessionID,
			"identity_verification.private_material.erased", "identity-erase-"+claim.ID.String(),
			map[string]any{"upload_id": claim.UploadID.String(), "attempt_count": claim.AttemptCount})
	}))
}

func (workflow *ProviderWorkflow) validateSettledMaterials(ctx context.Context, tx pgx.Tx, session providerSessionRecord,
	callback VerifiedProviderCallback) ([sha256.Size]byte, error) {
	rows, err := tx.Query(ctx, `SELECT material_kind,object_key,object_version,object_sha256,size_bytes,content_type,encryption_key_id
		FROM identity_verification_provider_uploads_v1 WHERE session_id=$1 AND state='finalized' ORDER BY material_kind,id`, session.ID)
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	defer rows.Close()
	found := map[string]bool{}
	facts := make([]map[string]any, 0, 8)
	for rows.Next() {
		var kind, key, version, mime, keyID string
		var digest []byte
		var size int64
		if err := rows.Scan(&kind, &key, &version, &digest, &size, &mime, &keyID); err != nil {
			return [sha256.Size]byte{}, err
		}
		if len(digest) != sha256.Size {
			return [sha256.Size]byte{}, ErrProviderObjectMismatch
		}
		found[kind] = true
		facts = append(facts, map[string]any{"kind": kind, "object_key": key, "object_version": version,
			"object_sha256": base64.RawURLEncoding.EncodeToString(digest), "size_bytes": size, "content_type": mime, "encryption_key_id": keyID})
	}
	if err := rows.Err(); err != nil {
		return [sha256.Size]byte{}, err
	}
	valid := found[identityverification.MaterialIdentityDocument] && found[identityverification.MaterialLivenessEvidence]
	if session.Kind == identityverification.KindEnterprise {
		valid = found[identityverification.MaterialBusinessLicense] && found[identityverification.MaterialLegalIdentity] &&
			found[identityverification.MaterialAgentIdentity] && validEnterpriseCallback(callback) &&
			(callback.AgentRelationship == identityverification.RelationshipLegalPerson || found[identityverification.MaterialAuthorization])
	}
	if !valid {
		return [sha256.Size]byte{}, ErrProviderMaterialsIncomplete
	}
	payload := struct {
		SessionID string           `json:"session_id"`
		Kind      string           `json:"kind"`
		Subject   string           `json:"subject"`
		Facts     []map[string]any `json:"facts"`
	}{
		SessionID: session.ID.String(), Kind: session.Kind, Subject: base64.RawURLEncoding.EncodeToString(callback.SubjectFingerprint[:]), Facts: facts}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	hash := sha256.New()
	_, _ = hash.Write([]byte(providerNormalizedDigestDomain))
	_, _ = hash.Write(encoded)
	var digest [sha256.Size]byte
	copy(digest[:], hash.Sum(nil))
	return digest, nil
}

const providerSessionSelect = `SELECT id,tenant_scope_id,actor_user_id,actor_session_id,kind,provider,provider_request_id,
	external_session_id,request_digest_sha256,state,revision,attempt_count,expires_at,updated_at
	FROM identity_verification_provider_sessions_v1`
const providerUploadSelect = `SELECT id,session_id,tenant_scope_id,actor_user_id,material_kind,object_key,object_version,
	object_sha256,size_bytes,content_type,encryption_key_id,idempotency_key,state,revision,expires_at,updated_at
	FROM identity_verification_provider_uploads_v1`

func scanProviderSession(row pgx.Row) (providerSessionRecord, error) {
	var value providerSessionRecord
	err := row.Scan(&value.ID, &value.TenantScopeID, &value.ActorUserID, &value.ActorSessionID, &value.Kind, &value.Provider,
		&value.ProviderRequestID, &value.ExternalSessionID, &value.RequestDigest, &value.State, &value.Revision,
		&value.AttemptCount, &value.ExpiresAt, &value.UpdatedAt)
	return value, err
}
func scanProviderUpload(row pgx.Row) (providerUploadRecord, error) {
	var value providerUploadRecord
	err := row.Scan(&value.ID, &value.SessionID, &value.TenantScopeID, &value.ActorUserID, &value.MaterialKind, &value.ObjectKey,
		&value.ObjectVersion, &value.ObjectSHA256, &value.SizeBytes, &value.ContentType, &value.EncryptionKeyID,
		&value.IdempotencyKey, &value.State, &value.Revision, &value.ExpiresAt, &value.UpdatedAt)
	return value, err
}

func (workflow *ProviderWorkflow) sessionView(record providerSessionRecord, replayed bool) ProviderSessionView {
	return ProviderSessionView{
		ID: record.ID, Kind: record.Kind, Provider: record.Provider, State: record.State, Revision: record.Revision,
		EvidenceToken: workflow.evidenceToken(record.ID), ExpiresAt: record.ExpiresAt, UpdatedAt: record.UpdatedAt, Replayed: replayed}
}
func (workflow *ProviderWorkflow) evidenceToken(sessionID uuid.UUID) string {
	mac := hmac.New(sha256.New, workflow.tokenKey)
	_, _ = mac.Write([]byte(providerTokenDomain))
	_, _ = mac.Write(sessionID[:])
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}
func (workflow *ProviderWorkflow) appendAudit(ctx context.Context, tx pgx.Tx, scopeID uuid.UUID, actorID *uuid.UUID,
	resourceID uuid.UUID, action, requestID string, payload map[string]any) error {
	return workflow.auditor.Append(ctx, tx, audit.Event{
		ScopeID: scopeID, ActorUserID: actorID, Action: action, ResourceType: "identity_verification_provider_session",
		ResourceID: resourceID.String(), RequestID: requestID, Result: "success", Payload: payload})
}

func validateStartProviderSession(actor identityverification.Actor, request StartProviderSessionRequest) error {
	if !actor.Valid() || !validKind(request.Kind) || !resolverNamePattern.MatchString(request.Provider) ||
		!validMetadata(WriteMetadata{IdempotencyKey: request.IdempotencyKey, RequestID: request.RequestID}) {
		return ErrProviderInvalid
	}
	return nil
}
func validateCreateProviderUpload(actor identityverification.Actor, request CreateProviderUploadRequest) error {
	if !actor.Valid() || request.SessionID == uuid.Nil || !validMaterialKind(request.MaterialKind) || !validMIME(request.ContentType) ||
		request.SizeBytes < 1 || request.SizeBytes > maximumProviderMaterialBytes || request.SHA256 == ([sha256.Size]byte{}) ||
		!validMetadata(WriteMetadata{IdempotencyKey: request.IdempotencyKey, RequestID: request.RequestID}) {
		return ErrProviderInvalid
	}
	return nil
}
func privateProviderObjectKey(actor identityverification.Actor, sessionID, uploadID uuid.UUID) (string, error) {
	if !actor.Valid() || sessionID == uuid.Nil || uploadID == uuid.Nil {
		return "", ErrProviderInvalid
	}
	return "identity-verification/" + actor.ScopeID.String() + "/" + actor.UserID.String() + "/" + sessionID.String() + "/" + uploadID.String(), nil
}
func validateVerifiedProviderCallback(value VerifiedProviderCallback, now time.Time, maxAge, futureSkew time.Duration) error {
	if now.IsZero() || maxAge <= 0 || futureSkew < 0 || !resolverNamePattern.MatchString(value.Provider) ||
		!providerEventIDPattern.MatchString(value.EventID) || !providerNoncePattern.MatchString(value.Nonce) || value.SessionID == uuid.Nil ||
		!providerExternalIDPattern.MatchString(value.ExternalSessionID) || !providerCallbackState(value.State) ||
		value.PayloadSHA256 == ([sha256.Size]byte{}) || value.SignatureSHA256 == ([sha256.Size]byte{}) ||
		!providerKeyIDPattern.MatchString(value.VerificationKeyID) || value.OccurredAt.IsZero() || value.ReceivedAt.IsZero() ||
		value.OccurredAt.Before(now.Add(-maxAge)) || value.OccurredAt.After(now.Add(futureSkew)) ||
		value.ReceivedAt.Before(now.Add(-time.Second)) || value.ReceivedAt.After(now.Add(time.Second)) {
		return ErrProviderCallbackAuth
	}
	if value.FailureCode != "" && !providerFailureCodePattern.MatchString(value.FailureCode) {
		return ErrProviderCallbackAuth
	}
	if (value.State == ProviderSessionPending || value.State == ProviderSessionProcessing ||
		value.State == ProviderSessionSucceeded) && value.FailureCode != "" {
		return ErrProviderCallbackAuth
	}
	return nil
}
func advanceProviderSessionState(current, incoming string) (string, bool, error) {
	if !providerCallbackState(incoming) {
		return "", false, ErrProviderInvalid
	}
	if providerSessionTerminal(current) {
		return current, false, nil
	}
	switch current {
	case ProviderSessionPending:
		switch incoming {
		case ProviderSessionPending:
			return current, false, nil
		case ProviderSessionProcessing, ProviderSessionSucceeded, ProviderSessionFailed, ProviderSessionCanceled, ProviderSessionExpired:
			return incoming, true, nil
		}
	case ProviderSessionProcessing:
		switch incoming {
		case ProviderSessionPending, ProviderSessionProcessing:
			return current, false, nil
		case ProviderSessionSucceeded, ProviderSessionFailed, ProviderSessionCanceled, ProviderSessionExpired:
			return incoming, true, nil
		}
	case ProviderSessionUnknown:
		if incoming == ProviderSessionPending {
			return incoming, true, nil
		}
	}
	return "", false, ErrProviderConflict
}
func providerCallbackState(value string) bool {
	switch value {
	case ProviderSessionPending, ProviderSessionProcessing, ProviderSessionSucceeded, ProviderSessionFailed, ProviderSessionCanceled, ProviderSessionExpired:
		return true
	}
	return false
}
func providerSessionTerminal(value string) bool {
	switch value {
	case ProviderSessionSucceeded, ProviderSessionFailed, ProviderSessionCanceled, ProviderSessionExpired:
		return true
	}
	return false
}
func validEnterpriseCallback(value VerifiedProviderCallback) bool {
	return strings.TrimSpace(value.OrganizationName) == value.OrganizationName &&
		value.OrganizationName != "" && value.LegalPersonFingerprint != ([sha256.Size]byte{}) && value.AgentFingerprint != ([sha256.Size]byte{}) && validRelationship(value.AgentRelationship)
}
func providerSessionRequestDigest(request StartProviderSessionRequest) [sha256.Size]byte {
	hash := sha256.New()
	_, _ = hash.Write([]byte(providerRequestDigestDomain))
	_, _ = hash.Write([]byte(request.Kind))
	_, _ = hash.Write([]byte{0})
	_, _ = hash.Write([]byte(request.Provider))
	var out [sha256.Size]byte
	copy(out[:], hash.Sum(nil))
	return out
}
func equalPrivateObjectFacts(record providerUploadRecord, facts PrivateObjectReference) bool {
	return facts.ObjectKey == record.ObjectKey &&
		providerObjectVersionPattern.MatchString(facts.ObjectVersion) && bytes.Equal(facts.SHA256[:], record.ObjectSHA256) &&
		facts.SizeBytes == record.SizeBytes && facts.ContentType == record.ContentType && facts.EncryptionKeyID == record.EncryptionKeyID
}
func bytesToDigest(value []byte) (out [sha256.Size]byte) { copy(out[:], value); return out }
func nullDigest(value [sha256.Size]byte) any {
	if value == ([sha256.Size]byte{}) {
		return nil
	}
	return value[:]
}
func nullString(value string) any {
	if value == "" {
		return nil
	}
	return value
}
func cloneStringMap(source map[string]string) map[string]string {
	result := make(map[string]string, len(source))
	for key, value := range source {
		result[key] = value
	}
	return result
}
func configuredPrivateObjectStore(store PrivateObjectStore) (configured bool) {
	if isNilDependency(store) {
		return false
	}
	defer func() {
		if recover() != nil {
			configured = false
		}
	}()
	return store.Configured()
}
func configuredKYCProvider(provider KYCProvider) (configured bool) {
	if isNilDependency(provider) {
		return false
	}
	defer func() {
		if recover() != nil {
			configured = false
		}
	}()
	return provider.Configured() && resolverNamePattern.MatchString(provider.Name())
}
func isNilProviderAuthorizer(value providerWriteAuthorizer) bool {
	if value == nil {
		return true
	}
	ref := reflect.ValueOf(value)
	switch ref.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Ptr, reflect.Slice:
		return ref.IsNil()
	}
	return false
}
func mapProviderWorkflowError(ctx context.Context, err error) error {
	if err == nil {
		return nil
	}
	if ctx != nil && ctx.Err() != nil {
		return ctx.Err()
	}
	switch {
	case errors.Is(err, identityverification.ErrInvalidInput), errors.Is(err, identityverification.ErrPermissionDenied),
		errors.Is(err, identityverification.ErrNotFound), errors.Is(err, identityverification.ErrRevisionConflict),
		errors.Is(err, ErrProviderInvalid), errors.Is(err, ErrProviderConflict), errors.Is(err, ErrProviderCallbackAuth),
		errors.Is(err, ErrProviderCallbackReplay), errors.Is(err, ErrProviderObjectUnavailable),
		errors.Is(err, ErrProviderObjectMismatch), errors.Is(err, ErrProviderMaterialsIncomplete):
		return err
	default:
		return fmt.Errorf("provider workflow: %w", ErrProviderUnavailable)
	}
}
