package identityverificationhttp

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"regexp"
	"strings"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/identityverification"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	EvidenceStateIssued      = "issued"
	EvidenceStateReserved    = "reserved"
	EvidenceStateAborted     = "aborted"
	EvidenceStateQuarantined = "quarantined"
	EvidenceStatePublished   = "published"

	evidenceReservationIdempotencyDomain  = "cdnca.identity-verification.evidence-reservation.idempotency.v1\x00"
	evidenceReservationAuditRequestPrefix = "evidence-reservation-idempotency-"
	evidenceIssueIdempotencyDomain        = "cdnca.identity-verification.evidence-issue.idempotency.v1\x00"
	evidenceIssueTokenDomain              = "cdnca.identity-verification.evidence-issue.token.v1\x00"
)

var (
	privateObjectReferencePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/=@+\-]*$`)
	evidenceProviderPattern       = regexp.MustCompile(`^[a-z][a-z0-9._-]*$`)
	evidenceKeyIDPattern          = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/-]*$`)
)

type PostgresRuntimeEvidenceSourceConfig struct {
	ResolverName  string
	IssueTokenKey []byte
	Clock         identityverification.Clock
}

type RuntimeEvidencePrincipal struct {
	TenantScopeID uuid.UUID
	ActorUserID   uuid.UUID
	SessionID     uuid.UUID
}

func (principal RuntimeEvidencePrincipal) Valid() bool {
	return principal.TenantScopeID != uuid.Nil && principal.ActorUserID != uuid.Nil && principal.SessionID != uuid.Nil
}

type RuntimeEvidenceIssueRequest struct {
	Kind                         string
	PrivateObjectReference       string
	PrivateEnvelopeDigest        [32]byte
	EvidenceClaimDigest          [32]byte
	Evidence                     ResolvedEvidence
	ExpiresAt                    time.Time
	RequestID                    string
	IssuerWorkloadID             string
	IssuerCertificateFingerprint [sha256.Size]byte
	IssuerIdempotencyKey         string
	IssuerRequestDigest          [sha256.Size]byte
}

type RuntimeEvidenceIssueResult struct {
	Token                 string
	ResolverReference     string
	EvidenceRequestDigest [32]byte
	EvidenceClaimDigest   [32]byte
	ExpiresAt             time.Time
}

type PostgresRuntimeEvidenceSource struct {
	pool          *pgxpool.Pool
	auditor       identityverification.AuditAppender
	now           identityverification.Clock
	resolverName  string
	issueTokenKey []byte
	ready         atomic.Bool
	closed        atomic.Bool
}

type postgresEvidenceReservation struct {
	ID                    uuid.UUID
	TenantScopeID         uuid.UUID
	ActorUserID           uuid.UUID
	SessionID             uuid.UUID
	Kind                  string
	IdempotencyDigest     []byte
	ResolverName          string
	ResolverReference     string
	EvidenceRequestDigest [32]byte
	EvidenceClaimDigest   [32]byte
	EvidencePayload       []byte
	State                 string
	Revision              int64
	CaseID                *uuid.UUID
	CoreRequestDigest     []byte
	ExpiresAt             time.Time
}

type postgresEvidenceIssueBinding struct {
	Principal                      RuntimeEvidencePrincipal
	Kind                           string
	WorkloadID                     string
	CertificateFingerprint         [sha256.Size]byte
	IdempotencyDigest              [sha256.Size]byte
	IssuerRequestDigest            [sha256.Size]byte
	EvidenceClaimDigest            [sha256.Size]byte
	TokenDigest                    [sha256.Size]byte
	ResolverReference              string
	EvidenceRequestDigest          [sha256.Size]byte
	ReservationEvidenceClaimDigest [sha256.Size]byte
	EvidencePayload                []byte
	ExpiresAt                      time.Time
	ReservationExpiresAt           time.Time
}

const postgresEvidenceReservationSelect = `
	SELECT id,tenant_scope_id,actor_user_id,session_id,kind,idempotency_digest,
	       resolver_name,resolver_reference,evidence_request_digest,evidence_claim_digest,
	       evidence_payload,state,revision,case_id,core_request_digest,expires_at
		FROM identity_verification_evidence_reservations`

const postgresEvidenceIssueBindingSelect = `
	SELECT binding.tenant_scope_id,binding.actor_user_id,binding.session_id,binding.kind,
	       binding.workload_id,binding.certificate_fingerprint,binding.idempotency_digest,
	       binding.issuer_request_digest,binding.evidence_claim_digest,binding.token_digest,
	       binding.expires_at,reservation.resolver_reference,reservation.evidence_request_digest,
	       reservation.evidence_claim_digest,reservation.evidence_payload,reservation.expires_at
	FROM identity_verification_evidence_issue_bindings_v1 binding
	JOIN identity_verification_evidence_reservations reservation ON reservation.id=binding.reservation_id`

func NewPostgresRuntimeEvidenceSource(ctx context.Context, pool *pgxpool.Pool,
	auditor identityverification.AuditAppender, config PostgresRuntimeEvidenceSourceConfig,
) (*PostgresRuntimeEvidenceSource, error) {
	if ctx == nil || pool == nil || isNilDependency(auditor) ||
		!resolverNamePattern.MatchString(config.ResolverName) || len(config.IssueTokenKey) < 32 || len(config.IssueTokenKey) > 128 {
		return nil, ErrTrustedEvidenceSourceRequired
	}
	if config.Clock == nil {
		config.Clock = time.Now
	}
	source := &PostgresRuntimeEvidenceSource{pool: pool, auditor: auditor,
		now: config.Clock, resolverName: config.ResolverName, issueTokenKey: append([]byte(nil), config.IssueTokenKey...)}
	if err := source.Ready(ctx); err != nil {
		return nil, err
	}
	return source, nil
}

func (source *PostgresRuntimeEvidenceSource) Ready(ctx context.Context) error {
	if source == nil || ctx == nil || source.closed.Load() || source.pool == nil ||
		isNilDependency(source.auditor) || source.now == nil ||
		!resolverNamePattern.MatchString(source.resolverName) || len(source.issueTokenKey) < 32 || len(source.issueTokenKey) > 128 {
		return ErrTrustedEvidenceSourceRequired
	}
	source.ready.Store(false)
	var schemaReady bool
	err := source.pool.QueryRow(ctx, `
		SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE version=75)
		   AND to_regclass('identity_verification_evidence_reservations') IS NOT NULL
		   AND 21 = (
		       SELECT count(*) FROM pg_attribute
		       WHERE attrelid=to_regclass('identity_verification_evidence_reservations')
		         AND attnum>0 AND NOT attisdropped
		   )
		   AND 21 = (
		       SELECT count(*) FROM pg_attribute
		       WHERE attrelid=to_regclass('identity_verification_evidence_reservations')
		         AND attname=ANY(ARRAY[
			             'id','tenant_scope_id','actor_user_id','session_id','kind','idempotency_digest',
		             'token_digest','resolver_name','resolver_reference','private_object_reference',
		             'private_envelope_digest','evidence_request_digest','evidence_claim_digest',
		             'evidence_payload','state','revision','case_id','core_request_digest',
		             'created_at','updated_at','expires_at'
		         ]) AND NOT attisdropped
		   )
			   AND EXISTS (
		       SELECT 1 FROM pg_trigger
		       WHERE tgrelid=to_regclass('identity_verification_evidence_reservations')
		         AND tgname='identity_verification_evidence_reservations_protected_075'
		         AND NOT tgisinternal AND tgenabled='A'
		   )
		   AND EXISTS (
		       SELECT 1 FROM pg_trigger
		       WHERE tgrelid=to_regclass('identity_verification_evidence_reservations')
		         AND tgname='identity_verification_evidence_reservations_no_truncate_075'
		         AND NOT tgisinternal AND tgenabled='A'
		   )
		   AND EXISTS (
		       SELECT 1 FROM pg_trigger
		       WHERE tgrelid=to_regclass('identity_verification_evidence_reservations')
		         AND tgname='identity_verification_evidence_reservations_require_audit_075'
		         AND tgenabled='A'
		   )
		   AND EXISTS (
		       SELECT 1 FROM pg_constraint
			       WHERE conrelid=to_regclass('identity_verification_evidence_reservations')
			         AND contype='f' AND conname='identity_verification_evidence_reservations_session_binding_fk'
			   )
			   AND to_regclass('identity_verification_evidence_issue_bindings_v1') IS NOT NULL`).Scan(&schemaReady)
	if err != nil {
		return mapEvidenceSourceError(ctx, err)
	}
	if !schemaReady {
		return ErrTrustedEvidenceSourceRequired
	}
	source.ready.Store(true)
	return nil
}

func (source *PostgresRuntimeEvidenceSource) Close() {
	if source == nil {
		return
	}
	source.closed.Store(true)
	source.ready.Store(false)
	clear(source.issueTokenKey)
	source.issueTokenKey = nil
}

func (source *PostgresRuntimeEvidenceSource) Capabilities() RuntimeEvidenceSourceCapabilities {
	if source == nil || source.closed.Load() || !source.ready.Load() {
		return RuntimeEvidenceSourceCapabilities{}
	}
	return RuntimeEvidenceSourceCapabilities{TrustedFacts: true, DurableReservations: true,
		ActorRequestBinding: true, AtomicTransitions: true, IdempotentTransitions: true}
}

func (source *PostgresRuntimeEvidenceSource) Issue(ctx context.Context, actor identityverification.Actor,
	request RuntimeEvidenceIssueRequest,
) (RuntimeEvidenceIssueResult, error) {
	if !actor.Valid() {
		return RuntimeEvidenceIssueResult{}, ErrInvalidEvidence
	}
	if request.IssuerWorkloadID == "" {
		sessionID := actor.SessionID()
		request.IssuerWorkloadID = "legacy-session"
		request.IssuerCertificateFingerprint = sha256.Sum256(sessionID[:])
		request.IssuerIdempotencyKey = request.RequestID
		request.IssuerRequestDigest = sha256.Sum256([]byte(request.RequestID + "\x00" + request.Kind))
	}
	return source.IssuePrincipal(ctx, RuntimeEvidencePrincipal{
		TenantScopeID: actor.ScopeID, ActorUserID: actor.UserID, SessionID: actor.SessionID(),
	}, request)
}

func (source *PostgresRuntimeEvidenceSource) IssuePrincipal(ctx context.Context, principal RuntimeEvidencePrincipal,
	request RuntimeEvidenceIssueRequest,
) (RuntimeEvidenceIssueResult, error) {
	if !source.usable(ctx) {
		return RuntimeEvidenceIssueResult{}, ErrEvidenceUnavailable
	}
	if !principal.Valid() || !validEvidenceIssueRequest(request) {
		return RuntimeEvidenceIssueResult{}, ErrInvalidEvidence
	}
	now := source.now().UTC().Truncate(time.Microsecond)
	expiresAt := request.ExpiresAt.UTC().Truncate(time.Microsecond)
	if !expiresAt.After(now) {
		return RuntimeEvidenceIssueResult{}, ErrInvalidEvidence
	}
	token := source.issueToken(principal, request)
	tokenDigest := sha256.Sum256([]byte(token))
	requestDigest := evidenceRequestDigest(CreateDraftInput{Kind: request.Kind, EvidenceToken: token})
	idempotencyDigest := evidenceIssueIdempotencyDigest(request.IssuerIdempotencyKey)
	payload, err := json.Marshal(cloneRuntimeEvidence(request.Evidence))
	if err != nil {
		return RuntimeEvidenceIssueResult{}, ErrInvalidEvidence
	}
	var result RuntimeEvidenceIssueResult
	err = pgx.BeginFunc(ctx, source.pool, func(tx pgx.Tx) error {
		if err := validateEvidencePrincipal(ctx, tx, principal.TenantScopeID, principal.ActorUserID,
			principal.SessionID, now); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended(
			'identity-evidence-issue:'||$1||':'||encode($2,'hex'),0))`,
			request.IssuerWorkloadID, idempotencyDigest[:]); err != nil {
			return err
		}
		var existing postgresEvidenceIssueBinding
		existing, err = scanPostgresEvidenceIssueBinding(tx.QueryRow(ctx, postgresEvidenceIssueBindingSelect+`
			WHERE binding.workload_id=$1 AND binding.idempotency_digest=$2 FOR UPDATE OF binding,reservation`,
			request.IssuerWorkloadID, idempotencyDigest[:]))
		if err == nil {
			if !existing.matches(principal, request, tokenDigest, requestDigest, payload, expiresAt) {
				return ErrEvidenceReservationConflict
			}
			// UTC like the first issue's result: pgx reads timestamptz in the
			// session's local zone, and a replay must return the same value.
			result = RuntimeEvidenceIssueResult{Token: token, ResolverReference: existing.ResolverReference,
				EvidenceRequestDigest: existing.EvidenceRequestDigest, EvidenceClaimDigest: existing.EvidenceClaimDigest,
				ExpiresAt: existing.ExpiresAt.UTC()}
			return nil
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		recordID, err := uuid.NewV7()
		if err != nil {
			return ErrEvidenceUnavailable
		}
		bindingID, err := uuid.NewV7()
		if err != nil {
			return ErrEvidenceUnavailable
		}
		resolverReference := source.resolverName + "/" + recordID.String()
		_, err = tx.Exec(ctx, `INSERT INTO identity_verification_evidence_reservations(
			id,tenant_scope_id,actor_user_id,session_id,kind,token_digest,resolver_name,
			resolver_reference,private_object_reference,private_envelope_digest,
			evidence_request_digest,evidence_claim_digest,evidence_payload,state,revision,
			created_at,updated_at,expires_at
		) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,'issued',1,$14,$14,$15)`,
			recordID, principal.TenantScopeID, principal.ActorUserID, principal.SessionID, request.Kind, tokenDigest[:],
			source.resolverName, resolverReference, request.PrivateObjectReference,
			request.PrivateEnvelopeDigest[:], requestDigest[:], request.EvidenceClaimDigest[:],
			payload, now, expiresAt)
		if err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `INSERT INTO identity_verification_evidence_issue_bindings_v1(
			id,reservation_id,tenant_scope_id,actor_user_id,session_id,kind,workload_id,
			certificate_fingerprint,idempotency_digest,issuer_request_digest,evidence_claim_digest,
			token_digest,created_at,expires_at
		) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`, bindingID, recordID,
			principal.TenantScopeID, principal.ActorUserID, principal.SessionID, request.Kind,
			request.IssuerWorkloadID, request.IssuerCertificateFingerprint[:], idempotencyDigest[:],
			request.IssuerRequestDigest[:], request.EvidenceClaimDigest[:], tokenDigest[:], now, expiresAt)
		if err != nil {
			return err
		}
		result = RuntimeEvidenceIssueResult{Token: token, ResolverReference: resolverReference,
			EvidenceRequestDigest: requestDigest, EvidenceClaimDigest: request.EvidenceClaimDigest, ExpiresAt: expiresAt}
		return source.appendAudit(ctx, tx, principal.TenantScopeID, principal.ActorUserID, recordID,
			"identity_verification.evidence_reservation.issued", request.RequestID,
			EvidenceStateIssued, 1, request.Kind)
	})
	if err != nil {
		return RuntimeEvidenceIssueResult{}, mapEvidenceSourceError(ctx, err)
	}
	return result, nil
}

func (source *PostgresRuntimeEvidenceSource) Reserve(ctx context.Context,
	request RuntimeEvidenceReserveRequest,
) (RuntimeEvidenceReserveResult, error) {
	if !source.usable(ctx) {
		return RuntimeEvidenceReserveResult{}, ErrEvidenceUnavailable
	}
	if request.TenantScopeID == uuid.Nil || request.ActorUserID == uuid.Nil ||
		request.SessionID == uuid.Nil || !validKind(request.Kind) ||
		!tokenPattern.MatchString(request.Token) || !metadataPattern.MatchString(request.IdempotencyKey) ||
		request.EvidenceRequestDigest == ([32]byte{}) {
		return RuntimeEvidenceReserveResult{}, ErrInvalidEvidence
	}
	tokenDigest := sha256.Sum256([]byte(request.Token))
	idempotencyDigest := evidenceReservationIdempotencyDigest(request.IdempotencyKey)
	now := source.now().UTC().Truncate(time.Microsecond)
	var result RuntimeEvidenceReserveResult
	err := pgx.BeginFunc(ctx, source.pool, func(tx pgx.Tx) error {
		if err := validateEvidencePrincipal(ctx, tx, request.TenantScopeID,
			request.ActorUserID, request.SessionID, now); err != nil {
			return err
		}
		record, err := scanPostgresEvidenceReservation(tx.QueryRow(ctx,
			postgresEvidenceReservationSelect+` WHERE token_digest=$1 FOR UPDATE`, tokenDigest[:]))
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrInvalidEvidence
		}
		if err != nil {
			return err
		}
		if record.TenantScopeID != request.TenantScopeID || record.ActorUserID != request.ActorUserID {
			return ErrInvalidEvidence
		}
		if record.SessionID != request.SessionID || record.Kind != request.Kind ||
			record.EvidenceRequestDigest != request.EvidenceRequestDigest {
			return ErrEvidenceReservationConflict
		}
		if record.State == EvidenceStateIssued {
			if !now.Before(record.ExpiresAt) {
				return ErrInvalidEvidence
			}
			command, err := tx.Exec(ctx, `UPDATE identity_verification_evidence_reservations
				SET idempotency_digest=$2,state='reserved',revision=revision+1,updated_at=$3
				WHERE id=$1 AND state='issued' AND revision=$4`,
				record.ID, idempotencyDigest[:], now, record.Revision)
			if err != nil {
				if isUniqueViolation(err) {
					return ErrEvidenceReservationConflict
				}
				return err
			}
			if command.RowsAffected() != 1 {
				return ErrEvidenceReservationConflict
			}
			record.State, record.Revision = EvidenceStateReserved, record.Revision+1
			record.IdempotencyDigest = idempotencyDigest[:]
			if err := source.appendAudit(ctx, tx, record.TenantScopeID, record.ActorUserID,
				record.ID, "identity_verification.evidence_reservation.reserved",
				evidenceReservationAuditRequestID(idempotencyDigest), record.State,
				record.Revision, record.Kind); err != nil {
				return err
			}
		} else if record.State == EvidenceStateReserved || record.State == EvidenceStatePublished {
			if !bytes.Equal(record.IdempotencyDigest, idempotencyDigest[:]) {
				return ErrEvidenceReservationConflict
			}
		} else {
			return ErrInvalidEvidence
		}
		var evidence ResolvedEvidence
		if err := json.Unmarshal(record.EvidencePayload, &evidence); err != nil ||
			!validRuntimeEvidenceFacts(record.Kind, evidence) {
			return ErrInvalidEvidence
		}
		result = RuntimeEvidenceReserveResult{ReservationID: request.Token,
			ResolverReference: record.ResolverReference, EvidenceClaimDigest: record.EvidenceClaimDigest,
			Evidence: cloneRuntimeEvidence(evidence)}
		return nil
	})
	if err != nil {
		return RuntimeEvidenceReserveResult{}, mapEvidenceSourceError(ctx, err)
	}
	return result, nil
}

func (source *PostgresRuntimeEvidenceSource) Abort(ctx context.Context, reservationID string) error {
	return source.transitionTerminal(ctx, reservationID, EvidenceStateAborted)
}

func (source *PostgresRuntimeEvidenceSource) Quarantine(ctx context.Context, reservationID string) error {
	return source.transitionTerminal(ctx, reservationID, EvidenceStateQuarantined)
}

func (source *PostgresRuntimeEvidenceSource) Publish(ctx context.Context,
	request RuntimeEvidencePublishRequest,
) error {
	if !source.usable(ctx) {
		return ErrEvidenceUnavailable
	}
	if !resolverReferencePattern.MatchString(request.ResolverReference) ||
		request.TenantScopeID == uuid.Nil || request.ActorUserID == uuid.Nil || request.CaseID == uuid.Nil ||
		!metadataPattern.MatchString(request.IdempotencyKey) || request.CoreRequestDigest == ([32]byte{}) ||
		request.EvidenceClaimDigest == ([32]byte{}) {
		return ErrInvalidEvidence
	}
	idempotencyDigest := evidenceReservationIdempotencyDigest(request.IdempotencyKey)
	now := source.now().UTC().Truncate(time.Microsecond)
	err := pgx.BeginFunc(ctx, source.pool, func(tx pgx.Tx) error {
		record, err := scanPostgresEvidenceReservation(tx.QueryRow(ctx,
			postgresEvidenceReservationSelect+` WHERE resolver_reference=$1 FOR UPDATE`,
			request.ResolverReference))
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrInvalidEvidence
		}
		if err != nil {
			return err
		}
		if record.TenantScopeID != request.TenantScopeID || record.ActorUserID != request.ActorUserID {
			return ErrInvalidEvidence
		}
		if record.EvidenceClaimDigest != request.EvidenceClaimDigest ||
			!bytes.Equal(record.IdempotencyDigest, idempotencyDigest[:]) {
			return ErrEvidenceReservationConflict
		}
		if record.State == EvidenceStatePublished {
			if record.CaseID == nil || *record.CaseID != request.CaseID ||
				!bytes.Equal(record.CoreRequestDigest, request.CoreRequestDigest[:]) {
				return ErrEvidenceReservationConflict
			}
			return nil
		}
		if record.State != EvidenceStateReserved {
			return ErrInvalidEvidence
		}
		var binding bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS(
			SELECT 1 FROM identity_verification_evidence_settlements
			WHERE tenant_scope_id=$1 AND actor_user_id=$2 AND case_id=$3
			  AND idempotency_key=$4 AND request_digest=$5
			  AND evidence_claim_digest=$6 AND resolver_name=$7 AND resolver_reference=$8
		)`, request.TenantScopeID, request.ActorUserID, request.CaseID, request.IdempotencyKey,
			request.CoreRequestDigest[:], request.EvidenceClaimDigest[:], record.ResolverName,
			request.ResolverReference).Scan(&binding); err != nil {
			return err
		}
		if !binding {
			return ErrInvalidEvidence
		}
		command, err := tx.Exec(ctx, `UPDATE identity_verification_evidence_reservations
			SET state='published',revision=revision+1,case_id=$2,core_request_digest=$3,updated_at=$4
			WHERE id=$1 AND state='reserved' AND revision=$5`, record.ID, request.CaseID,
			request.CoreRequestDigest[:], now, record.Revision)
		if err != nil {
			return err
		}
		if command.RowsAffected() != 1 {
			return ErrEvidenceReservationConflict
		}
		return source.appendAudit(ctx, tx, record.TenantScopeID, record.ActorUserID,
			record.ID, "identity_verification.evidence_reservation.published",
			evidenceReservationAuditRequestID(idempotencyDigest), EvidenceStatePublished,
			record.Revision+1, record.Kind)
	})
	return mapEvidenceSourceError(ctx, err)
}

func (source *PostgresRuntimeEvidenceSource) transitionTerminal(ctx context.Context,
	reservationID, targetState string,
) error {
	if !source.usable(ctx) {
		return ErrEvidenceUnavailable
	}
	if !tokenPattern.MatchString(reservationID) ||
		(targetState != EvidenceStateAborted && targetState != EvidenceStateQuarantined) {
		return ErrInvalidEvidence
	}
	tokenDigest := sha256.Sum256([]byte(reservationID))
	now := source.now().UTC().Truncate(time.Microsecond)
	err := pgx.BeginFunc(ctx, source.pool, func(tx pgx.Tx) error {
		record, err := scanPostgresEvidenceReservation(tx.QueryRow(ctx,
			postgresEvidenceReservationSelect+` WHERE token_digest=$1 FOR UPDATE`, tokenDigest[:]))
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrInvalidEvidence
		}
		if err != nil {
			return err
		}
		if record.State == targetState {
			return nil
		}
		if record.State != EvidenceStateReserved {
			return ErrInvalidEvidence
		}
		command, err := tx.Exec(ctx, `UPDATE identity_verification_evidence_reservations
			SET state=$2,revision=revision+1,updated_at=$3
			WHERE id=$1 AND state='reserved' AND revision=$4`,
			record.ID, targetState, now, record.Revision)
		if err != nil {
			return err
		}
		if command.RowsAffected() != 1 {
			return ErrEvidenceReservationConflict
		}
		action := "identity_verification.evidence_reservation." + targetState
		requestID := "evidence-" + targetState + "-" + record.ID.String()
		return source.appendAudit(ctx, tx, record.TenantScopeID, record.ActorUserID,
			record.ID, action, requestID, targetState, record.Revision+1, record.Kind)
	})
	return mapEvidenceSourceError(ctx, err)
}

func (source *PostgresRuntimeEvidenceSource) usable(ctx context.Context) bool {
	return source != nil && ctx != nil && !source.closed.Load() && source.ready.Load() &&
		source.pool != nil && !isNilDependency(source.auditor) && source.now != nil &&
		len(source.issueTokenKey) >= 32 && len(source.issueTokenKey) <= 128
}

func (source *PostgresRuntimeEvidenceSource) appendAudit(ctx context.Context, tx pgx.Tx,
	scopeID, actorUserID, recordID uuid.UUID, action, requestID, state string, revision int64, kind string,
) error {
	return source.auditor.Append(ctx, tx, audit.Event{ScopeID: scopeID, ActorUserID: &actorUserID,
		Action: action, ResourceType: "identity_verification_evidence_reservation",
		ResourceID: recordID.String(), RequestID: requestID, Result: "success",
		Payload: map[string]any{"state": state, "revision": revision, "kind": kind}})
}

func validateEvidencePrincipal(ctx context.Context, tx pgx.Tx, scopeID, actorUserID,
	sessionID uuid.UUID, now time.Time,
) error {
	var valid bool
	err := tx.QueryRow(ctx, `SELECT true
		FROM auth_sessions auth_session
		JOIN users user_account ON user_account.id=auth_session.user_id
		JOIN memberships membership
		  ON membership.scope_id=auth_session.scope_id AND membership.user_id=auth_session.user_id
		JOIN access_scopes access_scope ON access_scope.id=auth_session.scope_id
		JOIN tenants tenant ON tenant.id=access_scope.tenant_id
		WHERE auth_session.id=$1 AND auth_session.scope_id=$2 AND auth_session.user_id=$3
		  AND access_scope.kind='tenant' AND user_account.status='active'
		  AND membership.status='active' AND tenant.status='active'
		  AND auth_session.revoked_at IS NULL AND auth_session.expires_at>$4
		FOR SHARE OF auth_session,user_account,membership,access_scope,tenant`,
		sessionID, scopeID, actorUserID, now).Scan(&valid)
	if errors.Is(err, pgx.ErrNoRows) || !valid {
		return ErrInvalidEvidence
	}
	return err
}

func scanPostgresEvidenceReservation(row pgx.Row) (postgresEvidenceReservation, error) {
	var record postgresEvidenceReservation
	var requestDigest, claimDigest []byte
	err := row.Scan(&record.ID, &record.TenantScopeID, &record.ActorUserID, &record.SessionID,
		&record.Kind, &record.IdempotencyDigest, &record.ResolverName, &record.ResolverReference,
		&requestDigest, &claimDigest, &record.EvidencePayload, &record.State, &record.Revision,
		&record.CaseID, &record.CoreRequestDigest, &record.ExpiresAt)
	if err != nil {
		return postgresEvidenceReservation{}, err
	}
	if (record.IdempotencyDigest != nil && len(record.IdempotencyDigest) != sha256.Size) ||
		len(requestDigest) != sha256.Size || len(claimDigest) != sha256.Size {
		return postgresEvidenceReservation{}, ErrInvalidEvidence
	}
	copy(record.EvidenceRequestDigest[:], requestDigest)
	copy(record.EvidenceClaimDigest[:], claimDigest)
	return record, nil
}

func scanPostgresEvidenceIssueBinding(row pgx.Row) (postgresEvidenceIssueBinding, error) {
	var record postgresEvidenceIssueBinding
	var certificateFingerprint, idempotencyDigest, issuerRequestDigest, evidenceClaimDigest,
		tokenDigest, evidenceRequestDigest, reservationClaimDigest []byte
	err := row.Scan(&record.Principal.TenantScopeID, &record.Principal.ActorUserID, &record.Principal.SessionID,
		&record.Kind, &record.WorkloadID, &certificateFingerprint, &idempotencyDigest,
		&issuerRequestDigest, &evidenceClaimDigest, &tokenDigest, &record.ExpiresAt,
		&record.ResolverReference, &evidenceRequestDigest, &reservationClaimDigest,
		&record.EvidencePayload, &record.ReservationExpiresAt)
	if err != nil {
		return postgresEvidenceIssueBinding{}, err
	}
	for _, value := range [][]byte{certificateFingerprint, idempotencyDigest, issuerRequestDigest,
		evidenceClaimDigest, tokenDigest, evidenceRequestDigest, reservationClaimDigest} {
		if len(value) != sha256.Size {
			return postgresEvidenceIssueBinding{}, ErrInvalidEvidence
		}
	}
	copy(record.CertificateFingerprint[:], certificateFingerprint)
	copy(record.IdempotencyDigest[:], idempotencyDigest)
	copy(record.IssuerRequestDigest[:], issuerRequestDigest)
	copy(record.EvidenceClaimDigest[:], evidenceClaimDigest)
	copy(record.TokenDigest[:], tokenDigest)
	copy(record.EvidenceRequestDigest[:], evidenceRequestDigest)
	copy(record.ReservationEvidenceClaimDigest[:], reservationClaimDigest)
	return record, nil
}

func (record postgresEvidenceIssueBinding) matches(principal RuntimeEvidencePrincipal,
	request RuntimeEvidenceIssueRequest, tokenDigest, evidenceRequestDigest [sha256.Size]byte,
	payload []byte, expiresAt time.Time,
) bool {
	return record.Principal == principal && record.Kind == request.Kind &&
		record.WorkloadID == request.IssuerWorkloadID &&
		record.CertificateFingerprint == request.IssuerCertificateFingerprint &&
		record.IdempotencyDigest == evidenceIssueIdempotencyDigest(request.IssuerIdempotencyKey) &&
		record.IssuerRequestDigest == request.IssuerRequestDigest &&
		record.EvidenceClaimDigest == request.EvidenceClaimDigest &&
		record.ReservationEvidenceClaimDigest == request.EvidenceClaimDigest &&
		record.TokenDigest == tokenDigest && record.EvidenceRequestDigest == evidenceRequestDigest &&
		sameEvidencePayload(record.EvidencePayload, payload) && record.ExpiresAt.Equal(expiresAt) &&
		record.ReservationExpiresAt.Equal(expiresAt)
}

// sameEvidencePayload compares evidence payloads by value: evidence_payload is
// jsonb, which PostgreSQL returns in its own normal form (key order, spacing),
// never the bytes json.Marshal produced for the same evidence.
func sameEvidencePayload(stored, requested []byte) bool {
	var storedEvidence, requestedEvidence ResolvedEvidence
	if json.Unmarshal(stored, &storedEvidence) != nil || json.Unmarshal(requested, &requestedEvidence) != nil {
		return false
	}
	canonicalStored, storedErr := json.Marshal(storedEvidence)
	canonicalRequested, requestedErr := json.Marshal(requestedEvidence)
	return storedErr == nil && requestedErr == nil && bytes.Equal(canonicalStored, canonicalRequested)
}

func evidenceReservationIdempotencyDigest(key string) [sha256.Size]byte {
	return sha256.Sum256([]byte(evidenceReservationIdempotencyDomain + key))
}

func evidenceIssueIdempotencyDigest(key string) [sha256.Size]byte {
	return sha256.Sum256([]byte(evidenceIssueIdempotencyDomain + key))
}

func (source *PostgresRuntimeEvidenceSource) issueToken(principal RuntimeEvidencePrincipal,
	request RuntimeEvidenceIssueRequest,
) string {
	mac := hmac.New(sha256.New, source.issueTokenKey)
	_, _ = mac.Write([]byte(evidenceIssueTokenDomain))
	for _, value := range []string{principal.TenantScopeID.String(), principal.ActorUserID.String(),
		principal.SessionID.String(), request.Kind, request.IssuerWorkloadID, request.IssuerIdempotencyKey} {
		_, _ = mac.Write([]byte(value))
		_, _ = mac.Write([]byte{0})
	}
	_, _ = mac.Write(request.IssuerCertificateFingerprint[:])
	_, _ = mac.Write(request.IssuerRequestDigest[:])
	token := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	// tokenPattern (Reserve, the create request body) requires an
	// alphanumeric first byte; base64url starts with '-' or '_' for 1 in 32
	// digests. Only those get the prefix, so every other token is unchanged.
	if token[0] == '-' || token[0] == '_' {
		token = "t" + token
	}
	return token
}

func evidenceReservationAuditRequestID(digest [sha256.Size]byte) string {
	return evidenceReservationAuditRequestPrefix + hex.EncodeToString(digest[:])
}

func validEvidenceIssueRequest(request RuntimeEvidenceIssueRequest) bool {
	return validKind(request.Kind) && request.Evidence.Kind == request.Kind &&
		len(request.PrivateObjectReference) <= 1024 &&
		privateObjectReferencePattern.MatchString(request.PrivateObjectReference) &&
		request.PrivateEnvelopeDigest != ([32]byte{}) && request.EvidenceClaimDigest != ([32]byte{}) &&
		metadataPattern.MatchString(request.RequestID) && metadataPattern.MatchString(request.IssuerWorkloadID) &&
		metadataPattern.MatchString(request.IssuerIdempotencyKey) &&
		request.IssuerCertificateFingerprint != ([sha256.Size]byte{}) &&
		request.IssuerRequestDigest != ([sha256.Size]byte{}) && !request.ExpiresAt.IsZero() &&
		validRuntimeEvidenceFacts(request.Kind, request.Evidence)
}

func validRuntimeEvidenceFacts(kind string, evidence ResolvedEvidence) bool {
	if evidence.Kind != kind || len(evidence.SubjectFingerprint) != sha256.Size {
		return false
	}
	switch kind {
	case identityverification.KindPersonalInitial, identityverification.KindPersonalReverification:
		if evidence.OrganizationName != "" || len(evidence.LegalPersonFingerprint) != 0 ||
			len(evidence.AgentFingerprint) != 0 || evidence.AgentRelationship != "" {
			return false
		}
	case identityverification.KindEnterprise:
		if evidence.OrganizationName != strings.TrimSpace(evidence.OrganizationName) ||
			!utf8.ValidString(evidence.OrganizationName) ||
			utf8.RuneCountInString(evidence.OrganizationName) < 2 ||
			utf8.RuneCountInString(evidence.OrganizationName) > 256 ||
			len(evidence.LegalPersonFingerprint) != sha256.Size ||
			len(evidence.AgentFingerprint) != sha256.Size ||
			!validRelationship(evidence.AgentRelationship) ||
			(evidence.AgentRelationship == identityverification.RelationshipLegalPerson &&
				!bytes.Equal(evidence.AgentFingerprint, evidence.LegalPersonFingerprint)) {
			return false
		}
	default:
		return false
	}
	return validRuntimeEvidenceMaterials(kind, evidence.AgentRelationship, evidence.Materials)
}

func validRuntimeEvidenceMaterials(kind, relationship string,
	materials []identityverification.MaterialInput,
) bool {
	if len(materials) < 2 || len(materials) > 16 {
		return false
	}
	found := make(map[string]bool, len(materials))
	for _, material := range materials {
		if !validMaterialKind(material.Kind) ||
			(found[material.Kind] && material.Kind != identityverification.MaterialSupplementary) ||
			len(material.EnvelopeProvider) > 64 || !evidenceProviderPattern.MatchString(material.EnvelopeProvider) ||
			len(material.EnvelopeKeyID) > 256 || !evidenceKeyIDPattern.MatchString(material.EnvelopeKeyID) ||
			len(material.EncryptedEnvelope) < 16 || len(material.EncryptedEnvelope) > 16384 ||
			len(material.ObjectReference) > 1024 ||
			!privateObjectReferencePattern.MatchString(material.ObjectReference) ||
			len(material.ObjectSHA256) != sha256.Size || !validMIME(material.MIMEType) ||
			material.SizeBytes < 1 || material.SizeBytes > 20*1024*1024 {
			return false
		}
		found[material.Kind] = true
	}
	if kind != identityverification.KindEnterprise {
		return found[identityverification.MaterialIdentityDocument] &&
			found[identityverification.MaterialLivenessEvidence]
	}
	return found[identityverification.MaterialBusinessLicense] &&
		found[identityverification.MaterialLegalIdentity] &&
		found[identityverification.MaterialAgentIdentity] &&
		(relationship == identityverification.RelationshipLegalPerson ||
			found[identityverification.MaterialAuthorization])
}

func mapEvidenceSourceError(ctx context.Context, err error) error {
	if err == nil {
		return nil
	}
	if ctx != nil && ctx.Err() != nil {
		return ctx.Err()
	}
	switch {
	case errors.Is(err, ErrInvalidEvidence), errors.Is(err, ErrEvidenceReservationConflict),
		errors.Is(err, ErrEvidenceUnavailable), errors.Is(err, context.Canceled),
		errors.Is(err, context.DeadlineExceeded):
		return err
	default:
		return ErrEvidenceUnavailable
	}
}

func isUniqueViolation(err error) bool {
	var pgError *pgconn.PgError
	return errors.As(err, &pgError) && pgError.Code == "23505"
}
