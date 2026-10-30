package sitecapture

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/iamlock/protocol"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type auditAppender interface {
	Append(context.Context, pgx.Tx, audit.Event) error
}

type PostgresStore struct {
	pool    *pgxpool.Pool
	auditor auditAppender
}

func NewPostgresStore(pool *pgxpool.Pool, auditor auditAppender) (*PostgresStore, error) {
	if pool == nil {
		return nil, ErrInvalidConfig
	}
	if auditor == nil {
		auditor = audit.New(pool)
	}
	return &PostgresStore{pool: pool, auditor: auditor}, nil
}

func (store *PostgresStore) Get(ctx context.Context, actor Actor, scopeID, siteID uuid.UUID) (Policy, error) {
	if ctx == nil || store == nil || store.pool == nil || !validStoreActor(actor) || scopeID == uuid.Nil || siteID == uuid.Nil {
		return Policy{}, ErrInvalidInput
	}
	var policy Policy
	err := pgx.BeginFunc(ctx, store.pool, func(tx pgx.Tx) error {
		if err := authorizeStoreActor(ctx, tx, actor, scopeID, PermissionRead); err != nil {
			return err
		}
		if err := authorizeStoreSite(ctx, tx, actor, scopeID, siteID, false); err != nil {
			return err
		}
		var encoded, digest []byte
		err := tx.QueryRow(ctx, `SELECT revision.document_bytes,revision.document_sha256,
			revision.revision,revision.created_at,revision.actor_user_id,revision.request_id
			FROM site_capture_policy_heads AS head
			JOIN site_capture_policy_revisions AS revision
			  ON revision.scope_id=head.scope_id AND revision.site_id=head.site_id
			 AND revision.revision=head.current_revision
			WHERE head.scope_id=$1 AND head.site_id=$2`, scopeID, siteID).
			Scan(&encoded, &digest, &policy.Revision, &policy.UpdatedAt, &policy.UpdatedBy, &policy.RequestID)
		if errors.Is(err, pgx.ErrNoRows) {
			// The site exists and is visible (authorizeStoreSite passed) but no
			// policy was ever saved: that is the unconfigured default, not 404.
			return ErrUnconfigured
		}
		if err != nil {
			return fmt.Errorf("read capture policy: %w", ErrUnavailable)
		}
		document, err := decodeStoredDocument(encoded, digest)
		if err != nil {
			return err
		}
		policy.ScopeID, policy.SiteID, policy.Document = scopeID, siteID, document
		policy.EvidenceDigest = hex.EncodeToString(digest)
		return nil
	})
	if err != nil {
		return Policy{}, stableStoreError(err)
	}
	return policy, nil
}

func (store *PostgresStore) CompareAndSwap(
	ctx context.Context,
	actor Actor,
	request UpdateRequest,
	digest [sha256.Size]byte,
	auditFact AuditFact,
) (WriteResult, error) {
	if ctx == nil || store == nil || store.pool == nil {
		return WriteResult{}, ErrInvalidInput
	}
	if err := validateStoreWrite(actor, request, digest, auditFact); err != nil {
		return WriteResult{}, err
	}
	encoded, _ := json.Marshal(request.Document)
	var result WriteResult
	err := pgx.BeginFunc(ctx, store.pool, func(tx pgx.Tx) error {
		if err := authorizeStoreActor(ctx, tx, actor, request.ScopeID, PermissionManage); err != nil {
			return err
		}
		if err := authorizeStoreSite(ctx, tx, actor, request.ScopeID, request.SiteID, true); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`,
			actor.ScopeID.String()+":"+actor.UserID.String()+":"+actor.SessionID.String()+":"+request.IdempotencyKey); err != nil {
			return fmt.Errorf("lock capture policy receipt: %w", ErrUnavailable)
		}
		replayed, err := loadCaptureReceipt(ctx, tx, actor, request, digest)
		if err != nil {
			return err
		}
		if replayed != nil {
			result = *replayed
			return nil
		}
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`,
			request.ScopeID.String()+":"+request.SiteID.String()); err != nil {
			return fmt.Errorf("lock capture policy head: %w", ErrUnavailable)
		}
		now, err := transactionStoreClock(ctx, tx)
		if err != nil {
			return err
		}
		receiptID, err := uuid.NewV7()
		if err != nil {
			return fmt.Errorf("generate capture policy receipt: %w", ErrUnavailable)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO site_capture_policy_receipts(
			id,actor_scope_id,actor_user_id,actor_session_id,action_code,idempotency_key,
			request_id,trace_id,request_digest,target_scope_id,site_id,expected_revision,state,created_at)
			VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,'pending',$13)`, receiptID,
			actor.ScopeID, actor.UserID, actor.SessionID, AuditActionSet, request.IdempotencyKey,
			request.RequestID, request.TraceID, digest[:], request.ScopeID, request.SiteID,
			request.ExpectedRevision, now); err != nil {
			return fmt.Errorf("insert capture policy receipt: %w", ErrUnavailable)
		}
		var currentRevision int64
		err = tx.QueryRow(ctx, `SELECT current_revision FROM site_capture_policy_heads
			WHERE scope_id=$1 AND site_id=$2 FOR UPDATE`, request.ScopeID, request.SiteID).Scan(&currentRevision)
		if errors.Is(err, pgx.ErrNoRows) {
			currentRevision = 0
		} else if err != nil {
			return fmt.Errorf("read capture policy head: %w", ErrUnavailable)
		}
		if currentRevision != request.ExpectedRevision {
			return ErrRevisionConflict
		}
		nextRevision := currentRevision + 1
		if _, err := tx.Exec(ctx, `INSERT INTO site_capture_policy_revisions(
			scope_id,site_id,revision,document,document_bytes,document_sha256,actor_scope_id,
			actor_user_id,actor_session_id,request_id,trace_id,created_at)
			VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`, request.ScopeID, request.SiteID,
			nextRevision, encoded, encoded, digest[:], actor.ScopeID, actor.UserID, actor.SessionID,
			request.RequestID, request.TraceID, now); err != nil {
			return fmt.Errorf("insert capture policy revision: %w", ErrUnavailable)
		}
		if currentRevision == 0 {
			_, err = tx.Exec(ctx, `INSERT INTO site_capture_policy_heads(scope_id,site_id,current_revision,updated_at)
				VALUES($1,$2,$3,$4)`, request.ScopeID, request.SiteID, nextRevision, now)
		} else {
			_, err = tx.Exec(ctx, `UPDATE site_capture_policy_heads SET current_revision=$3,updated_at=$4
				WHERE scope_id=$1 AND site_id=$2 AND current_revision=$5`, request.ScopeID, request.SiteID,
				nextRevision, now, currentRevision)
		}
		if err != nil {
			return fmt.Errorf("advance capture policy head: %w", ErrUnavailable)
		}
		result = WriteResult{Policy: Policy{ScopeID: request.ScopeID, SiteID: request.SiteID,
			Revision: nextRevision, Document: request.Document, EvidenceDigest: hex.EncodeToString(digest[:]),
			UpdatedAt: now, UpdatedBy: actor.UserID, RequestID: request.RequestID}}
		if err := store.auditor.Append(ctx, tx, audit.Event{
			ScopeID: request.ScopeID, ActorUserID: &actor.UserID, Action: AuditActionSet,
			ResourceType: "site_capture_policy", ResourceID: request.SiteID.String(),
			RequestID: request.RequestID, Result: "success", Payload: map[string]any{
				"target_scope_id": request.ScopeID.String(), "site_id": request.SiteID.String(),
				"revision": nextRevision, "expected_revision": request.ExpectedRevision,
				"trace_id": request.TraceID, "document_sha256": result.Policy.EvidenceDigest,
			},
		}); err != nil {
			return fmt.Errorf("append capture policy audit: %w", ErrUnavailable)
		}
		response, err := json.Marshal(result)
		if err != nil {
			return fmt.Errorf("encode capture policy receipt: %w", ErrUnavailable)
		}
		command, err := tx.Exec(ctx, `UPDATE site_capture_policy_receipts
			SET state='completed',response_body=$2,completed_at=$3
			WHERE id=$1 AND state='pending'`, receiptID, response, now)
		if err != nil || command.RowsAffected() != 1 {
			return fmt.Errorf("complete capture policy receipt: %w", ErrUnavailable)
		}
		return nil
	})
	if err != nil {
		return WriteResult{}, stableStoreError(err)
	}
	return result, nil
}

func validateStoreWrite(actor Actor, request UpdateRequest, digest [sha256.Size]byte, fact AuditFact) error {
	if !validStoreActor(actor) || request.ScopeID == uuid.Nil || request.SiteID == uuid.Nil ||
		request.ExpectedRevision < 0 || !metadataPattern.MatchString(request.IdempotencyKey) ||
		!metadataPattern.MatchString(request.RequestID) || !metadataPattern.MatchString(request.TraceID) {
		return ErrInvalidInput
	}
	canonical, err := canonicalDocument(request.Document)
	if err != nil || !reflect.DeepEqual(canonical, request.Document) {
		return ErrInvalidInput
	}
	encoded, err := json.Marshal(canonical)
	computed := sha256.Sum256(encoded)
	if err != nil || subtle.ConstantTimeCompare(computed[:], digest[:]) != 1 {
		return ErrInvalidInput
	}
	expected := AuditFact{Action: AuditActionSet, ActorUserID: actor.UserID, ScopeID: request.ScopeID,
		SiteID: request.SiteID, ExpectedRevision: request.ExpectedRevision, RequestID: request.RequestID,
		TraceID: request.TraceID, DocumentSHA256: digest}
	if fact != expected {
		return ErrInvalidInput
	}
	return nil
}

func validStoreActor(actor Actor) bool {
	return actor.UserID != uuid.Nil && actor.ScopeID != uuid.Nil && actor.SessionID != uuid.Nil &&
		(actor.ScopeKind == "tenant" || actor.ScopeKind == "platform")
}

func authorizeStoreActor(ctx context.Context, tx pgx.Tx, actor Actor, targetScopeID uuid.UUID, permission string) error {
	if err := protocol.AcquireShared(ctx, tx); err != nil {
		return fmt.Errorf("acquire capture policy IAM lock: %w", ErrUnavailable)
	}
	if _, err := protocol.AcquireScopes(ctx, tx, []uuid.UUID{actor.ScopeID, targetScopeID}); err != nil {
		return fmt.Errorf("acquire capture policy scope locks: %w", ErrUnavailable)
	}
	var scopeKind, userStatus, membershipStatus string
	var tenantID *uuid.UUID
	var tenantStatus *string
	var revokedAt *time.Time
	var expiresAt, now time.Time
	err := tx.QueryRow(ctx, `SELECT scope.kind,scope.tenant_id,tenant.status,user_row.status,
		membership.status,session.revoked_at,session.expires_at,transaction_timestamp()
		FROM auth_sessions AS session
		JOIN users AS user_row ON user_row.id=session.user_id
		JOIN memberships AS membership ON membership.scope_id=session.scope_id AND membership.user_id=session.user_id
		JOIN access_scopes AS scope ON scope.id=session.scope_id
		LEFT JOIN tenants AS tenant ON tenant.id=scope.tenant_id
		WHERE session.id=$1 AND session.user_id=$2 AND session.scope_id=$3
		FOR KEY SHARE OF session,user_row,membership,scope`, actor.SessionID, actor.UserID, actor.ScopeID).
		Scan(&scopeKind, &tenantID, &tenantStatus, &userStatus, &membershipStatus, &revokedAt, &expiresAt, &now)
	if errors.Is(err, pgx.ErrNoRows) || revokedAt != nil || err == nil && (!now.Before(expiresAt) || scopeKind != actor.ScopeKind) {
		return ErrUnauthenticated
	}
	if err != nil {
		return fmt.Errorf("authenticate capture policy actor: %w", ErrUnavailable)
	}
	if userStatus != "active" || membershipStatus != "active" ||
		scopeKind == "platform" && tenantID != nil || scopeKind == "tenant" && (tenantID == nil || tenantStatus == nil || *tenantStatus != "active") {
		return ErrPermissionDenied
	}
	required := permission
	if actor.ScopeKind == "platform" {
		required = "platform.admin"
	}
	var allowed bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS(
		SELECT 1 FROM role_assignments AS assignment
		JOIN roles AS role ON role.id=assignment.role_id AND role.scope_id=assignment.scope_id
		JOIN role_permissions AS grant_row ON grant_row.role_id=role.id
		WHERE assignment.scope_id=$1 AND assignment.user_id=$2 AND grant_row.permission_name=$3
	)`, actor.ScopeID, actor.UserID, required).Scan(&allowed); err != nil {
		return fmt.Errorf("authorize capture policy actor: %w", ErrUnavailable)
	}
	if !allowed {
		return ErrPermissionDenied
	}
	return nil
}

func authorizeStoreSite(ctx context.Context, tx pgx.Tx, actor Actor, scopeID, siteID uuid.UUID, write bool) error {
	if actor.ScopeKind == "tenant" && actor.ScopeID != scopeID {
		return ErrNotFound
	}
	lock := " FOR KEY SHARE OF site,target_scope,target_tenant"
	if write {
		lock = " FOR UPDATE OF site"
	}
	var ownerID uuid.UUID
	err := tx.QueryRow(ctx, `SELECT site.owner_user_id FROM sites AS site
		JOIN access_scopes AS target_scope ON target_scope.id=site.scope_id AND target_scope.kind='tenant'
		JOIN tenants AS target_tenant ON target_tenant.id=target_scope.tenant_id AND target_tenant.status='active'
		WHERE site.scope_id=$1 AND site.id=$2 AND site.deleted_at IS NULL`+lock, scopeID, siteID).Scan(&ownerID)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("authorize capture policy site: %w", ErrUnavailable)
	}
	if actor.ScopeKind == "tenant" && ownerID != actor.UserID {
		return ErrNotFound
	}
	return nil
}

func loadCaptureReceipt(ctx context.Context, tx pgx.Tx, actor Actor, request UpdateRequest, digest [sha256.Size]byte) (*WriteResult, error) {
	var storedDigest, response []byte
	var targetScopeID, siteID uuid.UUID
	var expectedRevision int64
	var requestID, traceID, state string
	err := tx.QueryRow(ctx, `SELECT request_digest,target_scope_id,site_id,expected_revision,
		request_id,trace_id,state,response_body
		FROM site_capture_policy_receipts
		WHERE actor_scope_id=$1 AND actor_user_id=$2 AND actor_session_id=$3
		  AND action_code=$4 AND idempotency_key=$5 FOR UPDATE`, actor.ScopeID, actor.UserID,
		actor.SessionID, AuditActionSet, request.IdempotencyKey).
		Scan(&storedDigest, &targetScopeID, &siteID, &expectedRevision, &requestID, &traceID, &state, &response)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read capture policy receipt: %w", ErrUnavailable)
	}
	if subtle.ConstantTimeCompare(storedDigest, digest[:]) != 1 || targetScopeID != request.ScopeID ||
		siteID != request.SiteID || expectedRevision != request.ExpectedRevision ||
		requestID != request.RequestID || traceID != request.TraceID {
		return nil, ErrIdempotencyConflict
	}
	if state != "completed" || len(response) == 0 {
		return nil, ErrUnavailable
	}
	var result WriteResult
	decoder := json.NewDecoder(bytes.NewReader(response))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&result); err != nil {
		return nil, ErrUnavailable
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) ||
		!validPolicy(result.Policy, request.ScopeID, request.SiteID, request.ExpectedRevision+1, &digest) {
		return nil, ErrUnavailable
	}
	result.Replayed = true
	return &result, nil
}

func decodeStoredDocument(encoded, digest []byte) (PolicyDocument, error) {
	computed := sha256.Sum256(encoded)
	if len(digest) != sha256.Size || subtle.ConstantTimeCompare(computed[:], digest) != 1 {
		return PolicyDocument{}, ErrUnavailable
	}
	var document PolicyDocument
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&document); err != nil {
		return PolicyDocument{}, ErrUnavailable
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return PolicyDocument{}, ErrUnavailable
	}
	canonical, err := canonicalDocument(document)
	if err != nil || !reflect.DeepEqual(canonical, document) {
		return PolicyDocument{}, ErrUnavailable
	}
	return document, nil
}

func transactionStoreClock(ctx context.Context, tx pgx.Tx) (time.Time, error) {
	var now time.Time
	if err := tx.QueryRow(ctx, `SELECT transaction_timestamp()`).Scan(&now); err != nil {
		return time.Time{}, fmt.Errorf("sample capture policy clock: %w", ErrUnavailable)
	}
	return now.UTC().Truncate(time.Microsecond), nil
}

func stableStoreError(err error) error {
	for _, stable := range []error{ErrInvalidInput, ErrUnauthenticated, ErrPermissionDenied, ErrNotFound, ErrUnconfigured,
		ErrRevisionConflict, ErrIdempotencyConflict, ErrUnavailable, context.Canceled, context.DeadlineExceeded} {
		if errors.Is(err, stable) {
			return stable
		}
	}
	return ErrUnavailable
}
