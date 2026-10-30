package firewallcontrol

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type TxAuthorizer interface {
	Authorize(context.Context, pgx.Tx, Actor, uuid.UUID, string) error
}

type auditAppender interface {
	Append(context.Context, pgx.Tx, audit.Event) error
}

type HitReader interface {
	ListFirewallHits(context.Context, HitFilter) (HitPage, error)
}

type Store struct {
	pool       *pgxpool.Pool
	authorizer TxAuthorizer
	auditor    auditAppender
	hits       HitReader
	now        func() time.Time
}

func NewStore(pool *pgxpool.Pool, authorizer TxAuthorizer, hits HitReader, now func() time.Time) *Store {
	if now == nil {
		now = time.Now
	}
	return &Store{pool: pool, authorizer: authorizer, auditor: audit.NewWithClock(pool, now), hits: hits, now: now}
}

func (store *Store) ready() bool {
	return store != nil && store.pool != nil && store.authorizer != nil && store.auditor != nil && store.now != nil
}

func (store *Store) Put(ctx context.Context, request PutRequest) (WriteResult, error) {
	if !store.ready() {
		return WriteResult{}, ErrUnavailable
	}
	var result WriteResult
	err := pgx.BeginFunc(ctx, store.pool, func(tx pgx.Tx) error {
		if err := store.authorizer.Authorize(ctx, tx, request.Actor, request.TargetScopeID, PermissionManage); err != nil {
			return err
		}
		if replay, found, err := loadWrite(ctx, tx, request.TargetScopeID, request.IdempotencyKey, request.RequestSHA256); err != nil {
			return err
		} else if found {
			result = replay
			result.Replayed = true
			return nil
		}
		now := store.now().UTC().Truncate(time.Microsecond)
		var current Policy
		found, err := lockCurrent(ctx, tx, request.TargetScopeID, &current)
		if err != nil {
			return err
		}
		if !found && request.ExpectedRevision != 0 || found && current.Revision != request.ExpectedRevision {
			return ErrRevisionConflict
		}
		if found && (current.DeploymentState == DeploymentPending || current.DeploymentState == DeploymentCanary ||
			current.DeploymentState == DeploymentPartial) {
			return ErrRevisionConflict
		}
		if !found {
			current = Policy{ID: uuid.New(), TenantScopeID: request.TargetScopeID, CreatedAt: now}
		}
		if request.Policy.Enabled {
			if err := requireOwnedNode(ctx, tx, request.TargetScopeID); err != nil {
				return err
			}
		}
		current.PolicyInput = request.Policy
		current.Revision = request.ExpectedRevision + 1
		current.DeploymentState = DeploymentPending
		current.UpdatedAt = now
		if err := persistCurrent(ctx, tx, current, request.DocumentSHA256); err != nil {
			return err
		}
		if err := appendRevisionAndOutbox(ctx, tx, current, request.Actor, request.RequestID, request.DocumentSHA256, "apply", 0, ""); err != nil {
			return err
		}
		if err := store.auditor.Append(ctx, tx, audit.Event{ScopeID: request.TargetScopeID, ActorUserID: &request.Actor.UserID,
			Action: "firewall.policy.put", ResourceType: "global_firewall_policy", ResourceID: current.ID.String(),
			RequestID: request.RequestID, Result: "success", Payload: map[string]any{"revision": current.Revision, "deployment_state": current.DeploymentState}}); err != nil {
			return err
		}
		result = WriteResult{Policy: current}
		return saveWrite(ctx, tx, request.TargetScopeID, request.Actor.ScopeID, request.Actor.UserID, request.IdempotencyKey, request.RequestSHA256, result, now)
	})
	if err != nil {
		return WriteResult{}, normalizeStoreError(err)
	}
	return result, nil
}

func (store *Store) Get(ctx context.Context, request ReadRequest) (Policy, error) {
	if !store.ready() {
		return Policy{}, ErrUnavailable
	}
	var result Policy
	err := pgx.BeginFunc(ctx, store.pool, func(tx pgx.Tx) error {
		if err := store.authorizer.Authorize(ctx, tx, request.Actor, request.TargetScopeID, PermissionRead); err != nil {
			return err
		}
		found, err := lockCurrent(ctx, tx, request.TargetScopeID, &result)
		if err != nil {
			return err
		}
		if !found {
			return ErrNotFound
		}
		return nil
	})
	if err != nil {
		return Policy{}, normalizeStoreError(err)
	}
	return result, nil
}

func (store *Store) Recover(ctx context.Context, request RecoverRequest) (WriteResult, error) {
	if !store.ready() {
		return WriteResult{}, ErrUnavailable
	}
	digest := recoveryDigest(request)
	var result WriteResult
	err := pgx.BeginFunc(ctx, store.pool, func(tx pgx.Tx) error {
		if err := store.authorizer.Authorize(ctx, tx, request.Actor, request.TargetScopeID, PermissionManage); err != nil {
			return err
		}
		if replay, found, err := loadWrite(ctx, tx, request.TargetScopeID, request.IdempotencyKey, digest); err != nil {
			return err
		} else if found {
			result = replay
			result.Replayed = true
			return nil
		}
		var current Policy
		found, err := lockCurrent(ctx, tx, request.TargetScopeID, &current)
		if err != nil {
			return err
		}
		if !found {
			return ErrNotFound
		}
		if current.Revision != request.ExpectedRevision {
			return ErrRevisionConflict
		}
		if current.DeploymentState == DeploymentPending || current.DeploymentState == DeploymentCanary {
			return ErrRevisionConflict
		}
		var document []byte
		if err := tx.QueryRow(ctx, `SELECT revision.document FROM global_firewall_policy_revisions revision
			JOIN global_firewall_publication_outbox publication ON publication.tenant_scope_id=revision.tenant_scope_id
				AND publication.policy_id=revision.policy_id AND publication.revision=revision.revision
			WHERE revision.tenant_scope_id=$1 AND revision.revision=$2 AND publication.state IN ('active','rolled_back')`,
			request.TargetScopeID, request.RecoverRevision).Scan(&document); errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		} else if err != nil {
			return err
		}
		if err := json.Unmarshal(document, &current.PolicyInput); err != nil {
			return ErrUnavailable
		}
		current.Revision++
		current.DeploymentState = DeploymentPending
		current.UpdatedAt = store.now().UTC().Truncate(time.Microsecond)
		documentSHA := recoveryDocumentDigest(current.PolicyInput)
		if err := persistCurrent(ctx, tx, current, documentSHA); err != nil {
			return err
		}
		if err := appendRevisionAndOutbox(ctx, tx, current, request.Actor, request.RequestID, documentSHA, "recover", request.RecoverRevision, request.Reason); err != nil {
			return err
		}
		if err := store.auditor.Append(ctx, tx, audit.Event{ScopeID: request.TargetScopeID, ActorUserID: &request.Actor.UserID,
			Action: "firewall.policy.recover", ResourceType: "global_firewall_policy", ResourceID: current.ID.String(), RequestID: request.RequestID,
			Result: "success", Payload: map[string]any{"revision": current.Revision, "recover_revision": request.RecoverRevision, "reason": request.Reason}}); err != nil {
			return err
		}
		result = WriteResult{Policy: current}
		return saveWrite(ctx, tx, request.TargetScopeID, request.Actor.ScopeID, request.Actor.UserID, request.IdempotencyKey, digest, result, current.UpdatedAt)
	})
	if err != nil {
		return WriteResult{}, normalizeStoreError(err)
	}
	return result, nil
}

func (store *Store) ListHits(ctx context.Context, filter HitFilter) (HitPage, error) {
	if !store.ready() || store.hits == nil {
		return HitPage{}, ErrUnavailable
	}
	err := pgx.BeginFunc(ctx, store.pool, func(tx pgx.Tx) error {
		return store.authorizer.Authorize(ctx, tx, filter.Actor, filter.TargetScopeID, PermissionRead)
	})
	if err != nil {
		return HitPage{}, normalizeStoreError(err)
	}
	return store.hits.ListFirewallHits(ctx, filter)
}

func lockCurrent(ctx context.Context, tx pgx.Tx, scopeID uuid.UUID, policy *Policy) (bool, error) {
	var document []byte
	err := tx.QueryRow(ctx, `SELECT id,tenant_scope_id,document,revision,active_revision,deployment_state,
		COALESCE(encode(active_sha256,'hex'),''),created_at,updated_at FROM global_firewall_policies WHERE tenant_scope_id=$1 FOR UPDATE`, scopeID).
		Scan(&policy.ID, &policy.TenantScopeID, &document, &policy.Revision, &policy.ActiveRevision, &policy.DeploymentState,
			&policy.ActiveSHA256, &policy.CreatedAt, &policy.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if err := json.Unmarshal(document, &policy.PolicyInput); err != nil {
		return false, ErrUnavailable
	}
	return true, nil
}

func persistCurrent(ctx context.Context, tx pgx.Tx, policy Policy, digest [32]byte) error {
	document, err := json.Marshal(policy.PolicyInput)
	if err != nil {
		return ErrInvalidInput
	}
	_, err = tx.Exec(ctx, `INSERT INTO global_firewall_policies(id,tenant_scope_id,document,document_sha256,revision,active_revision,deployment_state,created_at,updated_at)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) ON CONFLICT(tenant_scope_id) DO UPDATE SET document=EXCLUDED.document,
		document_sha256=EXCLUDED.document_sha256,revision=EXCLUDED.revision,deployment_state=EXCLUDED.deployment_state,updated_at=EXCLUDED.updated_at`,
		policy.ID, policy.TenantScopeID, document, digest[:], policy.Revision, policy.ActiveRevision, policy.DeploymentState, policy.CreatedAt, policy.UpdatedAt)
	return err
}

func appendRevisionAndOutbox(ctx context.Context, tx pgx.Tx, policy Policy, actor Actor, requestID string, digest [32]byte, operation string, recoveryOf int64, reason string) error {
	document, _ := json.Marshal(policy.PolicyInput)
	_, err := tx.Exec(ctx, `INSERT INTO global_firewall_policy_revisions(tenant_scope_id,revision,policy_id,document,document_sha256,operation,recovery_of_revision,recovery_reason,actor_scope_id,actor_user_id,request_id,created_at)
		VALUES($1,$2,$3,$4,$5,$6,NULLIF($7,0),NULLIF($8,''),$9,$10,$11,$12)`, policy.TenantScopeID, policy.Revision, policy.ID,
		document, digest[:], operation, recoveryOf, reason, actor.ScopeID, actor.UserID, requestID, policy.UpdatedAt)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `INSERT INTO global_firewall_publication_outbox(id,tenant_scope_id,policy_id,revision,operation,recovery_reason,document,document_sha256,state,available_at,created_at,updated_at)
		VALUES($1,$2,$3,$4,$5,NULLIF($6,''),$7,$8,'pending',$9,$9,$9)`, uuid.New(), policy.TenantScopeID, policy.ID, policy.Revision, operation, reason, document, digest[:], policy.UpdatedAt)
	return err
}

func loadWrite(ctx context.Context, tx pgx.Tx, scopeID uuid.UUID, key string, digest [32]byte) (WriteResult, bool, error) {
	// PostgreSQL text cannot carry NUL; ':' is in neither a UUID nor a key.
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, scopeID.String()+":"+key); err != nil {
		return WriteResult{}, false, err
	}
	var storedDigest, response []byte
	err := tx.QueryRow(ctx, `SELECT request_sha256,response_body FROM global_firewall_write_receipts WHERE tenant_scope_id=$1 AND idempotency_key=$2`, scopeID, key).Scan(&storedDigest, &response)
	if errors.Is(err, pgx.ErrNoRows) {
		return WriteResult{}, false, nil
	}
	if err != nil {
		return WriteResult{}, false, err
	}
	if string(storedDigest) != string(digest[:]) {
		return WriteResult{}, false, ErrIdempotencyConflict
	}
	var result WriteResult
	if err := json.Unmarshal(response, &result); err != nil {
		return WriteResult{}, false, ErrUnavailable
	}
	return result, true, nil
}

func saveWrite(ctx context.Context, tx pgx.Tx, scopeID, actorScopeID, actorID uuid.UUID, key string, digest [32]byte, result WriteResult, now time.Time) error {
	response, _ := json.Marshal(result)
	_, err := tx.Exec(ctx, `INSERT INTO global_firewall_write_receipts(tenant_scope_id,idempotency_key,request_sha256,actor_scope_id,actor_user_id,response_body,created_at)
		VALUES($1,$2,$3,$4,$5,$6,$7)`, scopeID, key, digest[:], actorScopeID, actorID, response, now)
	return err
}

func recoveryDigest(request RecoverRequest) [32]byte {
	encoded, _ := json.Marshal(struct {
		Scope             uuid.UUID `json:"scope"`
		Expected, Recover int64
		Reason            string
	}{request.TargetScopeID, request.ExpectedRevision, request.RecoverRevision, request.Reason})
	return recoveryBytesDigest(encoded)
}

func recoveryDocumentDigest(policy PolicyInput) [32]byte {
	encoded, _ := json.Marshal(policy)
	return recoveryBytesDigest(encoded)
}

func recoveryBytesDigest(value []byte) [32]byte {
	return sha256.Sum256(value)
}

// requireOwnedNode refuses an enabled host policy for a scope that owns no
// active node: it would apply nowhere (shared platform nodes never take it).
func requireOwnedNode(ctx context.Context, tx pgx.Tx, scopeID uuid.UUID) error {
	var owned bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM nodes WHERE scope_id=$1 AND admin_state='active')`, scopeID).Scan(&owned); err != nil {
		return err
	}
	if !owned {
		return ErrSharedNodeOnly
	}
	return nil
}

func normalizeStoreError(err error) error {
	switch {
	case errors.Is(err, ErrUnauthenticated), errors.Is(err, ErrPermissionDenied), errors.Is(err, ErrNotFound),
		errors.Is(err, ErrInvalidInput), errors.Is(err, ErrRevisionConflict), errors.Is(err, ErrIdempotencyConflict),
		errors.Is(err, ErrSharedNodeOnly):
		return err
	default:
		return fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
}
