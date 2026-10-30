package firewallactioncontrol

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/firewallcontrol"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

var reasonCodePattern = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)

type auditAppender interface {
	Append(context.Context, pgx.Tx, audit.Event) error
}

type Store struct {
	pool       *pgxpool.Pool
	authorizer firewallcontrol.TxAuthorizer
	auditor    auditAppender
	now        func() time.Time
	revisions  SiteRevisionPublisher
}

// SiteRevisionPublisher is edgeautopublish.EnqueueUnrequestedSiteRevisionTx
// (injected: edgeautopublish imports this package). A Put or Recover advances
// the scope's source revision outside any site request; an automatic scope
// publishes it unless a request already covers the revision.
type SiteRevisionPublisher interface {
	EnqueueUnrequestedSiteRevisionTx(ctx context.Context, tx pgx.Tx, scopeID, siteID uuid.UUID, requestID string) (bool, error)
}

// WithSiteRevisionPublisher wires automatic publication of policy writes;
// without it a write stays pending until the scope's next publication.
func (store *Store) WithSiteRevisionPublisher(publisher SiteRevisionPublisher) *Store {
	store.revisions = publisher
	return store
}

func (store *Store) publishRevisionTx(ctx context.Context, tx pgx.Tx, scopeID, siteID uuid.UUID, requestID string) error {
	if store.revisions == nil {
		return nil
	}
	_, err := store.revisions.EnqueueUnrequestedSiteRevisionTx(ctx, tx, scopeID, siteID, "firewall-action/"+requestID)
	return err
}

func NewStore(pool *pgxpool.Pool, authorizer firewallcontrol.TxAuthorizer, now func() time.Time) *Store {
	if now == nil {
		now = time.Now
	}
	return &Store{pool: pool, authorizer: authorizer, auditor: audit.NewWithClock(pool, now), now: now}
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
		if err := store.authorize(ctx, tx, request.Actor, request.TargetScopeID, PermissionManage); err != nil {
			return err
		}
		if err := requireSite(ctx, tx, request.TargetScopeID, request.SiteID); err != nil {
			return err
		}
		if replay, found, err := loadReceipt(ctx, tx, request.TargetScopeID, request.SiteID, request.Actor, request.IdempotencyKey, request.RequestSHA256); err != nil {
			return err
		} else if found {
			result = replay
			result.Replayed = true
			return nil
		}
		current, found, err := lockPolicy(ctx, tx, request.TargetScopeID, request.SiteID)
		if err != nil {
			return err
		}
		if !found && request.ExpectedRevision != 0 || found && current.Revision != request.ExpectedRevision || found && current.DeploymentState == StatePending {
			return ErrRevisionConflict
		}
		request.Document.ExpectedActivePolicyVersion = 0
		if found {
			request.Document.ExpectedActivePolicyVersion = uint64(current.ActiveRevision)
			request.Document.PolicyID = current.ID.String()
		}
		document, err := json.Marshal(request.Document)
		if err != nil {
			return ErrInvalidInput
		}
		request.DocumentSHA256 = sha256.Sum256(document)
		now := store.now().UTC().Truncate(time.Microsecond)
		policyID, err := uuid.Parse(request.Document.PolicyID)
		if err != nil || policyID == uuid.Nil || policyID.String() != request.Document.PolicyID {
			return ErrInvalidInput
		}
		policy := Policy{
			ID: policyID, TenantScopeID: request.TargetScopeID, SiteID: request.SiteID,
			PolicyInput: request.Policy, Revision: request.ExpectedRevision + 1, DeploymentState: StatePending,
			DocumentSHA256: hex.EncodeToString(request.DocumentSHA256[:]), CreatedAt: now, UpdatedAt: now,
		}
		if found {
			policy.ID, policy.ActiveRevision, policy.LKGRevision, policy.CreatedAt = current.ID, current.ActiveRevision, current.LKGRevision, current.CreatedAt
		}
		if policy.HostEscalation, err = hostEscalation(ctx, tx, request.TargetScopeID); err != nil {
			return err
		}
		if err := persistCandidate(ctx, tx, request, policy, now); err != nil {
			return err
		}
		if err := advanceFirewallActionSourceRevision(ctx, tx, request.TargetScopeID, now); err != nil {
			return err
		}
		if err := store.auditor.Append(ctx, tx, audit.Event{
			ScopeID: request.TargetScopeID, ActorUserID: &request.Actor.UserID, Action: "firewall.action.put",
			ResourceType: "firewall_action_policy", ResourceID: policy.ID.String(), RequestID: request.RequestID,
			Result: "success", Payload: map[string]any{"site_id": request.SiteID.String(), "revision": policy.Revision, "state": StatePending},
		}); err != nil {
			return err
		}
		if err := store.publishRevisionTx(ctx, tx, request.TargetScopeID, request.SiteID, request.RequestID); err != nil {
			return err
		}
		result = WriteResult{Policy: policy}
		return saveReceipt(ctx, tx, request.TargetScopeID, request.SiteID, request.Actor, request.IdempotencyKey, request.RequestSHA256, result, now)
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
		if err := store.authorize(ctx, tx, request.Actor, request.TargetScopeID, PermissionRead); err != nil {
			return err
		}
		var found bool
		var err error
		result, found, err = lockPolicy(ctx, tx, request.TargetScopeID, request.SiteID)
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
	var result WriteResult
	err := pgx.BeginFunc(ctx, store.pool, func(tx pgx.Tx) error {
		if err := store.authorize(ctx, tx, request.Actor, request.TargetScopeID, PermissionManage); err != nil {
			return err
		}
		if replay, found, err := loadReceipt(ctx, tx, request.TargetScopeID, request.SiteID, request.Actor, request.IdempotencyKey, request.RequestSHA256); err != nil {
			return err
		} else if found {
			result = replay
			result.Replayed = true
			return nil
		}
		current, found, err := lockPolicy(ctx, tx, request.TargetScopeID, request.SiteID)
		if err != nil {
			return err
		}
		if !found {
			return ErrNotFound
		}
		if current.Revision != request.ExpectedRevision || current.DeploymentState == StatePending {
			return ErrRevisionConflict
		}
		if current.LKGRevision < 1 {
			return ErrNoLKG
		}
		var document []byte
		if err := tx.QueryRow(ctx, `SELECT document_bytes FROM firewall_action_policy_revisions
			WHERE tenant_scope_id=$1 AND site_id=$2 AND revision=$3`, request.TargetScopeID, request.SiteID, current.LKGRevision).Scan(&document); errors.Is(err, pgx.ErrNoRows) {
			return ErrNoLKG
		} else if err != nil {
			return err
		}
		var edge EdgePolicy
		if err := json.Unmarshal(document, &edge); err != nil {
			return ErrUnavailable
		}
		edge.PolicyVersion = uint64(current.Revision + 1)
		edge.ExpectedActivePolicyVersion = uint64(current.ActiveRevision)
		document, err = json.Marshal(edge)
		if err != nil {
			return ErrUnavailable
		}
		digest := sha256.Sum256(document)
		now := store.now().UTC().Truncate(time.Microsecond)
		policy := current
		policy.PolicyInput, policy.Revision, policy.DeploymentState = policyInputFromEdge(edge), current.Revision+1, StatePending
		policy.DocumentSHA256, policy.UpdatedAt = hex.EncodeToString(digest[:]), now
		put := PutRequest{Actor: request.Actor, TargetScopeID: request.TargetScopeID, SiteID: request.SiteID,
			ExpectedRevision: request.ExpectedRevision, IdempotencyKey: request.IdempotencyKey, RequestID: request.RequestID,
			Policy: policy.PolicyInput, Document: edge, RequestSHA256: request.RequestSHA256, DocumentSHA256: digest}
		if err := persistCandidate(ctx, tx, put, policy, now); err != nil {
			return err
		}
		if err := advanceFirewallActionSourceRevision(ctx, tx, request.TargetScopeID, now); err != nil {
			return err
		}
		if err := store.auditor.Append(ctx, tx, audit.Event{
			ScopeID: request.TargetScopeID, ActorUserID: &request.Actor.UserID, Action: "firewall.action.recover_lkg",
			ResourceType: "firewall_action_policy", ResourceID: policy.ID.String(), RequestID: request.RequestID,
			Result: "success", Payload: map[string]any{"site_id": request.SiteID.String(), "revision": policy.Revision, "lkg_revision": current.LKGRevision},
		}); err != nil {
			return err
		}
		if err := store.publishRevisionTx(ctx, tx, request.TargetScopeID, request.SiteID, request.RequestID); err != nil {
			return err
		}
		result = WriteResult{Policy: policy}
		return saveReceipt(ctx, tx, request.TargetScopeID, request.SiteID, request.Actor, request.IdempotencyKey, request.RequestSHA256, result, now)
	})
	if err != nil {
		return WriteResult{}, normalizeStoreError(err)
	}
	return result, nil
}

type firewallActionSourceRevisionTx interface {
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
}

func advanceFirewallActionSourceRevision(ctx context.Context, tx firewallActionSourceRevisionTx, scopeID uuid.UUID, now time.Time) error {
	command, err := tx.Exec(ctx, `UPDATE edge_configuration_scopes
		SET source_revision=source_revision+1,updated_at=$2 WHERE scope_id=$1`, scopeID, now)
	if err != nil {
		return err
	}
	if command.RowsAffected() != 1 {
		return ErrUnavailable
	}
	return nil
}

// RecordOutcome is the durable acknowledgement boundary used by the future
// publication adapter. A rejected candidate never changes active or LKG facts.
func (store *Store) RecordOutcome(ctx context.Context, request OutcomeRequest) (Policy, error) {
	if !store.ready() || request.TargetScopeID == uuid.Nil || request.SiteID == uuid.Nil || request.Revision < 1 ||
		request.DocumentSHA256 == ([32]byte{}) || !reasonCodePattern.MatchString(request.ReasonCode) {
		return Policy{}, ErrInvalidInput
	}
	var result Policy
	err := pgx.BeginFunc(ctx, store.pool, func(tx pgx.Tx) error {
		current, found, err := lockPolicy(ctx, tx, request.TargetScopeID, request.SiteID)
		if err != nil {
			return err
		}
		if !found {
			return ErrNotFound
		}
		now := store.now().UTC().Truncate(time.Microsecond)
		updated, outboxState, err := applyOutcome(current, request, now)
		if err != nil {
			return err
		}
		command, err := tx.Exec(ctx, `UPDATE firewall_action_publication_outbox SET state=$5,outcome_reason=$6,acknowledged_at=$7,updated_at=$7
			WHERE tenant_scope_id=$1 AND site_id=$2 AND revision=$3 AND document_sha256=$4 AND state='published'`,
			request.TargetScopeID, request.SiteID, request.Revision, request.DocumentSHA256[:], outboxState, request.ReasonCode, now)
		if err != nil {
			return err
		}
		if command.RowsAffected() != 1 {
			return ErrRevisionConflict
		}
		if _, err := tx.Exec(ctx, `UPDATE firewall_action_policy_heads SET active_revision=$3,lkg_revision=$4,deployment_state=$5,updated_at=$6
			WHERE tenant_scope_id=$1 AND site_id=$2`, request.TargetScopeID, request.SiteID, updated.ActiveRevision, updated.LKGRevision, updated.DeploymentState, now); err != nil {
			return err
		}
		result = updated
		return nil
	})
	if err != nil {
		return Policy{}, normalizeStoreError(err)
	}
	return result, nil
}

func (store *Store) ClaimPublications(ctx context.Context, limit int) ([]Publication, error) {
	if !store.ready() || limit < 1 || limit > 100 {
		return nil, ErrInvalidInput
	}
	now := store.now().UTC().Truncate(time.Microsecond)
	claimExpiresAt := now.Add(30 * time.Second)
	result := make([]Publication, 0, limit)
	err := pgx.BeginFunc(ctx, store.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `WITH exhausted AS (
			UPDATE firewall_action_publication_outbox SET state='failed',claim_expires_at=NULL,last_error='claim_expired',updated_at=$1
			WHERE state='projecting' AND attempts>=16 AND claim_expires_at<=$1
			RETURNING tenant_scope_id,site_id,revision
		) UPDATE firewall_action_policy_heads head SET deployment_state='failed',updated_at=$1
		FROM exhausted WHERE head.tenant_scope_id=exhausted.tenant_scope_id AND head.site_id=exhausted.site_id
			AND head.revision=exhausted.revision AND head.deployment_state='pending'`, now); err != nil {
			return err
		}
		rows, err := tx.Query(ctx, `WITH candidates AS (
			SELECT id FROM firewall_action_publication_outbox
			WHERE attempts<16 AND ((state IN ('pending','retryable') AND available_at<=$1) OR
				(state='projecting' AND claim_expires_at<=$1))
			ORDER BY available_at,id FOR UPDATE SKIP LOCKED LIMIT $2
		) UPDATE firewall_action_publication_outbox publication SET state='projecting',attempts=publication.attempts+1,claim_expires_at=$3,updated_at=$1
		FROM candidates WHERE publication.id=candidates.id
		RETURNING publication.id,publication.tenant_scope_id,publication.site_id,publication.policy_id,publication.revision,
			publication.document_bytes,publication.document_sha256,publication.attempts`, now, limit, claimExpiresAt)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var item Publication
			var digest []byte
			if err := rows.Scan(&item.ID, &item.TargetScopeID, &item.SiteID, &item.PolicyID, &item.Revision, &item.Document, &digest, &item.Attempt); err != nil {
				return err
			}
			if len(digest) != sha256.Size || !json.Valid(item.Document) {
				return ErrUnavailable
			}
			copy(item.DocumentSHA256[:], digest)
			result = append(result, item)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, normalizeStoreError(err)
	}
	return result, nil
}

func (store *Store) FinishProjection(ctx context.Context, result ProjectionResult) error {
	if !store.ready() || result.PublicationID == uuid.Nil || result.DocumentSHA256 == ([32]byte{}) ||
		result.Attempt < 1 || result.Attempt > 16 || !reasonCodePattern.MatchString(result.ReasonCode) {
		return ErrInvalidInput
	}
	now := store.now().UTC().Truncate(time.Microsecond)
	state, availableAt, lastError := "published", now, ""
	if !result.Published {
		if result.RetryAt.IsZero() || !result.RetryAt.After(now) {
			return ErrInvalidInput
		}
		state, availableAt, lastError = "retryable", result.RetryAt.UTC().Truncate(time.Microsecond), result.ReasonCode
	}
	err := pgx.BeginFunc(ctx, store.pool, func(tx pgx.Tx) error {
		var scopeID, siteID uuid.UUID
		var revision int64
		var finalState string
		err := tx.QueryRow(ctx, `UPDATE firewall_action_publication_outbox
			SET state=CASE WHEN $3='retryable' AND attempts>=16 THEN 'failed' ELSE $3 END,
			available_at=$4,last_error=NULLIF($5,''),projected_at=CASE WHEN $3='published' THEN $6 ELSE NULL END,
			claim_expires_at=NULL,updated_at=$6
			WHERE id=$1 AND document_sha256=$2 AND state='projecting' AND attempts=$7
			RETURNING tenant_scope_id,site_id,revision,state`, result.PublicationID, result.DocumentSHA256[:], state, availableAt, lastError, now, result.Attempt).
			Scan(&scopeID, &siteID, &revision, &finalState)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrRevisionConflict
		}
		if err != nil {
			return err
		}
		if finalState == "failed" {
			command, err := tx.Exec(ctx, `UPDATE firewall_action_policy_heads SET deployment_state='failed',updated_at=$4
				WHERE tenant_scope_id=$1 AND site_id=$2 AND revision=$3 AND deployment_state='pending'`, scopeID, siteID, revision, now)
			if err != nil {
				return err
			}
			if command.RowsAffected() != 1 {
				return ErrRevisionConflict
			}
		}
		return nil
	})
	if err != nil {
		return normalizeStoreError(err)
	}
	return nil
}

func applyOutcome(current Policy, request OutcomeRequest, now time.Time) (Policy, string, error) {
	if current.Revision != request.Revision || current.DeploymentState != StatePending ||
		current.DocumentSHA256 != hex.EncodeToString(request.DocumentSHA256[:]) {
		return Policy{}, "", ErrRevisionConflict
	}
	current.DeploymentState = StateFailed
	current.UpdatedAt = now
	if !request.Applied {
		return current, "failed", nil
	}
	current.DeploymentState = StateActive
	current.ActiveRevision = request.Revision
	current.LKGRevision = request.Revision
	return current, "acked", nil
}

func (store *Store) authorize(ctx context.Context, tx pgx.Tx, actor Actor, targetScopeID uuid.UUID, permission string) error {
	if err := store.authorizer.Authorize(ctx, tx, actor, targetScopeID, permission); err != nil {
		switch {
		case errors.Is(err, firewallcontrol.ErrUnauthenticated):
			return ErrUnauthenticated
		case errors.Is(err, firewallcontrol.ErrPermissionDenied), errors.Is(err, firewallcontrol.ErrInvalidInput):
			return ErrPermissionDenied
		default:
			return ErrUnavailable
		}
	}
	return nil
}

func requireSite(ctx context.Context, tx pgx.Tx, scopeID, siteID uuid.UUID) error {
	var exists bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM sites WHERE scope_id=$1 AND id=$2)`, scopeID, siteID).Scan(&exists); err != nil {
		return err
	}
	if !exists {
		return ErrNotFound
	}
	return nil
}

func persistCandidate(ctx context.Context, tx pgx.Tx, request PutRequest, policy Policy, now time.Time) error {
	document, err := json.Marshal(request.Document)
	if err != nil {
		return ErrInvalidInput
	}
	_, err = tx.Exec(ctx, `INSERT INTO firewall_action_policy_heads(id,tenant_scope_id,site_id,document,document_bytes,document_sha256,revision,active_revision,lkg_revision,deployment_state,created_at,updated_at)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$11) ON CONFLICT(tenant_scope_id,site_id) DO UPDATE SET
		document=EXCLUDED.document,document_bytes=EXCLUDED.document_bytes,document_sha256=EXCLUDED.document_sha256,revision=EXCLUDED.revision,deployment_state=EXCLUDED.deployment_state,updated_at=EXCLUDED.updated_at`,
		policy.ID, policy.TenantScopeID, policy.SiteID, document, document, request.DocumentSHA256[:], policy.Revision,
		policy.ActiveRevision, policy.LKGRevision, StatePending, now)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `INSERT INTO firewall_action_policy_revisions(tenant_scope_id,site_id,revision,policy_id,document,document_bytes,document_sha256,
		expected_active_revision,actor_scope_id,actor_user_id,request_id,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,
		policy.TenantScopeID, policy.SiteID, policy.Revision, policy.ID, document, document, request.DocumentSHA256[:], request.Document.ExpectedActivePolicyVersion,
		request.Actor.ScopeID, request.Actor.UserID, request.RequestID, now)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `INSERT INTO firewall_action_publication_outbox(id,tenant_scope_id,site_id,policy_id,revision,document,document_bytes,document_sha256,state,available_at,created_at,updated_at)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8,'pending',$9,$9,$9)`, uuid.New(), policy.TenantScopeID, policy.SiteID, policy.ID, policy.Revision,
		document, document, request.DocumentSHA256[:], now)
	if err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `SELECT advance_edge_configuration_scope_revision($1)`, policy.TenantScopeID); err != nil {
		return fmt.Errorf("advance firewall action edge source revision: %w", err)
	}
	return nil
}

func lockPolicy(ctx context.Context, tx pgx.Tx, scopeID, siteID uuid.UUID) (Policy, bool, error) {
	var policy Policy
	var document, digest []byte
	err := tx.QueryRow(ctx, `SELECT id,tenant_scope_id,site_id,document_bytes,document_sha256,revision,active_revision,lkg_revision,deployment_state,created_at,updated_at
		FROM firewall_action_policy_heads WHERE tenant_scope_id=$1 AND site_id=$2 FOR UPDATE`, scopeID, siteID).
		Scan(&policy.ID, &policy.TenantScopeID, &policy.SiteID, &document, &digest, &policy.Revision, &policy.ActiveRevision,
			&policy.LKGRevision, &policy.DeploymentState, &policy.CreatedAt, &policy.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Policy{}, false, nil
	}
	if err != nil {
		return Policy{}, false, err
	}
	var edge EdgePolicy
	if err := json.Unmarshal(document, &edge); err != nil || len(digest) != sha256.Size {
		return Policy{}, false, ErrUnavailable
	}
	policy.PolicyInput = policyInputFromEdge(edge)
	policy.DocumentSHA256 = hex.EncodeToString(digest)
	if policy.HostEscalation, err = hostEscalation(ctx, tx, scopeID); err != nil {
		return Policy{}, false, err
	}
	return policy, true, nil
}

// hostEscalation: the nftables escalation runs only on nodes the scope owns
// (A08); a scope on shared platform nodes only keeps the OpenResty actions.
func hostEscalation(ctx context.Context, tx pgx.Tx, scopeID uuid.UUID) (string, error) {
	var owned bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM nodes WHERE scope_id=$1 AND admin_state='active')`, scopeID).Scan(&owned); err != nil {
		return "", err
	}
	if owned {
		return HostEscalationOwned, nil
	}
	return HostEscalationSharedUnsupported, nil
}

func policyInputFromEdge(edge EdgePolicy) PolicyInput {
	return PolicyInput{
		NormalAction: edge.NormalAction, EscalatedAction: edge.EscalatedAction, EngageThreshold: edge.EngageThreshold,
		RecoverThreshold: edge.RecoverThreshold, RecoveryWindows: edge.RecoveryWindows, BlockNetworks: edge.BlockNetworks,
		TrustedProxies: edge.TrustedProxies, TrustedCrawlers: edge.TrustedCrawlers, ReturnPage: edge.ReturnPage,
	}
}

func loadReceipt(ctx context.Context, tx pgx.Tx, scopeID, siteID uuid.UUID, actor Actor, key string, digest [32]byte) (WriteResult, bool, error) {
	// "/" separates the parts: PostgreSQL text refuses a NUL byte (22021),
	// which failed every write here.
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, scopeID.String()+"/"+siteID.String()+"/"+key); err != nil {
		return WriteResult{}, false, err
	}
	var storedDigest, response []byte
	var actorScopeID, actorUserID uuid.UUID
	err := tx.QueryRow(ctx, `SELECT request_sha256,actor_scope_id,actor_user_id,response_body FROM firewall_action_write_receipts
		WHERE tenant_scope_id=$1 AND site_id=$2 AND idempotency_key=$3`, scopeID, siteID, key).Scan(&storedDigest, &actorScopeID, &actorUserID, &response)
	if errors.Is(err, pgx.ErrNoRows) {
		return WriteResult{}, false, nil
	}
	if err != nil {
		return WriteResult{}, false, err
	}
	if string(storedDigest) != string(digest[:]) || actorScopeID != actor.ScopeID || actorUserID != actor.UserID {
		return WriteResult{}, false, ErrIdempotencyConflict
	}
	var result WriteResult
	if err := json.Unmarshal(response, &result); err != nil {
		return WriteResult{}, false, ErrUnavailable
	}
	return result, true, nil
}

func saveReceipt(ctx context.Context, tx pgx.Tx, scopeID, siteID uuid.UUID, actor Actor, key string, digest [32]byte, result WriteResult, now time.Time) error {
	response, err := json.Marshal(result)
	if err != nil {
		return ErrUnavailable
	}
	_, err = tx.Exec(ctx, `INSERT INTO firewall_action_write_receipts(tenant_scope_id,site_id,idempotency_key,request_sha256,
		actor_scope_id,actor_user_id,response_body,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8)`,
		scopeID, siteID, key, digest[:], actor.ScopeID, actor.UserID, response, now)
	return err
}

func normalizeStoreError(err error) error {
	switch {
	case errors.Is(err, ErrUnauthenticated), errors.Is(err, ErrPermissionDenied), errors.Is(err, ErrNotFound), errors.Is(err, ErrNoLKG),
		errors.Is(err, ErrInvalidInput), errors.Is(err, ErrRevisionConflict), errors.Is(err, ErrIdempotencyConflict):
		return err
	default:
		return fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
}
