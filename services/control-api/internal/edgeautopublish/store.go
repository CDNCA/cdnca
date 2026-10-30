package edgeautopublish

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/edgedeployment"
	"github.com/cdnca/cdnca/services/control-api/internal/edgepublish"
	"github.com/cdnca/cdnca/services/control-api/internal/iamlock"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Store struct {
	pool    *pgxpool.Pool
	auditor *audit.Log
}

type requestState struct {
	Sequence       int64
	State          string
	Attempt        int
	LeaseOwner     *string
	LeaseToken     *uuid.UUID
	LeaseExpiresAt *time.Time
	PublicationID  *uuid.UUID
	RolloutID      *uuid.UUID
}

type enqueueDigestInput struct {
	TargetScopeID               string   `json:"target_scope_id"`
	ActorScopeID                string   `json:"actor_scope_id"`
	ActorUserID                 string   `json:"actor_user_id"`
	ActorScopeKind              string   `json:"actor_scope_kind"`
	SourceKind                  string   `json:"source_kind"`
	SourceResourceID            *string  `json:"source_resource_id,omitempty"`
	PublishIntentID             *string  `json:"publish_intent_id,omitempty"`
	ConfigurationSourceRevision *int64   `json:"configuration_source_revision,omitempty"`
	SourceRevision              int64    `json:"source_revision"`
	Operation                   string   `json:"operation"`
	Reason                      string   `json:"reason"`
	Permission                  string   `json:"permission"`
	SourceRequestID             string   `json:"source_request_id"`
	PolicyRevision              int64    `json:"policy_revision"`
	NodeIDs                     []string `json:"node_ids"`
	TargetSnapshotID            *string  `json:"target_snapshot_id,omitempty"`
	TargetRevision              *int64   `json:"target_snapshot_revision,omitempty"`
	TargetSHA256                *string  `json:"target_snapshot_sha256,omitempty"`
	ActivationMS                int64    `json:"activation_timeout_ms"`
	ObservationMS               int64    `json:"observation_window_ms"`
	Successes                   uint32   `json:"required_consecutive_successes"`
	MaxAttempts                 uint32   `json:"max_attempts"`
	DeadlineSeconds             int64    `json:"deadline_window_seconds"`
}

func NewStore(pool *pgxpool.Pool) *Store {
	return &Store{pool: pool, auditor: audit.New(pool)}
}

func AuthorizeMutationTx(
	ctx context.Context,
	tx pgx.Tx,
	actor Actor,
	targetScopeID uuid.UUID,
	permission string,
) error {
	return AuthorizeMutationsTx(ctx, tx, actor, []uuid.UUID{targetScopeID}, permission)
}

func AuthorizeMutationsTx(
	ctx context.Context,
	tx pgx.Tx,
	actor Actor,
	targetScopeIDs []uuid.UUID,
	permission string,
) error {
	if tx == nil || actor.UserID == uuid.Nil || actor.ScopeID == uuid.Nil || len(targetScopeIDs) == 0 ||
		(actor.ScopeKind != ScopeKindTenant && actor.ScopeKind != ScopeKindPlatform) ||
		(permission != PermissionSitesManage && permission != PermissionStreamsManage) {
		return ErrPermissionDenied
	}
	lockScopes := append([]uuid.UUID{actor.ScopeID}, targetScopeIDs...)
	for _, targetScopeID := range targetScopeIDs {
		if targetScopeID == uuid.Nil || actor.ScopeKind == ScopeKindTenant && actor.ScopeID != targetScopeID {
			return ErrPermissionDenied
		}
	}
	if err := iamlock.AcquireShared(ctx, tx); err != nil {
		return err
	}
	if _, err := iamlock.AcquireScopes(ctx, tx, lockScopes); err != nil {
		return err
	}
	targets := append([]uuid.UUID(nil), targetScopeIDs...)
	sort.Slice(targets, func(i, j int) bool { return bytes.Compare(targets[i][:], targets[j][:]) < 0 })
	for index, targetScopeID := range targets {
		if index > 0 && targetScopeID == targets[index-1] {
			continue
		}
		var actorKind, targetKind, accountStatus, membershipStatus, tenantStatus string
		err := tx.QueryRow(ctx, `
				SELECT actor_scope.kind,target_scope.kind,account.status,membership.status,tenant.status
				FROM access_scopes actor_scope
				JOIN memberships membership ON membership.scope_id=actor_scope.id AND membership.user_id=$2
				JOIN users account ON account.id=membership.user_id
				CROSS JOIN access_scopes target_scope
				JOIN tenants tenant ON tenant.id=target_scope.tenant_id
				WHERE actor_scope.id=$1 AND target_scope.id=$3`, actor.ScopeID, actor.UserID, targetScopeID).
			Scan(&actorKind, &targetKind, &accountStatus, &membershipStatus, &tenantStatus)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrPermissionDenied
		}
		if err != nil {
			return err
		}
		if actorKind != actor.ScopeKind || targetKind != ScopeKindTenant || accountStatus != "active" ||
			membershipStatus != "active" || tenantStatus != "active" {
			return ErrPermissionDenied
		}
		var allowed bool
		if actor.ScopeKind == ScopeKindTenant {
			err = tx.QueryRow(ctx, `SELECT EXISTS(
					SELECT 1 FROM custom_rbac_effective_permissions($1,$2) WHERE permission_name=$3
				)`, targetScopeID, actor.UserID, permission).Scan(&allowed)
		} else {
			err = tx.QueryRow(ctx, `SELECT EXISTS(
					SELECT 1
					FROM role_assignments assignment
					JOIN roles role ON role.id=assignment.role_id AND role.scope_id=assignment.scope_id
					JOIN role_permissions grant_row ON grant_row.role_id=role.id
					WHERE assignment.scope_id=$1 AND assignment.user_id=$2
					  AND grant_row.permission_name IN ($3,'platform.admin')
				)`, actor.ScopeID, actor.UserID, permission).Scan(&allowed)
		}
		if err != nil {
			return err
		}
		if !allowed {
			return ErrPermissionDenied
		}
	}
	return nil
}

func EnqueueTx(ctx context.Context, tx pgx.Tx, input EnqueueInput) (EnqueueResult, error) {
	if tx == nil || input.TargetScopeID == uuid.Nil || input.Actor.UserID == uuid.Nil || input.Actor.ScopeID == uuid.Nil ||
		input.Reason != sourceReason(input.SourceKind) || strings.TrimSpace(input.SourceRequestID) == "" || len(input.SourceRequestID) > 128 ||
		!validSourceOperation(input.SourceKind, input.Operation, input.Permission, input.SourceResourceID) {
		return EnqueueResult{}, ErrInvalidInput
	}
	var sourceRevision int64
	if input.SourceKind == SourceL4 {
		if err := tx.QueryRow(ctx, `SELECT source_revision FROM edge_configuration_scopes
			WHERE scope_id=$1 FOR UPDATE`, input.TargetScopeID).Scan(&sourceRevision); err != nil {
			return EnqueueResult{}, err
		}
		if !validConfigurationSourceBinding(input.SourceKind, input.PublishIntentID,
			input.ConfigurationSourceRevision, sourceRevision) {
			return EnqueueResult{}, ErrInvalidInput
		}
	} else if !validConfigurationSourceBinding(input.SourceKind, input.PublishIntentID,
		input.ConfigurationSourceRevision, 0) {
		return EnqueueResult{}, ErrInvalidInput
	}
	policy, found, err := loadCurrentPolicy(ctx, tx, input.TargetScopeID)
	if err != nil {
		return EnqueueResult{}, err
	}
	if !found || policy.Mode == ModeManual {
		return EnqueueResult{}, nil
	}
	if input.SourceKind != SourceL4 {
		if err := tx.QueryRow(ctx, `SELECT source_revision FROM edge_configuration_scopes
			WHERE scope_id=$1 FOR UPDATE`, input.TargetScopeID).Scan(&sourceRevision); err != nil {
			return EnqueueResult{}, err
		}
	}
	digest, err := automaticRequestDigest(input, policy, sourceRevision)
	if err != nil {
		return EnqueueResult{}, err
	}
	rows, err := tx.Query(ctx, `
		SELECT request_row.id,request_row.source_revision,request_row.request_digest,
		       state.sequence,state.state,state.attempt,state.lease_owner,state.lease_token,
		       state.lease_expires_at,state.publication_id,state.rollout_id
		FROM edge_automatic_publication_requests request_row
		JOIN LATERAL (
			SELECT * FROM edge_automatic_publication_request_state_facts
			WHERE request_id=request_row.id ORDER BY sequence DESC LIMIT 1
		) state ON true
		WHERE request_row.target_scope_id=$1
		ORDER BY request_row.source_revision,request_row.id
		FOR UPDATE OF request_row`, input.TargetScopeID)
	if err != nil {
		return EnqueueResult{}, err
	}
	type existingRequest struct {
		id             uuid.UUID
		sourceRevision int64
		digest         []byte
		state          requestState
	}
	existing := make([]existingRequest, 0)
	for rows.Next() {
		var item existingRequest
		if err := rows.Scan(&item.id, &item.sourceRevision, &item.digest, &item.state.Sequence,
			&item.state.State, &item.state.Attempt, &item.state.LeaseOwner, &item.state.LeaseToken,
			&item.state.LeaseExpiresAt, &item.state.PublicationID, &item.state.RolloutID); err != nil {
			rows.Close()
			return EnqueueResult{}, err
		}
		existing = append(existing, item)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return EnqueueResult{}, err
	}
	rows.Close()
	now, err := serverNow(ctx, tx)
	if err != nil {
		return EnqueueResult{}, err
	}
	newerExists := false
	for _, item := range existing {
		if item.sourceRevision == sourceRevision {
			if !bytes.Equal(item.digest, digest[:]) {
				return EnqueueResult{}, ErrIdempotencyConflict
			}
			return EnqueueResult{RequestID: item.id, Enqueued: true, Replayed: true}, nil
		}
		if item.sourceRevision > sourceRevision {
			newerExists = true
		}
		// A reconciling request already published; it finishes on its own
		// rollout (086 allows reconciling only to succeeded/failed).
		if item.sourceRevision < sourceRevision && nonterminalState(item.state.State) && item.state.State != StateReconciling {
			if err := appendStateTx(ctx, tx, item.id, item.state.Sequence+1, StateSuperseded,
				item.state.Attempt, nil, nil, nil, nil, nil, nil, "superseded_by_newer_revision", nil, now); err != nil {
				return EnqueueResult{}, err
			}
		}
	}
	requestID, err := uuid.NewV7()
	if err != nil {
		return EnqueueResult{}, err
	}
	correlationID, err := uuid.NewV7()
	if err != nil {
		return EnqueueResult{}, err
	}
	idempotencyKey := "edgeauto." + requestID.String()
	var resourceID *uuid.UUID
	if input.SourceResourceID != uuid.Nil {
		resourceID = &input.SourceResourceID
	}
	var publishIntentID *uuid.UUID
	if input.PublishIntentID != uuid.Nil {
		publishIntentID = &input.PublishIntentID
	}
	_, err = tx.Exec(ctx, `INSERT INTO edge_automatic_publication_requests(
		id,target_scope_id,actor_scope_id,actor_user_id,actor_scope_kind,source_kind,
		source_resource_id,publish_intent_id,source_revision,operation,reason,permission_name,source_request_id,
		idempotency_key,correlation_id,request_digest,policy_revision,created_at
	) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18)`,
		requestID, input.TargetScopeID, input.Actor.ScopeID, input.Actor.UserID, input.Actor.ScopeKind,
		input.SourceKind, resourceID, publishIntentID, sourceRevision, input.Operation, input.Reason, input.Permission,
		input.SourceRequestID, idempotencyKey, correlationID, digest[:], policy.Revision, now)
	if err != nil {
		return EnqueueResult{}, err
	}
	state, terminal := StatePending, ""
	if newerExists {
		state, terminal = StateSuperseded, "superseded_by_newer_revision"
	}
	if err := appendStateTx(ctx, tx, requestID, 1, state, 0, nil, nil, nil, nil, nil, nil, terminal, nil, now); err != nil {
		return EnqueueResult{}, err
	}
	return EnqueueResult{RequestID: requestID, Enqueued: true}, nil
}

func (s *Store) Claim(ctx context.Context, workerID string, leaseDuration time.Duration) (Claim, bool, error) {
	if s == nil || s.pool == nil || strings.TrimSpace(workerID) == "" || len(workerID) > 128 ||
		leaseDuration < time.Second || leaseDuration > time.Hour {
		return Claim{}, false, ErrInvalidInput
	}
	var result Claim
	var found bool
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		now, err := serverNow(ctx, tx)
		if err != nil {
			return err
		}
		var requestID uuid.UUID
		err = tx.QueryRow(ctx, `
			SELECT request_row.id
			FROM edge_automatic_publication_requests request_row
			JOIN LATERAL (
				SELECT state,available_at,lease_expires_at
				FROM edge_automatic_publication_request_state_facts
				WHERE request_id=request_row.id ORDER BY sequence DESC LIMIT 1
			) state ON true
			WHERE state.state='pending'
			   OR state.state='retry_wait' AND state.available_at <= $1
			   OR state.state='leased' AND state.lease_expires_at <= $1
			ORDER BY request_row.source_revision,request_row.created_at,request_row.id
			LIMIT 1 FOR UPDATE OF request_row SKIP LOCKED`, now).Scan(&requestID)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		request, policy, state, err := loadClaimFacts(ctx, tx, requestID)
		if err != nil {
			return err
		}
		var currentRevision int64
		if err := tx.QueryRow(ctx, `SELECT source_revision FROM edge_configuration_scopes
			WHERE scope_id=$1 FOR UPDATE`, request.TargetScopeID).Scan(&currentRevision); err != nil {
			return err
		}
		if currentRevision != request.SourceRevision {
			if currentRevision < request.SourceRevision {
				return ErrStaleClaim
			}
			if err := appendStateTx(ctx, tx, request.ID, state.Sequence+1, StateSuperseded,
				state.Attempt, nil, nil, nil, nil, nil, nil, "superseded_by_source_revision", nil, now); err != nil {
				return err
			}
			return continueSupersededTx(ctx, tx, request, currentRevision, now)
		}
		leaseToken, err := uuid.NewV7()
		if err != nil {
			return err
		}
		leaseExpires := now.Add(leaseDuration)
		attempt := state.Attempt + 1
		if err := appendStateTx(ctx, tx, request.ID, state.Sequence+1, StateLeased, attempt,
			&workerID, &leaseToken, &leaseExpires, nil, nil, nil, "", nil, now); err != nil {
			return err
		}
		result = Claim{Request: request, Policy: policy, LeaseToken: leaseToken,
			StateSequence: state.Sequence + 1, Attempt: attempt}
		found = true
		return nil
	})
	if errors.Is(err, ErrStaleClaim) {
		return Claim{}, false, nil
	}
	return result, found, err
}

// continueSupersededTx enqueues the scope's current revision when the claimed
// request was superseded by a revision nobody requested. Superseding assumes
// every newer revision has its own request, but site row writes outside a
// request (the CNAME projection's settle, 335 trigger) advance the revision
// too: without this the superseded change was never published (73, 10-27).
// The continuation keeps the request's actor, site and operation (the site's
// sync status follows its latest request); an L4 request is bound to its
// publish intent's revision, so its continuation is a scope republication by
// the policy's actor, as RequestRepublicationTx's site.batch triggers are.
// A scope back on manual publication, or an actor the request table refuses,
// leaves it superseded (manual scopes publish by hand).
func continueSupersededTx(ctx context.Context, tx pgx.Tx, request Request, currentRevision int64, now time.Time) error {
	var covered bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM edge_automatic_publication_requests
		WHERE target_scope_id=$1 AND source_revision>=$2)`, request.TargetScopeID, currentRevision).Scan(&covered); err != nil {
		return err
	}
	if covered {
		return nil
	}
	policy, found, err := loadCurrentPolicy(ctx, tx, request.TargetScopeID)
	if err != nil || !found || policy.Mode != ModeAutomatic {
		return err
	}
	input := EnqueueInput{
		Actor:         Actor{UserID: request.ActorUserID, ScopeID: request.ActorScopeID, ScopeKind: request.ActorScopeKind},
		TargetScopeID: request.TargetScopeID, SourceKind: request.SourceKind, SourceResourceID: request.SourceResourceID,
		Operation: request.Operation, Reason: request.Reason, Permission: request.Permission,
		SourceRequestID: request.SourceRequestID,
	}
	if request.SourceKind == SourceL4 {
		actor, automatic, err := automaticPolicyActor(ctx, tx, request.TargetScopeID)
		if err != nil || !automatic {
			return err
		}
		input.Actor, input.SourceKind, input.SourceResourceID = actor, SourceSite, uuid.Nil
		input.Operation, input.Reason, input.Permission = "site.batch.enable", ReasonResourceMutation, PermissionSitesManage
	}
	digest, err := automaticRequestDigest(input, policy, currentRevision)
	if err != nil {
		return err
	}
	requestID, err := uuid.NewV7()
	if err != nil {
		return err
	}
	correlationID, err := uuid.NewV7()
	if err != nil {
		return err
	}
	var resourceID *uuid.UUID
	if input.SourceResourceID != uuid.Nil {
		resourceID = &input.SourceResourceID
	}
	// A savepoint: a refused continuation must not fail the claim, or the
	// worker would retry this claim forever.
	savepoint, err := tx.Begin(ctx)
	if err != nil {
		return err
	}
	_, err = savepoint.Exec(ctx, `INSERT INTO edge_automatic_publication_requests(
		id,target_scope_id,actor_scope_id,actor_user_id,actor_scope_kind,source_kind,
		source_resource_id,source_revision,operation,reason,permission_name,source_request_id,
		idempotency_key,correlation_id,request_digest,policy_revision,created_at
	) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)`,
		requestID, input.TargetScopeID, input.Actor.ScopeID, input.Actor.UserID, input.Actor.ScopeKind,
		input.SourceKind, resourceID, currentRevision, input.Operation, input.Reason, input.Permission,
		input.SourceRequestID, "edgeauto."+requestID.String(), correlationID, digest[:], policy.Revision, now)
	if err == nil {
		err = appendStateTx(ctx, savepoint, requestID, 1, StatePending, 0, nil, nil, nil, nil, nil, nil, "", nil, now)
	}
	if err != nil {
		return savepoint.Rollback(ctx)
	}
	return savepoint.Commit(ctx)
}

func (s *Store) ClaimAutomaticPublication(
	ctx context.Context,
	workerID string,
	leaseDuration time.Duration,
) (edgepublish.AutomaticClaimReference, bool, error) {
	claim, found, err := s.Claim(ctx, workerID, leaseDuration)
	if err != nil || !found {
		return edgepublish.AutomaticClaimReference{}, found, err
	}
	return edgepublish.AutomaticClaimReference{
		RequestID: claim.Request.ID, LeaseToken: claim.LeaseToken, StateSequence: claim.StateSequence,
	}, true, nil
}

func (s *Store) Reauthorize(ctx context.Context, claim Claim) error {
	if err := validateClaim(claim); err != nil {
		return err
	}
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if err := AuthorizeMutationTx(ctx, tx, Actor{
			UserID: claim.Request.ActorUserID, ScopeID: claim.Request.ActorScopeID,
			ScopeKind: claim.Request.ActorScopeKind,
		}, claim.Request.TargetScopeID, claim.Request.Permission); err != nil {
			return err
		}
		state, err := lockClaimState(ctx, tx, claim)
		if err != nil {
			return err
		}
		var revision int64
		if err := tx.QueryRow(ctx, `SELECT source_revision FROM edge_configuration_scopes
			WHERE scope_id=$1 FOR UPDATE`, claim.Request.TargetScopeID).Scan(&revision); err != nil {
			return err
		}
		if revision != claim.Request.SourceRevision {
			now, nowErr := serverNow(ctx, tx)
			if nowErr != nil {
				return nowErr
			}
			if revision > claim.Request.SourceRevision {
				if err := appendStateTx(ctx, tx, claim.Request.ID, state.Sequence+1, StateSuperseded,
					state.Attempt, nil, nil, nil, nil, nil, nil, "superseded_before_publish", nil, now); err != nil {
					return err
				}
			}
			return ErrStaleClaim
		}
		return nil
	})
}

func (s *Store) PrepareAutomaticPublication(
	ctx context.Context,
	tx pgx.Tx,
	reference edgepublish.AutomaticClaimReference,
) (edgepublish.PreparedAutomaticPublication, error) {
	if s == nil || s.pool == nil || tx == nil || !validAutomaticReference(reference) {
		return edgepublish.PreparedAutomaticPublication{}, ErrInvalidInput
	}
	request, _, _, err := loadClaimFacts(ctx, tx, reference.RequestID)
	if errors.Is(err, pgx.ErrNoRows) {
		return edgepublish.PreparedAutomaticPublication{}, ErrStaleClaim
	}
	if err != nil {
		return edgepublish.PreparedAutomaticPublication{}, err
	}
	if err := AuthorizeMutationTx(ctx, tx, Actor{
		UserID: request.ActorUserID, ScopeID: request.ActorScopeID, ScopeKind: request.ActorScopeKind,
	}, request.TargetScopeID, request.Permission); err != nil {
		return edgepublish.PreparedAutomaticPublication{}, err
	}
	request, policy, state, err := lockAutomaticReference(ctx, tx, reference)
	if err != nil {
		return edgepublish.PreparedAutomaticPublication{}, err
	}
	var sourceRevision int64
	if err := tx.QueryRow(ctx, `SELECT source_revision FROM edge_configuration_scopes
		WHERE scope_id=$1 FOR UPDATE`, request.TargetScopeID).Scan(&sourceRevision); err != nil {
		return edgepublish.PreparedAutomaticPublication{}, err
	}
	now, err := serverNow(ctx, tx)
	if err != nil {
		return edgepublish.PreparedAutomaticPublication{}, err
	}
	deadline := request.CreatedAt.Add(policy.DeadlineWindow).UTC()
	if state.LeaseExpiresAt == nil || !state.LeaseExpiresAt.After(now) {
		return edgepublish.PreparedAutomaticPublication{}, ErrStaleClaim
	}
	if !deadline.After(now) {
		if err := appendStateTx(ctx, tx, request.ID, state.Sequence+1, StateFailed,
			state.Attempt, nil, nil, nil, nil, nil, nil, "request_deadline_expired", nil, now); err != nil {
			return edgepublish.PreparedAutomaticPublication{}, err
		}
		if err := s.appendTerminalAudit(ctx, tx, request, StateFailed, "request_deadline_expired"); err != nil {
			return edgepublish.PreparedAutomaticPublication{}, err
		}
		return edgepublish.PreparedAutomaticPublication{}, edgepublish.ErrAutomaticRequestExpired
	}
	if sourceRevision != request.SourceRevision || policy.TargetScopeID != request.TargetScopeID ||
		policy.Revision != request.PolicyRevision || policy.Mode != ModeAutomatic {
		return edgepublish.PreparedAutomaticPublication{}, ErrStaleClaim
	}
	publishRequest := edgepublish.PublishRequest{
		Actor: edgepublish.Actor{
			UserID: request.ActorUserID, ScopeID: request.ActorScopeID, ScopeKind: request.ActorScopeKind,
		},
		ConfigurationScopeID: request.TargetScopeID, ExpectedSourceRevision: request.SourceRevision,
		MaxAttempts: policy.MaxAttempts, Deadline: deadline, IdempotencyKey: request.IdempotencyKey,
		RequestID: request.ID.String(), CorrelationID: request.CorrelationID.String(),
	}
	publishRequest.HealthCheck.ActivationTimeout = policy.ActivationTimeout
	publishRequest.HealthCheck.ObservationWindow = policy.ObservationWindow
	publishRequest.HealthCheck.RequiredConsecutiveSuccesses = policy.RequiredConsecutiveSuccesses
	if policy.TargetSnapshot != nil {
		publishRequest.TargetSnapshot = &edgepublish.TargetSnapshotReference{
			ID: policy.TargetSnapshot.ID, Revision: policy.TargetSnapshot.Revision, SHA256: policy.TargetSnapshot.SHA256,
		}
	} else {
		// FX02: the node list follows the scope's line groups at publish time,
		// so a node added to a line group receives the next publication.
		publishRequest.NodeIDs, err = publicationNodeIDs(ctx, tx, request.TargetScopeID, policy.NodeIDs)
		if err != nil {
			return edgepublish.PreparedAutomaticPublication{}, err
		}
		if len(publishRequest.NodeIDs) == 0 {
			return edgepublish.PreparedAutomaticPublication{}, ErrNoTargetNodes
		}
	}
	return edgepublish.PreparedAutomaticPublication{Request: publishRequest, DatabaseNow: now}, nil
}

func (s *Store) Retry(ctx context.Context, claim Claim, reason string, delay time.Duration) error {
	if err := validateClaim(claim); err != nil || !validFailureClass(reason) || delay < 0 || delay > time.Hour {
		return ErrInvalidInput
	}
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		state, err := lockClaimState(ctx, tx, claim)
		if err != nil {
			return err
		}
		now, err := serverNow(ctx, tx)
		if err != nil {
			return err
		}
		available := now.Add(delay)
		return appendStateTx(ctx, tx, claim.Request.ID, state.Sequence+1, StateRetryWait,
			state.Attempt, nil, nil, nil, nil, nil, &available, "", &reason, now)
	})
}

func (s *Store) RetryAutomaticPublication(
	ctx context.Context,
	reference edgepublish.AutomaticClaimReference,
	reason string,
	delay time.Duration,
) error {
	if !validAutomaticReference(reference) || !validFailureClass(reason) || delay < 0 || delay > time.Hour {
		return ErrInvalidInput
	}
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		_, _, state, err := lockAutomaticReference(ctx, tx, reference)
		if err != nil {
			return err
		}
		now, err := serverNow(ctx, tx)
		if err != nil {
			return err
		}
		available := now.Add(delay)
		return appendStateTx(ctx, tx, reference.RequestID, state.Sequence+1, StateRetryWait,
			state.Attempt, nil, nil, nil, nil, nil, &available, "", &reason, now)
	})
}

func (s *Store) Fail(ctx context.Context, claim Claim, reason string) error {
	if err := validateClaim(claim); err != nil || !validTerminalReason(reason) {
		return ErrInvalidInput
	}
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		state, err := lockClaimState(ctx, tx, claim)
		if err != nil {
			return err
		}
		now, err := serverNow(ctx, tx)
		if err != nil {
			return err
		}
		if err := appendStateTx(ctx, tx, claim.Request.ID, state.Sequence+1, StateFailed,
			state.Attempt, nil, nil, nil, state.PublicationID, state.RolloutID, nil, reason, nil, now); err != nil {
			return err
		}
		return s.appendTerminalAudit(ctx, tx, claim.Request, StateFailed, reason)
	})
}

func (s *Store) FailAutomaticPublication(
	ctx context.Context,
	reference edgepublish.AutomaticClaimReference,
	reason string,
) error {
	if !validAutomaticReference(reference) || !validTerminalReason(reason) {
		return ErrInvalidInput
	}
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		request, _, state, err := lockAutomaticReference(ctx, tx, reference)
		if err != nil {
			return err
		}
		now, err := serverNow(ctx, tx)
		if err != nil {
			return err
		}
		if err := appendStateTx(ctx, tx, reference.RequestID, state.Sequence+1, StateFailed,
			state.Attempt, nil, nil, nil, state.PublicationID, state.RolloutID, nil, reason, nil, now); err != nil {
			return err
		}
		return s.appendTerminalAudit(ctx, tx, request, StateFailed, reason)
	})
}

func (s *Store) RecordPublication(ctx context.Context, claim Claim, result edgepublish.PublishResult) error {
	if err := validateClaim(claim); err != nil || result.PublicationID == uuid.Nil || result.RolloutID == uuid.Nil ||
		result.ConfigurationScopeID != claim.Request.TargetScopeID || result.SourceRevision != claim.Request.SourceRevision {
		return ErrInvalidInput
	}
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		state, err := lockClaimState(ctx, tx, claim)
		if err != nil {
			return err
		}
		var matches bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS(
			SELECT 1 FROM edge_config_publications
			WHERE id=$1 AND configuration_scope_id=$2 AND source_revision=$3 AND rollout_id=$4
		)`, result.PublicationID, result.ConfigurationScopeID, result.SourceRevision, result.RolloutID).Scan(&matches); err != nil {
			return err
		}
		if !matches {
			return ErrInvalidInput
		}
		now, err := serverNow(ctx, tx)
		if err != nil {
			return err
		}
		return appendStateTx(ctx, tx, claim.Request.ID, state.Sequence+1, StateReconciling,
			state.Attempt, nil, nil, nil, &result.PublicationID, &result.RolloutID, nil, "", nil, now)
	})
}

func (s *Store) RecordAutomaticPublication(
	ctx context.Context,
	tx pgx.Tx,
	reference edgepublish.AutomaticClaimReference,
	result edgepublish.PublishResult,
	databaseNow time.Time,
) error {
	if tx == nil || !validAutomaticReference(reference) || databaseNow.IsZero() ||
		result.PublicationID == uuid.Nil || result.RolloutID == uuid.Nil {
		return ErrInvalidInput
	}
	request, _, state, err := lockAutomaticReference(ctx, tx, reference)
	if err != nil {
		return err
	}
	if result.ConfigurationScopeID != request.TargetScopeID || result.SourceRevision != request.SourceRevision ||
		!result.CreatedAt.Equal(databaseNow) {
		return ErrInvalidInput
	}
	var matches bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS(
		SELECT 1 FROM edge_config_publications
		WHERE id=$1 AND configuration_scope_id=$2 AND source_revision=$3 AND rollout_id=$4
	)`, result.PublicationID, result.ConfigurationScopeID, result.SourceRevision, result.RolloutID).Scan(&matches); err != nil {
		return err
	}
	if !matches {
		return ErrInvalidInput
	}
	return appendStateTx(ctx, tx, reference.RequestID, state.Sequence+1, StateReconciling,
		state.Attempt, nil, nil, nil, &result.PublicationID, &result.RolloutID, nil, "", nil, databaseNow)
}

func (s *Store) ReconcileOne(ctx context.Context) (bool, error) {
	var processed bool
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		var requestID uuid.UUID
		err := tx.QueryRow(ctx, `
			SELECT request_row.id
			FROM edge_automatic_publication_requests request_row
			JOIN LATERAL (
				SELECT state FROM edge_automatic_publication_request_state_facts
				WHERE request_id=request_row.id ORDER BY sequence DESC LIMIT 1
			) state ON true
			WHERE state.state='reconciling'
			ORDER BY request_row.created_at,request_row.id LIMIT 1
			FOR UPDATE OF request_row SKIP LOCKED`).Scan(&requestID)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		request, _, state, err := loadClaimFacts(ctx, tx, requestID)
		if err != nil {
			return err
		}
		if state.RolloutID == nil {
			return ErrInvalidInput
		}
		var action, persistedState string
		var contractVersion int16
		if err := tx.QueryRow(ctx, `SELECT action,status,contract_version FROM rollouts
			WHERE configuration_scope_id=$1 AND id=$2`, request.TargetScopeID, *state.RolloutID).
			Scan(&action, &persistedState, &contractVersion); err != nil {
			return err
		}
		// An ignored old release reads as "superseded" (classifyRollout).
		rows, err := tx.Query(ctx, `
			SELECT latest.state
			FROM (
				SELECT DISTINCT ON (deployment.id) deployment.id,deployment.node_id,
				       CASE WHEN `+edgedeployment.SupersededDeploymentSQL+` THEN 'superseded' ELSE deployment.state END AS state
				FROM node_deployments deployment
				WHERE deployment.rollout_id=$1
				ORDER BY deployment.id,deployment.attempt DESC
			) latest ORDER BY latest.node_id,latest.id`, *state.RolloutID)
		if err != nil {
			return err
		}
		states := make([]string, 0)
		for rows.Next() {
			var value string
			if err := rows.Scan(&value); err != nil {
				rows.Close()
				return err
			}
			states = append(states, value)
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return err
		}
		rows.Close()
		terminal, outcome, reason := classifyPersistedRollout(contractVersion, action, persistedState, states)
		if !terminal {
			return nil
		}
		now, err := serverNow(ctx, tx)
		if err != nil {
			return err
		}
		if err := appendStateTx(ctx, tx, request.ID, state.Sequence+1, outcome, state.Attempt,
			nil, nil, nil, state.PublicationID, state.RolloutID, nil, reason, nil, now); err != nil {
			return err
		}
		if err := s.appendTerminalAudit(ctx, tx, request, outcome, reason); err != nil {
			return err
		}
		processed = true
		return nil
	})
	return processed, err
}

func (s *Store) appendTerminalAudit(ctx context.Context, tx pgx.Tx, request Request, outcome, reason string) error {
	return s.auditor.Append(ctx, tx, audit.Event{
		ScopeID: request.TargetScopeID, ActorUserID: &request.ActorUserID,
		Action: "edge_automatic_publication." + outcome, ResourceType: "edge_automatic_publication_request",
		ResourceID: request.ID.String(), RequestID: request.SourceRequestID, Result: terminalAuditResult(outcome),
		Payload: map[string]any{
			"actor_scope_id": request.ActorScopeID.String(), "target_scope_id": request.TargetScopeID.String(),
			"operation": request.Operation, "reason": reason, "source_revision": request.SourceRevision,
		},
	})
}

// terminalAuditResult maps a terminal request state onto audit_events.result
// (001: success/denied/failure); the state itself stays in the action name.
func terminalAuditResult(outcome string) string {
	if outcome == StateSucceeded {
		return "success"
	}
	return "failure"
}

func lockClaimState(ctx context.Context, tx pgx.Tx, claim Claim) (requestState, error) {
	if _, err := tx.Exec(ctx, `SELECT 1 FROM edge_automatic_publication_requests WHERE id=$1 FOR UPDATE`, claim.Request.ID); err != nil {
		return requestState{}, err
	}
	state, err := loadLatestState(ctx, tx, claim.Request.ID)
	if err != nil {
		return requestState{}, err
	}
	if state.Sequence != claim.StateSequence || state.State != StateLeased || state.LeaseToken == nil ||
		*state.LeaseToken != claim.LeaseToken {
		return requestState{}, ErrStaleClaim
	}
	return state, nil
}

func lockAutomaticReference(
	ctx context.Context,
	tx pgx.Tx,
	reference edgepublish.AutomaticClaimReference,
) (Request, Policy, requestState, error) {
	if !validAutomaticReference(reference) {
		return Request{}, Policy{}, requestState{}, ErrInvalidInput
	}
	if _, err := tx.Exec(ctx, `SELECT 1 FROM edge_automatic_publication_requests WHERE id=$1 FOR UPDATE`,
		reference.RequestID); err != nil {
		return Request{}, Policy{}, requestState{}, err
	}
	request, policy, state, err := loadClaimFacts(ctx, tx, reference.RequestID)
	if errors.Is(err, pgx.ErrNoRows) {
		return Request{}, Policy{}, requestState{}, ErrStaleClaim
	}
	if err != nil {
		return Request{}, Policy{}, requestState{}, err
	}
	if state.Sequence != reference.StateSequence || state.State != StateLeased || state.LeaseToken == nil ||
		*state.LeaseToken != reference.LeaseToken {
		return Request{}, Policy{}, requestState{}, ErrStaleClaim
	}
	return request, policy, state, nil
}

func loadClaimFacts(ctx context.Context, tx pgx.Tx, requestID uuid.UUID) (Request, Policy, requestState, error) {
	var request Request
	var resourceID *uuid.UUID
	var publishIntentID *uuid.UUID
	var digest []byte
	err := tx.QueryRow(ctx, `SELECT id,target_scope_id,actor_scope_id,actor_user_id,actor_scope_kind,
		source_kind,source_resource_id,publish_intent_id,source_revision,operation,reason,permission_name,
		source_request_id,idempotency_key,correlation_id,request_digest,policy_revision,created_at
		FROM edge_automatic_publication_requests WHERE id=$1`, requestID).Scan(
		&request.ID, &request.TargetScopeID, &request.ActorScopeID, &request.ActorUserID, &request.ActorScopeKind,
		&request.SourceKind, &resourceID, &publishIntentID, &request.SourceRevision, &request.Operation, &request.Reason,
		&request.Permission, &request.SourceRequestID, &request.IdempotencyKey, &request.CorrelationID,
		&digest, &request.PolicyRevision, &request.CreatedAt)
	if err != nil {
		return Request{}, Policy{}, requestState{}, err
	}
	if resourceID != nil {
		request.SourceResourceID = *resourceID
	}
	if publishIntentID != nil {
		request.PublishIntentID = *publishIntentID
	}
	if len(digest) != sha256.Size {
		return Request{}, Policy{}, requestState{}, ErrInvalidInput
	}
	copy(request.RequestDigest[:], digest)
	policy, err := loadPolicyRevision(ctx, tx, request.TargetScopeID, request.PolicyRevision)
	if err != nil {
		return Request{}, Policy{}, requestState{}, err
	}
	state, err := loadLatestState(ctx, tx, request.ID)
	return request, policy, state, err
}

func loadCurrentPolicy(ctx context.Context, tx pgx.Tx, scopeID uuid.UUID) (Policy, bool, error) {
	var revision int64
	err := tx.QueryRow(ctx, `SELECT revision FROM edge_automatic_publication_policy_facts
		WHERE target_scope_id=$1 ORDER BY revision DESC LIMIT 1`, scopeID).Scan(&revision)
	if errors.Is(err, pgx.ErrNoRows) {
		return Policy{}, false, nil
	}
	if err != nil {
		return Policy{}, false, err
	}
	policy, err := loadPolicyRevision(ctx, tx, scopeID, revision)
	return policy, true, err
}

func loadPolicyRevision(ctx context.Context, tx pgx.Tx, scopeID uuid.UUID, revision int64) (Policy, error) {
	var policy Policy
	var activationMS, observationMS, deadlineSeconds int64
	var successes, maxAttempts int
	var snapshotID *uuid.UUID
	var snapshotRevision *int64
	var snapshotDigest []byte
	err := tx.QueryRow(ctx, `SELECT target_scope_id,revision,mode,node_ids,target_snapshot_id,
		target_snapshot_revision,target_snapshot_sha256,activation_timeout_ms,observation_window_ms,
		required_consecutive_successes,max_attempts,deadline_window_seconds
		FROM edge_automatic_publication_policy_facts WHERE target_scope_id=$1 AND revision=$2`, scopeID, revision).Scan(
		&policy.TargetScopeID, &policy.Revision, &policy.Mode, &policy.NodeIDs, &snapshotID,
		&snapshotRevision, &snapshotDigest, &activationMS, &observationMS, &successes, &maxAttempts, &deadlineSeconds)
	if err != nil {
		return Policy{}, err
	}
	policy.ActivationTimeout = time.Duration(activationMS) * time.Millisecond
	policy.ObservationWindow = time.Duration(observationMS) * time.Millisecond
	policy.RequiredConsecutiveSuccesses = uint32(successes)
	policy.MaxAttempts = uint32(maxAttempts)
	policy.DeadlineWindow = time.Duration(deadlineSeconds) * time.Second
	if snapshotID != nil && snapshotRevision != nil && len(snapshotDigest) == sha256.Size {
		var value [32]byte
		copy(value[:], snapshotDigest)
		policy.TargetSnapshot = &TargetSnapshot{ID: *snapshotID, Revision: *snapshotRevision, SHA256: value}
	}
	return policy, nil
}

func loadLatestState(ctx context.Context, tx pgx.Tx, requestID uuid.UUID) (requestState, error) {
	var state requestState
	err := tx.QueryRow(ctx, `SELECT sequence,state,attempt,lease_owner,lease_token,lease_expires_at,
		publication_id,rollout_id FROM edge_automatic_publication_request_state_facts
		WHERE request_id=$1 ORDER BY sequence DESC LIMIT 1`, requestID).Scan(
		&state.Sequence, &state.State, &state.Attempt, &state.LeaseOwner, &state.LeaseToken,
		&state.LeaseExpiresAt, &state.PublicationID, &state.RolloutID)
	return state, err
}

func appendStateTx(
	ctx context.Context,
	tx pgx.Tx,
	requestID uuid.UUID,
	sequence int64,
	state string,
	attempt int,
	leaseOwner *string,
	leaseToken *uuid.UUID,
	leaseExpiresAt *time.Time,
	publicationID *uuid.UUID,
	rolloutID *uuid.UUID,
	availableAt *time.Time,
	terminalCode string,
	errorClass *string,
	occurredAt time.Time,
) error {
	var terminal *string
	if terminalCode != "" {
		terminal = &terminalCode
	}
	_, err := tx.Exec(ctx, `INSERT INTO edge_automatic_publication_request_state_facts(
		request_id,sequence,state,attempt,lease_owner,lease_token,lease_expires_at,
		publication_id,rollout_id,available_at,terminal_code,error_class,occurred_at
	) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`, requestID, sequence, state,
		attempt, leaseOwner, leaseToken, leaseExpiresAt, publicationID, rolloutID, availableAt,
		terminal, errorClass, occurredAt)
	return err
}

func serverNow(ctx context.Context, tx pgx.Tx) (time.Time, error) {
	var now time.Time
	err := tx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now)
	return now.UTC().Truncate(time.Microsecond), err
}

func automaticRequestDigest(input EnqueueInput, policy Policy, sourceRevision int64) ([32]byte, error) {
	if !validConfigurationSourceBinding(input.SourceKind, input.PublishIntentID,
		input.ConfigurationSourceRevision, sourceRevision) {
		return [32]byte{}, ErrInvalidInput
	}
	nodes := append([]uuid.UUID(nil), policy.NodeIDs...)
	sort.Slice(nodes, func(i, j int) bool { return bytes.Compare(nodes[i][:], nodes[j][:]) < 0 })
	nodeIDs := make([]string, len(nodes))
	for index, nodeID := range nodes {
		nodeIDs[index] = nodeID.String()
	}
	payload := enqueueDigestInput{
		TargetScopeID: input.TargetScopeID.String(), ActorScopeID: input.Actor.ScopeID.String(),
		ActorUserID: input.Actor.UserID.String(), ActorScopeKind: input.Actor.ScopeKind,
		SourceKind: input.SourceKind, SourceRevision: sourceRevision, Operation: input.Operation,
		Reason: input.Reason, Permission: input.Permission, SourceRequestID: input.SourceRequestID,
		PolicyRevision: policy.Revision, NodeIDs: nodeIDs,
		ActivationMS: policy.ActivationTimeout.Milliseconds(), ObservationMS: policy.ObservationWindow.Milliseconds(),
		Successes: policy.RequiredConsecutiveSuccesses, MaxAttempts: policy.MaxAttempts,
		DeadlineSeconds: int64(policy.DeadlineWindow / time.Second),
	}
	if input.SourceResourceID != uuid.Nil {
		value := input.SourceResourceID.String()
		payload.SourceResourceID = &value
	}
	if input.SourceKind == SourceL4 {
		intentID, revision := input.PublishIntentID.String(), input.ConfigurationSourceRevision
		payload.PublishIntentID, payload.ConfigurationSourceRevision = &intentID, &revision
	}
	if policy.TargetSnapshot != nil {
		id, revision, digest := policy.TargetSnapshot.ID.String(), policy.TargetSnapshot.Revision,
			fmt.Sprintf("%x", policy.TargetSnapshot.SHA256[:])
		payload.TargetSnapshotID, payload.TargetRevision, payload.TargetSHA256 = &id, &revision, &digest
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(encoded), nil
}

func validConfigurationSourceBinding(
	kind string,
	publishIntentID uuid.UUID,
	configurationSourceRevision, currentSourceRevision int64,
) bool {
	switch kind {
	case SourceL4:
		return publishIntentID != uuid.Nil && configurationSourceRevision > 0 &&
			currentSourceRevision > 0 && configurationSourceRevision == currentSourceRevision
	case SourceSite, SourceLineGroup, SourceNodeSync, SourceNodeCapability, SourceRuleCatalog, SourceChallengeDelivery,
		SourceModuleEntitlement, SourceNodeNetworks:
		return publishIntentID == uuid.Nil && configurationSourceRevision == 0
	default:
		return false
	}
}

func validSourceOperation(kind, operation, permission string, resourceID uuid.UUID) bool {
	switch kind {
	case SourceSite:
		if permission != PermissionSitesManage {
			return false
		}
		switch operation {
		case "site.create", "site.update", "site.origin.update", "site.delete":
			return resourceID != uuid.Nil
		case "site.batch.enable", "site.batch.disable", "site.batch.delete":
			return resourceID == uuid.Nil
		}
	case SourceL4:
		if permission == PermissionStreamsManage && resourceID != uuid.Nil {
			return operation == "stream.create" || operation == "stream.update" || operation == "stream.delete"
		}
	case SourceLineGroup:
		return permission == PermissionSitesManage && resourceID != uuid.Nil && operation == OperationLineGroupNodesChanged
	case SourceNodeSync:
		return permission == PermissionSitesManage && resourceID != uuid.Nil && operation == OperationNodeSyncRetry
	case SourceNodeCapability:
		return permission == PermissionSitesManage && resourceID != uuid.Nil && operation == OperationNodeCapabilitiesChange
	case SourceRuleCatalog:
		return permission == PermissionSitesManage && resourceID != uuid.Nil && operation == OperationRuleCatalogUpdated
	case SourceChallengeDelivery:
		return permission == PermissionSitesManage && resourceID != uuid.Nil && operation == OperationNodeChallengeDelivered
	case SourceModuleEntitlement:
		return permission == PermissionSitesManage && resourceID != uuid.Nil && operation == OperationModulesGranted
	case SourceNodeNetworks:
		return permission == PermissionSitesManage && resourceID != uuid.Nil && operation == OperationNodeNetworksChanged
	}
	return false
}

func sourceReason(kind string) string {
	switch kind {
	case SourceLineGroup:
		return ReasonNodeSetChanged
	case SourceNodeSync:
		return ReasonSyncRetry
	case SourceNodeCapability:
		return ReasonCapabilityChange
	case SourceRuleCatalog:
		return ReasonCatalogChange
	case SourceChallengeDelivery:
		return ReasonChallengeDelivered
	case SourceModuleEntitlement:
		return ReasonEntitlementChanged
	case SourceNodeNetworks:
		return ReasonNodeNetworksChange
	default:
		return ReasonResourceMutation
	}
}

func validateClaim(claim Claim) error {
	if claim.Request.ID == uuid.Nil || claim.Request.TargetScopeID == uuid.Nil || claim.LeaseToken == uuid.Nil ||
		claim.StateSequence < 2 || claim.Attempt < 1 {
		return ErrInvalidInput
	}
	return nil
}

func validAutomaticReference(reference edgepublish.AutomaticClaimReference) bool {
	return reference.RequestID != uuid.Nil && reference.LeaseToken != uuid.Nil && reference.StateSequence >= 2
}

func nonterminalState(state string) bool {
	return state == StatePending || state == StateLeased || state == StateRetryWait || state == StateReconciling
}

func validFailureClass(reason string) bool {
	return reason == FailurePublishUnknown || reason == FailureActorUnavailable
}

func validTerminalReason(reason string) bool {
	switch reason {
	case FailureRBACRevoked, FailureApplyReverted, FailureRollbackUnexpected,
		FailureDeploymentFailed, FailureRollbackFailed, FailureCancelled,
		FailureNoTargetNodes, FailureNodeCapability, FailureNodeArtifactsSyncing, FailureNodeScopeConflict:
		return true
	default:
		return false
	}
}
