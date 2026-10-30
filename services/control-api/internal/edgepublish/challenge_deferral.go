package edgepublish

import (
	"context"
	"fmt"
	"slices"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// ChallengeDeferral is a JS challenge promotion that published its binding
// to the ready nodes only: the deferred nodes
// (offline, isolated, disabled) did not hold it back.
type ChallengeDeferral struct {
	Actor            Actor
	ScopeID          uuid.UUID
	SourceRevision   int64
	RequestID        string
	PublishedNodeIDs []uuid.UUID
	DeferredNodeIDs  []uuid.UUID
	SiteID, PolicyID uuid.UUID
	PolicyVersion    int64
	// SecretRolloutID is the promoted challenge secret rollout.
	SecretRolloutID uuid.UUID
}

// DeferChallengeNodesTx records, in the publication's transaction, that the
// revision was asked for the published and the deferred nodes (a capability
// hold refusing the deferred ones, so system republication targets them),
// and makes each deferred node's secret deployment still on its way (or
// installed meanwhile) its redelivery: the redeliverer observes it, and its
// healthy receipt republishes the scope with trigger challenge_delivery. A
// deferred node whose deployment failed or ran out is queued afresh by the
// redeliverer once it is eligible again.
func (s *Service) DeferChallengeNodesTx(ctx context.Context, tx pgx.Tx, deferral ChallengeDeferral) error {
	if s == nil || ctx == nil || tx == nil || deferral.ScopeID == uuid.Nil || deferral.SourceRevision < 1 ||
		deferral.Actor.system != nil || deferral.Actor.UserID == uuid.Nil || deferral.Actor.ScopeID == uuid.Nil ||
		len(deferral.PublishedNodeIDs) == 0 || len(deferral.DeferredNodeIDs) == 0 || deferral.SiteID == uuid.Nil ||
		deferral.PolicyID == uuid.Nil || deferral.PolicyVersion < 1 || deferral.SecretRolloutID == uuid.Nil ||
		slices.ContainsFunc(deferral.DeferredNodeIDs, func(nodeID uuid.UUID) bool {
			return nodeID == uuid.Nil || slices.Contains(deferral.PublishedNodeIDs, nodeID)
		}) {
		return ErrInvalidInput
	}
	request := PublishRequest{Actor: deferral.Actor, ConfigurationScopeID: deferral.ScopeID,
		ExpectedSourceRevision: deferral.SourceRevision, RequestID: deferral.RequestID}
	if err := s.insertCapabilityHoldTx(ctx, tx, request, slices.Concat(deferral.PublishedNodeIDs, deferral.DeferredNodeIDs),
		deferral.DeferredNodeIDs, map[string]any{"feature": "JS challenge policy not installed", "challenge": map[string]any{
			"site_id": deferral.SiteID, "policy_id": deferral.PolicyID, "policy_version": deferral.PolicyVersion,
			"secret_rollout_id": deferral.SecretRolloutID, "deferred": true,
		}}, true); err != nil {
		return fmt.Errorf("%w: hold deferred challenge nodes: %w", ErrPersistence, err)
	}
	var held bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM edge_capability_publication_holds
		WHERE scope_id=$1 AND source_revision=$2 AND published)`, deferral.ScopeID, deferral.SourceRevision).Scan(&held); err != nil {
		return fmt.Errorf("%w: read deferred challenge hold: %w", ErrPersistence, err)
	}
	if !held {
		// The scope moved past the revision inside its own publication.
		return ErrRevisionConflict
	}
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, challengeRedeliveryLockKey(deferral.ScopeID)); err != nil {
		return fmt.Errorf("%w: lock challenge redeliveries: %w", ErrPersistence, err)
	}
	// The node's latest attempt of the promoted rollout, unless it failed or
	// ran out: a row being delivered already is left alone.
	if _, err := tx.Exec(ctx, `INSERT INTO edge_challenge_redeliveries AS redelivery(
			scope_id,node_id,policy_id,policy_version,site_id,origin_config_version_id,state,attempt,session_epoch,
			due_at,rollout_id,deadline_at,created_at,updated_at)
		SELECT $1,deployment.node_id,$3,$4,$5,rollout.config_version_id,'delivering',1,
		       COALESCE((SELECT presence.session_epoch FROM node_presence presence WHERE presence.node_id=deployment.node_id),0),
		       clock_timestamp(),rollout.id,deployment.deadline_at,clock_timestamp(),clock_timestamp()
		FROM rollouts rollout
		JOIN LATERAL (SELECT DISTINCT ON (node_id) node_id,state,deadline_at FROM node_deployments
		  WHERE rollout_id=rollout.id AND node_id=ANY($6::uuid[]) ORDER BY node_id,attempt DESC) deployment ON true
		WHERE rollout.configuration_scope_id=$1 AND rollout.id=$2
		  AND (deployment.state='healthy' OR deployment.state NOT IN ('failed','reverted','rollback_failed','cancelled')
		       AND deployment.deadline_at>clock_timestamp())
		ON CONFLICT (scope_id,node_id,policy_id,policy_version) DO UPDATE SET state='delivering',attempt=1,
		  session_epoch=EXCLUDED.session_epoch,site_id=EXCLUDED.site_id,
		  origin_config_version_id=EXCLUDED.origin_config_version_id,due_at=EXCLUDED.due_at,
		  rollout_id=EXCLUDED.rollout_id,deadline_at=EXCLUDED.deadline_at,delivered_at=NULL,last_error=NULL,
		  updated_at=EXCLUDED.updated_at
		WHERE redelivery.state<>'delivering'`, deferral.ScopeID, deferral.SecretRolloutID, deferral.PolicyID,
		deferral.PolicyVersion, deferral.SiteID, deferral.DeferredNodeIDs); err != nil {
		return fmt.Errorf("%w: adopt deferred challenge deployments: %w", ErrPersistence, err)
	}
	return nil
}
