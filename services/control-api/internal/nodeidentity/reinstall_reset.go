package nodeidentity

import (
	"context"
	"errors"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/edgedeployment"
	"github.com/cdnca/cdnca/services/control-api/internal/nodemonitoringconfig"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// A node enrolled again ("重装此节点" re_enrollment, or a re-enrollment after
// its certificate expired) may be a new host under the same node ID: it holds
// nothing the control plane delivered to the previous one. Each distributor
// decides "already delivered" from the node's state below; that state still
// describes the previous host, so the distributors would never send again
// (no service ticket, no signer trust, no site
// configuration). resetHostDeliveryStateTx makes the node look like a host
// that holds nothing, in the enrollment transaction. History, audit, metrics
// and line group endpoints are kept.
//
// Distributors whose "delivered" proof is node_deployments history (artifact
// sets, challenge and origin authentication secrets) only count deployments of
// the current host (edgedeployment.CurrentHostDeployment) and need no reset;
// the previous host's running deployments are ended
// (edgedeployment.CloseReplacedHostDeploymentsTx).

// hostResetRequestPrefix names the republications a reinstall queues.
const hostResetRequestPrefix = "node-reinstall/"

// lockNodeConfigurationScopesTx locks, in scope order, the edge configuration
// scopes the node carries, before the node row: the publication lock order
// (scope, then node), so a concurrent publication does not deadlock with the
// enrollment that republishes these scopes.
func lockNodeConfigurationScopesTx(ctx context.Context, tx pgx.Tx, nodeID uuid.UUID) error {
	_, err := tx.Exec(ctx, `SELECT scope.scope_id FROM edge_configuration_scopes scope
		WHERE scope.scope_id IN (SELECT configuration_scope_id FROM node_config_state WHERE node_id=$1)
		ORDER BY scope.scope_id FOR UPDATE OF scope`, nodeID)
	if err != nil {
		return ErrPersistence
	}
	return nil
}

func resetHostDeliveryStateTx(ctx context.Context, tx pgx.Tx, republish NodeScopeRepublisher, nodeID,
	authorizationID uuid.UUID) ([]string, error) {
	for _, statement := range []string{
		// Service ticket and ban notice (installationban.deliveryDue).
		`DELETE FROM installation_ban_node_state WHERE node_id=$1`,
		// Signer trust (edgesignertrustsync.EnforcedRevisions); the service
		// ticket waits for it.
		`DELETE FROM edge_signer_trust_node_state WHERE node_id=$1`,
		// Security bans and level D site drops: the revision stays (the agent
		// refuses a lower one), the node has applied nothing.
		`UPDATE security_ban_node_state SET applied_revision=0,applied_sha256=NULL,applied=NULL,applied_bans=NULL,
			applied_releases=NULL,error_code='',reported_at=NULL WHERE node_id=$1`,
		`UPDATE escalate_site_drop_node_states SET applied_revision=0,applied=false,mode='',error_code='',
			rejected='[]'::jsonb,reported_at=NULL WHERE node_id=$1`,
		// Auto-defense snapshot: unanswered, published again at once.
		`UPDATE autodefense_node_snapshots SET receipt_revision=NULL,receipt_applied=NULL,receipt_error=NULL,
			receipt_sites=NULL,receipt_signatures=NULL,receipt_mitigations=NULL,receipt_at=NULL,
			published_at=NULL,publish_count=0,updated_at=clock_timestamp() WHERE node_id=$1`,
		// What the previous host reported about itself (attack states freeze
		// WAF relaxation; release acks and WAF limits are shown per node).
		`DELETE FROM autodefense_site_node_states WHERE node_id=$1`,
		`DELETE FROM autodefense_site_release_acks WHERE node_id=$1`,
		`DELETE FROM waf_adapt_node_limits WHERE node_id=$1`,
		// The capability watcher takes the new host's set as a new baseline.
		`DELETE FROM edge_node_capability_marks WHERE node_id=$1`,
		// "Only the controller may SSH": the setting goes out again.
		`UPDATE node_ssh_access SET revision=revision+1,state='pending',failure_code='',applied_at=NULL,
			confirmed_at=NULL,published_operation='',published_at=NULL,updated_at=clock_timestamp()
			WHERE node_id=$1 AND state<>'pending'`,
		// Site configuration: the node runs none of its scopes' versions.
		`UPDATE node_config_state SET current_config_version_id=NULL,previous_config_version_id=NULL,
			current_config_identity_schema=NULL,current_config_artifact_sha256=NULL,
			previous_config_identity_schema=NULL,previous_config_artifact_sha256=NULL,
			reconciliation_required=false,reconciliation_reason=NULL,reconciliation_deployment_id=NULL,
			reconciliation_deployment_attempt=NULL,reconciliation_requested_at=NULL,
			revision=revision+1,updated_at=clock_timestamp() WHERE node_id=$1`,
	} {
		if _, err := tx.Exec(ctx, statement, nodeID); err != nil {
			return nil, ErrPersistence
		}
	}
	// Node monitoring: one artifact per (node, effective revision) went to
	// a work queue the previous host acknowledged, so it is never sent again.
	// One more override revision (fields unchanged, by the user who issued
	// the enrollment token) is a new effective revision, published once the
	// new host serves (nodemonitoringoutbox reconciliation).
	if _, err := tx.Exec(ctx, `INSERT INTO node_monitoring_overrides AS override(node_id,scope_id,revision,
			updated_by_user_id,created_at,updated_at)
		SELECT node.id,node.scope_id,1,token.created_by_user_id,stamp.at,stamp.at
		FROM nodes node
		JOIN node_identity_authorizations issued ON issued.id=$2 AND issued.node_id=node.id
		JOIN node_enrollment_tokens token ON token.id=issued.token_id
		CROSS JOIN (SELECT clock_timestamp() AS at) stamp
		WHERE node.id=$1
		ON CONFLICT (node_id) DO UPDATE SET revision=override.revision+1,
			updated_by_user_id=EXCLUDED.updated_by_user_id,updated_at=GREATEST(override.updated_at,EXCLUDED.updated_at)
		WHERE override.revision < $3`, nodeID, authorizationID, nodemonitoringconfig.MaxOverrideRevision); err != nil {
		return nil, ErrPersistence
	}
	// The previous host's running deployments end as failed (host_replaced),
	// before the republication queues the new host's.
	if _, err := edgedeployment.CloseReplacedHostDeploymentsTx(ctx, tx, nodeID); err != nil {
		return nil, ErrPersistence
	}
	return republishNodeScopesTx(ctx, tx, republish, nodeID, authorizationID)
}

// ErrNodeNotReinstalled refuses ResetReinstalledHost for a node enrolled once.
var ErrNodeNotReinstalled = errors.New("node was not re-enrolled")

// HostResetResult is what ResetReinstalledHost did.
type HostResetResult struct {
	NodeID            uuid.UUID `json:"node_id"`
	EnrolledAt        time.Time `json:"enrolled_at"`
	RepublishedScopes []string  `json:"republished_scope_ids"`
}

// ResetReinstalledHost applies, once, the enrollment reset to a node that was
// re-enrolled before the enrollment transaction did it (field repair for nodes
// reinstalled on an older control plane; control-api reset-node-host-delivery).
// It refuses a node with a single enrollment, so it cannot drop the delivery
// state of a host that holds it. Running it again only republishes again.
func (s *Store) ResetReinstalledHost(ctx context.Context, nodeID uuid.UUID, requestID string) (HostResetResult, error) {
	if s == nil || s.pool == nil || nodeID == uuid.Nil || requestID == "" || len(requestID) > 128 {
		return HostResetResult{}, ErrInvalidInput
	}
	result := HostResetResult{NodeID: nodeID}
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if err := lockNodeConfigurationScopesTx(ctx, tx, nodeID); err != nil {
			return err
		}
		var scopeID uuid.UUID
		var state string
		var enrollments int
		var enrolledAt *time.Time
		var authorizationID *uuid.UUID
		err := tx.QueryRow(ctx, `SELECT node.scope_id,node.admin_state,
			(SELECT count(*) FROM node_certificates WHERE node_id=node.id AND issuance_kind='initial'),
			(SELECT max(issued_at) FROM node_certificates WHERE node_id=node.id AND issuance_kind='initial'),
			(SELECT enrollment_authorization_id FROM node_certificates WHERE node_id=node.id AND issuance_kind='initial'
			 ORDER BY issued_at DESC LIMIT 1)
			FROM nodes node WHERE node.id=$1 FOR UPDATE OF node`, nodeID).Scan(&scopeID, &state, &enrollments,
			&enrolledAt, &authorizationID)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrCertificateNotFound
		}
		if err != nil {
			return ErrPersistence
		}
		if enrollments < 2 || enrolledAt == nil || authorizationID == nil {
			return ErrNodeNotReinstalled
		}
		if state == "disabled" || state == "retired" {
			return ErrNodeStateDenied
		}
		result.EnrolledAt = enrolledAt.UTC()
		if result.RepublishedScopes, err = resetHostDeliveryStateTx(ctx, tx, s.republishReinstalled, nodeID, *authorizationID); err != nil {
			return err
		}
		return s.auditor.Append(ctx, tx, audit.Event{
			ScopeID: scopeID, Action: "node.host_delivery.reset", ResourceType: "node", ResourceID: nodeID.String(),
			RequestID: requestID, Result: "success", ActorKind: "system", ActorRef: "cli:reset-node-host-delivery",
			Payload: map[string]any{"enrollment_authorization_id": authorizationID.String(),
				"enrolled_at": result.EnrolledAt.Format(time.RFC3339Nano), "republished_scope_ids": result.RepublishedScopes},
		})
	})
	if err != nil {
		if errors.Is(err, ErrNodeNotReinstalled) || errors.Is(err, ErrNodeStateDenied) ||
			errors.Is(err, ErrCertificateNotFound) || errors.Is(err, ErrInvalidInput) {
			return HostResetResult{}, err
		}
		return HostResetResult{}, ErrPersistence
	}
	return result, nil
}

// NodeScopeRepublisher queues, in tx, the republication of scopeIDs (in
// scope order) for a node a new host took over: the scopes' latest
// publications compiled again, their configuration artifacts sealed to the new
// host's key (main: edgeautopublish.RepublishReinstalledNodeTx, trigger
// node_sync). nil (tests) republishes nothing.
type NodeScopeRepublisher func(ctx context.Context, tx pgx.Tx, nodeID uuid.UUID, scopeIDs []uuid.UUID, sourceRequestID string) error

func republishNodeScopesTx(ctx context.Context, tx pgx.Tx, republish NodeScopeRepublisher, nodeID,
	authorizationID uuid.UUID) ([]string, error) {
	rows, err := tx.Query(ctx, `SELECT scope.scope_id FROM edge_configuration_scopes scope
		WHERE scope.scope_id IN (SELECT configuration_scope_id FROM node_config_state WHERE node_id=$1)
		ORDER BY scope.scope_id`, nodeID)
	if err != nil {
		return nil, ErrPersistence
	}
	scopes, err := pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
	if err != nil {
		return nil, ErrPersistence
	}
	if republish == nil || len(scopes) == 0 {
		return []string{}, nil
	}
	if err := republish(ctx, tx, nodeID, scopes, hostResetRequestPrefix+authorizationID.String()); err != nil {
		return nil, ErrPersistence
	}
	queued := make([]string, len(scopes))
	for index, scopeID := range scopes {
		queued[index] = scopeID.String()
	}
	return queued, nil
}
