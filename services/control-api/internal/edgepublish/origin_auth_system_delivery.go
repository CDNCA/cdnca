package edgepublish

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"slices"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/edgedeployment"
	"github.com/cdnca/cdnca/services/control-api/internal/originauthcontrol"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Origin auth system delivery. A
// market leaf writes the subscriber's origin auth rules on its own site
// (originauthcontrol.SetSiteSystem) and publishes them; the credentials must
// then reach the nodes carrying the tenant without anyone pressing "publish
// to nodes" on the leaf. The deliverer gives every eligible target node of
// the scope (challengeRedeliveryTargetsTx; active, online, not isolated,
// carrying the tenant, with an active artifact key) the scope's latest origin
// auth publication through a system secret rollout, audited as the system.
//
// What a node holds is derived from its deployments of rollouts whose config
// snapshot is the publication's canonical snapshot (healthy, or in flight
// within its deadline). A node whose deployments of it failed is retried
// after RetryDelay doubling per failure up to the system republication
// maximum, and given up after SystemRepublicationMaxAttempts until a new
// publication. A rollout that cannot be built (credential unreadable,
// invalid publication) is retried with the same backoff, counted in
// origin_auth_delivery_build_failures (migration 577, fix-mktsiteconf7 §2:
// a restart does not reset it).
// The tenant's own manual publication (originauthpublicationhttp) is
// unchanged and uses the same generator, so either one's rollout counts.
const (
	OriginAuthSecretGeneratorName    = "origin-auth-edge-publication" // = originauthpublicationhttp generatorName
	OriginAuthSecretGeneratorVersion = "v1"
	originAuthDeliveryDeadline       = 15 * time.Minute
	originAuthDeliveryReason         = "market_origin_auth_delivery"
)

// Delivery states.
const (
	OriginAuthDeliveryNone         = "none"          // nothing published with rules
	OriginAuthDeliveryDelivered    = "delivered"     // every target node holds it
	OriginAuthDeliveryDelivering   = "delivering"    // a rollout is on its way
	OriginAuthDeliveryWaitingNodes = "waiting_nodes" // target nodes offline/unready
	OriginAuthDeliveryRetrying     = "retrying"      // last attempt failed, retry due
	OriginAuthDeliveryFailed       = "failed"        // attempts exhausted
)

// Delivery failure reasons (no error text crosses to the subscriber).
const (
	OriginAuthDeliveryNoNodes            = "no_nodes"
	OriginAuthDeliveryNodeRejected       = "node_rejected"
	OriginAuthDeliveryCredential         = "credential_unreadable"
	OriginAuthDeliveryPublicationInvalid = "publication_invalid"
	OriginAuthDeliveryUnavailable        = "delivery_unavailable"
)

// OriginAuthDeliveryStatus is one scope's delivery of its latest publication.
type OriginAuthDeliveryStatus struct {
	Revision  int64      `json:"revision"`
	State     string     `json:"state"`
	Nodes     int        `json:"nodes"`
	Delivered int        `json:"delivered"`
	Reason    string     `json:"reason,omitempty"`
	RolloutID *uuid.UUID `json:"rollout_id,omitempty"`
}

type originAuthSystemRolloutStore interface {
	CreateSystemSecretRolloutTx(context.Context, pgx.Tx, edgedeployment.SystemSecretRolloutRequest,
		edgedeployment.SecretArtifactBuilder) (edgedeployment.CreateRolloutResult, error)
}

type OriginAuthDelivererConfig struct {
	// RetryDelay is the first backoff (0: one minute).
	RetryDelay  time.Duration
	HealthCheck edgedeployment.HealthCheckPolicy
}

type OriginAuthDeliverer struct {
	pool     *pgxpool.Pool
	store    originAuthSystemRolloutStore
	source   OriginAuthProductionSource
	producer *OriginAuthArtifactProducer
	auditor  AuditAppender
	config   OriginAuthDelivererConfig
	now      func() time.Time
}

// originAuthBuildFailure counts failed builds of one scope's revision
// (a row of origin_auth_delivery_build_failures).
type originAuthBuildFailure struct {
	revision int64
	attempts int
	at       time.Time
	reason   string
}

func NewOriginAuthDeliverer(pool *pgxpool.Pool, store originAuthSystemRolloutStore, source OriginAuthProductionSource,
	producer *OriginAuthArtifactProducer, auditor AuditAppender, config OriginAuthDelivererConfig) (*OriginAuthDeliverer, error) {
	if pool == nil || nilServiceDependency(store) || nilServiceDependency(source) || producer == nil ||
		nilServiceDependency(auditor) || config.RetryDelay < 0 || config.RetryDelay > time.Hour ||
		config.HealthCheck.ActivationTimeout <= 0 || config.HealthCheck.ObservationWindow <= 0 ||
		config.HealthCheck.RequiredConsecutiveSuccesses == 0 {
		return nil, ErrInvalidInput
	}
	if config.RetryDelay == 0 {
		config.RetryDelay = time.Minute
	}
	return &OriginAuthDeliverer{pool: pool, store: store, source: source, producer: producer, auditor: auditor,
		config: config, now: time.Now}, nil
}

// Deliver starts what the scope's latest publication still needs (owner is
// the tenant user the rollout is accountable to) and reports the delivery.
func (deliverer *OriginAuthDeliverer) Deliver(ctx context.Context, scopeID, ownerID uuid.UUID) (OriginAuthDeliveryStatus, error) {
	return deliverer.run(ctx, scopeID, ownerID, true)
}

// Status reports the delivery without starting anything.
func (deliverer *OriginAuthDeliverer) Status(ctx context.Context, scopeID uuid.UUID) (OriginAuthDeliveryStatus, error) {
	return deliverer.run(ctx, scopeID, uuid.Nil, false)
}

func (deliverer *OriginAuthDeliverer) run(ctx context.Context, scopeID, ownerID uuid.UUID, start bool) (OriginAuthDeliveryStatus, error) {
	if deliverer == nil || ctx == nil || scopeID == uuid.Nil || start && ownerID == uuid.Nil {
		return OriginAuthDeliveryStatus{}, ErrInvalidInput
	}
	var status OriginAuthDeliveryStatus
	err := pgx.BeginFunc(ctx, deliverer.pool, func(tx pgx.Tx) error {
		if start {
			if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, originAuthDeliveryLockKey(scopeID)); err != nil {
				return err
			}
		}
		var err error
		status, err = deliverer.deliverTx(ctx, tx, scopeID, ownerID, start)
		return err
	})
	return status, err
}

type originAuthNodeState struct {
	nodeID      uuid.UUID
	eligible    bool
	healthy     bool
	inFlight    bool
	failures    int
	lastFailure *time.Time
}

func (deliverer *OriginAuthDeliverer) deliverTx(ctx context.Context, tx pgx.Tx, scopeID, ownerID uuid.UUID,
	start bool) (OriginAuthDeliveryStatus, error) {
	var status OriginAuthDeliveryStatus
	var snapshot []byte
	var rules int
	err := tx.QueryRow(ctx, `SELECT revision,canonical_snapshot,
			COALESCE(jsonb_array_length(convert_from(canonical_snapshot,'UTF8')::jsonb->'rules'),0)
		FROM origin_auth_publications WHERE tenant_scope_id=$1 ORDER BY revision DESC LIMIT 1`, scopeID).
		Scan(&status.Revision, &snapshot, &rules)
	if errors.Is(err, pgx.ErrNoRows) || err == nil && rules == 0 {
		// Nothing to sign with; a node keeps an older bundle no site uses.
		status.State = OriginAuthDeliveryNone
		return status, nil
	}
	if err != nil {
		return status, err
	}
	targets, err := challengeRedeliveryTargetsTx(ctx, tx, scopeID)
	if err != nil {
		return status, err
	}
	nodes, err := originAuthNodeStatesTx(ctx, tx, scopeID, targets, snapshot)
	if err != nil {
		return status, err
	}
	now := deliverer.now().UTC()
	status.Nodes = len(nodes)
	var due []uuid.UUID
	exhausted, delivering, waiting := false, false, false
	for _, node := range nodes {
		switch {
		case node.healthy:
			status.Delivered++
		case node.inFlight:
			delivering = true
		case !node.eligible:
			waiting = true
		case node.failures >= SystemRepublicationMaxAttempts:
			exhausted = true
		case node.failures == 0 || node.lastFailure == nil ||
			!now.Before(node.lastFailure.Add(deliverer.backoff(node.failures))):
			due = append(due, node.nodeID)
		default:
			status.State, status.Reason = OriginAuthDeliveryRetrying, OriginAuthDeliveryNodeRejected
		}
	}
	stored, err := loadBuildFailureTx(ctx, tx, scopeID, start)
	if err != nil {
		return status, err
	}
	build, buildFailed := currentBuildFailure(stored, status.Revision)
	if len(due) > 0 && start {
		if buildFailed && (build.attempts >= SystemRepublicationMaxAttempts || now.Before(build.at.Add(deliverer.backoff(build.attempts)))) {
			due = nil // the build is not due yet
		} else {
			rolloutID, reason, err := deliverer.startTx(ctx, tx, scopeID, ownerID, due)
			if err != nil {
				return status, err
			}
			if reason != "" {
				build, buildFailed = nextBuildFailure(stored, status.Revision, reason, now), true
				if err := saveBuildFailureTx(ctx, tx, scopeID, build); err != nil {
					return status, err
				}
			} else {
				if err := clearBuildFailureTx(ctx, tx, scopeID); err != nil {
					return status, err
				}
				buildFailed, delivering, due = false, true, nil
				status.RolloutID = &rolloutID
			}
		}
	}
	switch {
	case buildFailed && build.attempts >= SystemRepublicationMaxAttempts:
		status.State, status.Reason = OriginAuthDeliveryFailed, build.reason
	case buildFailed:
		status.State, status.Reason = OriginAuthDeliveryRetrying, build.reason
	case exhausted:
		status.State, status.Reason = OriginAuthDeliveryFailed, OriginAuthDeliveryNodeRejected
	case status.State == OriginAuthDeliveryRetrying:
	case delivering || len(due) > 0:
		status.State = OriginAuthDeliveryDelivering
	case len(nodes) == 0:
		status.State, status.Reason = OriginAuthDeliveryWaitingNodes, OriginAuthDeliveryNoNodes
	case waiting:
		status.State = OriginAuthDeliveryWaitingNodes
	default:
		status.State = OriginAuthDeliveryDelivered
	}
	return status, nil
}

// startTx persists one system secret rollout of the latest publication to
// nodeIDs in a savepoint. A failure to build or persist it is a reason (and
// a failure audit event), not an error; only the outer tx failing is.
func (deliverer *OriginAuthDeliverer) startTx(ctx context.Context, tx pgx.Tx, scopeID, ownerID uuid.UUID,
	nodeIDs []uuid.UUID) (uuid.UUID, string, error) {
	source, err := NewOriginAuthSecretRolloutSource(scopeID, deliverer.source, deliverer.producer)
	if err != nil {
		return uuid.Nil, "", err
	}
	savepoint, err := tx.Begin(ctx)
	if err != nil {
		return uuid.Nil, "", err
	}
	rolloutID, createErr := func() (uuid.UUID, error) {
		material, err := source(ctx, savepoint)
		if err != nil {
			return uuid.Nil, err
		}
		defer zeroOriginAuthBytes(material.CanonicalSnapshot)
		attempt, err := uuid.NewV7()
		if err != nil {
			return uuid.Nil, err
		}
		result, err := deliverer.store.CreateSystemSecretRolloutTx(ctx, savepoint, edgedeployment.SystemSecretRolloutRequest{
			ConfigurationScopeID: scopeID, AccountableUserID: ownerID, NodeIDs: slices.Clone(nodeIDs),
			CanonicalSnapshot: material.CanonicalSnapshot, GeneratorName: OriginAuthSecretGeneratorName,
			GeneratorVersion: OriginAuthSecretGeneratorVersion, PayloadDigest: material.PayloadDigest,
			HealthCheck: deliverer.config.HealthCheck, Deadline: deliverer.now().UTC().Add(originAuthDeliveryDeadline).Truncate(time.Microsecond),
			IdempotencyKey: "origin-auth-system." + attempt.String(), RequestID: uuid.NewString(),
			CorrelationID: uuid.NewString(), Reason: originAuthDeliveryReason,
		}, material.Builder)
		if err != nil {
			return uuid.Nil, err
		}
		return result.Rollout.ID, nil
	}()
	if createErr == nil && rolloutID != uuid.Nil {
		return rolloutID, "", savepoint.Commit(ctx)
	}
	if err := savepoint.Rollback(ctx); err != nil {
		return uuid.Nil, "", err
	}
	if ctx.Err() != nil {
		return uuid.Nil, "", ctx.Err()
	}
	reason := OriginAuthDeliveryFailureReason(createErr)
	nodes := make([]string, len(nodeIDs))
	for index, nodeID := range nodeIDs {
		nodes[index] = nodeID.String()
	}
	if err := deliverer.auditor.Append(ctx, tx, audit.Event{
		ScopeID: scopeID, ActorKind: audit.ActorSystem, ActorRef: "job:" + originAuthDeliveryReason,
		Action: "edge_secret_rollout.create", ResourceType: "origin_auth_scope", ResourceID: scopeID.String(),
		// audit_events.request_id is NOT NULL non-empty (001): a build failure that
		// started no rollout still needs its own request id.
		RequestID: uuid.NewString(), Result: "failure", ReasonCode: reason,
		Payload: map[string]any{"reason": originAuthDeliveryReason, "reason_code": reason, "node_ids": nodes,
			"accountable_user_id": ownerID.String()},
	}); err != nil {
		return uuid.Nil, "", err
	}
	return uuid.Nil, reason, nil
}

// OriginAuthDeliveryFailureReason classifies a failed rollout start.
func OriginAuthDeliveryFailureReason(err error) string {
	switch {
	case errors.Is(err, originauthcontrol.ErrEncryptionUnavailable):
		return OriginAuthDeliveryCredential
	case errors.Is(err, originauthcontrol.ErrValidation), errors.Is(err, originauthcontrol.ErrNotFound),
		errors.Is(err, ErrOriginAuthArtifact), errors.Is(err, originauthcontrol.ErrUnavailable):
		return OriginAuthDeliveryPublicationInvalid
	case errors.Is(err, edgedeployment.ErrNodeRecipientKeyUnavailable), errors.Is(err, edgedeployment.ErrNodeNotFound),
		errors.Is(err, edgedeployment.ErrConfigurationScopeConflict):
		return OriginAuthDeliveryNodeRejected
	default:
		return OriginAuthDeliveryUnavailable
	}
}

// backoff is the wait after the failures-th failure.
func (deliverer *OriginAuthDeliverer) backoff(failures int) time.Duration {
	delay := deliverer.config.RetryDelay << max(failures-1, 0)
	if delay > systemRepublicationMaxBackoff || delay <= 0 {
		delay = systemRepublicationMaxBackoff
	}
	return delay
}

// currentBuildFailure is the stored count when it is of revision; a count of
// another (older) publication does not apply: a new publication starts over.
func currentBuildFailure(stored *originAuthBuildFailure, revision int64) (originAuthBuildFailure, bool) {
	if stored == nil || stored.revision != revision {
		return originAuthBuildFailure{}, false
	}
	return *stored, true
}

// nextBuildFailure is the count after one more failed build of revision.
func nextBuildFailure(stored *originAuthBuildFailure, revision int64, reason string, at time.Time) originAuthBuildFailure {
	failure, _ := currentBuildFailure(stored, revision)
	failure.revision = revision
	failure.attempts = min(failure.attempts+1, 100)
	failure.at, failure.reason = at, reason
	return failure
}

// loadBuildFailureTx reads the scope's stored count (locked when the caller
// may write it; the advisory lock already serialises Deliver per scope).
func loadBuildFailureTx(ctx context.Context, tx pgx.Tx, scopeID uuid.UUID, lock bool) (*originAuthBuildFailure, error) {
	query := `SELECT revision,attempts,last_failed_at,reason FROM origin_auth_delivery_build_failures WHERE tenant_scope_id=$1`
	if lock {
		query += ` FOR UPDATE`
	}
	var failure originAuthBuildFailure
	err := tx.QueryRow(ctx, query, scopeID).Scan(&failure.revision, &failure.attempts, &failure.at, &failure.reason)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	failure.at = failure.at.UTC()
	return &failure, nil
}

func saveBuildFailureTx(ctx context.Context, tx pgx.Tx, scopeID uuid.UUID, failure originAuthBuildFailure) error {
	_, err := tx.Exec(ctx, `INSERT INTO origin_auth_delivery_build_failures(tenant_scope_id,revision,attempts,last_failed_at,reason)
		VALUES($1,$2,$3,$4,$5) ON CONFLICT (tenant_scope_id) DO UPDATE SET revision=EXCLUDED.revision,
		attempts=EXCLUDED.attempts, last_failed_at=EXCLUDED.last_failed_at, reason=EXCLUDED.reason`,
		scopeID, failure.revision, failure.attempts, failure.at, failure.reason)
	return err
}

func clearBuildFailureTx(ctx context.Context, tx pgx.Tx, scopeID uuid.UUID) error {
	_, err := tx.Exec(ctx, `DELETE FROM origin_auth_delivery_build_failures WHERE tenant_scope_id=$1`, scopeID)
	return err
}

// originAuthNodeStatesTx reads, per target node, whether it may get a secret
// now and what it did with rollouts of snapshot.
func originAuthNodeStatesTx(ctx context.Context, tx pgx.Tx, scopeID uuid.UUID, targets []uuid.UUID,
	snapshot []byte) ([]originAuthNodeState, error) {
	rows, err := tx.Query(ctx, `WITH target AS (SELECT DISTINCT unnest($2::uuid[]) AS node_id),
		attempt AS (
			SELECT deployment.node_id,deployment.state,deployment.updated_at,
			       deployment.state IN ('failed','reverted','rollback_failed') OR
			       deployment.state<>'healthy' AND deployment.deadline_at<=clock_timestamp() AS failed
			FROM rollouts rollout
			JOIN config_versions version ON version.id=rollout.config_version_id
			 AND version.configuration_scope_id=rollout.configuration_scope_id
			JOIN node_deployments deployment ON deployment.rollout_id=rollout.id
			WHERE rollout.configuration_scope_id=$1 AND version.generator_name=$3 AND version.canonical_snapshot=$4
			  AND deployment.node_id IN (SELECT node_id FROM target))
		SELECT target.node_id,
		       EXISTS(SELECT 1 FROM nodes node
		         JOIN node_presence presence ON presence.node_id=node.id AND presence.status='online'
		         JOIN node_identity_state identity_state ON identity_state.node_id=node.id
		         JOIN node_artifact_encryption_keys key ON key.node_id=node.id
		          AND key.id=identity_state.active_artifact_key_id AND key.status='active' AND key.deactivated_at IS NULL
		         WHERE node.id=target.node_id AND node.admin_state='active' AND tenant_carries_node_287($1,node.id)
		           AND NOT EXISTS(SELECT 1 FROM node_isolation_states isolation
		             WHERE isolation.node_id=node.id AND isolation.status='isolated')),
		       COALESCE(bool_or(attempt.state='healthy'),false),
		       COALESCE(bool_or(attempt.state<>'healthy' AND NOT attempt.failed),false),
		       count(*) FILTER (WHERE attempt.failed),
		       max(attempt.updated_at) FILTER (WHERE attempt.failed)
		FROM target LEFT JOIN attempt ON attempt.node_id=target.node_id
		GROUP BY target.node_id ORDER BY target.node_id`, scopeID, targets, OriginAuthSecretGeneratorName, snapshot)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(row pgx.CollectableRow) (originAuthNodeState, error) {
		var state originAuthNodeState
		err := row.Scan(&state.nodeID, &state.eligible, &state.healthy, &state.inFlight, &state.failures, &state.lastFailure)
		return state, err
	})
}

func originAuthDeliveryLockKey(scopeID uuid.UUID) int64 {
	digest := sha256.Sum256([]byte("cdnca-origin-auth-delivery-v1\x00" + scopeID.String()))
	return int64(binary.BigEndian.Uint64(digest[:8]))
}
