package edgepublish

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/edgedeployment"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// JS challenge policy redelivery. A challenge
// policy (and its key) reaches the nodes its publication targeted at that
// time. A node that later joins the scope's targets (a line group change, a
// node a release refused), or that was offline or isolated then, does not
// hold it, and every release with the site's challenge leaves the node out
// (ChallengePolicyUnavailableError). The redeliverer gives such a node every
// policy version a live site of the scope is bound to, through a system
// secret rollout of the published policy document; once the node confirms it
// (a healthy deployment receipt) the scope is republished with trigger
// challenge_delivery.
//
// Bounds: a node is attempted only while it is active, online and not
// isolated; a failed attempt retries with the system republication backoff
// up to SystemRepublicationMaxAttempts, then the redelivery stays failed. It
// starts over only when the node comes back: a new session (reconnect), or
// the node left the eligible set (offline, isolated, disabled, out of the
// targets) and returned.
const (
	ChallengeRedeliveryStatePending    = "pending"
	ChallengeRedeliveryStateDelivering = "delivering"
	ChallengeRedeliveryStateDelivered  = "delivered"
	ChallengeRedeliveryStateFailed     = "failed"

	challengeRedeliveryDeadline      = 15 * time.Minute
	challengeRedeliverySweepInterval = 30 * time.Second
	challengeRedeliveryBatch         = 100
)

// ErrChallengeRedeliveryUnrecoverable marks a redelivery no retry can fix
// (the published policy can no longer be rebuilt byte for byte, its key facts
// are gone): it fails at once; the tenant republishes the policy.
var ErrChallengeRedeliveryUnrecoverable = errors.New("challenge policy redelivery is unrecoverable")

// ChallengeRedelivery is one policy version to redeliver to one node.
type ChallengeRedelivery struct {
	ScopeID, NodeID, PolicyID, SiteID uuid.UUID
	PolicyVersion                     int64
	// OriginConfigVersionID is the challenge secret config version the
	// site's binding published: its canonical snapshot is the policy document.
	OriginConfigVersionID uuid.UUID
	// AccountableUserID published the binding.
	AccountableUserID uuid.UUID
	Attempt           int
	Deadline          time.Time
	IdempotencyKey    string
}

// ChallengeSecretRedeliverer persists, in tx, the system secret rollout that
// gives the node the policy and returns its rollout.
type ChallengeSecretRedeliverer interface {
	RedeliverChallengeSecretTx(context.Context, pgx.Tx, ChallengeRedelivery) (uuid.UUID, error)
}

// ChallengeDeliveryRepublisher queues, in tx, the republication of the scope
// with trigger challenge_delivery (edgeautopublish.ChallengeDeliveryPublisher:
// manual scopes through the system channel, automatic ones through their
// policy).
type ChallengeDeliveryRepublisher interface {
	RepublishChallengeDeliveryTx(ctx context.Context, tx pgx.Tx, scopeID, nodeID, rolloutID uuid.UUID) error
}

type ChallengeRedelivererConfig struct {
	// RetryDelay is the first backoff; it doubles per attempt up to the
	// system republication maximum.
	RetryDelay time.Duration
	// SweepInterval bounds how often the eligible nodes are rescanned.
	SweepInterval time.Duration
}

type ChallengeRedeliverer struct {
	pool        *pgxpool.Pool
	deliverer   ChallengeSecretRedeliverer
	republisher ChallengeDeliveryRepublisher
	config      ChallengeRedelivererConfig
	now         func() time.Time
	lastSweep   time.Time
}

func NewChallengeRedeliverer(pool *pgxpool.Pool, deliverer ChallengeSecretRedeliverer,
	republisher ChallengeDeliveryRepublisher, config ChallengeRedelivererConfig) (*ChallengeRedeliverer, error) {
	if pool == nil || nilServiceDependency(deliverer) || nilServiceDependency(republisher) ||
		config.RetryDelay < 0 || config.RetryDelay > time.Hour || config.SweepInterval < 0 || config.SweepInterval > time.Hour {
		return nil, ErrInvalidInput
	}
	if config.SweepInterval == 0 {
		config.SweepInterval = challengeRedeliverySweepInterval
	}
	return &ChallengeRedeliverer{pool: pool, deliverer: deliverer, republisher: republisher, config: config, now: time.Now}, nil
}

// RunOnce settles confirmed or failed deliveries, rescans at most once per
// sweep interval, then dispatches one due redelivery.
func (redeliverer *ChallengeRedeliverer) RunOnce(ctx context.Context) (bool, error) {
	if redeliverer == nil || ctx == nil {
		return false, ErrInvalidInput
	}
	observed, err := redeliverer.ObserveOnce(ctx)
	if err != nil {
		return observed > 0, err
	}
	if now := redeliverer.now(); redeliverer.lastSweep.IsZero() || now.Sub(redeliverer.lastSweep) >= redeliverer.config.SweepInterval {
		redeliverer.lastSweep = now
		if _, err := redeliverer.SweepOnce(ctx); err != nil {
			return observed > 0, err
		}
	}
	dispatched, err := redeliverer.DispatchOnce(ctx)
	return observed > 0 || dispatched, err
}

// SweepOnce rescans every scope with a challenge-bound live site (and every
// scope still holding redelivery rows) and returns the redeliveries queued.
func (redeliverer *ChallengeRedeliverer) SweepOnce(ctx context.Context) (int, error) {
	if redeliverer == nil || ctx == nil {
		return 0, ErrInvalidInput
	}
	rows, err := redeliverer.pool.Query(ctx, `SELECT tenant_scope_id FROM challenge_site_bindings_138
		WHERE active_binding_revision IS NOT NULL
		UNION SELECT scope_id FROM edge_challenge_redeliveries ORDER BY 1`)
	if err != nil {
		return 0, err
	}
	scopes, err := pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
	if err != nil {
		return 0, err
	}
	queued := 0
	for _, scopeID := range scopes {
		var count int
		if err := pgx.BeginFunc(ctx, redeliverer.pool, func(tx pgx.Tx) error {
			var err error
			count, err = sweepChallengeRedeliveriesTx(ctx, tx, scopeID)
			return err
		}); err != nil {
			return queued, err
		}
		queued += count
	}
	return queued, nil
}

// sweepChallengeRedeliveriesTx makes the scope's redelivery rows the
// (node, policy version) pairs it needs now: rows no longer needed go, a new
// need is queued, a delivered row needed again (the node lost the policy) and
// a failed row of an earlier node session start over.
func sweepChallengeRedeliveriesTx(ctx context.Context, tx pgx.Tx, scopeID uuid.UUID) (int, error) {
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, challengeRedeliveryLockKey(scopeID)); err != nil {
		return 0, err
	}
	targets, err := challengeRedeliveryTargetsTx(ctx, tx, scopeID)
	if err != nil {
		return 0, err
	}
	// One statement: the need, the rows it no longer has (never an
	// in-flight one) and the upsert see the same snapshot and touch disjoint rows.
	var queued int
	if err := tx.QueryRow(ctx, `WITH bound AS (
			SELECT revision.policy_id,revision.policy_revision AS policy_version,binding.site_id,
			       revision.secret_config_version_id
			FROM challenge_site_bindings_138 binding
			JOIN challenge_site_binding_revisions_138 revision ON revision.tenant_scope_id=binding.tenant_scope_id
			 AND revision.site_id=binding.site_id AND revision.binding_revision=binding.active_binding_revision
			JOIN sites site ON site.scope_id=binding.tenant_scope_id AND site.id=binding.site_id
			 AND site.deleted_at IS NULL AND site.enabled AND site.status NOT IN ('package_expired','traffic_exceeded')
			WHERE binding.tenant_scope_id=$1 AND revision.state IN ('candidate','active')),
		eligible AS (
			SELECT node.id AS node_id,presence.session_epoch FROM nodes node
			JOIN node_presence presence ON presence.node_id=node.id AND presence.status='online'
			WHERE node.id=ANY($2::uuid[]) AND node.admin_state='active'
			  AND NOT EXISTS(SELECT 1 FROM node_isolation_states isolation
			    WHERE isolation.node_id=node.id AND isolation.status='isolated')),
		held AS (
			-- Installed (healthy) or still on its way (not failed, within its
			-- deadline): the snapshot is decoded only for challenge secret rollouts.
			SELECT DISTINCT deployment.node_id,
			       CASE WHEN version.generator_name=$3 THEN convert_from(version.canonical_snapshot,'UTF8')::jsonb END AS policy
			FROM rollouts rollout
			JOIN config_versions version ON version.id=rollout.config_version_id
			 AND version.configuration_scope_id=rollout.configuration_scope_id
			JOIN node_deployments deployment ON deployment.rollout_id=rollout.id
			WHERE rollout.configuration_scope_id=$1 AND version.generator_name=$3
			  AND deployment.node_id=ANY($2::uuid[])
			  AND (deployment.state='healthy' OR deployment.state NOT IN ('failed','reverted','rollback_failed')
			       AND deployment.deadline_at>clock_timestamp())),
		need AS (
			SELECT eligible.node_id,bound.policy_id,bound.policy_version,bound.site_id,bound.secret_config_version_id,
			       eligible.session_epoch
			FROM eligible CROSS JOIN bound
			WHERE NOT EXISTS(SELECT 1 FROM held WHERE held.node_id=eligible.node_id
			  AND (held.policy->>'policy_version')::bigint=bound.policy_version
			  AND jsonb_path_exists(held.policy,'strict $.rules[*] ? (@.rule_id == $id)',
			        jsonb_build_object('id',bound.policy_id::text)))),
		gone AS (
			DELETE FROM edge_challenge_redeliveries redelivery
			WHERE redelivery.scope_id=$1 AND redelivery.state<>'delivering' AND NOT EXISTS(
			  SELECT 1 FROM need WHERE need.node_id=redelivery.node_id
			    AND need.policy_id=redelivery.policy_id AND need.policy_version=redelivery.policy_version)
			RETURNING 1),
		queued AS (
			INSERT INTO edge_challenge_redeliveries AS redelivery(
				scope_id,node_id,policy_id,policy_version,site_id,origin_config_version_id,state,attempt,session_epoch,
				due_at,created_at,updated_at)
			SELECT $1,node_id,policy_id,policy_version,site_id,secret_config_version_id,'pending',0,session_epoch,
			       clock_timestamp(),clock_timestamp(),clock_timestamp()
			FROM need
			ON CONFLICT (scope_id,node_id,policy_id,policy_version) DO UPDATE SET
			  state='pending',attempt=0,session_epoch=EXCLUDED.session_epoch,site_id=EXCLUDED.site_id,
			  origin_config_version_id=EXCLUDED.origin_config_version_id,due_at=EXCLUDED.due_at,
			  rollout_id=NULL,deadline_at=NULL,delivered_at=NULL,last_error=NULL,updated_at=EXCLUDED.updated_at
			WHERE redelivery.state='delivered' OR
			  redelivery.state='failed' AND redelivery.session_epoch<>EXCLUDED.session_epoch
			RETURNING 1)
		SELECT (SELECT count(*) FROM queued)+0*(SELECT count(*) FROM gone)`,
		scopeID, targets, ChallengeSecretGeneratorName).Scan(&queued); err != nil {
		return 0, fmt.Errorf("%w: sweep challenge redeliveries: %w", ErrPersistence, err)
	}
	return queued, nil
}

// challengeRedeliveryTargetsTx is the scope's intended node set
// (systemTargetNodes): its latest publication's nodes, the nodes a newer
// refused publication asked for, nodes a system republication excluded, and
// every node of a line group its live sites use.
func challengeRedeliveryTargetsTx(ctx context.Context, tx pgx.Tx, scopeID uuid.UUID) ([]uuid.UUID, error) {
	rows, err := tx.Query(ctx, `WITH latest AS (
			SELECT rollout_id,source_revision FROM edge_config_publications
			WHERE configuration_scope_id=$1 AND contract_version=1 ORDER BY source_revision DESC LIMIT 1)
		SELECT DISTINCT deployment.node_id FROM latest JOIN node_deployments deployment ON deployment.rollout_id=latest.rollout_id
		UNION SELECT unnest(hold.requested_node_ids||hold.refused_node_ids) FROM edge_capability_publication_holds hold
		  WHERE hold.scope_id=$1 AND hold.source_revision>=COALESCE((SELECT source_revision FROM latest),0)
		UNION SELECT unnest(head.excluded_node_ids) FROM edge_system_republication_heads head WHERE head.scope_id=$1`, scopeID)
	if err != nil {
		return nil, err
	}
	seeds, err := pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
	if err != nil {
		return nil, err
	}
	targets, _, err := systemTargetNodes(ctx, tx, scopeID, seeds, true)
	return targets, err
}

func challengeRedeliveryLockKey(scopeID uuid.UUID) int64 {
	digest := sha256.Sum256([]byte("cdnca-challenge-redelivery-v1\x00" + scopeID.String()))
	return int64(binary.BigEndian.Uint64(digest[:8]))
}

// DispatchOnce starts one due redelivery: it re-checks that the binding is
// still the site's and the node still eligible (else the row goes), then
// persists the secret rollout in a savepoint.
func (redeliverer *ChallengeRedeliverer) DispatchOnce(ctx context.Context) (bool, error) {
	if redeliverer == nil || ctx == nil {
		return false, ErrInvalidInput
	}
	worked := false
	err := pgx.BeginFunc(ctx, redeliverer.pool, func(tx pgx.Tx) error {
		var item ChallengeRedelivery
		err := tx.QueryRow(ctx, `SELECT scope_id,node_id,policy_id,policy_version,site_id,origin_config_version_id,attempt
			FROM edge_challenge_redeliveries WHERE state='pending' AND due_at<=clock_timestamp()
			ORDER BY due_at,scope_id,node_id LIMIT 1 FOR UPDATE SKIP LOCKED`).Scan(&item.ScopeID, &item.NodeID,
			&item.PolicyID, &item.PolicyVersion, &item.SiteID, &item.OriginConfigVersionID, &item.Attempt)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		worked = true
		var eligible bool
		err = tx.QueryRow(ctx, `SELECT revision.actor_user_id,EXISTS(SELECT 1 FROM nodes node
				JOIN node_presence presence ON presence.node_id=node.id AND presence.status='online'
				WHERE node.id=$5 AND node.admin_state='active' AND NOT EXISTS(SELECT 1 FROM node_isolation_states isolation
				  WHERE isolation.node_id=node.id AND isolation.status='isolated'))
			FROM challenge_site_bindings_138 binding
			JOIN challenge_site_binding_revisions_138 revision ON revision.tenant_scope_id=binding.tenant_scope_id
			 AND revision.site_id=binding.site_id AND revision.binding_revision=binding.active_binding_revision
			WHERE binding.tenant_scope_id=$1 AND binding.site_id=$2 AND revision.policy_id=$3
			  AND revision.policy_revision=$4 AND revision.secret_config_version_id=$6
			  AND revision.state IN ('candidate','active')`, item.ScopeID, item.SiteID, item.PolicyID, item.PolicyVersion,
			item.NodeID, item.OriginConfigVersionID).Scan(&item.AccountableUserID, &eligible)
		if errors.Is(err, pgx.ErrNoRows) || err == nil && !eligible {
			return deleteChallengeRedeliveryTx(ctx, tx, item)
		}
		if err != nil {
			return err
		}
		item.Attempt++
		if err := tx.QueryRow(ctx, `SELECT clock_timestamp()+$1::bigint*interval '1 millisecond'`,
			challengeRedeliveryDeadline.Milliseconds()).Scan(&item.Deadline); err != nil {
			return err
		}
		item.Deadline = item.Deadline.UTC().Truncate(time.Microsecond)
		attemptID, err := uuid.NewV7()
		if err != nil {
			return err
		}
		item.IdempotencyKey = "challenge-redelivery." + attemptID.String()
		savepoint, err := tx.Begin(ctx)
		if err != nil {
			return err
		}
		rolloutID, deliverErr := redeliverer.deliverer.RedeliverChallengeSecretTx(ctx, savepoint, item)
		if deliverErr == nil && rolloutID == uuid.Nil {
			deliverErr = ErrInvalidInput
		}
		if deliverErr == nil {
			if err := savepoint.Commit(ctx); err != nil {
				return err
			}
			_, err := tx.Exec(ctx, `UPDATE edge_challenge_redeliveries SET state='delivering',attempt=$5,rollout_id=$6,
				deadline_at=$7,last_error=NULL,updated_at=clock_timestamp()
				WHERE scope_id=$1 AND node_id=$2 AND policy_id=$3 AND policy_version=$4`, item.ScopeID, item.NodeID,
				item.PolicyID, item.PolicyVersion, item.Attempt, rolloutID, item.Deadline)
			return err
		}
		if err := savepoint.Rollback(ctx); err != nil {
			return err
		}
		return redeliverer.retryOrFailTx(ctx, tx, item, deliverErr)
	})
	return worked, err
}

func deleteChallengeRedeliveryTx(ctx context.Context, tx pgx.Tx, item ChallengeRedelivery) error {
	_, err := tx.Exec(ctx, `DELETE FROM edge_challenge_redeliveries
		WHERE scope_id=$1 AND node_id=$2 AND policy_id=$3 AND policy_version=$4`,
		item.ScopeID, item.NodeID, item.PolicyID, item.PolicyVersion)
	return err
}

// retryOrFailTx records a failed attempt (item.Attempt is its number): retry
// after backoff, or failed after SystemRepublicationMaxAttempts or when no
// retry can fix it.
func (redeliverer *ChallengeRedeliverer) retryOrFailTx(ctx context.Context, tx pgx.Tx, item ChallengeRedelivery, cause error) error {
	class := cause.Error()
	if len(class) > 256 {
		class = class[:256]
	}
	failed := item.Attempt >= SystemRepublicationMaxAttempts || errors.Is(cause, ErrChallengeRedeliveryUnrecoverable)
	backoff := redeliverer.config.RetryDelay << max(item.Attempt-1, 0)
	if backoff > systemRepublicationMaxBackoff || backoff < 0 {
		backoff = systemRepublicationMaxBackoff
	}
	state := ChallengeRedeliveryStatePending
	if failed {
		state = ChallengeRedeliveryStateFailed
	}
	_, err := tx.Exec(ctx, `UPDATE edge_challenge_redeliveries SET state=$5,attempt=$6,last_error=$7,
		due_at=clock_timestamp()+$8::bigint*interval '1 millisecond',rollout_id=CASE WHEN $5='failed' THEN rollout_id END,
		deadline_at=NULL,updated_at=clock_timestamp()
		WHERE scope_id=$1 AND node_id=$2 AND policy_id=$3 AND policy_version=$4`, item.ScopeID, item.NodeID,
		item.PolicyID, item.PolicyVersion, state, item.Attempt, class, backoff.Milliseconds())
	return err
}

// ObserveOnce settles in-flight redeliveries from the node's receipt: healthy
// confirms the delivery and republishes the scope (trigger
// challenge_delivery); failed, reverted or past its deadline is a failed
// attempt. Rows are settled in scope order (the scope lock order).
func (redeliverer *ChallengeRedeliverer) ObserveOnce(ctx context.Context) (int, error) {
	if redeliverer == nil || ctx == nil {
		return 0, ErrInvalidInput
	}
	settled := 0
	err := pgx.BeginFunc(ctx, redeliverer.pool, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT redelivery.scope_id,redelivery.node_id,redelivery.policy_id,
				redelivery.policy_version,redelivery.attempt,redelivery.rollout_id,
				COALESCE(latest.state,'missing'),COALESCE(latest.superseded,false),
				redelivery.deadline_at<=clock_timestamp()
			FROM edge_challenge_redeliveries redelivery
			LEFT JOIN LATERAL (SELECT deployment.state,`+edgedeployment.SupersededDeploymentSQL+` AS superseded
			  FROM node_deployments deployment
			  WHERE deployment.rollout_id=redelivery.rollout_id AND deployment.node_id=redelivery.node_id
			  ORDER BY deployment.attempt DESC LIMIT 1) latest ON true
			WHERE redelivery.state='delivering'
			ORDER BY redelivery.scope_id,redelivery.node_id,redelivery.policy_id,redelivery.policy_version
			LIMIT $1 FOR UPDATE OF redelivery SKIP LOCKED`, challengeRedeliveryBatch)
		if err != nil {
			return err
		}
		type delivering struct {
			item       ChallengeRedelivery
			rolloutID  uuid.UUID
			state      string
			superseded bool
			expired    bool
		}
		items, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (delivering, error) {
			var value delivering
			return value, row.Scan(&value.item.ScopeID, &value.item.NodeID, &value.item.PolicyID,
				&value.item.PolicyVersion, &value.item.Attempt, &value.rolloutID, &value.state, &value.superseded,
				&value.expired)
		})
		if err != nil {
			return err
		}
		var republished []uuid.UUID
		for _, value := range items {
			switch challengeRedeliverySettlement(value.state, value.superseded, value.expired) {
			case redeliverySkipped:
				// The node runs a newer revision of the scope: not a failed
				// attempt; the next sweep decides whether it still needs one.
				if err := deleteChallengeRedeliveryTx(ctx, tx, value.item); err != nil {
					return err
				}
			case redeliveryDelivered:
				if _, err := tx.Exec(ctx, `UPDATE edge_challenge_redeliveries SET state='delivered',
					delivered_at=clock_timestamp(),deadline_at=NULL,updated_at=clock_timestamp()
					WHERE scope_id=$1 AND node_id=$2 AND policy_id=$3 AND policy_version=$4`, value.item.ScopeID,
					value.item.NodeID, value.item.PolicyID, value.item.PolicyVersion); err != nil {
					return err
				}
				// One republication per scope covers every node it delivered to.
				if !slices.Contains(republished, value.item.ScopeID) {
					if err := redeliverer.republisher.RepublishChallengeDeliveryTx(ctx, tx, value.item.ScopeID,
						value.item.NodeID, value.rolloutID); err != nil {
						return err
					}
					republished = append(republished, value.item.ScopeID)
				}
			case redeliveryFailedAttempt:
				if err := redeliverer.retryOrFailTx(ctx, tx, value.item,
					fmt.Errorf("challenge redelivery deployment %s", value.state)); err != nil {
					return err
				}
			case redeliveryExpired:
				if err := redeliverer.retryOrFailTx(ctx, tx, value.item,
					errors.New("challenge redelivery deployment passed its deadline")); err != nil {
					return err
				}
			default:
				continue
			}
			settled++
		}
		return nil
	})
	return settled, err
}

type challengeRedeliveryOutcome int

const (
	redeliveryWaiting challengeRedeliveryOutcome = iota
	redeliveryDelivered
	redeliverySkipped
	redeliveryFailedAttempt
	redeliveryExpired
)

// challengeRedeliverySettlement classifies an in-flight redelivery by its
// deployment's latest attempt. An ignored old release
// (edgedeployment.SupersededDeploymentSQL) is skipped, not failed: it
// neither burns an attempt nor ends the row failed (fix-tails1028 §1).
func challengeRedeliverySettlement(state string, superseded, expired bool) challengeRedeliveryOutcome {
	switch {
	case state == "healthy":
		return redeliveryDelivered
	case superseded:
		return redeliverySkipped
	case state == "failed" || state == "reverted" || state == "rollback_failed" || state == "missing":
		return redeliveryFailedAttempt
	case expired:
		return redeliveryExpired
	}
	return redeliveryWaiting
}
