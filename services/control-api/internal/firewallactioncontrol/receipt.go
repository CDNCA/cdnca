package firewallactioncontrol

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/firewallcontrol"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Publication receipts: a candidate revision is "projected" when
// a site runtime release (edge publication or security activation candidate)
// carries it — config_versions.canonical_snapshot sites[].firewall_action names
// its policy, revision and document digest — and settled from the node
// deployments of the apply rollouts that carry it:
//   - any carrying rollout has a healthy node → applied (active = LKG = revision);
//   - every carrying rollout ended, none healthy, a node failed (a frozen
//     node's refusal is no failure: it waits for redelivery) → rejected
//     (failed, LKG kept; the scope's next release delivers the LKG);
//   - otherwise it waits.
// A candidate no release carries (a manual scope not yet published, a
// disabled policy) stays pending without spending attempts: exhausting them
// would fail a candidate nothing ever tried to deliver. A candidate replaced
// by a newer revision (saved again, recovered, restored to inherit) is closed
// as superseded; its head is not touched.

// ReceiptInterval is how often RunReceipts settles the outbox.
const ReceiptInterval = 5 * time.Second

const (
	receiptBatchSize        = 100
	receiptRolloutsPerScope = 16
	receiptCacheLimit       = 4096
	// receiptRolloutSkew tolerates the publication clock running behind the
	// writer's when picking the releases that may carry a candidate.
	receiptRolloutSkew = 10 * time.Minute
)

const (
	reasonApplied      = "applied"
	reasonNodeRejected = "node_rejected"
	reasonSuperseded   = "superseded"
)

type receiptBinding struct {
	siteID, policyID uuid.UUID
	revision         int64
	digest           string
}

type receiptCandidate struct {
	id              uuid.UUID
	scopeID, siteID uuid.UUID
	policyID        uuid.UUID
	revision        int64
	digest          [32]byte
	state           string
	createdAt       time.Time
}

type receiptRollout struct {
	configID                 uuid.UUID
	healthy, failed, running int64
}

type receiptOutcome int

const (
	receiptWait receiptOutcome = iota
	receiptApplied
	receiptRejected
)

// settleReceipt decides a projected candidate from the rollouts carrying it.
func settleReceipt(carriers []receiptRollout) receiptOutcome {
	failed, running := false, false
	for _, rollout := range carriers {
		if rollout.healthy > 0 {
			return receiptApplied
		}
		failed = failed || rollout.failed > 0
		running = running || rollout.running > 0
	}
	if failed && !running {
		return receiptRejected
	}
	return receiptWait
}

// ReceiptWorker settles firewall action publications; snapshots are immutable,
// so the bindings each release carries are cached by config version.
type ReceiptWorker struct {
	store    *Store
	bindings map[uuid.UUID]map[receiptBinding]bool
}

// NewReceiptWorker settles on pool; the worker acts for no user, so its
// store authorizes nothing.
func NewReceiptWorker(pool *pgxpool.Pool, now func() time.Time) (*ReceiptWorker, error) {
	if pool == nil {
		return nil, ErrUnavailable
	}
	store := NewStore(pool, denyAuthorizer{}, now)
	return &ReceiptWorker{store: store, bindings: map[uuid.UUID]map[receiptBinding]bool{}}, nil
}

type denyAuthorizer struct{}

func (denyAuthorizer) Authorize(context.Context, pgx.Tx, Actor, uuid.UUID, string) error {
	return firewallcontrol.ErrPermissionDenied
}

// RunReceipts settles the outbox every interval until ctx ends.
func RunReceipts(ctx context.Context, worker *ReceiptWorker, interval time.Duration, logger *slog.Logger) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		if settled, err := worker.Tick(ctx); err != nil && ctx.Err() == nil {
			logger.Warn("firewall action publication receipts failed", "error", err)
		} else if settled > 0 {
			logger.Info("firewall action publication receipts settled", "publications", settled)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// Tick runs one settlement pass; settled counts publications that changed
// state (superseded, projected or acknowledged).
func (worker *ReceiptWorker) Tick(ctx context.Context) (int, error) {
	settled, err := worker.closeSuperseded(ctx)
	if err != nil {
		return settled, err
	}
	candidates, err := worker.openCandidates(ctx)
	if err != nil {
		return settled, err
	}
	defaults, err := worker.pendingDefaults(ctx)
	if err != nil {
		return settled, err
	}
	byScope := map[uuid.UUID][]receiptCandidate{}
	defaultOf := map[uuid.UUID]*receiptDefault{}
	var scopes []uuid.UUID
	for _, candidate := range candidates {
		if byScope[candidate.scopeID] == nil {
			scopes = append(scopes, candidate.scopeID)
		}
		byScope[candidate.scopeID] = append(byScope[candidate.scopeID], candidate)
	}
	for index := range defaults {
		scopeID := defaults[index].scopeID
		if byScope[scopeID] == nil {
			scopes = append(scopes, scopeID)
			byScope[scopeID] = []receiptCandidate{}
		}
		defaultOf[scopeID] = &defaults[index]
	}
	var first error
	for _, scopeID := range scopes {
		count, err := worker.settleScope(ctx, scopeID, byScope[scopeID], defaultOf[scopeID])
		settled += count
		if err != nil && first == nil {
			first = err
		}
	}
	return settled, first
}

// receiptDefault is a tenant default revision waiting for its receipt (607).
type receiptDefault struct {
	scopeID   uuid.UUID
	revision  int64
	updatedAt time.Time
}

func (worker *ReceiptWorker) pendingDefaults(ctx context.Context) ([]receiptDefault, error) {
	var result []receiptDefault
	after := uuid.Nil
	for {
		rows, err := worker.store.pool.Query(ctx, `SELECT tenant_scope_id,revision,updated_at FROM firewall_action_tenant_defaults
			WHERE deployment_state='pending' AND tenant_scope_id>$2 ORDER BY tenant_scope_id LIMIT $1`, receiptBatchSize, after)
		if err != nil {
			return nil, normalizeStoreError(err)
		}
		page, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (receiptDefault, error) {
			var item receiptDefault
			return item, row.Scan(&item.scopeID, &item.revision, &item.updatedAt)
		})
		if err != nil {
			return nil, normalizeStoreError(err)
		}
		result = append(result, page...)
		if len(page) < receiptBatchSize {
			return result, nil
		}
		after = page[len(page)-1].scopeID
	}
}

// carriesDefault: the release delivers revision of scopeID's tenant default
// to an inheriting site (its inherited policy ID, versioned by the default).
func carriesDefault(bindings map[receiptBinding]bool, scopeID uuid.UUID, revision int64) bool {
	for binding := range bindings {
		if binding.revision == revision && binding.policyID == InheritedPolicyID(scopeID, binding.siteID) {
			return true
		}
	}
	return false
}

// settleDefault records a tenant default's receipt: applied moves active and
// LKG to the revision, rejected keeps the LKG (607 guard).
func (worker *ReceiptWorker) settleDefault(ctx context.Context, item receiptDefault, outcome receiptOutcome) (bool, error) {
	now := worker.store.now().UTC().Truncate(time.Microsecond)
	query := `UPDATE firewall_action_tenant_defaults SET deployment_state='failed',updated_at=GREATEST(updated_at,$3)
		WHERE tenant_scope_id=$1 AND revision=$2 AND deployment_state='pending'`
	if outcome == receiptApplied {
		query = `UPDATE firewall_action_tenant_defaults SET deployment_state='active',active_revision=revision,lkg_revision=revision,
			updated_at=GREATEST(updated_at,$3) WHERE tenant_scope_id=$1 AND revision=$2 AND deployment_state='pending'`
	}
	command, err := worker.store.pool.Exec(ctx, query, item.scopeID, item.revision, now)
	if err != nil {
		return false, normalizeStoreError(err)
	}
	return command.RowsAffected() == 1, nil
}

// supersededSQL: the head moved past the publication's revision.
const supersededSQL = `EXISTS(SELECT 1 FROM firewall_action_policy_heads head
	WHERE head.tenant_scope_id=publication.tenant_scope_id AND head.site_id=publication.site_id
	  AND head.revision>publication.revision)`

func (worker *ReceiptWorker) closeSuperseded(ctx context.Context) (int, error) {
	now := worker.store.now().UTC().Truncate(time.Microsecond)
	settled := 0
	err := pgx.BeginFunc(ctx, worker.store.pool, func(tx pgx.Tx) error {
		// 174 allows pending/retryable → failed only through projecting.
		if _, err := tx.Exec(ctx, `UPDATE firewall_action_publication_outbox publication
			SET state='projecting',attempts=attempts+1,
			    claim_expires_at=GREATEST(updated_at,$1)+interval '30 seconds',updated_at=GREATEST(updated_at,$1)
			WHERE state IN ('pending','retryable') AND attempts<16 AND `+supersededSQL, now); err != nil {
			return err
		}
		command, err := tx.Exec(ctx, `UPDATE firewall_action_publication_outbox publication
			SET state='failed',claim_expires_at=NULL,last_error=$2,updated_at=GREATEST(updated_at,$1)
			WHERE state='projecting' AND `+supersededSQL, now, reasonSuperseded)
		if err != nil {
			return err
		}
		settled += int(command.RowsAffected())
		command, err = tx.Exec(ctx, `UPDATE firewall_action_publication_outbox publication
			SET state='failed',outcome_reason=$2,acknowledged_at=GREATEST(updated_at,$1),updated_at=GREATEST(updated_at,$1)
			WHERE state='published' AND `+supersededSQL, now, reasonSuperseded)
		if err != nil {
			return err
		}
		settled += int(command.RowsAffected())
		return nil
	})
	if err != nil {
		return 0, normalizeStoreError(err)
	}
	return settled, nil
}

// openCandidates: publications of the head's current pending revision, all
// of them (keyset pages): a candidate no release carries must not hide the
// ones behind it.
func (worker *ReceiptWorker) openCandidates(ctx context.Context) ([]receiptCandidate, error) {
	now := worker.store.now().UTC().Truncate(time.Microsecond)
	var result []receiptCandidate
	after := uuid.Nil
	for {
		rows, err := worker.store.pool.Query(ctx, `SELECT publication.id,publication.tenant_scope_id,publication.site_id,
				publication.policy_id,publication.revision,publication.document_sha256,publication.state,publication.created_at
			FROM firewall_action_publication_outbox publication
			JOIN firewall_action_policy_heads head ON head.tenant_scope_id=publication.tenant_scope_id
			  AND head.site_id=publication.site_id AND head.id=publication.policy_id AND head.revision=publication.revision
			WHERE head.deployment_state='pending' AND NOT head.inherited AND publication.attempts<16 AND publication.id>$3 AND (
				publication.state IN ('pending','retryable','published') OR
				publication.state='projecting' AND publication.claim_expires_at<=$1)
			ORDER BY publication.id LIMIT $2`, now, receiptBatchSize, after)
		if err != nil {
			return nil, normalizeStoreError(err)
		}
		page, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (receiptCandidate, error) {
			var candidate receiptCandidate
			var digest []byte
			if err := row.Scan(&candidate.id, &candidate.scopeID, &candidate.siteID, &candidate.policyID, &candidate.revision,
				&digest, &candidate.state, &candidate.createdAt); err != nil {
				return candidate, err
			}
			if len(digest) != len(candidate.digest) {
				return candidate, ErrUnavailable
			}
			copy(candidate.digest[:], digest)
			return candidate, nil
		})
		if err != nil {
			return nil, normalizeStoreError(err)
		}
		result = append(result, page...)
		if len(page) < receiptBatchSize {
			return result, nil
		}
		after = page[len(page)-1].id
	}
}

func (worker *ReceiptWorker) settleScope(ctx context.Context, scopeID uuid.UUID, candidates []receiptCandidate,
	pendingDefault *receiptDefault) (int, error) {
	var since time.Time
	if pendingDefault != nil {
		since = pendingDefault.updatedAt
	}
	for _, candidate := range candidates {
		if since.IsZero() || candidate.createdAt.Before(since) {
			since = candidate.createdAt
		}
	}
	rollouts, err := worker.carryingRollouts(ctx, scopeID, since.Add(-receiptRolloutSkew))
	if err != nil {
		return 0, err
	}
	settled := 0
	var first error
	if pendingDefault != nil {
		var carriers []receiptRollout
		for _, rollout := range rollouts {
			if carriesDefault(worker.bindings[rollout.configID], scopeID, pendingDefault.revision) {
				carriers = append(carriers, rollout)
			}
		}
		if outcome := settleReceipt(carriers); outcome != receiptWait {
			changed, err := worker.settleDefault(ctx, *pendingDefault, outcome)
			if changed {
				settled++
			}
			if err != nil {
				first = err
			}
		}
	}
	for _, candidate := range candidates {
		key := receiptBinding{siteID: candidate.siteID, policyID: candidate.policyID, revision: candidate.revision,
			digest: hex.EncodeToString(candidate.digest[:])}
		var carriers []receiptRollout
		for _, rollout := range rollouts {
			if worker.bindings[rollout.configID][key] {
				carriers = append(carriers, rollout)
			}
		}
		if len(carriers) == 0 {
			continue // no release carries it yet
		}
		changed, err := worker.settleCandidate(ctx, candidate, carriers)
		if changed {
			settled++
		}
		// A concurrent write or worker moved the row first: the next pass sees it.
		if err != nil && !errors.Is(err, ErrRevisionConflict) && !errors.Is(err, ErrNotFound) && first == nil {
			first = err
		}
	}
	return settled, first
}

func (worker *ReceiptWorker) settleCandidate(ctx context.Context, candidate receiptCandidate, carriers []receiptRollout) (bool, error) {
	changed := false
	if candidate.state != "published" {
		attempt, err := worker.claim(ctx, candidate.id)
		if err != nil {
			return false, err
		}
		if err := worker.store.FinishProjection(ctx, ProjectionResult{PublicationID: candidate.id,
			DocumentSHA256: candidate.digest, Attempt: attempt, Published: true, ReasonCode: "carried"}); err != nil {
			return false, err
		}
		changed = true
	}
	outcome := settleReceipt(carriers)
	if outcome == receiptWait {
		return changed, nil
	}
	request := OutcomeRequest{TargetScopeID: candidate.scopeID, SiteID: candidate.siteID, Revision: candidate.revision,
		DocumentSHA256: candidate.digest, Applied: outcome == receiptApplied, ReasonCode: reasonApplied}
	if outcome == receiptRejected {
		request.ReasonCode = reasonNodeRejected
	}
	if _, err := worker.store.RecordOutcome(ctx, request); err != nil {
		return changed, err
	}
	return true, nil
}

// claim takes one publication into projecting (the 174 claim transition).
func (worker *ReceiptWorker) claim(ctx context.Context, id uuid.UUID) (int, error) {
	now := worker.store.now().UTC().Truncate(time.Microsecond)
	var attempt int
	err := worker.store.pool.QueryRow(ctx, `UPDATE firewall_action_publication_outbox
		SET state='projecting',attempts=attempts+1,claim_expires_at=$2::timestamptz+interval '30 seconds',updated_at=$2
		WHERE id=$1 AND attempts<16 AND updated_at<=$2 AND
			(state IN ('pending','retryable') OR state='projecting' AND claim_expires_at<=$2)
		RETURNING attempts`, id, now).Scan(&attempt)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, ErrRevisionConflict
	}
	if err != nil {
		return 0, normalizeStoreError(err)
	}
	return attempt, nil
}

// carryingRollouts: the scope's recent apply rollouts of site runtime
// releases with their node progress; their bindings are loaded into the cache.
func (worker *ReceiptWorker) carryingRollouts(ctx context.Context, scopeID uuid.UUID, since time.Time) ([]receiptRollout, error) {
	rows, err := worker.store.pool.Query(ctx, `SELECT rollout.config_version_id,progress.healthy,progress.failed,progress.running
		FROM rollouts rollout
		CROSS JOIN LATERAL (
			SELECT count(*) FILTER (WHERE latest.state='healthy') AS healthy,
			       count(*) FILTER (WHERE latest.state IN ('failed','reverted','rollback_failed') AND NOT EXISTS(
			           SELECT 1 FROM node_deployment_frozen_refusals mark
			           WHERE mark.deployment_id=latest.id AND mark.attempt=latest.attempt)) AS failed,
			       count(*) FILTER (WHERE latest.state NOT IN ('healthy','failed','reverted','rollback_failed','cancelled')) AS running
			FROM (SELECT DISTINCT ON (deployment.id) deployment.id,deployment.attempt,deployment.state
			      FROM node_deployments deployment WHERE deployment.rollout_id=rollout.id
			      ORDER BY deployment.id,deployment.attempt DESC) latest
		) progress
		WHERE rollout.configuration_scope_id=$1 AND rollout.action='apply' AND rollout.created_at>=$2 AND (
			EXISTS(SELECT 1 FROM edge_config_publications publication WHERE publication.rollout_id=rollout.id) OR
			EXISTS(SELECT 1 FROM security_policy_activation_config_facts fact
			       WHERE fact.tenant_scope_id=rollout.configuration_scope_id AND fact.config_version_id=rollout.config_version_id))
		ORDER BY rollout.created_at DESC,rollout.id DESC LIMIT $3`, scopeID, since, receiptRolloutsPerScope)
	if err != nil {
		return nil, normalizeStoreError(err)
	}
	result, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (receiptRollout, error) {
		var rollout receiptRollout
		return rollout, row.Scan(&rollout.configID, &rollout.healthy, &rollout.failed, &rollout.running)
	})
	if err != nil {
		return nil, normalizeStoreError(err)
	}
	var missing []uuid.UUID
	for _, rollout := range result {
		if _, cached := worker.bindings[rollout.configID]; !cached {
			missing = append(missing, rollout.configID)
		}
	}
	if len(missing) == 0 {
		return result, nil
	}
	if len(worker.bindings)+len(missing) > receiptCacheLimit {
		worker.bindings = map[uuid.UUID]map[receiptBinding]bool{}
	}
	snapshots, err := worker.store.pool.Query(ctx, `SELECT id,canonical_snapshot FROM config_versions WHERE id=ANY($1::uuid[])`, missing)
	if err != nil {
		return nil, normalizeStoreError(err)
	}
	defer snapshots.Close()
	for snapshots.Next() {
		var configID uuid.UUID
		var snapshot []byte
		if err := snapshots.Scan(&configID, &snapshot); err != nil {
			return nil, normalizeStoreError(err)
		}
		worker.bindings[configID] = snapshotFirewallActionBindings(snapshot)
	}
	if err := snapshots.Err(); err != nil {
		return nil, normalizeStoreError(err)
	}
	return result, nil
}

// snapshotFirewallActionBindings reads the firewall action bindings of a site
// runtime v2 snapshot; anything else carries none.
func snapshotFirewallActionBindings(snapshot []byte) map[receiptBinding]bool {
	var document struct {
		Sites []struct {
			ID             string `json:"id"`
			FirewallAction *struct {
				PolicyID       string `json:"policy_id"`
				PolicyRevision int64  `json:"policy_revision"`
				DocumentSHA256 string `json:"document_sha256"`
			} `json:"firewall_action"`
		} `json:"sites"`
	}
	result := map[receiptBinding]bool{}
	if json.Unmarshal(snapshot, &document) != nil {
		return result
	}
	for _, site := range document.Sites {
		if site.FirewallAction == nil {
			continue
		}
		siteID, siteErr := uuid.Parse(site.ID)
		policyID, policyErr := uuid.Parse(site.FirewallAction.PolicyID)
		if siteErr != nil || policyErr != nil {
			continue
		}
		result[receiptBinding{siteID: siteID, policyID: policyID, revision: site.FirewallAction.PolicyRevision,
			digest: site.FirewallAction.DocumentSHA256}] = true
	}
	return result
}
