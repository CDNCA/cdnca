package cnameallocation

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"slices"
	"strconv"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/dnscheck"
	"github.com/cdnca/cdnca/services/control-api/internal/dnsreconcile"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

const (
	retargetPlanLimit  = 100
	retargetOpenLimit  = 32
	retargetRetryAfter = 5 * time.Minute

	// BlackholeAddress is what a site CNAME at attack escalation level D
	// resolves to (0.0.0.0, never a third party's address), with
	// BlackholeTTL so the way back is quick.
	BlackholeAddress = "0.0.0.0"
	BlackholeTTL     = 60
)

// Retarget republishes the A/AAAA values of a settled CNAME hostname when the
// published endpoints of its line group change (node_line_endpoint_published,
// migration 299: serving per node_line_endpoint_serving, standby IPs by priority;
// admin enabled and not held by monitoring or auto-disable). A site bound to
// a node market supply, or whose default line the aggregated edge points at
// a supply, is published as a CNAME to it instead (DefaultLineTarget). The
// hostname, claim and allocation revision stay as they are.
type Retarget struct {
	ID                uuid.UUID
	TenantID          uuid.UUID
	ScopeID           uuid.UUID
	AllocationID      uuid.UUID
	BaseJobID         uuid.UUID
	Sequence          int64
	SiteID            uuid.UUID
	ZoneID            uuid.UUID
	ZoneRevision      int64
	OwnerName         string
	Values            TargetValues
	Digest            string
	ActorUserID       uuid.UUID
	RequestID         string
	State             string
	ChildTaskID       uuid.UUID
	ChildTaskRevision int64
	NodeGroupID       uuid.UUID
	NodeGroupRevision int64
	Publish           PublishSettings
	// ttl is the row's TTL: BlackholeTTL at escalation level D, else the
	// scope's TTL from Publish applies.
	ttl int32
}

// RetargetStore persists retargets. It is optional for the worker.
type RetargetStore interface {
	PlanRetargets(context.Context) (int, error)
	OpenRetargets(context.Context) ([]Retarget, error)
	AttachRetarget(context.Context, Retarget, dnsreconcile.Task) error
	SettleRetarget(context.Context, Retarget, string, string) error
}

type retargetCandidate struct {
	tenantID, scopeID, allocationID, jobID, siteID, groupID, zoneID, actorUserID uuid.UUID
	// groupScopeID owns the node group: the tenant's own or the platform's.
	groupScopeID                              uuid.UUID
	groupRevision, zoneRevision, nextSequence int64
	// appliedRevision is the line group revision the published values (and,
	// with 开启IP权重, weights) were taken from.
	appliedRevision int64
	ownerName       string
	applied         TargetValues
	// blackhole: the site is at escalation level D (escalate_site_routes).
	blackhole bool
	// stream: a stream's own allocation (492); market supplies and the
	// HTTP-01 serving gate are per site and do not apply.
	stream bool
}

// PlanRetargets inserts one pending retarget for each settled allocation whose
// published values differ from its line group's current serving endpoints.
// Allocations with a retarget in flight, or one that failed within
// retargetRetryAfter, are skipped. Returns the number of retargets created.
func (store *Store) PlanRetargets(ctx context.Context) (int, error) {
	if store == nil || ctx == nil {
		return 0, ErrInvalidInput
	}
	rows, err := store.pool.Query(ctx, `SELECT allocation.tenant_id,allocation.tenant_scope_id,allocation.id,allocation.job_id,
			COALESCE(frozen.site_id,frozen.stream_id),line_group.id,line_group.tenant_scope_id,line_group.current_revision,frozen.zone_id,zone.revision,frozen.owner_name,
			frozen.actor_user_id,COALESCE(applied.target_a,frozen.target_a),COALESCE(applied.target_aaaa,frozen.target_aaaa),
			COALESCE(applied.target_cname,''),COALESCE(applied.node_group_revision,frozen.node_group_revision),
			COALESCE((SELECT max(sequence) FROM dns_cname_retargets prior
				WHERE prior.tenant_scope_id=allocation.tenant_scope_id AND prior.allocation_id=allocation.id),0)+1,
			COALESCE(route.dns_target='blackhole',false),allocation.stream_owner_id IS NOT NULL
		FROM cname_allocations allocation
		JOIN cname_allocation_targets frozen ON frozen.tenant_id=allocation.tenant_id AND frozen.job_id=allocation.job_id
		-- Attack escalation (460) overrides the line group of a site-mode
		-- owner (B/C) or sends it to the blackhole (D); package owners are shared.
		LEFT JOIN escalate_site_routes route ON allocation.mode='site' AND allocation.stream_owner_id IS NULL
		 AND route.tenant_scope_id=allocation.tenant_scope_id AND route.site_id=frozen.site_id
		-- 保底链 (561): the default line on the package's backup line group
		-- (below an attack escalation line group override, which wins).
		LEFT JOIN LATERAL (SELECT NULLIF(subscription.product_snapshot#>>'{spec,backup_node_group_id}','')::uuid AS group_id
			FROM aggregated_edge_line_targets chain_line
			JOIN sites chain_site ON chain_site.id=chain_line.site_id AND chain_site.deleted_at IS NULL
			JOIN package_subscriptions subscription ON subscription.tenant_scope_id=chain_site.scope_id
			 AND subscription.id=chain_site.package_subscription_id AND subscription.deleted_at IS NULL
			WHERE chain_line.site_id=frozen.site_id AND chain_line.line_scope='' AND chain_line.kind='backup_group'
			  AND allocation.mode='site' AND allocation.stream_owner_id IS NULL) backup ON true
		-- A stream's own allocation (492) follows its current line: the stream's
		-- own line group, else its package's (转发 > 套餐; no website, 493).
		LEFT JOIN LATERAL (SELECT COALESCE(forward.node_group_id,
				NULLIF(subscription.product_snapshot#>>'{spec,node_group_id}','')::uuid,
				-- community edition: no package -> the platform default line group
				(SELECT platform_default.id FROM node_line_groups platform_default
				 WHERE platform_default.is_platform_default AND platform_default.deleted_at IS NULL
				   AND forward.package_subscription_id IS NULL)) AS node_group_id
			FROM l4_forwards forward
			LEFT JOIN package_subscriptions subscription ON subscription.tenant_scope_id=forward.scope_id
			 AND subscription.id=forward.package_subscription_id
			WHERE forward.scope_id=allocation.tenant_scope_id AND forward.id=allocation.stream_owner_id
			  AND forward.deleted_at IS NULL) stream_line ON allocation.stream_owner_id IS NOT NULL
		JOIN node_line_groups line_group ON line_group.deleted_at IS NULL AND (
		     (allocation.stream_owner_id IS NOT NULL AND line_group.id=stream_line.node_group_id AND
		      (line_group.tenant_scope_id=allocation.tenant_scope_id OR line_group.tenant_scope_id=(
		       SELECT platform.id FROM access_scopes platform WHERE platform.kind='platform'))) OR
		     (allocation.stream_owner_id IS NULL AND route.dns_target='line_group' AND
		      line_group.tenant_scope_id=route.line_owner_scope_id AND line_group.id=route.line_group_id) OR
		     (allocation.stream_owner_id IS NULL AND route.dns_target IS DISTINCT FROM 'line_group' AND backup.group_id IS NOT NULL AND
		      (line_group.tenant_scope_id IN (frozen.tenant_scope_id, frozen.node_group_scope_id) OR line_group.tenant_scope_id=(
		       SELECT platform.id FROM access_scopes platform WHERE platform.kind='platform')) AND line_group.id=backup.group_id) OR
		     (allocation.stream_owner_id IS NULL AND route.dns_target IS DISTINCT FROM 'line_group' AND backup.group_id IS NULL AND
		      line_group.tenant_scope_id=frozen.node_group_scope_id AND line_group.id=frozen.node_group_id))
		JOIN node_line_group_revisions revision ON revision.tenant_scope_id=line_group.tenant_scope_id
		 AND revision.line_group_id=line_group.id AND revision.revision=line_group.current_revision AND revision.sealed_at IS NOT NULL
		JOIN dns_zones zone ON zone.scope_id=frozen.tenant_scope_id AND zone.id=frozen.zone_id AND zone.status<>'failed'
		LEFT JOIN LATERAL (SELECT target_a,target_aaaa,target_cname,node_group_revision FROM dns_cname_retargets prior
			WHERE prior.tenant_scope_id=allocation.tenant_scope_id AND prior.allocation_id=allocation.id
			  AND prior.base_job_id=allocation.job_id AND prior.state='committed'
			ORDER BY prior.sequence DESC LIMIT 1) applied ON true
		WHERE allocation.state='done'
		  AND NOT EXISTS (SELECT 1 FROM dns_cname_retargets busy WHERE busy.tenant_scope_id=allocation.tenant_scope_id
			AND busy.allocation_id=allocation.id AND (busy.state IN ('pending','applying') OR
			(busy.state='failed' AND busy.updated_at>clock_timestamp()-$1::interval)))
		ORDER BY allocation.updated_at,allocation.id`, retargetRetryAfter.String())
	if err != nil {
		return 0, retargetError(err)
	}
	candidates, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (retargetCandidate, error) {
		var value retargetCandidate
		return value, row.Scan(&value.tenantID, &value.scopeID, &value.allocationID, &value.jobID, &value.siteID,
			&value.groupID, &value.groupScopeID, &value.groupRevision, &value.zoneID, &value.zoneRevision, &value.ownerName,
			&value.actorUserID, &value.applied.A, &value.applied.AAAA, &value.applied.CNAME, &value.appliedRevision,
			&value.nextSequence, &value.blackhole, &value.stream)
	})
	if err != nil {
		return 0, retargetError(err)
	}
	gated, err := store.gatedSites(ctx)
	if err != nil {
		return 0, retargetError(err)
	}
	desired := map[string]TargetValues{}
	created := 0
	for _, candidate := range candidates {
		if created >= retargetPlanLimit || ctx.Err() != nil {
			break
		}
		var values TargetValues
		market := ""
		if !candidate.blackhole && !candidate.stream {
			if market, err = DefaultLineTarget(ctx, store.pool, candidate.scopeID, candidate.siteID); err != nil {
				return created, err
			}
		}
		if candidate.blackhole {
			values = TargetValues{A: []string{BlackholeAddress}, AAAA: []string{}}
		} else if market != "" {
			values = TargetValues{A: []string{}, AAAA: []string{}, CNAME: market}
		} else if !candidate.stream && gated[[2]uuid.UUID{candidate.scopeID, candidate.siteID}] {
			// The HTTP-01 serving gate keeps some nodes off this site.
			values, err = store.gatedServingValues(ctx, candidate.groupScopeID, candidate.groupID, candidate.groupRevision,
				candidate.scopeID, candidate.siteID)
			if err != nil {
				return created, err
			}
		} else {
			key := candidate.scopeID.String() + "/" + candidate.groupID.String() + "/" + strconv.FormatInt(candidate.groupRevision, 10)
			var ok bool
			if values, ok = desired[key]; !ok {
				values, err = store.servingValues(ctx, candidate.groupScopeID, candidate.groupID, candidate.groupRevision)
				if err != nil {
					return created, err
				}
				desired[key] = values
			}
		}
		applied := TargetValues{A: slices.Sorted(slices.Values(candidate.applied.A)),
			AAAA: slices.Sorted(slices.Values(candidate.applied.AAAA)), CNAME: candidate.applied.CNAME}
		if values.empty() {
			continue
		}
		if values.CNAME == applied.CNAME && slices.Equal(values.A, applied.A) && slices.Equal(values.AAAA, applied.AAAA) {
			// Same addresses: republish only when the written weights moved
			// (weights are versioned with the line group revision).
			if values.CNAME != "" || candidate.appliedRevision == candidate.groupRevision {
				continue
			}
			changed, err := store.weightsChanged(ctx, candidate, values)
			if err != nil {
				return created, err
			}
			if !changed {
				continue
			}
		}
		inserted, err := store.insertRetarget(ctx, candidate, values)
		if err != nil {
			return created, err
		}
		if inserted {
			created++
		}
	}
	return created, nil
}

// weightsChanged reports whether the weights written for values differ
// between the applied and the current line group revision. Both are empty
// unless 开启IP权重 applies to the zone (LoadPublishSettings).
func (store *Store) weightsChanged(ctx context.Context, candidate retargetCandidate, values TargetValues) (bool, error) {
	current, err := LoadPublishSettings(ctx, store.pool, candidate.scopeID, candidate.zoneID, candidate.groupID,
		candidate.groupRevision)
	if err != nil {
		return false, err
	}
	applied, err := LoadPublishSettings(ctx, store.pool, candidate.scopeID, candidate.zoneID, candidate.groupID,
		candidate.appliedRevision)
	if err != nil {
		return false, err
	}
	for _, address := range append(slices.Clone(values.A), values.AAAA...) {
		currentWeight, _ := current.DefaultLineWeight(address)
		appliedWeight, _ := applied.DefaultLineWeight(address)
		if currentWeight != appliedWeight {
			return true, nil
		}
	}
	return false, nil
}

func (store *Store) servingValues(ctx context.Context, scopeID, groupID uuid.UUID, revision int64) (TargetValues, error) {
	rows, err := store.pool.Query(ctx, `SELECT host(address) FROM node_line_endpoint_published
		WHERE tenant_scope_id=$1 AND line_group_id=$2 AND config_revision=$3 AND published ORDER BY address`,
		scopeID, groupID, revision)
	if err != nil {
		return TargetValues{}, retargetError(err)
	}
	addresses, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return TargetValues{}, retargetError(err)
	}
	if len(addresses) == 0 {
		return TargetValues{}, nil
	}
	return canonicalTargetValues(addresses)
}

// gatedSites: sites the ACME HTTP-01 serving gate may affect (migration 342):
// an open epoch, an unresolved cleanup debt or a quarantined 063 backfill.
func (store *Store) gatedSites(ctx context.Context) (map[[2]uuid.UUID]bool, error) {
	rows, err := store.pool.Query(ctx, `SELECT tenant_scope_id,site_id FROM acme_http01_gated_sites()`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := map[[2]uuid.UUID]bool{}
	for rows.Next() {
		var key [2]uuid.UUID
		if err := rows.Scan(&key[0], &key[1]); err != nil {
			return nil, err
		}
		result[key] = true
	}
	return result, rows.Err()
}

// gatedServingValues are servingValues without the nodes the HTTP-01 serving
// gate keeps off the site (an unconfirmed cleanup debt, outside the open
// epoch's required members, a quarantined backfill). An empty result keeps
// the published values (the planner skips empty sets).
func (store *Store) gatedServingValues(ctx context.Context, scopeID, groupID uuid.UUID, revision int64,
	siteScopeID, siteID uuid.UUID) (TargetValues, error) {
	rows, err := store.pool.Query(ctx, `SELECT host(address) FROM node_line_endpoint_published endpoint
		WHERE tenant_scope_id=$1 AND line_group_id=$2 AND config_revision=$3 AND published
		  AND (endpoint.node_id IS NULL OR acme_http01_site_node_serving_blocked($4,$5,endpoint.node_id) IS NULL)
		ORDER BY address`, scopeID, groupID, revision, siteScopeID, siteID)
	if err != nil {
		return TargetValues{}, retargetError(err)
	}
	addresses, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return TargetValues{}, retargetError(err)
	}
	if len(addresses) == 0 {
		return TargetValues{}, nil
	}
	return canonicalTargetValues(addresses)
}

func (store *Store) insertRetarget(ctx context.Context, candidate retargetCandidate, values TargetValues) (bool, error) {
	digestPayload, _ := json.Marshal(struct {
		Version                                   int
		Scope, Allocation, Job, Site, Group, Zone string
		Owner                                     string
		Sequence, GroupRevision, ZoneRevision     int64
		Values                                    TargetValues
	}{1, candidate.scopeID.String(), candidate.allocationID.String(), candidate.jobID.String(), candidate.siteID.String(),
		candidate.groupID.String(), candidate.zoneID.String(), candidate.ownerName, candidate.nextSequence,
		candidate.groupRevision, candidate.zoneRevision, values})
	digest := sha256.Sum256(digestPayload)
	requestID := "cname-retarget/" + candidate.allocationID.String() + "/" + strconv.FormatInt(candidate.nextSequence, 10)
	ttl := 300
	if candidate.blackhole {
		ttl = BlackholeTTL
	}
	inserted := false
	err := pgx.BeginTxFunc(ctx, store.pool, pgx.TxOptions{}, func(tx pgx.Tx) error {
		var current bool
		// The share lock orders this insert after any concurrent regeneration.
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM cname_allocations WHERE tenant_scope_id=$1 AND id=$2
			AND job_id=$3 AND state='done' FOR SHARE)`, candidate.scopeID, candidate.allocationID, candidate.jobID).Scan(&current); err != nil {
			return err
		}
		if !current {
			return nil
		}
		// A stream's retarget is anchored at the stream (migration 507); $7 is the anchor ID.
		command, err := tx.Exec(ctx, `INSERT INTO dns_cname_retargets(id,tenant_id,tenant_scope_id,allocation_id,base_job_id,
			sequence,site_id,node_group_id,node_group_revision,node_group_scope_id,zone_id,zone_revision,owner_name,target_a,target_aaaa,target_cname,ttl,
			target_digest,actor_user_id,request_id,state,created_at,updated_at,stream_id)
			VALUES($1,$2,$3,$4,$5,$6,CASE WHEN $21 THEN NULL ELSE $7::uuid END,$8,$9,$20,$10,$11,$12,$13,$14,NULLIF($18,''),$19,$15,$16,$17,'pending',
				clock_timestamp(),clock_timestamp(),CASE WHEN $21 THEN $7::uuid END)
			ON CONFLICT DO NOTHING`, uuid.New(), candidate.tenantID, candidate.scopeID, candidate.allocationID, candidate.jobID,
			candidate.nextSequence, candidate.siteID, candidate.groupID, candidate.groupRevision, candidate.zoneID,
			candidate.zoneRevision, candidate.ownerName, values.A, values.AAAA, hex.EncodeToString(digest[:]),
			candidate.actorUserID, requestID, values.CNAME, ttl, candidate.groupScopeID, candidate.stream)
		inserted = err == nil && command.RowsAffected() == 1
		return err
	})
	return inserted, retargetError(err)
}

// OpenRetargets returns in-flight retargets; one whose allocation moved to a
// new job meanwhile is superseded instead (the new frozen target wins).
func (store *Store) OpenRetargets(ctx context.Context) ([]Retarget, error) {
	if store == nil || ctx == nil {
		return nil, ErrInvalidInput
	}
	if _, err := store.pool.Exec(ctx, `UPDATE dns_cname_retargets retarget SET state='superseded',updated_at=clock_timestamp()
		FROM cname_allocations allocation WHERE retarget.state IN ('pending','applying')
		AND allocation.tenant_scope_id=retarget.tenant_scope_id AND allocation.id=retarget.allocation_id
		AND (allocation.job_id<>retarget.base_job_id OR allocation.state<>'done')`); err != nil {
		return nil, retargetError(err)
	}
	rows, err := store.pool.Query(ctx, `SELECT id,tenant_id,tenant_scope_id,allocation_id,base_job_id,sequence,COALESCE(site_id,stream_id),zone_id,
			zone_revision,owner_name,target_a,target_aaaa,COALESCE(target_cname,''),target_digest,actor_user_id,request_id,state,child_task_id,child_task_revision,
			node_group_id,node_group_revision,ttl
		FROM dns_cname_retargets WHERE state IN ('pending','applying') ORDER BY updated_at,id LIMIT $1`, retargetOpenLimit)
	if err != nil {
		return nil, retargetError(err)
	}
	result, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (Retarget, error) {
		var value Retarget
		var child *uuid.UUID
		var childRevision *int64
		err := row.Scan(&value.ID, &value.TenantID, &value.ScopeID, &value.AllocationID, &value.BaseJobID, &value.Sequence,
			&value.SiteID, &value.ZoneID, &value.ZoneRevision, &value.OwnerName, &value.Values.A, &value.Values.AAAA, &value.Values.CNAME,
			&value.Digest, &value.ActorUserID, &value.RequestID, &value.State, &child, &childRevision,
			&value.NodeGroupID, &value.NodeGroupRevision, &value.ttl)
		if child != nil && childRevision != nil {
			value.ChildTaskID, value.ChildTaskRevision = *child, *childRevision
		}
		return value, err
	})
	if err != nil {
		return nil, retargetError(err)
	}
	for index := range result {
		retarget := &result[index]
		if retarget.Publish, err = LoadPublishSettings(ctx, store.pool, retarget.ScopeID, retarget.ZoneID,
			retarget.NodeGroupID, retarget.NodeGroupRevision); err != nil {
			return nil, err
		}
		if retarget.ttl == BlackholeTTL {
			retarget.Publish.TTL, retarget.Publish.Weights = BlackholeTTL, nil
		}
	}
	return result, nil
}

func (store *Store) AttachRetarget(ctx context.Context, retarget Retarget, task dnsreconcile.Task) error {
	if store == nil || ctx == nil || task.ID == uuid.Nil || task.Revision < 1 {
		return ErrInvalidInput
	}
	command, err := store.pool.Exec(ctx, `UPDATE dns_cname_retargets SET state='applying',child_task_id=$3,
		child_task_revision=$4,updated_at=clock_timestamp() WHERE tenant_scope_id=$1 AND id=$2 AND state='pending'
		AND child_task_id IS NULL`, retarget.ScopeID, retarget.ID, task.ID, task.Revision)
	if err != nil {
		return retargetError(err)
	}
	if command.RowsAffected() != 1 {
		return ErrClaimLost
	}
	return nil
}

// SettleRetarget moves an in-flight retarget to committed, failed (with a
// failure code) or superseded. Settling an already settled row is a no-op.
func (store *Store) SettleRetarget(ctx context.Context, retarget Retarget, state, failure string) error {
	if store == nil || ctx == nil || (state != "committed" && state != "failed" && state != "superseded") ||
		(state == "failed") != (failure != "") || failure != "" && !errorCodePattern.MatchString(failure) {
		return ErrInvalidInput
	}
	var code any
	if failure != "" {
		code = failure
	}
	_, err := store.pool.Exec(ctx, `UPDATE dns_cname_retargets SET state=$3,failure_code=$4,updated_at=clock_timestamp()
		WHERE tenant_scope_id=$1 AND id=$2 AND state IN ('pending','applying')
		AND ($3<>'committed' OR child_task_id IS NOT NULL)`, retarget.ScopeID, retarget.ID, state, code)
	return retargetError(err)
}

func (retarget Retarget) checkRequest() dnscheck.CheckRequest {
	return Target{TenantID: retarget.TenantID, SiteID: retarget.SiteID, OwnerName: retarget.OwnerName,
		Values: retarget.Values, TTL: defaultPublishTTL, ZoneID: retarget.ZoneID, ZoneRevision: retarget.ZoneRevision,
		Publish: retarget.Publish}.checkRequest()
}

func (retarget Retarget) traceparent() string {
	return Target{Digest: retarget.Digest}.traceparent()
}

// runRetargets advances DNS retargets. Errors are per row: a transient
// reconcile error leaves the row for the next pass, a definitive one fails it
// so the planner retries after retargetRetryAfter.
func (worker *Worker) runRetargets(ctx context.Context) error {
	retargets := worker.dependencies.Retargets
	if _, err := retargets.PlanRetargets(ctx); err != nil {
		return err
	}
	open, err := retargets.OpenRetargets(ctx)
	if err != nil {
		return err
	}
	reconcile := worker.dependencies.Reconcile
	for _, retarget := range open {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if retarget.ChildTaskID == uuid.Nil {
			check, key, snapshotErr := worker.withProviderSnapshot(ctx, retarget.checkRequest(), "cnrt-"+retarget.Digest,
				retarget.TenantID, retarget.SiteID, retarget.ZoneID)
			if snapshotErr != nil {
				continue // the provider cannot be listed now: retry on the next pass
			}
			task, applyErr := reconcile.Apply(ctx, dnsreconcile.ApplyRequest{
				TenantID: retarget.TenantID, SiteID: retarget.SiteID, ActorUserID: retarget.ActorUserID,
				IdempotencyKey: key, RequestID: retarget.RequestID,
				Traceparent: retarget.traceparent(), ExpectedRevision: retarget.ZoneRevision,
				RequiredConsecutive: 3, Check: check,
			})
			if applyErr != nil {
				if !transientReconcileError(applyErr) {
					code := ApplyFailureCode(applyErr)
					slog.Warn("CNAME retarget DNS reconcile apply refused", "tenant_id", retarget.TenantID,
						"site_id", retarget.SiteID, "zone_id", retarget.ZoneID, "code", code, "error", applyErr)
					_ = retargets.SettleRetarget(ctx, retarget, "failed", code)
				}
				continue
			}
			if err := retargets.AttachRetarget(ctx, retarget, task); err != nil && !errors.Is(err, ErrClaimLost) {
				return err
			}
			continue
		}
		task, err := reconcile.Get(ctx, retarget.TenantID, retarget.ChildTaskID)
		if err != nil {
			continue
		}
		if task.Result.Status == dnscheck.TaskReadyToCommit {
			committed, commitErr := reconcile.Commit(ctx, dnsreconcile.CommitRequest{
				TenantID: retarget.TenantID, SiteID: retarget.SiteID, TaskID: task.ID, ActorUserID: retarget.ActorUserID,
				IdempotencyKey: "cnrt-commit-" + retarget.Digest[:48], RequestID: retarget.RequestID,
				Traceparent: retarget.traceparent(), ExpectedRevision: task.Revision,
			})
			if commitErr != nil {
				// N25: this was a silent continue; a rejected commit held its
				// lease for 16 minutes and was retried into the same rejection.
				if transientReconcileError(commitErr) || errors.Is(commitErr, dnsreconcile.ErrCommitNotReady) {
					slog.Warn("CNAME retarget commit not done, retrying next pass", "tenant_id", retarget.TenantID,
						"site_id", retarget.SiteID, "retarget_id", retarget.ID, "task_id", task.ID, "error", commitErr)
					continue
				}
				slog.Error("CNAME retarget commit rejected; failing the retarget", "tenant_id", retarget.TenantID,
					"site_id", retarget.SiteID, "retarget_id", retarget.ID, "task_id", task.ID, "error", commitErr)
				if err := retargets.SettleRetarget(ctx, retarget, "failed", "dns_reconcile_commit_rejected"); err != nil {
					return err
				}
				continue
			}
			task = committed
		}
		switch task.Result.Status {
		case dnscheck.TaskCommitted:
			if err := retargets.SettleRetarget(ctx, retarget, "committed", ""); err != nil {
				return err
			}
		case dnscheck.TaskFailed, dnscheck.TaskCommitFailed:
			slog.Warn("CNAME retarget DNS task failed", "tenant_id", retarget.TenantID, "site_id", retarget.SiteID,
				"retarget_id", retarget.ID, "task_id", task.ID, "status", task.Result.Status, "code", task.Result.ErrorCode)
			if err := retargets.SettleRetarget(ctx, retarget, "failed", "dns_reconcile_failed"); err != nil {
				return err
			}
		}
	}
	return nil
}

func retargetError(err error) error {
	if err == nil {
		return nil
	}
	return mapError(err)
}

func transientReconcileError(err error) bool {
	return errors.Is(err, dnsreconcile.ErrUnavailable) || errors.Is(err, dnsreconcile.ErrOperationInFlight) ||
		errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
}
