package cnameallocation

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand/v2"
	"regexp"
	"strings"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/dnsacme"
	"github.com/cdnca/cdnca/services/control-api/internal/dnsreconcile"
	"github.com/cdnca/cdnca/services/control-api/internal/edgeautopublish"
	"github.com/cdnca/cdnca/services/control-api/internal/domaintrust"
	"github.com/cdnca/cdnca/services/control-api/internal/iamlock"
	"github.com/cdnca/cdnca/services/control-api/internal/jobstate"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	databaseJobKind    = "dns.cname.allocation"
	maximumJobAttempts = 20
)

var (
	keyIDPattern       = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
	idempotencyPattern = regexp.MustCompile(`^[A-Za-z0-9._-]{1,128}$`)
	errorCodePattern   = regexp.MustCompile(`^[a-z][a-z0-9._-]{0,127}$`)
)

type siteAuthority struct {
	tenantID              uuid.UUID
	ownerUserID           uuid.UUID
	packageSubscriptionID *uuid.UUID
	packageID             *uuid.UUID
	revision              int64
	cnameTaskID           *uuid.UUID
}

type zoneAuthority struct {
	providerID uuid.UUID
	zoneID     uuid.UUID
	domain     string
	revision   int64
}

type allocationAuthority struct {
	id                    uuid.UUID
	tenantID              uuid.UUID
	scopeID               uuid.UUID
	ownerUserID           uuid.UUID
	mode                  Mode
	siteOwnerID           *uuid.UUID
	packageSubscriptionID *uuid.UUID
	streamOwnerID         *uuid.UUID
	claimID               uuid.UUID
	lkgClaimID            *uuid.UUID
	revision              int64
	lkgRevision           *int64
	generation            int64
	state                 State
	jobID                 uuid.UUID
	failureCode           *string
	claim                 claimAuthority
}

type claimAuthority struct {
	id       uuid.UUID
	provider uuid.UUID
	zone     uuid.UUID
	domain   string
	hostname string
	explicit bool
	keyID    *string
}

type bindingAuthority struct {
	currentID uuid.UUID
	lkgID     *uuid.UUID
	revision  int64
}

func NewStore(pool *pgxpool.Pool, keyring Keyring, now func() time.Time) (*Store, error) {
	if pool == nil || keyring == nil {
		return nil, ErrInvalidInput
	}
	if now == nil {
		now = time.Now
	}
	return &Store{pool: pool, keyring: keyring, now: now, auditor: audit.NewWithClock(pool, now)}, nil
}

func (store *Store) Allocate(ctx context.Context, req AllocateRequest) (Allocation, error) {
	if ctx == nil || ctx.Err() != nil || !validAllocateRequest(req) {
		return Allocation{}, ErrInvalidInput
	}
	req.Domain = normalizeName(req.Domain)
	req.Hostname = normalizeName(req.Hostname)
	digest, err := allocateDigest(req)
	if err != nil {
		return Allocation{}, ErrInvalidInput
	}
	if replayed, found, err := store.readReplay(ctx, req, digest); err != nil {
		return Allocation{}, mapError(err)
	} else if found {
		replayed.Replayed = true
		return replayed, nil
	}

	var activeKey Key
	if req.Hostname == "" {
		activeKey, err = store.keyring.Active(ctx)
		if err != nil || !validKey(activeKey) {
			return Allocation{}, ErrUnavailable
		}
	}

	// A tenant created after the platform DNS configuration was saved has no
	// copy of it yet; write the copy before resolving the CNAME zone. The
	// error only matters when the scope then has no DNS provider at all.
	platformSyncErr := store.ensurePlatformDNS(ctx, req.TargetScopeID)

	var result Allocation
	err = pgx.BeginTxFunc(ctx, store.pool, pgx.TxOptions{IsoLevel: pgx.Serializable}, func(tx pgx.Tx) error {
		if req.ActorScopeID != req.TargetScopeID {
			if err := iamlock.AcquireShared(ctx, tx); err != nil {
				return err
			}
			if _, err := iamlock.AcquireScopes(ctx, tx, []uuid.UUID{req.ActorScopeID, req.TargetScopeID}); err != nil {
				return err
			}
		}
		// N20: take the publication lock order (configuration scope row, then
		// resource rows). The site update below bumps the scope revision
		// (sites trigger); a publication holds the scope row, the subscription,
		// then key-shares the site (site_ipv6_rollout_targets FK). Locking the
		// site and subscription first deadlocked with it (40P01).
		if err := lockEdgeConfigurationScope(ctx, tx, req.TargetScopeID); err != nil {
			return err
		}
		replayed, found, err := loadReplay(ctx, tx, req, digest)
		if err != nil {
			return err
		}
		if found {
			result = replayed
			result.Replayed = true
			return nil
		}

		site, err := lockSiteAuthority(ctx, tx, req)
		if err != nil {
			return err
		}
		// The platform blocklist (#11) also covers CNAME names: a root entry
		// on the zone or any parent blocks every hostname under it.
		blockCheck := []string{req.Domain}
		if req.Hostname != "" {
			blockCheck = append(blockCheck, req.Hostname+"."+req.Domain)
		}
		if _, blocked, err := domaintrust.BlockedDomain(ctx, tx, blockCheck); err != nil {
			return err
		} else if blocked {
			return ErrBlocked
		}
		// fix-cnamerand: a CNAME without a domain keeps the zone the site
		// already has (regenerate, re-intents), else draws a random zone.
		var keep []uuid.UUID
		if req.Domain == "" {
			owner := req.SiteID
			if req.Mode == ModePackage && site.packageSubscriptionID != nil {
				owner = *site.packageSubscriptionID
			}
			if keep, err = keptZones(ctx, tx, req.TargetScopeID, req.Mode, owner, req.SiteID,
				site.packageSubscriptionID != nil); err != nil {
				return err
			}
		}
		zone, err := resolveZoneAuthority(ctx, tx, req.TargetScopeID, req.Domain, keep, store.zonePick())
		if platformSyncErr != nil && failureCode(err) == FailureDNSProviderNotConfigured {
			// The platform DNS is configured but its tenant copy failed:
			// report that instead of "not configured".
			return platformSyncErr
		}
		if err != nil {
			if site.packageSubscriptionID == nil && req.Domain == "" && failureCode(err) == FailureCNAMEZoneNotConfigured {
				return failWith(FailureNoDefaultZone, ErrNotFound)
			}
			return err
		}
		ownerID, packageID, err := resolveModeOwner(ctx, tx, req, site)
		if err != nil {
			return err
		}
		binding, bindingFound, err := lockBinding(ctx, tx, req.TargetScopeID, req.SiteID)
		if err != nil {
			return err
		}
		target, targetFound, err := lockOwnerAllocation(ctx, tx, req.TargetScopeID, req.Mode, ownerID)
		if err != nil {
			return err
		}

		if targetFound && req.Mode == ModePackage && req.platformIntentID != uuid.Nil && claimMatches(target.claim, zone, req.Hostname) {
			var sameRequest bool
			if err := tx.QueryRow(ctx, `SELECT request_id=$3 FROM background_jobs WHERE tenant_id=$1 AND id=$2`, site.tenantID, target.jobID, req.RequestID).Scan(&sameRequest); err != nil {
				return err
			}
			if sameRequest {
				result, err = store.bindPackageSite(ctx, tx, req, digest, site, target, binding, bindingFound)
				return err
			}
		}
		if targetFound && req.Mode == ModePackage && (!bindingFound || binding.currentID != target.id) &&
			target.state == StateDone && !req.Regenerate && claimMatches(target.claim, zone, req.Hostname) {
			result, err = store.bindPackageSite(ctx, tx, req, digest, site, target, binding, bindingFound)
			return err
		}
		if targetFound && target.state == StatePending {
			return ErrConflict
		}
		if targetFound && bindingFound && binding.currentID == target.id && !req.Regenerate {
			// fix-nopkg (533): a site that binds, leaves or changes its package
			// re-allocates its own CNAME on the new package's line group.
			var packageChanged bool
			if err := tx.QueryRow(ctx, `SELECT COALESCE((SELECT package_subscription_id IS DISTINCT FROM $3::uuid
				FROM cname_allocation_targets WHERE tenant_scope_id=$1 AND allocation_id=$2
				ORDER BY allocation_revision DESC LIMIT 1),false)`,
				req.TargetScopeID, target.id, site.packageSubscriptionID).Scan(&packageChanged); err != nil {
				return err
			}
			if !packageChanged || req.intentJobID == uuid.Nil {
				return ErrConflict
			}
		}

		refresh := targetFound && req.platformIntentID != uuid.Nil && claimMatches(target.claim, zone, req.Hostname)
		operation := "allocate"
		allocationID := uuid.New()
		claimID := uuid.New()
		jobID := uuid.New()
		generation := int64(1)
		expectedRevision := int64(0)
		resultRevision := int64(1)
		var lkgClaimID *uuid.UUID
		var lkgRevision *int64
		if targetFound {
			allocationID = target.id
			generation = target.generation + 1
			if refresh {
				generation = target.generation
				claimID = target.claim.id
			}
			expectedRevision = target.revision
			resultRevision = target.revision + 1
			lkgClaimID, lkgRevision = nextLKG(target)
			operation = "rebind"
			if bindingFound && binding.currentID == target.id {
				operation = "regenerate"
			}
			if req.Hostname != "" && claimMatches(target.claim, zone, req.Hostname) {
				claimID = target.claim.id
			}
		}

		hostname, keyID, err := allocationHostname(ctx, tx, activeKey, req, site.tenantID, zone, ownerID, uint64(generation))
		if err != nil {
			return err
		}
		if targetFound && claimID == target.claim.id {
			hostname, keyID = target.claim.hostname, target.claim.keyID
		}
		jobDigest := backgroundJobDigest(digest, allocationID, generation)
		if err := insertJob(ctx, tx, site.tenantID, jobID, allocationID, req, jobDigest, store.timestamp()); err != nil {
			return err
		}
		if refresh {
			if _, err := tx.Exec(ctx, `INSERT INTO cname_platform_allocation_jobs(tenant_id,job_id,intent_job_id,allocation_id)
             VALUES($1,$2,$3,$4)`, site.tenantID, jobID, req.platformIntentID, allocationID); err != nil {
				return err
			}
		}
		if !targetFound {
			if err := insertAllocation(ctx, tx, allocationID, claimID, jobID, site, req, ownerID,
				packageID, store.timestamp()); err != nil {
				return err
			}
		}
		if !targetFound || claimID != target.claim.id {
			if err := insertClaim(ctx, tx, claimID, allocationID, req.TargetScopeID, generation,
				zone, hostname, req.Hostname != "", keyID, store.timestamp()); err != nil {
				return err
			}
		}
		if targetFound {
			if err := advanceAllocation(ctx, tx, target, claimID, jobID, lkgClaimID, lkgRevision,
				generation, resultRevision, store.timestamp()); err != nil {
				return err
			}
		}

		lkgAllocationID := bindingLKG(binding, bindingFound, target, targetFound)
		if err := upsertBinding(ctx, tx, req.TargetScopeID, req.SiteID, allocationID,
			lkgAllocationID, binding, bindingFound, store.timestamp()); err != nil {
			return err
		}
		// n12b: the owner the allocation moves past, and the site-mode
		// allocation a site leaves, were written to the provider; the
		// retirement worker deletes them once no live site serves them.
		if targetFound && claimID != target.claim.id {
			if err := retireRotatedClaimTx(ctx, tx, req.TargetScopeID, target.id, target.claim.id, req.SiteID,
				target.state == StateDone, store.timestamp()); err != nil {
				return err
			}
		}
		if bindingFound && binding.currentID != allocationID {
			if err := retireLeftSiteAllocationTx(ctx, tx, req.TargetScopeID, binding.currentID, req.SiteID,
				store.timestamp()); err != nil {
				return err
			}
		}
		// A site without a package (migration 533) freezes the platform
		// default line group; site mode only (resolveModeOwner).
		packageSubscriptionID := uuid.Nil
		if site.packageSubscriptionID != nil {
			packageSubscriptionID = *site.packageSubscriptionID
		}
		if err := insertFrozenTarget(ctx, tx, frozenTargetInput{
			tenantID: site.tenantID, scopeID: req.TargetScopeID, allocationID: allocationID,
			jobID: jobID, siteID: req.SiteID, packageSubscriptionID: packageSubscriptionID,
			zone: zone, ownerName: hostname, actorUserID: req.ActorUserID, requestID: req.RequestID,
			siteRevision: site.revision, allocationRevision: resultRevision,
		}, store.timestamp()); err != nil {
			return err
		}
		if targetFound && req.Mode == ModePackage {
			if err := advancePackageBindings(ctx, tx, req.TargetScopeID, req.SiteID, target, store.timestamp()); err != nil {
				return err
			}
		}
		if err := projectBoundSites(ctx, tx, req.TargetScopeID, allocationID, req.Domain,
			req.Hostname, store.timestamp(), req.SiteID); err != nil {
			return err
		}

		factTime := store.timestamp()
		auditID, err := store.appendAudit(ctx, tx, req, operation, allocationID, StatePending, "", factTime)
		if err != nil {
			return err
		}
		if err := insertRequest(ctx, tx, requestFact{
			id: uuid.New(), tenantID: site.tenantID, scopeID: req.TargetScopeID,
			allocationID: allocationID, siteID: req.SiteID, actorScopeID: req.ActorScopeID,
			actorUserID: req.ActorUserID, operation: operation, idempotencyKey: req.IdempotencyKey,
			digest: digest, requestID: req.RequestID, jobID: jobID, keyID: keyID,
			generation: generation, expectedRevision: expectedRevision, resultRevision: resultRevision,
			lkgRevision: lkgRevision, state: StatePending, auditID: auditID, createdAt: factTime,
		}); err != nil {
			return err
		}
		result, err = loadAllocation(ctx, tx, req.TargetScopeID, req.SiteID)
		return err
	})
	if err != nil {
		return Allocation{}, mapError(err)
	}
	return result, nil
}

func (store *Store) Complete(ctx context.Context, req ResultRequest) (Allocation, error) {
	return store.settle(ctx, req, StateDone)
}

func (store *Store) Fail(ctx context.Context, req ResultRequest) (Allocation, error) {
	return store.settle(ctx, req, StateFailed)
}

func (store *Store) Get(ctx context.Context, scopeID, siteID uuid.UUID) (Allocation, error) {
	if ctx == nil || ctx.Err() != nil || scopeID == uuid.Nil || siteID == uuid.Nil {
		return Allocation{}, ErrInvalidInput
	}
	var result Allocation
	err := pgx.BeginTxFunc(ctx, store.pool, pgx.TxOptions{
		IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly,
	}, func(tx pgx.Tx) error {
		var err error
		result, err = loadAllocation(ctx, tx, scopeID, siteID)
		return err
	})
	if err != nil {
		return Allocation{}, mapError(err)
	}
	return result, nil
}

type frozenTargetInput struct {
	tenantID, scopeID, allocationID, jobID, siteID, packageSubscriptionID uuid.UUID
	zone                                                                  zoneAuthority
	ownerName                                                             string
	actorUserID                                                           uuid.UUID
	requestID                                                             string
	siteRevision, allocationRevision                                      int64
	// streamID: a stream's own allocation (migration 505); its line group is
	// the stream's own, else the package's (no website, migration 506), the
	// row is anchored at the stream (site_id NULL, migration 507) and the
	// site's HTTP-01 serving gate does not apply (the gate is per site).
	streamID *uuid.UUID
}

// noPackageTargetSource: a site without a package uses its own line group,
// else the platform default line group (migration 533).
const noPackageTargetSource = `FROM sites selected_site
		JOIN node_line_groups line_group
		  ON (line_group.tenant_scope_id=selected_site.scope_id OR line_group.tenant_scope_id=(
		      SELECT platform.id FROM access_scopes platform WHERE platform.kind='platform'))
		 AND (line_group.id=selected_site.node_group_id OR (selected_site.node_group_id IS NULL AND line_group.is_platform_default))
		 AND line_group.deleted_at IS NULL
		JOIN node_line_group_revisions revision
		  ON revision.tenant_scope_id=line_group.tenant_scope_id
		 AND revision.line_group_id=line_group.id
		 AND revision.revision=line_group.current_revision AND revision.sealed_at IS NOT NULL`

func insertFrozenTarget(ctx context.Context, tx pgx.Tx, input frozenTargetInput, now time.Time) error {
	var nodeGroupID, nodeGroupScopeID uuid.UUID
	var nodeGroupRevision int64
	if input.packageSubscriptionID == uuid.Nil && input.streamID == nil {
		return insertNoPackageFrozenTarget(ctx, tx, input, now)
	}
	if input.packageSubscriptionID == uuid.Nil {
		return insertNoPackageStreamFrozenTarget(ctx, tx, input, now)
	}
	rows, err := tx.Query(ctx, `SELECT host(endpoint.address)
		FROM package_subscriptions subscription
		LEFT JOIN sites selected_site ON selected_site.scope_id=subscription.tenant_scope_id AND selected_site.id=$3
		JOIN node_line_groups line_group
		  ON (line_group.tenant_scope_id=subscription.tenant_scope_id OR line_group.tenant_scope_id=(
		      SELECT platform.id FROM access_scopes platform WHERE platform.kind='platform'))
		 AND line_group.id=COALESCE((SELECT forward.node_group_id FROM l4_forwards forward WHERE forward.scope_id=$1 AND forward.id=$4::uuid),
		      selected_site.node_group_id,(subscription.product_snapshot->'spec'->>'node_group_id')::uuid)
		 AND line_group.deleted_at IS NULL
		JOIN node_line_group_revisions revision
		  ON revision.tenant_scope_id=line_group.tenant_scope_id
		 AND revision.line_group_id=line_group.id
		 AND revision.revision=line_group.current_revision AND revision.sealed_at IS NOT NULL
		JOIN node_line_endpoint_published endpoint
		  ON endpoint.tenant_scope_id=revision.tenant_scope_id
		 AND endpoint.line_group_id=revision.line_group_id
		 AND endpoint.config_revision=revision.revision AND endpoint.published
		 -- ACME HTTP-01 serving gate (migration 342).
		 AND ($4::uuid IS NOT NULL OR endpoint.node_id IS NULL OR acme_http01_site_node_serving_blocked($1,$3,endpoint.node_id) IS NULL)
		WHERE subscription.tenant_scope_id=$1 AND subscription.id=$2
		  AND subscription.lifecycle_status='active'
		  AND subscription.admin_enabled=true AND subscription.deleted_at IS NULL
		  AND ($4::uuid IS NOT NULL OR selected_site.id IS NOT NULL)
		ORDER BY endpoint.address,endpoint.endpoint_id`, input.scopeID, input.packageSubscriptionID, nullableUUID(input.siteID), input.streamID)
	if err != nil {
		return err
	}
	addresses := make([]string, 0)
	for rows.Next() {
		var address string
		if err := rows.Scan(&address); err != nil {
			rows.Close()
			return err
		}
		addresses = append(addresses, address)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()
	if err := tx.QueryRow(ctx, `SELECT line_group.id,line_group.current_revision,line_group.tenant_scope_id
		FROM package_subscriptions subscription
		LEFT JOIN sites selected_site ON selected_site.scope_id=subscription.tenant_scope_id AND selected_site.id=$3
		JOIN node_line_groups line_group
		  ON (line_group.tenant_scope_id=subscription.tenant_scope_id OR line_group.tenant_scope_id=(
		      SELECT platform.id FROM access_scopes platform WHERE platform.kind='platform'))
		 AND line_group.id=COALESCE((SELECT forward.node_group_id FROM l4_forwards forward WHERE forward.scope_id=$1 AND forward.id=$4::uuid),
		      selected_site.node_group_id,(subscription.product_snapshot->'spec'->>'node_group_id')::uuid)
		 AND line_group.deleted_at IS NULL
		JOIN node_line_group_revisions revision
		  ON revision.tenant_scope_id=line_group.tenant_scope_id
		 AND revision.line_group_id=line_group.id
		 AND revision.revision=line_group.current_revision AND revision.sealed_at IS NOT NULL
		WHERE subscription.tenant_scope_id=$1 AND subscription.id=$2
		  AND subscription.lifecycle_status='active'
		  AND subscription.admin_enabled=true AND subscription.deleted_at IS NULL
		  AND ($4::uuid IS NOT NULL OR selected_site.id IS NOT NULL)
		  FOR SHARE OF subscription,line_group,revision NOWAIT`,
		input.scopeID, input.packageSubscriptionID, nullableUUID(input.siteID), input.streamID).Scan(&nodeGroupID, &nodeGroupRevision, &nodeGroupScopeID); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return failWith(FailureNodeGroupUnavailable, ErrNotFound)
		}
		return err
	}
	return writeFrozenTarget(ctx, tx, input, addresses, nodeGroupID, nodeGroupScopeID, nodeGroupRevision, now)
}

func insertNoPackageFrozenTarget(ctx context.Context, tx pgx.Tx, input frozenTargetInput, now time.Time) error {
	var nodeGroupID, nodeGroupScopeID uuid.UUID
	var nodeGroupRevision int64
	if err := tx.QueryRow(ctx, `SELECT line_group.id,line_group.current_revision,line_group.tenant_scope_id
		`+noPackageTargetSource+`
		WHERE selected_site.scope_id=$1 AND selected_site.id=$2
		FOR SHARE OF line_group,revision NOWAIT`, input.scopeID, input.siteID).Scan(&nodeGroupID, &nodeGroupRevision, &nodeGroupScopeID); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return failWith(FailureNoDefaultLineGroup, ErrNotFound)
		}
		return err
	}
	rows, err := tx.Query(ctx, `SELECT host(endpoint.address)
		`+noPackageTargetSource+`
		JOIN node_line_endpoint_published endpoint
		  ON endpoint.tenant_scope_id=revision.tenant_scope_id
		 AND endpoint.line_group_id=revision.line_group_id
		 AND endpoint.config_revision=revision.revision AND endpoint.published
		 -- ACME HTTP-01 serving gate (migration 342).
		 AND (endpoint.node_id IS NULL OR acme_http01_site_node_serving_blocked($1,$2,endpoint.node_id) IS NULL)
		WHERE selected_site.scope_id=$1 AND selected_site.id=$2
		ORDER BY endpoint.address,endpoint.endpoint_id`, input.scopeID, input.siteID)
	if err != nil {
		return err
	}
	addresses, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return err
	}
	return writeFrozenTarget(ctx, tx, input, addresses, nodeGroupID, nodeGroupScopeID, nodeGroupRevision, now)
}

// noPackageStreamTargetSource: a stream without a package (community
// edition) uses its own line group, else the platform default line group.
const noPackageStreamTargetSource = `FROM l4_forwards selected_stream
		JOIN node_line_groups line_group
		  ON (line_group.tenant_scope_id=selected_stream.scope_id OR line_group.tenant_scope_id=(
		      SELECT platform.id FROM access_scopes platform WHERE platform.kind='platform'))
		 AND (line_group.id=selected_stream.node_group_id OR (selected_stream.node_group_id IS NULL AND line_group.is_platform_default))
		 AND line_group.deleted_at IS NULL
		JOIN node_line_group_revisions revision
		  ON revision.tenant_scope_id=line_group.tenant_scope_id
		 AND revision.line_group_id=line_group.id
		 AND revision.revision=line_group.current_revision AND revision.sealed_at IS NOT NULL`

func insertNoPackageStreamFrozenTarget(ctx context.Context, tx pgx.Tx, input frozenTargetInput, now time.Time) error {
	var nodeGroupID, nodeGroupScopeID uuid.UUID
	var nodeGroupRevision int64
	if err := tx.QueryRow(ctx, `SELECT line_group.id,line_group.current_revision,line_group.tenant_scope_id
		`+noPackageStreamTargetSource+`
		WHERE selected_stream.scope_id=$1 AND selected_stream.id=$2 AND selected_stream.deleted_at IS NULL
		FOR SHARE OF line_group,revision NOWAIT`, input.scopeID, *input.streamID).Scan(&nodeGroupID, &nodeGroupRevision, &nodeGroupScopeID); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return failWith(FailureNoDefaultLineGroup, ErrNotFound)
		}
		return err
	}
	rows, err := tx.Query(ctx, `SELECT host(endpoint.address)
		`+noPackageStreamTargetSource+`
		JOIN node_line_endpoint_published endpoint
		  ON endpoint.tenant_scope_id=revision.tenant_scope_id
		 AND endpoint.line_group_id=revision.line_group_id
		 AND endpoint.config_revision=revision.revision AND endpoint.published
		WHERE selected_stream.scope_id=$1 AND selected_stream.id=$2 AND selected_stream.deleted_at IS NULL
		ORDER BY endpoint.address,endpoint.endpoint_id`, input.scopeID, *input.streamID)
	if err != nil {
		return err
	}
	addresses, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return err
	}
	return writeFrozenTarget(ctx, tx, input, addresses, nodeGroupID, nodeGroupScopeID, nodeGroupRevision, now)
}

func writeFrozenTarget(ctx context.Context, tx pgx.Tx, input frozenTargetInput, addresses []string,
	nodeGroupID, nodeGroupScopeID uuid.UUID, nodeGroupRevision int64, now time.Time) error {
	values, err := canonicalTargetValues(addresses)
	if err != nil {
		return failWith(FailureNoServingAddress, ErrInvalidInput)
	}
	digestPayload, _ := json.Marshal(struct {
		ScopeID, SiteID, SubscriptionID, NodeGroupID, ProviderID, ZoneID, Owner string
		NodeRevision, ZoneRevision, SiteRevision, AllocationRevision            int64
		TTL                                                                     uint32
		Values                                                                  TargetValues
	}{input.scopeID.String(), input.siteID.String(), input.packageSubscriptionID.String(),
		nodeGroupID.String(), input.zone.providerID.String(), input.zone.zoneID.String(), input.ownerName,
		nodeGroupRevision, input.zone.revision, input.siteRevision, input.allocationRevision, 300, values})
	digest := sha256.Sum256(digestPayload)
	_, err = tx.Exec(ctx, `INSERT INTO cname_allocation_targets(
		tenant_id,tenant_scope_id,allocation_id,job_id,site_id,package_subscription_id,
		node_group_id,node_group_revision,provider_id,zone_id,zone_revision,owner_name,
		target_a,target_aaaa,ttl,target_digest,actor_user_id,request_id,site_revision,
		allocation_revision,created_at,updated_at,node_group_scope_id,stream_id
	) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,300,$15,$16,$17,$18,$19,$20,$20,$21,$22)`,
		input.tenantID, input.scopeID, input.allocationID, input.jobID, nullableUUID(input.siteID),
		nullableUUID(input.packageSubscriptionID), nodeGroupID, nodeGroupRevision, input.zone.providerID,
		input.zone.zoneID, input.zone.revision, input.ownerName, values.A, values.AAAA,
		hex.EncodeToString(digest[:]), input.actorUserID, input.requestID, input.siteRevision,
		input.allocationRevision, now, nodeGroupScopeID, input.streamID)
	return err
}

func (store *Store) PendingTenants(ctx context.Context, limit int) ([]uuid.UUID, error) {
	if ctx == nil || limit < 1 || limit > 1000 {
		return nil, ErrInvalidInput
	}
	rows, err := store.pool.Query(ctx, `SELECT DISTINCT tenant_id FROM background_jobs
		WHERE kind=ANY($1::text[]) AND state IN ('queued','running') AND claimable_at<=clock_timestamp()
		ORDER BY tenant_id LIMIT $2`, []string{databaseJobKind, "dns.cname.intent", StreamIntentJobKind}, limit)
	if err != nil {
		return nil, unavailable(err)
	}
	defer rows.Close()
	result := make([]uuid.UUID, 0, limit)
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			return nil, unavailable(err)
		}
		result = append(result, id)
	}
	if err := rows.Err(); err != nil {
		return nil, unavailable(err)
	}
	return result, nil
}

// unavailable keeps the database cause next to ErrUnavailable so callers can
// still tell a dropped connection (57P01 after a PostgreSQL restart) from a
// permanent failure; control-api retries the former instead of exiting.
func unavailable(err error) error {
	return fmt.Errorf("%w: %w", ErrUnavailable, err)
}

func (store *Store) PrepareIntent(ctx context.Context, claim jobstate.Claim) error {
	if ctx == nil || claim.Job.ID == uuid.Nil || claim.Job.TenantID == uuid.Nil || claim.LeaseID == uuid.Nil || claim.WorkerID == "" {
		return ErrInvalidInput
	}
	var req AllocateRequest
	err := store.pool.QueryRow(ctx, `SELECT intent.tenant_scope_id,intent.site_id,intent.actor_scope_id,
		intent.actor_user_id,intent.mode,intent.domain,intent.hostname,intent.idempotency_key,
		intent.request_id,intent.trace_id,intent.expected_site_revision,intent.regenerate
		FROM cname_allocation_intents intent JOIN background_jobs job
		  ON job.tenant_id=intent.tenant_id AND job.id=intent.job_id
		WHERE intent.tenant_id=$1 AND intent.job_id=$2 AND job.kind='dns.cname.intent'
		  AND job.state='running' AND job.attempt=$3
		  AND job.lease_id=$4 AND job.lease_owner=$5 AND job.lease_expires_at>clock_timestamp()`,
		claim.Job.TenantID, claim.Job.ID, claim.Job.Attempt, claim.LeaseID, claim.WorkerID).Scan(
		&req.TargetScopeID, &req.SiteID, &req.ActorScopeID, &req.ActorUserID, &req.Mode, &req.Domain,
		&req.Hostname, &req.IdempotencyKey, &req.RequestID, &req.TraceID, &req.ExpectedSiteRevision, &req.Regenerate)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrClaimLost
	}
	if err != nil {
		return mapError(err)
	}
	if req.ActorScopeID != req.TargetScopeID {
		req.platformIntentID = claim.Job.ID
	}
	req.intentJobID = claim.Job.ID
	_, allocateErr := store.Allocate(ctx, req)
	// The worker retries ErrRetryable and ErrConflict within seconds (Worker.retrySoon).
	if errors.Is(allocateErr, ErrUnavailable) || errors.Is(allocateErr, ErrConflict) || errors.Is(allocateErr, ErrRetryable) {
		return allocateErr
	}
	state := StateDone
	failure := ""
	if allocateErr != nil {
		state = StateFailed
		failure = failureCode(allocateErr)
	}
	settleReq := ResultRequest{JobID: claim.Job.ID, WorkerID: claim.WorkerID, Attempt: claim.Job.Attempt,
		LeaseID: claim.LeaseID, Sequence: 1, FailureCode: failure}
	err = pgx.BeginTxFunc(ctx, store.pool, pgx.TxOptions{IsoLevel: pgx.Serializable}, func(tx pgx.Tx) error {
		if state == StateFailed {
			// N20: the site update below bumps the scope row.
			if err := lockEdgeConfigurationScope(ctx, tx, req.TargetScopeID); err != nil {
				return err
			}
		}
		if err := settleBackgroundJob(ctx, tx, claim.Job.TenantID, settleReq, state, store.timestamp()); err != nil {
			return err
		}
		if state == StateFailed {
			command, err := tx.Exec(ctx, `UPDATE sites SET cname_state='failed',updated_at=$4
				WHERE scope_id=$1 AND id=$2 AND cname_task_id=$3 AND cname_state='pending'`,
				req.TargetScopeID, req.SiteID, claim.Job.ID, store.timestamp())
			if err != nil {
				return err
			}
			if command.RowsAffected() > 0 {
				return publishProjectedSitesTx(ctx, tx, req.TargetScopeID, []uuid.UUID{req.SiteID}, claim.Job.ID)
			}
		}
		return nil
	})
	if err != nil {
		return mapError(err)
	}
	return nil
}

func (store *Store) LoadTarget(ctx context.Context, claim jobstate.Claim) (Target, error) {
	if ctx == nil || claim.Job.ID == uuid.Nil || claim.Job.TenantID == uuid.Nil || claim.LeaseID == uuid.Nil || claim.WorkerID == "" {
		return Target{}, ErrInvalidInput
	}
	var target Target
	var traceID string
	var childTaskID *uuid.UUID
	var childTaskRevision *int64
	err := store.pool.QueryRow(ctx, `SELECT target.tenant_id,target.tenant_scope_id,COALESCE(target.site_id,target.stream_id),
		target.allocation_id,target.job_id,COALESCE(target.package_subscription_id,'00000000-0000-0000-0000-000000000000'::uuid),target.node_group_id,
		target.node_group_revision,target.provider_id,target.zone_id,target.zone_revision,target.owner_name,
		target.actor_user_id,target.request_id,target.site_revision,target.allocation_revision,target.ttl,
		target.target_a,target.target_aaaa,target.target_digest,target.child_task_id,target.child_task_revision,job.trace_id
		FROM cname_allocation_targets target JOIN background_jobs job
		  ON job.tenant_id=target.tenant_id AND job.id=target.job_id
		WHERE target.tenant_id=$1 AND target.job_id=$2 AND job.state='running'
		  AND job.attempt=$3 AND job.lease_id=$4 AND job.lease_owner=$5
		  AND job.lease_expires_at>clock_timestamp()`, claim.Job.TenantID, claim.Job.ID,
		claim.Job.Attempt, claim.LeaseID, claim.WorkerID).Scan(&target.TenantID, &target.ScopeID, &target.SiteID,
		&target.AllocationID, &target.JobID, &target.PackageSubscriptionID, &target.NodeGroupID,
		&target.NodeGroupRevision, &target.ProviderID, &target.ZoneID, &target.ZoneRevision, &target.OwnerName,
		&target.ActorUserID, &target.RequestID, &target.SiteRevision, &target.AllocationRevision, &target.TTL,
		&target.Values.A, &target.Values.AAAA, &target.Digest, &childTaskID, &childTaskRevision, &traceID)
	if errors.Is(err, pgx.ErrNoRows) {
		return Target{}, ErrClaimLost
	}
	if err != nil {
		return Target{}, mapError(err)
	}
	target.Traceparent = traceID
	if childTaskID != nil {
		target.ChildTaskID = *childTaskID
		target.ChildTaskRevision = *childTaskRevision
	}
	if target.Publish, err = LoadPublishSettings(ctx, store.pool, target.ScopeID, target.ZoneID,
		target.NodeGroupID, target.NodeGroupRevision); err != nil {
		return Target{}, err
	}
	return target, nil
}

func (store *Store) AttachChild(ctx context.Context, claim jobstate.Claim, target Target, task dnsreconcile.Task) error {
	if ctx == nil || task.ID == uuid.Nil || task.Revision < 1 || task.TenantID != target.TenantID || task.SiteID != target.SiteID {
		return ErrInvalidInput
	}
	command, err := store.pool.Exec(ctx, `UPDATE cname_allocation_targets target
		SET child_task_id=$6,child_task_revision=$7,updated_at=$8
		FROM background_jobs job
		WHERE target.tenant_id=$1 AND target.job_id=$2 AND target.allocation_revision=$9
		  AND target.child_task_id IS NULL AND job.tenant_id=target.tenant_id AND job.id=target.job_id
		  AND job.state='running' AND job.attempt=$3 AND job.lease_id=$4 AND job.lease_owner=$5
		  AND job.lease_expires_at>$8`, target.TenantID, target.JobID, claim.Job.Attempt, claim.LeaseID,
		claim.WorkerID, task.ID, task.Revision, store.timestamp(), target.AllocationRevision)
	if err != nil {
		return mapError(err)
	}
	if command.RowsAffected() != 1 {
		return ErrClaimLost
	}
	return nil
}

// Yield releases the allocation job's lease (jobstate voluntary yield,
// migration 115) so it is claimable again after delay.
func (store *Store) Yield(ctx context.Context, claim jobstate.Claim, delay time.Duration) error {
	if ctx == nil || delay <= 0 {
		return ErrInvalidInput
	}
	now := store.timestamp()
	err := pgx.BeginFunc(ctx, store.pool, func(tx pgx.Tx) error {
		return jobstate.VoluntaryYieldTx(ctx, tx, jobstate.VoluntaryYieldInput{
			TenantID: claim.Job.TenantID, JobID: claim.Job.ID, Kind: claim.Job.Kind, Attempt: claim.Job.Attempt,
			LeaseID: claim.LeaseID, WorkerID: claim.WorkerID, YieldedAt: now, NotBefore: now.Add(delay),
		})
	})
	if err == nil {
		return nil
	}
	if errors.Is(err, jobstate.ErrClaimLost) {
		return ErrClaimLost
	}
	return mapError(err)
}

func (store *Store) settle(ctx context.Context, req ResultRequest, state State) (Allocation, error) {
	if ctx == nil || ctx.Err() != nil || !validResultRequest(req, state) {
		return Allocation{}, ErrInvalidInput
	}
	digest := resultDigest(req, state)
	var result Allocation
	err := pgx.BeginTxFunc(ctx, store.pool, pgx.TxOptions{IsoLevel: pgx.Serializable}, func(tx pgx.Tx) error {
		replayed, found, err := loadResultReplay(ctx, tx, req, digest)
		if err != nil {
			return err
		}
		if found {
			result = replayed
			result.Replayed = true
			return nil
		}

		// N20: projectBoundSites updates sites, which bumps the scope row.
		if err := lockEdgeConfigurationScope(ctx, tx, req.TargetScopeID); err != nil {
			return err
		}
		allocation, actorScopeID, actorUserID, requestID, err := lockSettlement(ctx, tx, req)
		if err != nil {
			return err
		}
		if err := settleBackgroundJob(ctx, tx, allocation.tenantID, req, state, store.timestamp()); err != nil {
			return err
		}
		result, err = store.settleAllocationTx(ctx, tx, req, state, digest, allocation, actorScopeID, actorUserID, requestID)
		return err
	})
	if err != nil {
		return Allocation{}, mapError(err)
	}
	return result, nil
}

// settleAllocationTx records the allocation outcome once its job has ended:
// the allocation, its bindings, the bound sites, the settle audit and request
// fact. The worker (settle) and jobstate's terminal hook (ended.go) share it.
func (store *Store) settleAllocationTx(
	ctx context.Context,
	tx pgx.Tx,
	req ResultRequest,
	state State,
	digest [32]byte,
	allocation allocationAuthority,
	actorScopeID, actorUserID uuid.UUID,
	requestID string,
) (Allocation, error) {
	newRevision := allocation.revision + 1
	var failureCode *string
	lkgClaimID := allocation.lkgClaimID
	lkgRevision := allocation.lkgRevision
	if state == StateDone {
		lkgClaimID = &allocation.claimID
		lkgRevision = &newRevision
	} else {
		failureCode = &req.FailureCode
	}
	command, err := tx.Exec(ctx, `UPDATE cname_allocations
		SET state=$4,failure_code=$5,lkg_claim_id=$6,lkg_revision=$7,
		    current_revision=$3,updated_at=$8
		WHERE tenant_scope_id=$1 AND id=$2 AND current_revision=$9 AND state='pending'`,
		req.TargetScopeID, req.AllocationID, newRevision, string(state), failureCode,
		lkgClaimID, lkgRevision, store.timestamp(), req.ExpectedRevision)
	if err != nil {
		return Allocation{}, err
	}
	if command.RowsAffected() != 1 {
		return Allocation{}, ErrConflict
	}
	if state == StateDone {
		if _, err := tx.Exec(ctx, `UPDATE cname_site_bindings
			SET lkg_allocation_id=current_allocation_id,binding_revision=binding_revision+1,updated_at=$3
			WHERE tenant_scope_id=$1 AND current_allocation_id=$2`,
			req.TargetScopeID, req.AllocationID, store.timestamp()); err != nil {
			return Allocation{}, err
		}
	}
	if err := projectBoundSites(ctx, tx, req.TargetScopeID, req.AllocationID, "", "", store.timestamp()); err != nil {
		return Allocation{}, err
	}

	settleReq := AllocateRequest{
		TargetScopeID: req.TargetScopeID, SiteID: req.SiteID,
		ActorScopeID: actorScopeID, ActorUserID: actorUserID, RequestID: requestID,
	}
	if allocation.streamOwnerID != nil {
		settleReq.SiteID = uuid.Nil // req.SiteID is the stream anchor (migration 507)
	}
	factTime := store.timestamp()
	var auditID uuid.UUID
	if allocation.streamOwnerID != nil {
		auditID, err = store.appendStreamAudit(ctx, tx, settleReq, *allocation.streamOwnerID, "settle", req.AllocationID,
			state, req.FailureCode)
	} else {
		auditID, err = store.appendAudit(ctx, tx, settleReq, "settle", req.AllocationID,
			state, req.FailureCode, factTime)
	}
	if err != nil {
		return Allocation{}, err
	}
	settlementKey := settlementIdempotencyKey(req)
	if err := insertRequest(ctx, tx, requestFact{
		id: uuid.New(), tenantID: allocation.tenantID, scopeID: req.TargetScopeID,
		allocationID: req.AllocationID, siteID: settleReq.SiteID, streamID: allocation.streamOwnerID, actorScopeID: actorScopeID,
		actorUserID: actorUserID, operation: "settle", idempotencyKey: settlementKey,
		digest: digest, requestID: requestID, jobID: req.JobID, keyID: allocation.claim.keyID,
		generation: allocation.generation, expectedRevision: allocation.revision,
		resultRevision: newRevision, lkgRevision: lkgRevision, state: state,
		failureCode: failureCode, auditID: auditID, createdAt: factTime,
	}); err != nil {
		return Allocation{}, err
	}
	if allocation.streamOwnerID != nil {
		return loadStreamAllocation(ctx, tx, req.TargetScopeID, *allocation.streamOwnerID)
	}
	return loadAllocation(ctx, tx, req.TargetScopeID, req.SiteID)
}

func (store *Store) bindPackageSite(
	ctx context.Context,
	tx pgx.Tx,
	req AllocateRequest,
	digest [32]byte,
	site siteAuthority,
	target allocationAuthority,
	binding bindingAuthority,
	bindingFound bool,
) (Allocation, error) {
	lkgID := bindingLKG(binding, bindingFound, target, true)
	if target.state == StateDone {
		lkgID = &target.id
	}
	if err := upsertBinding(ctx, tx, req.TargetScopeID, req.SiteID, target.id, lkgID,
		binding, bindingFound, store.timestamp()); err != nil {
		return Allocation{}, err
	}
	if bindingFound && binding.currentID != target.id {
		if err := retireLeftSiteAllocationTx(ctx, tx, req.TargetScopeID, binding.currentID, req.SiteID,
			store.timestamp()); err != nil {
			return Allocation{}, err
		}
	}
	if err := projectBoundSites(ctx, tx, req.TargetScopeID, target.id, req.Domain,
		req.Hostname, store.timestamp(), req.SiteID); err != nil {
		return Allocation{}, err
	}
	factTime := store.timestamp()
	auditID, err := store.appendAudit(ctx, tx, req, "bind", target.id, target.state, "", factTime)
	if err != nil {
		return Allocation{}, err
	}
	if err := insertRequest(ctx, tx, requestFact{
		id: uuid.New(), tenantID: site.tenantID, scopeID: req.TargetScopeID, allocationID: target.id,
		siteID: req.SiteID, actorScopeID: req.ActorScopeID, actorUserID: req.ActorUserID,
		operation: "bind", idempotencyKey: req.IdempotencyKey, digest: digest, requestID: req.RequestID,
		jobID: target.jobID, keyID: target.claim.keyID, generation: target.generation,
		expectedRevision: target.revision, resultRevision: target.revision,
		lkgRevision: target.lkgRevision, state: target.state, failureCode: target.failureCode,
		auditID: auditID, createdAt: factTime,
	}); err != nil {
		return Allocation{}, err
	}
	return loadAllocation(ctx, tx, req.TargetScopeID, req.SiteID)
}

// lockEdgeConfigurationScope takes the publication lock order (configuration
// scope row before site and subscription rows), as site.lockEdgeConfigurationScope.
// Subscriptions are then share-locked NOWAIT: site writers lock the
// subscription before the scope row (checkPackageRuntime), so waiting on one
// here would reverse their order; 55P03 is retried instead (ErrRetryable).
func lockEdgeConfigurationScope(ctx context.Context, tx pgx.Tx, scopeID uuid.UUID) error {
	if _, err := tx.Exec(ctx, `INSERT INTO edge_configuration_scopes(scope_id,source_revision,updated_at)
		VALUES($1,1,clock_timestamp()) ON CONFLICT(scope_id) DO NOTHING`, scopeID); err != nil {
		return err
	}
	_, err := tx.Exec(ctx, `SELECT 1 FROM edge_configuration_scopes WHERE scope_id=$1 FOR UPDATE`, scopeID)
	return err
}

// retryableDatabaseError: the transaction was aborted by a deadlock (40P01),
// a serialization failure (40001) or a NOWAIT lock (55P03); running it again
// can succeed.
func retryableDatabaseError(err error) bool {
	var postgresError *pgconn.PgError
	if !errors.As(err, &postgresError) {
		return false
	}
	switch postgresError.Code {
	case "40P01", "40001", "55P03":
		return true
	}
	return false
}

func lockSiteAuthority(ctx context.Context, tx pgx.Tx, req AllocateRequest) (siteAuthority, error) {
	if req.ActorScopeID != req.TargetScopeID {
		return lockPlatformSiteAuthority(ctx, tx, req)
	}
	var site siteAuthority
	err := tx.QueryRow(ctx, `SELECT scope.tenant_id,site.owner_user_id,
			site.package_subscription_id,site.package_id,site.revision,site.cname_task_id
		FROM sites AS site
		JOIN access_scopes AS scope ON scope.id=site.scope_id AND scope.kind='tenant'
		JOIN tenants AS tenant ON tenant.id=scope.tenant_id AND tenant.status='active'
		JOIN memberships AS actor_membership
		  ON actor_membership.scope_id=$1 AND actor_membership.user_id=$3
		 AND actor_membership.status='active'
		WHERE site.scope_id=$1 AND site.id=$2 AND site.deleted_at IS NULL
		  AND $4::uuid=$1
		  AND EXISTS (
		      SELECT 1 FROM role_assignments assignment
		      JOIN role_permissions permission ON permission.role_id=assignment.role_id
		      WHERE assignment.scope_id=$4 AND assignment.user_id=$3
		        AND permission.permission_name='dns.manage'
		  )
		  AND EXISTS (
		      SELECT 1 FROM role_assignments assignment
		      JOIN role_permissions permission ON permission.role_id=assignment.role_id
		      WHERE assignment.scope_id=$4 AND assignment.user_id=$3
		        AND permission.permission_name='sites.manage'
		  )
		FOR UPDATE OF site`, req.TargetScopeID, req.SiteID, req.ActorUserID, req.ActorScopeID).Scan(
		&site.tenantID, &site.ownerUserID, &site.packageSubscriptionID, &site.packageID, &site.revision, &site.cnameTaskID)
	if errors.Is(err, pgx.ErrNoRows) {
		return siteAuthority{}, failWith(FailureSiteAuthority, ErrNotFound)
	}
	if err != nil {
		return siteAuthority{}, err
	}
	return site, checkSiteCurrency(site, req)
}

// checkSiteCurrency: an intent execution needs its intent to still be the
// site's CNAME task (a CNAME input change issues a new one); a direct
// allocation keeps the exact site revision check.
func checkSiteCurrency(site siteAuthority, req AllocateRequest) error {
	if req.intentJobID != uuid.Nil {
		if site.cnameTaskID == nil || *site.cnameTaskID != req.intentJobID {
			return errIntentSuperseded
		}
		return nil
	}
	if site.revision != req.ExpectedSiteRevision {
		return ErrConflict
	}
	return nil
}

// UsePlatformDNS lets Allocate copy the platform DNS configuration into a
// tenant scope that has none yet.
func (store *Store) UsePlatformDNS(platformDNS PlatformDNS) { store.platformDNS = platformDNS }

// ensurePlatformDNS returns nil when the scope holds (or now holds) the
// platform DNS copy or the platform has no DNS configuration; otherwise the
// error Allocate reports if the scope has no DNS provider.
func (store *Store) ensurePlatformDNS(ctx context.Context, scopeID uuid.UUID) error {
	if store.platformDNS == nil {
		return nil
	}
	_, err := store.platformDNS.EnsurePlatformTenantCopy(ctx, scopeID)
	switch {
	case err == nil:
		return nil
	case errors.Is(err, dnsacme.ErrPlatformTenantSyncFailed):
		return failWith(FailurePlatformDNSSyncFailed, ErrNotFound)
	default:
		// In-flight DNS mutation claim, serialization failure, database
		// error: the intent stays leased and is retried.
		return fmt.Errorf("%w: platform DNS tenant copy: %v", ErrUnavailable, err)
	}
}

// usableZone is a zone allocation may write into: not failed, on an enabled
// DNS provider. Any provider of the scope qualifies (fix-cnamerand).
const usableZone = `SELECT zone.provider_id,zone.id,zone.name,zone.revision
	FROM dns_zones AS zone
	JOIN dns_providers AS provider ON provider.scope_id=zone.scope_id AND provider.id=zone.provider_id
	WHERE zone.scope_id=$1 AND zone.status<>'failed' AND provider.status<>'disabled'`

// resolveZoneAuthority picks the zone of a new claim. A domain names its
// zone. Without one (a site without a package, a stream without a domain) the
// owner keeps the zone it already has (keep: regenerate and re-intents do not
// move a CNAME), else one of the zones marked for random allocation is drawn
// uniformly, else the default zone is used.
func resolveZoneAuthority(ctx context.Context, tx pgx.Tx, scopeID uuid.UUID, domain string, keep []uuid.UUID,
	pick func(int) int) (zoneAuthority, error) {
	if domain != "" {
		zone, found, err := lockZone(ctx, tx, usableZone+` AND lower(zone.name)=lower($2)`, scopeID, domain)
		if err != nil || found {
			return zone, err
		}
		return zoneAuthority{}, zoneFailure(ctx, tx, scopeID, domain)
	}
	for _, zoneID := range keep {
		zone, found, err := lockZone(ctx, tx, usableZone+` AND zone.id=$2`, scopeID, zoneID)
		if err != nil || found {
			return zone, err
		}
	}
	rows, err := tx.Query(ctx, usableZone+` AND zone.random_allocation ORDER BY lower(zone.name),zone.id`, scopeID)
	if err != nil {
		return zoneAuthority{}, err
	}
	candidates, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (zoneAuthority, error) {
		var zone zoneAuthority
		return zone, row.Scan(&zone.providerID, &zone.zoneID, &zone.domain, &zone.revision)
	})
	if err != nil {
		return zoneAuthority{}, err
	}
	if len(candidates) > 0 {
		// Only the drawn zone is locked: share-locking every candidate in name
		// order could deadlock with the platform sync updating zones.
		zone, found, err := lockZone(ctx, tx, usableZone+` AND zone.id=$2`, scopeID, chooseZone(candidates, pick).zoneID)
		if err != nil || found {
			return zone, err
		}
	}
	zone, found, err := lockZone(ctx, tx, usableZone+` AND zone.is_default`, scopeID)
	if err != nil || found {
		return zone, err
	}
	return zoneAuthority{}, zoneFailure(ctx, tx, scopeID, "")
}

func lockZone(ctx context.Context, tx pgx.Tx, query string, args ...any) (zoneAuthority, bool, error) {
	var zone zoneAuthority
	err := tx.QueryRow(ctx, query+` FOR SHARE OF zone,provider`, args...).Scan(
		&zone.providerID, &zone.zoneID, &zone.domain, &zone.revision)
	if errors.Is(err, pgx.ErrNoRows) {
		return zoneAuthority{}, false, nil
	}
	return zone, err == nil, err
}

// chooseZone draws one candidate uniformly; pick(n) returns an index in
// [0,n). An out-of-range pick falls back to the first candidate.
func chooseZone(candidates []zoneAuthority, pick func(int) int) zoneAuthority {
	if len(candidates) == 1 || pick == nil {
		return candidates[0]
	}
	index := pick(len(candidates))
	if index < 0 || index >= len(candidates) {
		index = 0
	}
	return candidates[index]
}

// UseZonePick replaces the random draw of CNAME zones (tests).
func (store *Store) UseZonePick(pick func(int) int) { store.pick = pick }

func (store *Store) zonePick() func(int) int {
	if store.pick != nil {
		return store.pick
	}
	return rand.IntN
}

// keptZones are the zones a CNAME without a domain stays in, best first:
// the zone of the owner's own allocation (regenerate, re-intents), then, for
// a site that still has its package, the zone of the allocation it is bound
// to (escalation splits a package site into its own CNAME under the same
// domain). A site leaving its package has neither and draws like a new site.
// Read before the allocation row is locked, keeping the lock order.
func keptZones(ctx context.Context, tx pgx.Tx, scopeID uuid.UUID, mode Mode, ownerID, siteID uuid.UUID,
	packaged bool) ([]uuid.UUID, error) {
	condition := "allocation.site_owner_id=$3"
	if mode == ModePackage {
		condition = "allocation.package_subscription_id=$3"
	}
	rows, err := tx.Query(ctx, `SELECT zone_id FROM (
		SELECT 1 AS rank,claim.zone_id FROM cname_allocations allocation
		JOIN cname_hostname_claims claim ON claim.id=allocation.current_claim_id AND claim.allocation_id=allocation.id
		WHERE allocation.tenant_scope_id=$1 AND allocation.mode=$2 AND `+condition+`
		UNION ALL
		SELECT 2,claim.zone_id FROM cname_site_bindings binding
		JOIN cname_allocations allocation ON allocation.tenant_scope_id=binding.tenant_scope_id
		 AND allocation.id=binding.current_allocation_id
		JOIN cname_hostname_claims claim ON claim.id=allocation.current_claim_id AND claim.allocation_id=allocation.id
		WHERE $5 AND binding.tenant_scope_id=$1 AND binding.site_id=$4) AS kept ORDER BY rank`,
		scopeID, string(mode), ownerID, siteID, packaged)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
}

// zoneFailure explains why no allocation zone resolved: no usable DNS
// provider, no zone named after the CNAME domain (or no default zone), or a
// zone whose own DNS provider is disabled.
func zoneFailure(ctx context.Context, tx pgx.Tx, scopeID uuid.UUID, domain string) error {
	var providerReady, zoneExists bool
	err := tx.QueryRow(ctx, `SELECT
		EXISTS(SELECT 1 FROM dns_providers WHERE scope_id=$1 AND status<>'disabled'),
		EXISTS(SELECT 1 FROM dns_zones WHERE scope_id=$1 AND status<>'failed'
		       AND (($2='' AND (is_default OR random_allocation)) OR ($2<>'' AND lower(name)=lower($2))))`,
		scopeID, domain).Scan(&providerReady, &zoneExists)
	switch {
	case err != nil:
		return err
	case !providerReady:
		return failWith(FailureDNSProviderNotConfigured, ErrNotFound)
	case !zoneExists:
		return failWith(FailureCNAMEZoneNotConfigured, ErrNotFound)
	}
	return failWith(FailureCNAMEZoneProviderDiffers, ErrNotFound)
}

func resolveModeOwner(
	ctx context.Context,
	tx pgx.Tx,
	req AllocateRequest,
	site siteAuthority,
) (uuid.UUID, *uuid.UUID, error) {
	if req.Mode == ModeSite {
		return req.SiteID, nil, nil
	}
	if site.packageSubscriptionID == nil || site.packageID == nil {
		return uuid.Nil, nil, failWith(FailurePackageInactive, ErrNotFound)
	}
	var subscriptionID uuid.UUID
	err := tx.QueryRow(ctx, `SELECT subscription.id
		FROM package_subscriptions AS subscription
		JOIN package_monitor_subscription_owners AS owner
		  ON owner.subscription_id=subscription.id
		 AND owner.tenant_scope_id=subscription.tenant_scope_id
		 AND owner.owner_user_id=$3
		LEFT JOIN package_order_fulfillments AS fulfillment
		  ON fulfillment.id=owner.source_fulfillment_id
		 AND fulfillment.subscription_id=subscription.id
		 AND fulfillment.tenant_scope_id=subscription.tenant_scope_id
		LEFT JOIN package_orders AS package_order
		  ON package_order.id=fulfillment.order_id
		 AND package_order.tenant_scope_id=subscription.tenant_scope_id
		 AND package_order.user_id=$3
		 AND package_order.product_kind='package_subscription'
		WHERE subscription.tenant_scope_id=$1 AND subscription.id=$2
		  AND subscription.product_id=$4 AND subscription.lifecycle_status='active'
		  AND subscription.admin_enabled=true AND subscription.deleted_at IS NULL
		  AND (owner.source_kind='subscription_state' OR EXISTS (SELECT 1 FROM package_order_events AS event
		              WHERE event.order_id=package_order.id AND event.event_type='fulfilled'))
		FOR SHARE OF subscription,owner NOWAIT`,
		req.TargetScopeID, *site.packageSubscriptionID, site.ownerUserID, *site.packageID).Scan(&subscriptionID)
	if errors.Is(err, pgx.ErrNoRows) {
		return uuid.Nil, nil, failWith(FailurePackageInactive, ErrNotFound)
	}
	if err != nil {
		return uuid.Nil, nil, err
	}
	return subscriptionID, &subscriptionID, nil
}

func lockBinding(ctx context.Context, tx pgx.Tx, scopeID, siteID uuid.UUID) (bindingAuthority, bool, error) {
	var binding bindingAuthority
	err := tx.QueryRow(ctx, `SELECT current_allocation_id,lkg_allocation_id,binding_revision
		FROM cname_site_bindings WHERE tenant_scope_id=$1 AND site_id=$2 FOR UPDATE`,
		scopeID, siteID).Scan(&binding.currentID, &binding.lkgID, &binding.revision)
	if errors.Is(err, pgx.ErrNoRows) {
		return bindingAuthority{}, false, nil
	}
	return binding, err == nil, err
}

func lockOwnerAllocation(
	ctx context.Context,
	tx pgx.Tx,
	scopeID uuid.UUID,
	mode Mode,
	ownerID uuid.UUID,
) (allocationAuthority, bool, error) {
	condition := "allocation.site_owner_id=$2"
	if mode == ModePackage {
		condition = "allocation.package_subscription_id=$2"
	}
	query := `SELECT allocation.id,allocation.tenant_id,allocation.tenant_scope_id,
		allocation.owner_user_id,allocation.mode,allocation.site_owner_id,
		allocation.package_subscription_id,allocation.current_claim_id,allocation.lkg_claim_id,
		allocation.current_revision,allocation.lkg_revision,allocation.generation,
		allocation.state,allocation.job_id,allocation.failure_code,
		claim.id,claim.provider_id,claim.zone_id,claim.domain,claim.hostname,
		claim.explicit_hostname,claim.hmac_key_id,allocation.stream_owner_id
		FROM cname_allocations AS allocation
		JOIN cname_hostname_claims AS claim
		  ON claim.id=allocation.current_claim_id AND claim.allocation_id=allocation.id
		WHERE allocation.tenant_scope_id=$1 AND allocation.mode=$3 AND ` + condition + ` FOR UPDATE OF allocation`
	var allocation allocationAuthority
	err := scanAllocationAuthority(tx.QueryRow(ctx, query, scopeID, ownerID, string(mode)), &allocation)
	if errors.Is(err, pgx.ErrNoRows) {
		return allocationAuthority{}, false, nil
	}
	return allocation, err == nil, err
}

func scanAllocationAuthority(row pgx.Row, allocation *allocationAuthority) error {
	return row.Scan(&allocation.id, &allocation.tenantID, &allocation.scopeID,
		&allocation.ownerUserID, &allocation.mode, &allocation.siteOwnerID,
		&allocation.packageSubscriptionID, &allocation.claimID, &allocation.lkgClaimID,
		&allocation.revision, &allocation.lkgRevision, &allocation.generation,
		&allocation.state, &allocation.jobID, &allocation.failureCode,
		&allocation.claim.id, &allocation.claim.provider, &allocation.claim.zone,
		&allocation.claim.domain, &allocation.claim.hostname, &allocation.claim.explicit,
		&allocation.claim.keyID, &allocation.streamOwnerID)
}

func insertJob(
	ctx context.Context,
	tx pgx.Tx,
	tenantID, jobID, allocationID uuid.UUID,
	req AllocateRequest,
	digest [32]byte,
	now time.Time,
) error {
	key := "cname." + hex.EncodeToString(digest[:])
	_, err := tx.Exec(ctx, `INSERT INTO background_jobs(
		id,tenant_id,kind,subject,idempotency_key,request_digest,request_id,trace_id,
		state,attempt,max_attempts,claimable_at,total_count,created_at,updated_at
	) VALUES($1,$2,$3,$4,$5,$6,$7,$8,'queued',0,$9,$10,1,$10,$10)`,
		jobID, tenantID, databaseJobKind, "cname_allocation/"+allocationID.String(), key,
		digest[:], req.RequestID, req.TraceID, maximumJobAttempts, now)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `INSERT INTO background_job_items(
		tenant_id,job_id,ordinal,item_id,state
	) VALUES($1,$2,1,$3,'pending')`, tenantID, jobID, JobItemID)
	return err
}

func insertAllocation(
	ctx context.Context,
	tx pgx.Tx,
	allocationID, claimID, jobID uuid.UUID,
	site siteAuthority,
	req AllocateRequest,
	ownerID uuid.UUID,
	packageID *uuid.UUID,
	now time.Time,
) error {
	var siteOwnerID *uuid.UUID
	if req.Mode == ModeSite {
		siteOwnerID = &ownerID
	}
	_, err := tx.Exec(ctx, `INSERT INTO cname_allocations(
		id,tenant_id,tenant_scope_id,owner_user_id,mode,site_owner_id,package_subscription_id,
		current_claim_id,current_revision,generation,state,job_id,created_at,updated_at
	) VALUES($1,$2,$3,$4,$5,$6,$7,$8,1,1,$9,$10,$11,$11)`,
		allocationID, site.tenantID, req.TargetScopeID, site.ownerUserID, string(req.Mode),
		siteOwnerID, packageID, claimID, string(StatePending), jobID, now)
	return err
}

func insertClaim(
	ctx context.Context,
	tx pgx.Tx,
	claimID, allocationID, scopeID uuid.UUID,
	generation int64,
	zone zoneAuthority,
	hostname string,
	explicit bool,
	keyID *string,
	now time.Time,
) error {
	_, err := tx.Exec(ctx, `INSERT INTO cname_hostname_claims(
		id,tenant_scope_id,allocation_id,generation,provider_id,zone_id,domain,hostname,
		explicit_hostname,hmac_key_id,created_at
	) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`, claimID, scopeID, allocationID,
		generation, zone.providerID, zone.zoneID, zone.domain, hostname, explicit, keyID, now)
	return err
}

func advanceAllocation(
	ctx context.Context,
	tx pgx.Tx,
	old allocationAuthority,
	claimID, jobID uuid.UUID,
	lkgClaimID *uuid.UUID,
	lkgRevision *int64,
	generation, revision int64,
	now time.Time,
) error {
	command, err := tx.Exec(ctx, `UPDATE cname_allocations
		SET current_claim_id=$3,lkg_claim_id=$4,current_revision=$5,lkg_revision=$6,
		    generation=$7,state=$8,job_id=$9,failure_code=NULL,updated_at=$10
		WHERE tenant_scope_id=$1 AND id=$2 AND current_revision=$11`, old.scopeID, old.id,
		claimID, lkgClaimID, revision, lkgRevision, generation, string(StatePending), jobID,
		now, old.revision)
	if err != nil {
		return err
	}
	if command.RowsAffected() != 1 {
		return ErrConflict
	}
	return nil
}

func upsertBinding(
	ctx context.Context,
	tx pgx.Tx,
	scopeID, siteID, allocationID uuid.UUID,
	lkgID *uuid.UUID,
	old bindingAuthority,
	found bool,
	now time.Time,
) error {
	if !found {
		_, err := tx.Exec(ctx, `INSERT INTO cname_site_bindings(
			tenant_scope_id,site_id,current_allocation_id,lkg_allocation_id,
			binding_revision,created_at,updated_at
		) VALUES($1,$2,$3,$4,1,$5,$5)`, scopeID, siteID, allocationID, lkgID, now)
		return err
	}
	command, err := tx.Exec(ctx, `UPDATE cname_site_bindings
		SET current_allocation_id=$3,lkg_allocation_id=$4,
		    binding_revision=binding_revision+1,updated_at=$5
		WHERE tenant_scope_id=$1 AND site_id=$2 AND binding_revision=$6`,
		scopeID, siteID, allocationID, lkgID, now, old.revision)
	if err != nil {
		return err
	}
	if command.RowsAffected() != 1 {
		return ErrConflict
	}
	return nil
}

func advancePackageBindings(
	ctx context.Context,
	tx pgx.Tx,
	scopeID, excludedSiteID uuid.UUID,
	old allocationAuthority,
	now time.Time,
) error {
	var lkgID *uuid.UUID
	if old.state == StateDone || old.lkgClaimID != nil {
		lkgID = &old.id
	}
	_, err := tx.Exec(ctx, `UPDATE cname_site_bindings
		SET lkg_allocation_id=COALESCE($3,lkg_allocation_id),
		    binding_revision=binding_revision+1,updated_at=$4
		WHERE tenant_scope_id=$1 AND current_allocation_id=$2 AND site_id<>$5`,
		scopeID, old.id, lkgID, now, excludedSiteID)
	return err
}

func projectBoundSites(
	ctx context.Context,
	tx pgx.Tx,
	scopeID, allocationID uuid.UUID,
	requestDomain, requestHostname string,
	now time.Time,
	intentSiteIDs ...uuid.UUID,
) error {
	var intentSiteID *uuid.UUID
	if len(intentSiteIDs) > 0 {
		intentSiteID = &intentSiteIDs[0]
	}
	rows, err := tx.Query(ctx, `UPDATE sites AS site
		SET cname=COALESCE(lkg_claim.hostname,''),
		    cname_mode=allocation.mode,
		    cname_domain=CASE WHEN current_zone.is_default THEN '' ELSE current_claim.domain END,
		    cname_hostname2=CASE WHEN current_claim.explicit_hostname THEN current_claim.hostname ELSE '' END,
		    cname_state=allocation.state,cname_task_id=allocation.job_id,
		    cname_current_revision=allocation.current_revision,
		    cname_lkg_revision=lkg_allocation.lkg_revision,
		    revision=site.revision+1,updated_at=$3
		FROM cname_site_bindings AS binding
		JOIN cname_allocations AS allocation
		  ON allocation.tenant_scope_id=binding.tenant_scope_id
		 AND allocation.id=binding.current_allocation_id
		JOIN cname_hostname_claims AS current_claim
		  ON current_claim.id=allocation.current_claim_id AND current_claim.allocation_id=allocation.id
		JOIN dns_zones AS current_zone
		  ON current_zone.scope_id=current_claim.tenant_scope_id AND current_zone.id=current_claim.zone_id
		LEFT JOIN cname_allocations AS lkg_allocation
		  ON lkg_allocation.tenant_scope_id=binding.tenant_scope_id
		 AND lkg_allocation.id=binding.lkg_allocation_id
		LEFT JOIN cname_hostname_claims AS lkg_claim
		  ON lkg_claim.id=lkg_allocation.lkg_claim_id AND lkg_claim.allocation_id=lkg_allocation.id
		WHERE site.scope_id=$1 AND site.id=binding.site_id
		  AND binding.tenant_scope_id=$1 AND binding.current_allocation_id=$2
		  AND (site.id=$4 OR NOT EXISTS(SELECT 1 FROM cname_allocation_intents intent JOIN background_jobs job
		    ON job.tenant_id=intent.tenant_id AND job.id=intent.job_id
		    WHERE intent.tenant_scope_id=site.scope_id AND intent.site_id=site.id AND intent.job_id=site.cname_task_id
		      AND job.state IN ('queued','running')))
		RETURNING site.id`,
		scopeID, allocationID, now, intentSiteID)
	if err != nil {
		return err
	}
	sites, err := pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
	if err != nil {
		return err
	}
	_ = requestDomain
	_ = requestHostname
	return publishProjectedSitesTx(ctx, tx, scopeID, sites, allocationID)
}

// publishProjectedSitesTx: the projection's site writes advance the scope's
// source revision (335 trigger) outside any site request; an automatic scope
// publishes them unless this transaction's request already covers the
// revision (fix-autopub: the settle after a published save left the nodes on
// the old configuration).
func publishProjectedSitesTx(ctx context.Context, tx pgx.Tx, scopeID uuid.UUID, sites []uuid.UUID, causeID uuid.UUID) error {
	for _, siteID := range sites {
		if _, err := edgeautopublish.EnqueueUnrequestedSiteRevisionTx(ctx, tx, scopeID, siteID,
			"cname-projection/"+causeID.String()); err != nil {
			return err
		}
	}
	return nil
}

type requestFact struct {
	id, tenantID, scopeID, allocationID, siteID  uuid.UUID
	streamID                                     *uuid.UUID // a stream's own allocation (migration 505)
	actorScopeID, actorUserID, jobID, auditID    uuid.UUID
	operation, idempotencyKey, requestID         string
	digest                                       [32]byte
	keyID                                        *string
	generation, expectedRevision, resultRevision int64
	lkgRevision                                  *int64
	state                                        State
	failureCode                                  *string
	createdAt                                    time.Time
}

// nullableUUID is a fact row's site_id: NULL for a stream's own allocation,
// which is anchored at the stream instead (migration 507).
func nullableUUID(value uuid.UUID) *uuid.UUID {
	if value == uuid.Nil {
		return nil
	}
	return &value
}

func insertRequest(ctx context.Context, tx pgx.Tx, fact requestFact) error {
	_, err := tx.Exec(ctx, `INSERT INTO cname_allocation_requests(
		id,tenant_id,tenant_scope_id,allocation_id,site_id,actor_scope_id,actor_user_id,
		operation,idempotency_key,request_digest,request_id,job_id,hmac_key_id,generation,
		expected_revision,result_revision,result_lkg_revision,result_state,failure_code,
		audit_event_id,created_at,stream_id
	) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22)`,
		fact.id, fact.tenantID, fact.scopeID, fact.allocationID, nullableUUID(fact.siteID),
		fact.actorScopeID, fact.actorUserID, fact.operation, fact.idempotencyKey,
		fact.digest[:], fact.requestID, fact.jobID, fact.keyID, fact.generation,
		fact.expectedRevision, fact.resultRevision, fact.lkgRevision, string(fact.state),
		fact.failureCode, fact.auditID, fact.createdAt, fact.streamID)
	return err
}

func (store *Store) appendAudit(
	ctx context.Context,
	tx pgx.Tx,
	req AllocateRequest,
	operation string,
	allocationID uuid.UUID,
	state State,
	failureCode string,
	now time.Time,
) (uuid.UUID, error) {
	payload := map[string]any{
		"tenant_scope_id": req.TargetScopeID.String(),
		"state":           state, "failure_code": failureCode,
	}
	if req.SiteID != uuid.Nil {
		payload["site_id"] = req.SiteID.String()
	}
	if req.streamID != uuid.Nil {
		payload["stream_id"] = req.streamID.String()
	}
	if err := store.auditor.Append(ctx, tx, audit.Event{
		ScopeID: req.ActorScopeID, ActorUserID: &req.ActorUserID,
		Action: "dns.cname." + operation, ResourceType: "cname_allocation",
		ResourceID: allocationID.String(), RequestID: req.RequestID,
		Result: auditResult(state), Payload: payload,
	}); err != nil {
		return uuid.Nil, err
	}
	var auditID uuid.UUID
	err := tx.QueryRow(ctx, `SELECT id FROM audit_events
		WHERE scope_id=$1 AND actor_user_id=$2 AND action=$3
		  AND resource_type='cname_allocation' AND resource_id=$4 AND request_id=$5
		ORDER BY stream_position DESC LIMIT 1`, req.ActorScopeID, req.ActorUserID,
		"dns.cname."+operation, allocationID.String(), req.RequestID).Scan(&auditID)
	_ = now
	return auditID, err
}

func loadAllocation(ctx context.Context, tx pgx.Tx, scopeID, siteID uuid.UUID) (Allocation, error) {
	var result Allocation
	var siteOwnerID, packageID *uuid.UUID
	var keyID, failureCode *string
	var lkgRevision *int64
	err := tx.QueryRow(ctx, `SELECT allocation.id,allocation.tenant_id,allocation.tenant_scope_id,
		binding.site_id,
		CASE WHEN allocation.mode='site' THEN allocation.site_owner_id
		     ELSE allocation.package_subscription_id END AS owner_id,
		claim.provider_id,claim.zone_id,allocation.package_subscription_id,allocation.job_id,
		allocation.mode,allocation.state,claim.domain,claim.hostname,claim.hmac_key_id,
		allocation.failure_code,allocation.current_revision,allocation.lkg_revision,site.revision,
		allocation.site_owner_id
		FROM cname_site_bindings AS binding
		JOIN cname_allocations AS allocation
		  ON allocation.tenant_scope_id=binding.tenant_scope_id
		 AND allocation.id=binding.current_allocation_id
		JOIN cname_hostname_claims AS claim
		  ON claim.id=allocation.current_claim_id AND claim.allocation_id=allocation.id
		JOIN sites AS site ON site.scope_id=binding.tenant_scope_id AND site.id=binding.site_id
		WHERE binding.tenant_scope_id=$1 AND binding.site_id=$2`, scopeID, siteID).Scan(
		&result.ID, &result.TenantID, &result.ScopeID, &result.SiteID, &result.OwnerID,
		&result.ProviderID, &result.ZoneID, &packageID, &result.JobID, &result.Mode, &result.State,
		&result.Domain, &result.Hostname, &keyID, &failureCode, &result.Revision, &lkgRevision,
		&result.SiteRevision, &siteOwnerID)
	if errors.Is(err, pgx.ErrNoRows) {
		return Allocation{}, ErrNotFound
	}
	if err != nil {
		return Allocation{}, err
	}
	if packageID != nil {
		result.PackageSubscriptionID = *packageID
	}
	if keyID != nil {
		result.KeyID = *keyID
	}
	if failureCode != nil {
		result.FailureCode = *failureCode
	}
	if lkgRevision != nil {
		result.LKGRevision = *lkgRevision
	}
	return result, nil
}

func loadReplay(ctx context.Context, tx pgx.Tx, req AllocateRequest, digest [32]byte) (Allocation, bool, error) {
	var existingDigest []byte
	err := tx.QueryRow(ctx, `SELECT request_digest FROM cname_allocation_requests
		WHERE actor_scope_id=$1 AND actor_user_id=$2 AND idempotency_key=$3 FOR SHARE`,
		req.ActorScopeID, req.ActorUserID, req.IdempotencyKey).Scan(&existingDigest)
	if errors.Is(err, pgx.ErrNoRows) {
		return Allocation{}, false, nil
	}
	if err != nil {
		return Allocation{}, false, err
	}
	if !bytes.Equal(existingDigest, digest[:]) {
		return Allocation{}, false, ErrConflict
	}
	result, err := loadAllocation(ctx, tx, req.TargetScopeID, req.SiteID)
	return result, err == nil, err
}

func (store *Store) readReplay(
	ctx context.Context,
	req AllocateRequest,
	digest [32]byte,
) (Allocation, bool, error) {
	var result Allocation
	var found bool
	err := pgx.BeginTxFunc(ctx, store.pool, pgx.TxOptions{
		IsoLevel: pgx.RepeatableRead,
	}, func(tx pgx.Tx) error {
		var err error
		result, found, err = loadReplay(ctx, tx, req, digest)
		return err
	})
	return result, found, err
}

func loadResultReplay(ctx context.Context, tx pgx.Tx, req ResultRequest, digest [32]byte) (Allocation, bool, error) {
	var existingDigest []byte
	err := tx.QueryRow(ctx, `SELECT request_digest FROM cname_allocation_requests
		WHERE tenant_scope_id=$1 AND allocation_id=$2 AND site_id=$3 AND job_id=$4
		  AND operation='settle' AND result_revision=$5`, req.TargetScopeID, req.AllocationID,
		req.SiteID, req.JobID, req.ExpectedRevision+1).Scan(&existingDigest)
	if errors.Is(err, pgx.ErrNoRows) {
		return Allocation{}, false, nil
	}
	if err != nil {
		return Allocation{}, false, err
	}
	if !bytes.Equal(existingDigest, digest[:]) {
		return Allocation{}, false, ErrConflict
	}
	var streamOwnerID *uuid.UUID
	if err := tx.QueryRow(ctx, `SELECT stream_owner_id FROM cname_allocations WHERE tenant_scope_id=$1 AND id=$2`,
		req.TargetScopeID, req.AllocationID).Scan(&streamOwnerID); err != nil {
		return Allocation{}, false, err
	}
	if streamOwnerID != nil {
		result, err := loadStreamAllocation(ctx, tx, req.TargetScopeID, *streamOwnerID)
		return result, err == nil, err
	}
	result, err := loadAllocation(ctx, tx, req.TargetScopeID, req.SiteID)
	return result, err == nil, err
}

func lockSettlement(
	ctx context.Context,
	tx pgx.Tx,
	req ResultRequest,
) (allocationAuthority, uuid.UUID, uuid.UUID, string, error) {
	var allocation allocationAuthority
	var actorScopeID, actorUserID uuid.UUID
	var requestID string
	err := scanAllocationAuthority(tx.QueryRow(ctx, `SELECT allocation.id,allocation.tenant_id,
		allocation.tenant_scope_id,allocation.owner_user_id,allocation.mode,
		allocation.site_owner_id,allocation.package_subscription_id,allocation.current_claim_id,
		allocation.lkg_claim_id,allocation.current_revision,allocation.lkg_revision,
		allocation.generation,allocation.state,allocation.job_id,allocation.failure_code,
		claim.id,claim.provider_id,claim.zone_id,claim.domain,claim.hostname,
		claim.explicit_hostname,claim.hmac_key_id,allocation.stream_owner_id
		FROM cname_allocations AS allocation
		JOIN cname_hostname_claims AS claim
		  ON claim.id=allocation.current_claim_id AND claim.allocation_id=allocation.id
		WHERE allocation.tenant_scope_id=$1 AND allocation.id=$3 AND allocation.job_id=$4 AND (
		  EXISTS (SELECT 1 FROM cname_site_bindings binding WHERE binding.tenant_scope_id=$1 AND binding.site_id=$2
		    AND binding.current_allocation_id=allocation.id) OR
		  -- A stream's own allocation (migration 505), anchored at the stream ($2, migration 507).
		  EXISTS (SELECT 1 FROM cname_stream_bindings binding
		    WHERE binding.tenant_scope_id=$1 AND binding.stream_id=$2 AND binding.allocation_id=allocation.id))
		FOR UPDATE OF allocation`,
		req.TargetScopeID, req.SiteID, req.AllocationID, req.JobID), &allocation)
	if errors.Is(err, pgx.ErrNoRows) {
		return allocationAuthority{}, uuid.Nil, uuid.Nil, "", ErrNotFound
	}
	if err != nil {
		return allocationAuthority{}, uuid.Nil, uuid.Nil, "", err
	}
	if allocation.revision != req.ExpectedRevision || allocation.state != StatePending {
		return allocationAuthority{}, uuid.Nil, uuid.Nil, "", ErrConflict
	}
	err = tx.QueryRow(ctx, `SELECT actor_scope_id,actor_user_id,request_id
		FROM cname_allocation_requests
		WHERE tenant_scope_id=$1 AND allocation_id=$2 AND job_id=$3
		  AND operation IN ('allocate','regenerate','rebind')
		ORDER BY generation DESC,created_at DESC LIMIT 1 FOR SHARE`,
		req.TargetScopeID, req.AllocationID, req.JobID).Scan(&actorScopeID, &actorUserID, &requestID)
	return allocation, actorScopeID, actorUserID, requestID, err
}

func settleBackgroundJob(
	ctx context.Context,
	tx pgx.Tx,
	tenantID uuid.UUID,
	req ResultRequest,
	state State,
	now time.Time,
) error {
	var jobState string
	var attempt, maximum int
	// A concurrent worker that settled first clears the lease (NULL owner,
	// id and expiry): that is a lost claim, not a scan failure.
	var leaseID *uuid.UUID
	var owner *string
	var expires *time.Time
	err := tx.QueryRow(ctx, `SELECT state,attempt,max_attempts,lease_id,lease_owner,lease_expires_at
		FROM background_jobs WHERE tenant_id=$1 AND id=$2 FOR UPDATE`, tenantID, req.JobID).Scan(
		&jobState, &attempt, &maximum, &leaseID, &owner, &expires)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	if jobState != "running" || attempt != int(req.Attempt) || leaseID == nil || *leaseID != req.LeaseID ||
		owner == nil || *owner != req.WorkerID || expires == nil || !expires.After(now) {
		return ErrClaimLost
	}
	itemState := "succeeded"
	var itemCode any
	jobTerminal := "succeeded"
	var jobCode any
	if state == StateFailed {
		itemState = "failed"
		itemCode = req.FailureCode
		jobTerminal = "failed"
		jobCode = "all_items_failed"
	}
	if _, err := tx.Exec(ctx, `INSERT INTO background_job_results(
		id,tenant_id,job_id,item_id,attempt,sequence,state,error_code,source,reported_at
	) VALUES($1,$2,$3,$4,$5,$6,$7,$8,'worker',$9)`, uuid.New(), tenantID, req.JobID,
		JobItemID, req.Attempt, int64(req.Sequence), itemState, itemCode, now); err != nil {
		return err
	}
	failed, succeeded := 0, 1
	if state == StateFailed {
		failed, succeeded = 1, 0
	}
	if _, err := tx.Exec(ctx, `UPDATE background_jobs
		SET state=$3,completed_count=1,succeeded_count=$4,failed_count=$5,cancelled_count=0,
		    lease_id=NULL,lease_owner=NULL,lease_expires_at=NULL,claimable_at=NULL,
		    last_error_code=$6,completed_at=$7,updated_at=$7
		WHERE tenant_id=$1 AND id=$2`, tenantID, req.JobID, jobTerminal, succeeded, failed, jobCode, now); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `UPDATE background_job_items
		SET state=$4,attempt=$5,sequence=$6,error_code=$7,completed_at=$8
		WHERE tenant_id=$1 AND job_id=$2 AND item_id=$3`, tenantID, req.JobID, JobItemID,
		itemState, req.Attempt, int64(req.Sequence), itemCode, now); err != nil {
		return err
	}
	command, err := tx.Exec(ctx, `UPDATE background_job_attempts
		SET state=$6,completed_at=$7,error_code=$8
		WHERE tenant_id=$1 AND job_id=$2 AND attempt=$3 AND lease_id=$4
		  AND worker_id=$5 AND state='running'`, tenantID, req.JobID, req.Attempt,
		req.LeaseID, req.WorkerID, jobTerminal, now, jobCode)
	if err != nil {
		return err
	}
	if command.RowsAffected() != 1 {
		return ErrClaimLost
	}
	_ = maximum
	return nil
}

func allocationHostname(
	ctx context.Context,
	tx pgx.Tx,
	key Key,
	req AllocateRequest,
	tenantID uuid.UUID,
	zone zoneAuthority,
	ownerID uuid.UUID,
	generation uint64,
) (string, *string, error) {
	if req.Hostname != "" {
		if !hostnameWithinDomain(req.Hostname, zone.domain) {
			return "", nil, ErrInvalidInput
		}
		return req.Hostname, nil, nil
	}
	hostname, err := freeGeneratedHostname(key, tenantID, zone.providerID, ownerID, req.Mode, zone.domain, generation,
		func(hostname string) (bool, error) {
			var taken bool
			err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM cname_hostname_claims WHERE lower(hostname)=$1)`,
				hostname).Scan(&taken)
			return taken, err
		})
	if err != nil {
		return "", nil, err
	}
	return hostname, &key.ID, nil
}

// freeGeneratedHostname derives label.domain for the allocation generation; when
// that name is already claimed (any zone/tenant: claims are globally unique) it
// re-derives with the label generation advanced by one, at most MaxLabelAttempts
// times, then fails with FailureLabelExhausted. The allocation generation itself
// is not changed: only the HMAC input of the label is.
func freeGeneratedHostname(
	key Key,
	tenantID, providerID, ownerID uuid.UUID,
	mode Mode,
	domain string,
	generation uint64,
	taken func(string) (bool, error),
) (string, error) {
	for attempt := uint64(0); attempt < MaxLabelAttempts; attempt++ {
		label, err := GenerateLabel(key, tenantID, providerID, ownerID, mode, domain, generation+attempt)
		if err != nil {
			return "", err
		}
		hostname := label + "." + normalizeName(domain)
		used, err := taken(hostname)
		if err != nil {
			return "", err
		}
		if !used {
			return hostname, nil
		}
	}
	// ErrInvalidInput (not ErrConflict) so the intent worker settles it as a
	// failure carrying the code instead of retrying forever.
	return "", failWith(FailureLabelExhausted, ErrInvalidInput)
}

func claimMatches(claim claimAuthority, zone zoneAuthority, hostname string) bool {
	if claim.provider != zone.providerID || claim.zone != zone.zoneID || claim.domain != zone.domain {
		return false
	}
	if hostname == "" {
		return !claim.explicit
	}
	return claim.explicit && claim.hostname == hostname
}

func nextLKG(allocation allocationAuthority) (*uuid.UUID, *int64) {
	if allocation.state == StateDone {
		claimID := allocation.claimID
		revision := allocation.revision
		return &claimID, &revision
	}
	return allocation.lkgClaimID, allocation.lkgRevision
}

func bindingLKG(
	binding bindingAuthority,
	bindingFound bool,
	target allocationAuthority,
	targetFound bool,
) *uuid.UUID {
	if bindingFound {
		if targetFound && binding.currentID == target.id && target.state == StateDone {
			id := target.id
			return &id
		}
		return binding.lkgID
	}
	return nil
}

func allocateDigest(req AllocateRequest) ([32]byte, error) {
	payload := struct {
		Version                   int
		TargetScopeID, SiteID     string
		ActorScopeID, ActorUserID string
		Mode, Domain, Hostname    string
		ExpectedSiteRevision      int64
		Regenerate                bool
	}{
		Version: 1, TargetScopeID: req.TargetScopeID.String(), SiteID: req.SiteID.String(),
		ActorScopeID: req.ActorScopeID.String(), ActorUserID: req.ActorUserID.String(),
		Mode: string(req.Mode), Domain: normalizeName(req.Domain), Hostname: normalizeName(req.Hostname),
		ExpectedSiteRevision: req.ExpectedSiteRevision, Regenerate: req.Regenerate,
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(encoded), nil
}

func resultDigest(req ResultRequest, state State) [32]byte {
	encoded, _ := json.Marshal(struct {
		Version                                                     int
		Scope, Site, Allocation, Job, Worker, Lease, State, Failure string
		Revision                                                    int64
		Attempt                                                     uint32
		Sequence                                                    uint64
	}{1, req.TargetScopeID.String(), req.SiteID.String(), req.AllocationID.String(),
		req.JobID.String(), req.WorkerID, req.LeaseID.String(), string(state), req.FailureCode,
		req.ExpectedRevision, req.Attempt, req.Sequence})
	return sha256.Sum256(encoded)
}

func backgroundJobDigest(request [32]byte, allocationID uuid.UUID, generation int64) [32]byte {
	encoded := append([]byte("cdnca:cname-allocation:job:v1\x00"), request[:]...)
	encoded = append(encoded, allocationID[:]...)
	encoded = append(encoded, []byte(fmt.Sprintf("/%d", generation))...)
	return sha256.Sum256(encoded)
}

func settlementIdempotencyKey(req ResultRequest) string {
	digest := resultDigest(req, settlementState(req))
	return "settle." + hex.EncodeToString(digest[:])
}

func settlementState(req ResultRequest) State {
	if req.FailureCode == "" {
		return StateDone
	}
	return StateFailed
}

func validAllocateRequest(req AllocateRequest) bool {
	return req.TargetScopeID != uuid.Nil && req.SiteID != uuid.Nil && req.ActorScopeID != uuid.Nil &&
		req.ActorUserID != uuid.Nil && (req.ActorScopeID == req.TargetScopeID || req.platformIntentID != uuid.Nil) && validMode(req.Mode) &&
		idempotencyPattern.MatchString(req.IdempotencyKey) && validSafeText(req.RequestID, 128, false) &&
		validSafeText(req.TraceID, 512, true) && req.ExpectedSiteRevision > 0 &&
		validDNSName(normalizeName(req.Domain), true) && validDNSName(normalizeName(req.Hostname), true)
}

func validResultRequest(req ResultRequest, state State) bool {
	valid := req.TargetScopeID != uuid.Nil && req.SiteID != uuid.Nil && req.AllocationID != uuid.Nil &&
		req.JobID != uuid.Nil && req.ExpectedRevision > 0 && validSafeText(req.WorkerID, 128, false) &&
		req.Attempt > 0 && req.LeaseID != uuid.Nil && req.Sequence > 0
	if state == StateDone {
		return valid && req.FailureCode == ""
	}
	return valid && errorCodePattern.MatchString(req.FailureCode)
}

func validMode(mode Mode) bool { return mode == ModeSite || mode == ModePackage }

func validKeyID(value string) bool { return keyIDPattern.MatchString(value) }

func validDNSName(value string, allowEmpty bool) bool {
	if value == "" {
		return allowEmpty
	}
	if len(value) > 253 || strings.ContainsAny(value, "\x00\r\n\t ") {
		return false
	}
	for _, label := range strings.Split(value, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, char := range label {
			if (char < 'a' || char > 'z') && (char < '0' || char > '9') && char != '-' {
				return false
			}
		}
	}
	return true
}

func hostnameWithinDomain(hostname, domain string) bool {
	return hostname != domain && strings.HasSuffix(hostname, "."+domain)
}

func validSafeText(value string, maximum int, allowEmpty bool) bool {
	if (!allowEmpty && value == "") || value != strings.TrimSpace(value) || len(value) > maximum {
		return false
	}
	for _, char := range value {
		if char < 0x20 || char == 0x7f || char == '\u2028' || char == '\u2029' {
			return false
		}
	}
	return true
}

func auditResult(state State) string {
	if state == StateFailed {
		return "failure"
	}
	return "success"
}

func (store *Store) timestamp() time.Time {
	return store.now().UTC().Truncate(time.Microsecond)
}

func mapError(err error) error {
	var failure *allocationFailure
	if errors.As(err, &failure) {
		return failure
	}
	if errors.Is(err, ErrRetryable) {
		return err
	}
	for _, known := range []error{ErrInvalidInput, ErrNotFound, ErrConflict, ErrUnavailable, ErrClaimLost, ErrBlocked, errIntentSuperseded} {
		if errors.Is(err, known) {
			return known
		}
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	if retryableDatabaseError(err) {
		return fmt.Errorf("%w: %w", ErrRetryable, err)
	}
	var postgresError *pgconn.PgError
	if errors.As(err, &postgresError) {
		switch postgresError.Code {
		case "23505", "P1131", "P1132", "P1133", "P1134", "P1135":
			return ErrConflict
		case "23503", "23514":
			return ErrNotFound
		}
	}
	return fmt.Errorf("%w: %w", ErrUnavailable, err)
}
