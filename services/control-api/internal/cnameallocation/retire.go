package cnameallocation

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// A CNAME owner written to the DNS provider is retired (migration 476) when
// its site is deleted or its allocation moves past it; the worker deletes the
// records the system wrote under it once no live site serves the claim.
const (
	RetireSiteDeleted       = "site_deleted"
	RetireGenerationRotated = "generation_rotated"

	// rotationGrace keeps a rotated owner that was served (LKG) answering so
	// customers can repoint their own CNAME to the new hostname.
	rotationGrace        = 24 * time.Hour
	retirementLease      = 10 * time.Minute
	retirementMaxBackoff = 6 * time.Hour
	retirementMaxTries   = 20
	retirementBatch      = 16
)

// RetiredOwner is one retired CNAME owner with the record values the system
// wrote under it (frozen allocation targets and DNS retargets).
type RetiredOwner struct {
	ID, TenantID, ScopeID, AllocationID, ClaimID, SiteID, ProviderID, ZoneID uuid.UUID
	Owner                                                                    string
	Reason                                                                   string
	Attempts                                                                 int
	A, AAAA, CNAME                                                           []string
}

// RetiredOwnerCleaner deletes the provider records of a retired owner whose
// type and value the system wrote, and reports how many it deleted and how
// many other records it left under the owner.
type RetiredOwnerCleaner interface {
	CleanRetiredOwner(ctx context.Context, owner RetiredOwner) (deleted, kept int, err error)
}

// RetireSiteOwnersTx registers, in the site delete transaction, the current
// and LKG claims of the deleted site's own (site-mode) allocation. A package
// allocation stays: the subscription's other or next site serves it.
func RetireSiteOwnersTx(ctx context.Context, tx pgx.Tx, scopeID, siteID uuid.UUID, now time.Time) error {
	return retireSiteOwnersTx(ctx, tx, scopeID, siteID, now, 0)
}

// TransferGrace keeps the CNAME of a site moved to another user (site
// transfer: the old site is deleted, the new one gets a new CNAME) on the
// provider for a day, so the customer can repoint the domain.
const TransferGrace = rotationGrace

// RetireTransferredSiteOwnersTx is RetireSiteOwnersTx with TransferGrace; it
// runs before the delete so the delete's own registration is a no-op.
func RetireTransferredSiteOwnersTx(ctx context.Context, tx pgx.Tx, scopeID, siteID uuid.UUID, now time.Time) error {
	return retireSiteOwnersTx(ctx, tx, scopeID, siteID, now, TransferGrace)
}

func retireSiteOwnersTx(ctx context.Context, tx pgx.Tx, scopeID, siteID uuid.UUID, now time.Time, grace time.Duration) error {
	_, err := tx.Exec(ctx, `INSERT INTO cname_record_retirements(id,tenant_id,tenant_scope_id,allocation_id,claim_id,
			site_id,provider_id,zone_id,owner_name,reason,eligible_at,state,attempts,next_attempt_at,created_at,updated_at)
		SELECT gen_random_uuid(),allocation.tenant_id,allocation.tenant_scope_id,allocation.id,claim.id,$2,
			claim.provider_id,claim.zone_id,lower(claim.hostname),$4,$5,'pending',0,$5,$3,$3
		FROM cname_allocations allocation
		JOIN cname_hostname_claims claim ON claim.allocation_id=allocation.id
		 AND claim.id IN (allocation.current_claim_id,allocation.lkg_claim_id)
		WHERE allocation.tenant_scope_id=$1 AND allocation.mode='site' AND allocation.site_owner_id=$2
		ON CONFLICT (claim_id) DO NOTHING`, scopeID, siteID, now, RetireSiteDeleted, now.Add(grace))
	return err
}

// retireRotatedClaimTx registers the claim an allocation moves past (a new
// generation, or a site leaving its own allocation for a package one).
func retireRotatedClaimTx(ctx context.Context, tx pgx.Tx, scopeID, allocationID, claimID, siteID uuid.UUID,
	served bool, now time.Time) error {
	eligible := now
	if served {
		eligible = now.Add(rotationGrace)
	}
	_, err := tx.Exec(ctx, `INSERT INTO cname_record_retirements(id,tenant_id,tenant_scope_id,allocation_id,claim_id,
			site_id,provider_id,zone_id,owner_name,reason,eligible_at,state,attempts,next_attempt_at,created_at,updated_at)
		SELECT gen_random_uuid(),allocation.tenant_id,allocation.tenant_scope_id,allocation.id,claim.id,$4,
			claim.provider_id,claim.zone_id,lower(claim.hostname),$7,$6,'pending',0,$6,$5,$5
		FROM cname_allocations allocation
		JOIN cname_hostname_claims claim ON claim.allocation_id=allocation.id AND claim.id=$3
		WHERE allocation.tenant_scope_id=$1 AND allocation.id=$2
		ON CONFLICT (claim_id) DO NOTHING`, scopeID, allocationID, claimID, siteID, now, eligible, RetireGenerationRotated)
	return err
}

// retireLeftSiteAllocationTx registers the current and LKG claims of the
// site-mode allocation a site's binding leaves (a package allocation stays
// with its subscription). They keep answering for rotationGrace.
func retireLeftSiteAllocationTx(ctx context.Context, tx pgx.Tx, scopeID, allocationID, siteID uuid.UUID, now time.Time) error {
	_, err := tx.Exec(ctx, `INSERT INTO cname_record_retirements(id,tenant_id,tenant_scope_id,allocation_id,claim_id,
			site_id,provider_id,zone_id,owner_name,reason,eligible_at,state,attempts,next_attempt_at,created_at,updated_at)
		SELECT gen_random_uuid(),allocation.tenant_id,allocation.tenant_scope_id,allocation.id,claim.id,$3,
			claim.provider_id,claim.zone_id,lower(claim.hostname),$6,$5,'pending',0,$5,$4,$4
		FROM cname_allocations allocation
		JOIN cname_hostname_claims claim ON claim.allocation_id=allocation.id
		 AND claim.id IN (allocation.current_claim_id,allocation.lkg_claim_id)
		WHERE allocation.tenant_scope_id=$1 AND allocation.id=$2 AND allocation.mode='site'
		ON CONFLICT (claim_id) DO NOTHING`, scopeID, allocationID, siteID, now, now.Add(rotationGrace), RetireGenerationRotated)
	return err
}

// RetireSubscriptionOwnersTx registers, in the subscription cancel
// transaction, the current and LKG claims of the cancelled subscription's
// package allocations: no new site can bind a cancelled subscription, so
// nothing else retires them. site_id is a site the allocation was bound to
// (as in 476's backfill). The claim is released only once no live site
// serves it (cname_claim_released_476), so suspended sites keep answering.
// 476 allows two reasons; a cancel is recorded as generation_rotated.
func RetireSubscriptionOwnersTx(ctx context.Context, tx pgx.Tx, scopeID, subscriptionID uuid.UUID, now time.Time) error {
	_, err := tx.Exec(ctx, `INSERT INTO cname_record_retirements(id,tenant_id,tenant_scope_id,allocation_id,claim_id,
			site_id,provider_id,zone_id,owner_name,reason,eligible_at,state,attempts,next_attempt_at,created_at,updated_at)
		SELECT gen_random_uuid(),allocation.tenant_id,allocation.tenant_scope_id,allocation.id,claim.id,bound.site_id,
			claim.provider_id,claim.zone_id,lower(claim.hostname),$4,$3,'pending',0,$3,$3,$3
		FROM cname_allocations allocation
		JOIN cname_hostname_claims claim ON claim.allocation_id=allocation.id
		 AND claim.id IN (allocation.current_claim_id,allocation.lkg_claim_id)
		JOIN LATERAL (SELECT binding.site_id FROM cname_site_bindings binding
			WHERE binding.tenant_scope_id=allocation.tenant_scope_id
			  AND allocation.id IN (binding.current_allocation_id,binding.lkg_allocation_id)
			ORDER BY binding.site_id LIMIT 1) bound ON true
		WHERE allocation.tenant_scope_id=$1 AND allocation.mode='package' AND allocation.package_subscription_id=$2
		ON CONFLICT (claim_id) DO NOTHING`, scopeID, subscriptionID, now, RetireGenerationRotated)
	return err
}

// DueRetirements leases up to limit released retirements (476
// cname_claim_released_476) for one cleaning attempt.
func (store *Store) DueRetirements(ctx context.Context, limit int) ([]RetiredOwner, error) {
	if ctx == nil || limit < 1 || limit > 1000 {
		return nil, ErrInvalidInput
	}
	now := store.timestamp()
	rows, err := store.pool.Query(ctx, `WITH due AS (
			SELECT id FROM cname_record_retirements
			WHERE state='pending' AND next_attempt_at<=$1 AND cname_claim_released_476(claim_id)
			ORDER BY next_attempt_at,id LIMIT $2 FOR UPDATE SKIP LOCKED
		), leased AS (
			UPDATE cname_record_retirements retirement SET next_attempt_at=$3,updated_at=GREATEST(retirement.updated_at,$1)
			FROM due WHERE retirement.id=due.id
			RETURNING retirement.*
		)
		SELECT leased.id,leased.tenant_id,leased.tenant_scope_id,leased.allocation_id,leased.claim_id,COALESCE(leased.site_id,leased.stream_id),
			leased.provider_id,leased.zone_id,leased.owner_name,leased.reason,leased.attempts,
			COALESCE(ARRAY(SELECT DISTINCT value FROM (
				SELECT unnest(target.target_a) FROM cname_allocation_targets target
				WHERE target.allocation_id=leased.allocation_id AND lower(rtrim(target.owner_name,'.'))=rtrim(leased.owner_name,'.')
				UNION SELECT unnest(retarget.target_a) FROM dns_cname_retargets retarget
				WHERE retarget.allocation_id=leased.allocation_id AND lower(rtrim(retarget.owner_name,'.'))=rtrim(leased.owner_name,'.')
			) AS written(value)),'{}'),
			COALESCE(ARRAY(SELECT DISTINCT value FROM (
				SELECT unnest(target.target_aaaa) FROM cname_allocation_targets target
				WHERE target.allocation_id=leased.allocation_id AND lower(rtrim(target.owner_name,'.'))=rtrim(leased.owner_name,'.')
				UNION SELECT unnest(retarget.target_aaaa) FROM dns_cname_retargets retarget
				WHERE retarget.allocation_id=leased.allocation_id AND lower(rtrim(retarget.owner_name,'.'))=rtrim(leased.owner_name,'.')
			) AS written(value)),'{}'),
			COALESCE(ARRAY(SELECT DISTINCT retarget.target_cname FROM dns_cname_retargets retarget
				WHERE retarget.allocation_id=leased.allocation_id AND lower(rtrim(retarget.owner_name,'.'))=rtrim(leased.owner_name,'.')
				  AND COALESCE(retarget.target_cname,'')<>''),'{}')
		FROM leased ORDER BY leased.next_attempt_at,leased.id`, now, limit, now.Add(retirementLease))
	if err != nil {
		return nil, unavailable(err)
	}
	return pgx.CollectRows(rows, func(row pgx.CollectableRow) (RetiredOwner, error) {
		var owner RetiredOwner
		err := row.Scan(&owner.ID, &owner.TenantID, &owner.ScopeID, &owner.AllocationID, &owner.ClaimID, &owner.SiteID,
			&owner.ProviderID, &owner.ZoneID, &owner.Owner, &owner.Reason, &owner.Attempts, &owner.A, &owner.AAAA, &owner.CNAME)
		return owner, err
	})
}

// FinishRetirement records one cleaning attempt: cleaned, or a retry after a
// back-off, or failed for good after retirementMaxTries.
func (store *Store) FinishRetirement(ctx context.Context, owner RetiredOwner, deleted, kept int, code string) error {
	if ctx == nil || owner.ID == uuid.Nil || deleted < 0 || kept < 0 || code != "" && !errorCodePattern.MatchString(code) {
		return ErrInvalidInput
	}
	now := store.timestamp()
	attempts := owner.Attempts + 1
	state, next, completed := "cleaned", now, &now
	var lastError *string
	if code != "" {
		lastError = &code
		state, completed = "pending", nil
		next = now.Add(RetirementBackoff(attempts))
		if attempts >= retirementMaxTries {
			state, completed = "failed", &now
		}
	}
	command, err := store.pool.Exec(ctx, `UPDATE cname_record_retirements
		SET state=$2,attempts=$3,next_attempt_at=GREATEST($4,eligible_at),last_error_code=$5,
		    deleted_records=deleted_records+$6,kept_records=$7,completed_at=$8,updated_at=GREATEST(updated_at,$9)
		WHERE id=$1 AND state='pending' AND attempts=$10`,
		owner.ID, state, attempts, next, lastError, deleted, kept, completed, now, owner.Attempts)
	if err != nil {
		return unavailable(err)
	}
	if command.RowsAffected() != 1 {
		return ErrClaimLost
	}
	return nil
}

// RetirementBackoff is the delay before attempt+1: one minute doubling,
// capped at six hours.
func RetirementBackoff(attempt int) time.Duration {
	delay := time.Minute
	for step := 1; step < attempt && delay < retirementMaxBackoff; step++ {
		delay *= 2
	}
	return min(delay, retirementMaxBackoff)
}

// RunRetirements cleans the due retired owners once. A provider failure is
// retried with back-off and logged; the last attempt is logged as an error.
func (worker *Worker) RunRetirements(ctx context.Context) error {
	if worker.dependencies.Retirements == nil || worker.dependencies.RetiredOwners == nil {
		return nil
	}
	owners, err := worker.dependencies.Retirements.DueRetirements(ctx, retirementBatch)
	if err != nil {
		return err
	}
	for _, owner := range owners {
		deleted, kept, cleanErr := worker.dependencies.RetiredOwners.CleanRetiredOwner(ctx, owner)
		code := ""
		if cleanErr != nil {
			code = "dns_retire_failed"
			var permanent interface{ FailureCode() string }
			if errors.As(cleanErr, &permanent) && errorCodePattern.MatchString(permanent.FailureCode()) {
				code = permanent.FailureCode()
			}
			level := slog.LevelWarn
			if owner.Attempts+1 >= retirementMaxTries {
				level = slog.LevelError
			}
			slog.Log(ctx, level, "retired CNAME owner cleanup failed", "tenant_id", owner.TenantID,
				"site_id", owner.SiteID, "zone_id", owner.ZoneID, "owner", owner.Owner, "reason", owner.Reason,
				"attempt", owner.Attempts+1, "code", code, "error", cleanErr)
		} else if kept > 0 {
			slog.Info("retired CNAME owner keeps records the system did not write", "tenant_id", owner.TenantID,
				"zone_id", owner.ZoneID, "owner", owner.Owner, "deleted", deleted, "kept", kept)
		}
		if err := worker.dependencies.Retirements.FinishRetirement(ctx, owner, deleted, kept, code); err != nil &&
			!errors.Is(err, ErrClaimLost) {
			return err
		}
	}
	return nil
}
