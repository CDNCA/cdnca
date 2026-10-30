package cnameallocation

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/domaintrust"
	"github.com/cdnca/cdnca/services/control-api/internal/iamlock"
	"github.com/cdnca/cdnca/services/control-api/internal/jobstate"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// 四层转发自有 CNAME (migration 505): a stream with its own CNAME domain or
// mode gets its own hostname, written to DNS like a site's. The allocation
// has the stream as owner (stream_owner_id, always mode site); the stream's
// 按网站/按套餐 choice only enters the label HMAC (a mode change is a new
// generation, so a new hostname) and is kept on cname_stream_bindings.
// A stream has no website (migration 506): the DNS reconcile task and every
// CNAME fact of its allocation are anchored at the stream itself (migration
// 494; site_id NULL, stream_id set). Done = written to the DNS provider and
// answered consistently by its authoritative servers (dnsreconcile commit).
const (
	StreamIntentJobKind = "dns.cname.stream_intent"

	RetireStreamDeleted  = "stream_deleted"
	RetireStreamReleased = "stream_released"
)

// StreamIntent asks for the stream's own CNAME hostname. Domain "" is the
// scope's default CNAME zone.
type StreamIntent struct {
	TenantScopeID, StreamID   uuid.UUID
	ActorScopeID, ActorUserID uuid.UUID
	Mode                      Mode
	Domain                    string
	Regenerate                bool
	RequestID                 string
}

// EnqueueStreamIntentTx writes the intent and its dns.cname.stream_intent job
// in the caller's transaction (the stream batch action). Returns the job ID.
func EnqueueStreamIntentTx(ctx context.Context, tx pgx.Tx, intent StreamIntent, now time.Time) (uuid.UUID, error) {
	if tx == nil || intent.TenantScopeID == uuid.Nil || intent.StreamID == uuid.Nil ||
		intent.ActorScopeID == uuid.Nil || intent.ActorUserID == uuid.Nil || !validMode(intent.Mode) ||
		!validDNSName(normalizeName(intent.Domain), true) || !validSafeText(intent.RequestID, 128, false) {
		return uuid.Nil, ErrInvalidInput
	}
	intent.Domain = normalizeName(intent.Domain)
	var tenantID uuid.UUID
	if err := tx.QueryRow(ctx, `SELECT tenant_id FROM access_scopes WHERE id=$1 AND kind='tenant'`,
		intent.TenantScopeID).Scan(&tenantID); err != nil {
		return uuid.Nil, mapError(err)
	}
	jobID := uuid.New()
	payload, _ := json.Marshal(struct {
		Version                   int
		Stream, Job, Mode, Domain string
		Regenerate                bool
	}{1, intent.StreamID.String(), jobID.String(), string(intent.Mode), intent.Domain, intent.Regenerate})
	digest := sha256.Sum256(payload)
	if _, err := tx.Exec(ctx, `INSERT INTO background_jobs(id,tenant_id,kind,subject,idempotency_key,
		request_digest,request_id,trace_id,state,attempt,max_attempts,claimable_at,total_count,created_at,updated_at)
		VALUES($1,$2,$3,$4,$5,$6,$7,$7,'queued',0,20,$8,1,$8,$8)`, jobID, tenantID, StreamIntentJobKind,
		"cname_stream_intent/"+intent.StreamID.String(), "cname-stream."+jobID.String(), digest[:], intent.RequestID, now); err != nil {
		return uuid.Nil, err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO background_job_items(tenant_id,job_id,ordinal,item_id,state)
		VALUES($1,$2,1,$3,'pending')`, tenantID, jobID, JobItemID); err != nil {
		return uuid.Nil, err
	}
	_, err := tx.Exec(ctx, `INSERT INTO cname_stream_intents(tenant_id,tenant_scope_id,job_id,stream_id,
		actor_scope_id,actor_user_id,mode,domain,regenerate,request_id,trace_id,created_at)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$10,$11)`, tenantID, intent.TenantScopeID, jobID, intent.StreamID,
		intent.ActorScopeID, intent.ActorUserID, string(intent.Mode), intent.Domain, intent.Regenerate,
		intent.RequestID, now)
	return jobID, err
}

// RetireStreamOwnersTx registers the current and LKG claims of the stream's
// own allocation for cleanup, in the transaction that clears the stream's
// override (stream_released) or deletes the stream (stream_deleted). They
// are cleaned once released (cname_claim_released_476).
func RetireStreamOwnersTx(ctx context.Context, tx pgx.Tx, scopeID, streamID uuid.UUID, reason string, now time.Time) error {
	if reason != RetireStreamDeleted && reason != RetireStreamReleased {
		return ErrInvalidInput
	}
	_, err := tx.Exec(ctx, `INSERT INTO cname_record_retirements(id,tenant_id,tenant_scope_id,allocation_id,claim_id,
			site_id,stream_id,provider_id,zone_id,owner_name,reason,eligible_at,state,attempts,next_attempt_at,created_at,updated_at)
		SELECT gen_random_uuid(),allocation.tenant_id,allocation.tenant_scope_id,allocation.id,claim.id,NULL,$2,
			claim.provider_id,claim.zone_id,lower(claim.hostname),$4,$3,'pending',0,$3,$3,$3
		FROM cname_allocations allocation
		JOIN cname_hostname_claims claim ON claim.allocation_id=allocation.id
		 AND claim.id IN (allocation.current_claim_id,allocation.lkg_claim_id)
		WHERE allocation.tenant_scope_id=$1 AND allocation.stream_owner_id=$2
		ON CONFLICT (claim_id) DO NOTHING`, scopeID, streamID, now, reason)
	return err
}

// PrepareStreamIntent executes a claimed dns.cname.stream_intent job: it
// allocates the stream's hostname (AllocateStream) and settles the intent.
// A configuration error settles the intent failed with its code (shown on
// the stream list); ErrUnavailable/ErrConflict/ErrRetryable keep it leased.
func (store *Store) PrepareStreamIntent(ctx context.Context, claim jobstate.Claim) error {
	if ctx == nil || claim.Job.ID == uuid.Nil || claim.Job.TenantID == uuid.Nil || claim.LeaseID == uuid.Nil || claim.WorkerID == "" {
		return ErrInvalidInput
	}
	var intent StreamIntent
	err := store.pool.QueryRow(ctx, `SELECT intent.tenant_scope_id,intent.stream_id,intent.actor_scope_id,
		intent.actor_user_id,intent.mode,intent.domain,intent.regenerate,intent.request_id
		FROM cname_stream_intents intent JOIN background_jobs job ON job.tenant_id=intent.tenant_id AND job.id=intent.job_id
		WHERE intent.tenant_id=$1 AND intent.job_id=$2 AND job.kind=$6 AND job.state='running' AND job.attempt=$3
		  AND job.lease_id=$4 AND job.lease_owner=$5 AND job.lease_expires_at>clock_timestamp()`,
		claim.Job.TenantID, claim.Job.ID, claim.Job.Attempt, claim.LeaseID, claim.WorkerID, StreamIntentJobKind).Scan(
		&intent.TenantScopeID, &intent.StreamID, &intent.ActorScopeID, &intent.ActorUserID, &intent.Mode,
		&intent.Domain, &intent.Regenerate, &intent.RequestID)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrClaimLost
	}
	if err != nil {
		return mapError(err)
	}
	_, allocateErr := store.AllocateStream(ctx, claim.Job.ID, intent)
	if errors.Is(allocateErr, ErrUnavailable) || errors.Is(allocateErr, ErrConflict) || errors.Is(allocateErr, ErrRetryable) {
		return allocateErr
	}
	state, failure := StateDone, ""
	if allocateErr != nil {
		state, failure = StateFailed, failureCode(allocateErr)
	}
	settleReq := ResultRequest{JobID: claim.Job.ID, WorkerID: claim.WorkerID, Attempt: claim.Job.Attempt,
		LeaseID: claim.LeaseID, Sequence: 1, FailureCode: failure}
	err = pgx.BeginTxFunc(ctx, store.pool, pgx.TxOptions{IsoLevel: pgx.Serializable}, func(tx pgx.Tx) error {
		return settleBackgroundJob(ctx, tx, claim.Job.TenantID, settleReq, state, store.timestamp())
	})
	if err != nil {
		return mapError(err)
	}
	return nil
}

type streamAuthority struct {
	tenantID, ownerUserID, subscriptionID uuid.UUID
	nodeGroupID                           *uuid.UUID
}

// AllocateStream starts generation n+1 of the stream's own allocation: a new
// generated hostname under the intent's zone, frozen A/AAAA targets of the
// stream's effective line group (转发 > 套餐) and a dns.cname.allocation
// job the worker writes to DNS and checks (runAllocation). The intent must
// still be the stream's latest one and the stream must still carry its
// override (errIntentSuperseded otherwise). A done allocation of the same
// zone and mode is kept unless the intent regenerates.
func (store *Store) AllocateStream(ctx context.Context, intentJobID uuid.UUID, intent StreamIntent) (Allocation, error) {
	if ctx == nil || ctx.Err() != nil || intentJobID == uuid.Nil || !validMode(intent.Mode) ||
		!validDNSName(normalizeName(intent.Domain), true) {
		return Allocation{}, ErrInvalidInput
	}
	intent.Domain = normalizeName(intent.Domain)
	activeKey, err := store.keyring.Active(ctx)
	if err != nil || !validKey(activeKey) {
		return Allocation{}, ErrUnavailable
	}
	platformSyncErr := store.ensurePlatformDNS(ctx, intent.TenantScopeID)
	var result Allocation
	err = pgx.BeginTxFunc(ctx, store.pool, pgx.TxOptions{IsoLevel: pgx.Serializable}, func(tx pgx.Tx) error {
		if err := iamlock.AcquireShared(ctx, tx); err != nil {
			return err
		}
		if _, err := iamlock.AcquireScopes(ctx, tx, []uuid.UUID{intent.ActorScopeID, intent.TenantScopeID}); err != nil {
			return err
		}
		stream, err := lockStreamAuthority(ctx, tx, intentJobID, intent)
		if err != nil {
			return err
		}
		if _, blocked, err := domaintrust.BlockedDomain(ctx, tx, []string{intent.Domain}); err != nil {
			return err
		} else if blocked && intent.Domain != "" {
			return ErrBlocked
		}
		target, targetFound, err := lockStreamAllocation(ctx, tx, intent.TenantScopeID, intent.StreamID)
		if err != nil {
			return err
		}
		// fix-cnamerand: a stream without a domain keeps its zone, else
		// draws one of the random-allocation zones.
		var keep []uuid.UUID
		if targetFound && intent.Domain == "" {
			keep = []uuid.UUID{target.claim.zone}
		}
		zone, err := resolveZoneAuthority(ctx, tx, intent.TenantScopeID, intent.Domain, keep, store.zonePick())
		if platformSyncErr != nil && failureCode(err) == FailureDNSProviderNotConfigured {
			return platformSyncErr
		}
		if err != nil {
			return err
		}
		if intent.Domain == "" {
			if _, blocked, err := domaintrust.BlockedDomain(ctx, tx, []string{zone.domain}); err != nil {
				return err
			} else if blocked {
				return ErrBlocked
			}
		}
		var bindingMode Mode
		var bindingRevision int64
		if targetFound {
			if err := tx.QueryRow(ctx, `SELECT mode,binding_revision FROM cname_stream_bindings
				WHERE tenant_scope_id=$1 AND stream_id=$2 FOR UPDATE`, intent.TenantScopeID, intent.StreamID).Scan(
				&bindingMode, &bindingRevision); err != nil {
				return err
			}
			if target.state == StatePending {
				return ErrConflict
			}
			// Keep a done hostname of the same zone and mode, unless it was
			// retired (override cleared, possibly already removed from DNS).
			var retired bool
			if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM cname_record_retirements WHERE claim_id=$1)`,
				target.claim.id).Scan(&retired); err != nil {
				return err
			}
			if target.state == StateDone && !retired && !intent.Regenerate && bindingMode == intent.Mode &&
				claimMatches(target.claim, zone, "") {
				result, err = loadStreamAllocation(ctx, tx, intent.TenantScopeID, intent.StreamID)
				return err
			}
		}
		now := store.timestamp()
		allocationID, claimID, jobID := uuid.New(), uuid.New(), uuid.New()
		generation, expectedRevision, resultRevision, operation := int64(1), int64(0), int64(1), "allocate"
		var lkgClaimID *uuid.UUID
		var lkgRevision *int64
		if targetFound {
			allocationID = target.id
			generation, expectedRevision, resultRevision, operation = target.generation+1, target.revision, target.revision+1, "regenerate"
			lkgClaimID, lkgRevision = nextLKG(target)
		}
		hostname, err := freeGeneratedHostname(activeKey, stream.tenantID, zone.providerID, intent.StreamID, intent.Mode,
			zone.domain, uint64(generation), func(hostname string) (bool, error) {
				var taken bool
				err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM cname_hostname_claims WHERE lower(hostname)=$1)`,
					hostname).Scan(&taken)
				return taken, err
			})
		if err != nil {
			return err
		}
		keyID := activeKey.ID
		requestDigest := sha256.Sum256([]byte("cdnca:cname-stream:" + intentJobID.String()))
		jobReq := AllocateRequest{RequestID: intent.RequestID, TraceID: intent.RequestID}
		if err := insertJob(ctx, tx, stream.tenantID, jobID, allocationID, jobReq,
			backgroundJobDigest(requestDigest, allocationID, generation), now); err != nil {
			return err
		}
		if !targetFound {
			if _, err := tx.Exec(ctx, `INSERT INTO cname_allocations(
				id,tenant_id,tenant_scope_id,owner_user_id,mode,stream_owner_id,current_claim_id,current_revision,
				generation,state,job_id,created_at,updated_at
			) VALUES($1,$2,$3,$4,'site',$5,$6,1,1,'pending',$7,$8,$8)`, allocationID, stream.tenantID, intent.TenantScopeID,
				stream.ownerUserID, intent.StreamID, claimID, jobID, now); err != nil {
				return err
			}
		}
		if err := insertClaim(ctx, tx, claimID, allocationID, intent.TenantScopeID, generation, zone, hostname, false,
			&keyID, now); err != nil {
			return err
		}
		if targetFound {
			if err := advanceAllocation(ctx, tx, target, claimID, jobID, lkgClaimID, lkgRevision, generation,
				resultRevision, now); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `UPDATE cname_stream_bindings SET mode=$3,binding_revision=binding_revision+1,updated_at=$4
				WHERE tenant_scope_id=$1 AND stream_id=$2 AND binding_revision=$5`, intent.TenantScopeID, intent.StreamID,
				string(intent.Mode), now, bindingRevision); err != nil {
				return err
			}
			// n12b: the owner moved past keeps answering for rotationGrace if it was served.
			if err := retireStreamClaimTx(ctx, tx, intent.TenantScopeID, target.id, target.claim.id,
				intent.StreamID, target.state == StateDone, now); err != nil {
				return err
			}
		} else if _, err := tx.Exec(ctx, `INSERT INTO cname_stream_bindings(tenant_scope_id,stream_id,allocation_id,mode,
			binding_revision,created_at,updated_at) VALUES($1,$2,$3,$4,1,$5,$5)`, intent.TenantScopeID, intent.StreamID,
			allocationID, string(intent.Mode), now); err != nil {
			return err
		}
		if err := insertStreamFrozenTarget(ctx, tx, frozenTargetInput{
			tenantID: stream.tenantID, scopeID: intent.TenantScopeID, allocationID: allocationID, jobID: jobID,
			packageSubscriptionID: stream.subscriptionID, zone: zone, ownerName: hostname,
			actorUserID: intent.ActorUserID, requestID: intent.RequestID, siteRevision: bindingRevision + 1, // no website: the frozen target's site_revision is the next binding revision
			allocationRevision: resultRevision,
		}, intent.StreamID, now); err != nil {
			return err
		}
		auditReq := AllocateRequest{TargetScopeID: intent.TenantScopeID,
			ActorScopeID: intent.ActorScopeID, ActorUserID: intent.ActorUserID, RequestID: intent.RequestID}
		auditID, err := store.appendStreamAudit(ctx, tx, auditReq, intent.StreamID, operation, allocationID, StatePending, "")
		if err != nil {
			return err
		}
		if err := insertRequest(ctx, tx, requestFact{
			id: uuid.New(), tenantID: stream.tenantID, scopeID: intent.TenantScopeID, allocationID: allocationID,
			streamID: &intent.StreamID, actorScopeID: intent.ActorScopeID,
			actorUserID: intent.ActorUserID, operation: operation, idempotencyKey: "cname-stream." + intentJobID.String(),
			digest: requestDigest, requestID: intent.RequestID, jobID: jobID, keyID: &keyID, generation: generation,
			expectedRevision: expectedRevision, resultRevision: resultRevision, lkgRevision: lkgRevision,
			state: StatePending, auditID: auditID, createdAt: now,
		}); err != nil {
			return err
		}
		result, err = loadStreamAllocation(ctx, tx, intent.TenantScopeID, intent.StreamID)
		return err
	})
	if err != nil {
		return Allocation{}, mapError(err)
	}
	return result, nil
}

// lockStreamAuthority share-locks the stream and checks the intent is still
// what it asks: the stream's latest intent, the stream undeleted with its
// override (no website needed, migration 506), and the platform actor still
// allowed to manage streams. Errors carry an intent failure code.
func lockStreamAuthority(ctx context.Context, tx pgx.Tx, intentJobID uuid.UUID, intent StreamIntent) (streamAuthority, error) {
	var stream streamAuthority
	var overridden, latest bool
	err := tx.QueryRow(ctx, `SELECT scope.tenant_id,forward.owner_user_id,
			COALESCE(forward.package_subscription_id,'00000000-0000-0000-0000-000000000000'::uuid),
			forward.node_group_id,
			(forward.cname_domain IS NOT NULL OR forward.cname_mode IS NOT NULL),
			(SELECT latest.job_id FROM cname_stream_intents latest WHERE latest.tenant_scope_id=forward.scope_id
			 AND latest.stream_id=forward.id ORDER BY latest.created_at DESC,latest.job_id DESC LIMIT 1)=$3
		FROM l4_forwards forward
		JOIN access_scopes scope ON scope.id=forward.scope_id AND scope.kind='tenant'
		JOIN tenants tenant ON tenant.id=scope.tenant_id AND tenant.status='active'
		WHERE forward.scope_id=$1 AND forward.id=$2 AND forward.deleted_at IS NULL
		  AND EXISTS (SELECT 1 FROM memberships membership JOIN access_scopes actor_scope ON actor_scope.id=membership.scope_id
		      AND actor_scope.kind='platform' JOIN users actor ON actor.id=membership.user_id AND actor.status='active'
		      WHERE membership.scope_id=$4 AND membership.user_id=$5 AND membership.status='active')
		  AND EXISTS (SELECT 1 FROM role_assignments assignment JOIN role_permissions permission ON permission.role_id=assignment.role_id
		      WHERE assignment.scope_id=$4 AND assignment.user_id=$5 AND permission.permission_name IN ('platform.admin','streams.manage'))
		FOR SHARE OF forward`, intent.TenantScopeID, intent.StreamID, intentJobID, intent.ActorScopeID,
		intent.ActorUserID).Scan(&stream.tenantID, &stream.ownerUserID, &stream.subscriptionID,
		&stream.nodeGroupID, &overridden, &latest)
	if errors.Is(err, pgx.ErrNoRows) {
		return streamAuthority{}, failWith(FailureSiteAuthority, ErrNotFound)
	}
	if err != nil {
		return streamAuthority{}, err
	}
	if !overridden || !latest {
		return streamAuthority{}, errIntentSuperseded
	}
	return stream, nil
}

func lockStreamAllocation(ctx context.Context, tx pgx.Tx, scopeID, streamID uuid.UUID) (allocationAuthority, bool, error) {
	var allocation allocationAuthority
	err := scanAllocationAuthority(tx.QueryRow(ctx, `SELECT allocation.id,allocation.tenant_id,allocation.tenant_scope_id,
		allocation.owner_user_id,allocation.mode,allocation.site_owner_id,
		allocation.package_subscription_id,allocation.current_claim_id,allocation.lkg_claim_id,
		allocation.current_revision,allocation.lkg_revision,allocation.generation,
		allocation.state,allocation.job_id,allocation.failure_code,
		claim.id,claim.provider_id,claim.zone_id,claim.domain,claim.hostname,
		claim.explicit_hostname,claim.hmac_key_id,allocation.stream_owner_id
		FROM cname_allocations AS allocation
		JOIN cname_hostname_claims AS claim ON claim.id=allocation.current_claim_id AND claim.allocation_id=allocation.id
		WHERE allocation.tenant_scope_id=$1 AND allocation.stream_owner_id=$2 FOR UPDATE OF allocation`,
		scopeID, streamID), &allocation)
	if errors.Is(err, pgx.ErrNoRows) {
		return allocationAuthority{}, false, nil
	}
	return allocation, err == nil, err
}

// insertStreamFrozenTarget freezes the stream allocation's target: the
// frozen target query with the stream's line group, else its package's.
func insertStreamFrozenTarget(ctx context.Context, tx pgx.Tx, input frozenTargetInput, streamID uuid.UUID, now time.Time) error {
	input.streamID = &streamID
	return insertFrozenTarget(ctx, tx, input, now)
}

// retireStreamClaimTx registers the claim a stream allocation moves past.
func retireStreamClaimTx(ctx context.Context, tx pgx.Tx, scopeID, allocationID, claimID, streamID uuid.UUID,
	served bool, now time.Time) error {
	eligible := now
	if served {
		eligible = now.Add(rotationGrace)
	}
	_, err := tx.Exec(ctx, `INSERT INTO cname_record_retirements(id,tenant_id,tenant_scope_id,allocation_id,claim_id,
			site_id,stream_id,provider_id,zone_id,owner_name,reason,eligible_at,state,attempts,next_attempt_at,created_at,updated_at)
		SELECT gen_random_uuid(),allocation.tenant_id,allocation.tenant_scope_id,allocation.id,claim.id,NULL,$4,
			claim.provider_id,claim.zone_id,lower(claim.hostname),$7,$6,'pending',0,$6,$5,$5
		FROM cname_allocations allocation
		JOIN cname_hostname_claims claim ON claim.allocation_id=allocation.id AND claim.id=$3
		WHERE allocation.tenant_scope_id=$1 AND allocation.id=$2
		ON CONFLICT (claim_id) DO NOTHING`, scopeID, allocationID, claimID, streamID, now, eligible,
		RetireGenerationRotated)
	return err
}

func (store *Store) appendStreamAudit(ctx context.Context, tx pgx.Tx, req AllocateRequest, streamID uuid.UUID,
	operation string, allocationID uuid.UUID, state State, failureCode string) (uuid.UUID, error) {
	req.streamID = streamID
	return store.appendAudit(ctx, tx, req, operation, allocationID, state, failureCode, store.timestamp())
}

// StreamAllocation is a stream's own CNAME as the stream list shows it.
func (store *Store) GetStream(ctx context.Context, scopeID, streamID uuid.UUID) (Allocation, error) {
	if ctx == nil || scopeID == uuid.Nil || streamID == uuid.Nil {
		return Allocation{}, ErrInvalidInput
	}
	var result Allocation
	err := pgx.BeginTxFunc(ctx, store.pool, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly},
		func(tx pgx.Tx) error {
			var err error
			result, err = loadStreamAllocation(ctx, tx, scopeID, streamID)
			return err
		})
	if err != nil {
		return Allocation{}, mapError(err)
	}
	return result, nil
}

func loadStreamAllocation(ctx context.Context, tx pgx.Tx, scopeID, streamID uuid.UUID) (Allocation, error) {
	var result Allocation
	var keyID, failureCode *string
	var lkgRevision *int64
	// No website (migration 506): SiteID stays zero; SiteRevision is the
	// binding's revision.
	err := tx.QueryRow(ctx, `SELECT allocation.id,allocation.tenant_id,allocation.tenant_scope_id,
		allocation.stream_owner_id,claim.provider_id,claim.zone_id,allocation.job_id,binding.mode,allocation.state,
		claim.domain,claim.hostname,claim.hmac_key_id,allocation.failure_code,allocation.current_revision,
		allocation.lkg_revision,binding.binding_revision
		FROM cname_stream_bindings binding
		JOIN cname_allocations allocation ON allocation.tenant_scope_id=binding.tenant_scope_id AND allocation.id=binding.allocation_id
		JOIN cname_hostname_claims claim ON claim.id=allocation.current_claim_id AND claim.allocation_id=allocation.id
		WHERE binding.tenant_scope_id=$1 AND binding.stream_id=$2`, scopeID, streamID).Scan(
		&result.ID, &result.TenantID, &result.ScopeID, &result.OwnerID, &result.ProviderID,
		&result.ZoneID, &result.JobID, &result.Mode, &result.State, &result.Domain, &result.Hostname, &keyID,
		&failureCode, &result.Revision, &lkgRevision, &result.SiteRevision)
	if errors.Is(err, pgx.ErrNoRows) {
		return Allocation{}, ErrNotFound
	}
	if err != nil {
		return Allocation{}, err
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
