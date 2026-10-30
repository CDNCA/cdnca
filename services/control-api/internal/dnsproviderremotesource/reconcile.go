package dnsproviderremotesource

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/dnsacme"
	"github.com/cdnca/cdnca/services/control-api/internal/dnscheck"
	"github.com/cdnca/cdnca/services/control-api/internal/dnsproviderremote"
	"github.com/cdnca/cdnca/services/control-api/internal/tenantaccess"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

const mutationClaimLease = 2 * time.Minute

type ReconcileResolver struct {
	adapter *dnsproviderremote.ReconcileAdapter
}

func NewReconcileResolver(source *Source, remote dnsproviderremote.ReconcileRemote) (*ReconcileResolver, error) {
	adapter, err := dnsproviderremote.NewReconcileAdapter(source, remote)
	if err != nil {
		return nil, ErrUnavailable
	}
	return &ReconcileResolver{adapter: adapter}, nil
}

func (resolver *ReconcileResolver) ResolveProvider(ctx context.Context, tenantID, siteID, zoneID uuid.UUID) (dnscheck.ProviderAdapter, error) {
	if resolver == nil || resolver.adapter == nil || tenantID == uuid.Nil || siteID == uuid.Nil || zoneID == uuid.Nil {
		return nil, ErrUnavailable
	}
	if _, err := resolver.adapter.CurrentRevision(ctx, dnscheck.ProviderRevisionRequest{
		TenantID: tenantID, SiteID: siteID, ZoneID: zoneID,
	}); err != nil {
		return nil, ErrUnavailable
	}
	return resolver.adapter, nil
}

func (source *Source) CurrentRevision(ctx context.Context, request dnscheck.ProviderRevisionRequest) (int64, error) {
	if source == nil || source.pool == nil || ctx == nil || request.TenantID == uuid.Nil || request.SiteID == uuid.Nil || request.ZoneID == uuid.Nil {
		return 0, ErrUnavailable
	}
	var (
		revision   int64
		ciphertext []byte
	)
	err := source.pool.QueryRow(ctx, reconcileScopeQuery(false), request.TenantID, request.SiteID, request.ZoneID).Scan(
		&revision, new(uuid.UUID), new(uuid.UUID), new(string), new(string), new(string), &ciphertext, new(string),
	)
	defer clear(ciphertext)
	if err != nil || revision < 1 {
		return 0, ErrUnavailable
	}
	return revision, nil
}

func (source *Source) AcquireMutationClaim(ctx context.Context,
	mutation dnscheck.ProviderMutation) (dnsproviderremote.MutationClaim, error) {
	if source == nil || source.pool == nil || source.cipher == nil || ctx == nil ||
		mutation.TenantID == uuid.Nil || mutation.SiteID == uuid.Nil || mutation.ZoneID == uuid.Nil ||
		mutation.ExpectedRevision < 1 {
		return dnsproviderremote.MutationClaim{}, ErrUnavailable
	}
	boundCipher, ok := source.cipher.(dnsacme.BoundCredentialCipher)
	if !ok {
		return dnsproviderremote.MutationClaim{}, ErrUnavailable
	}
	var result dnsproviderremote.MutationClaim
	var recoveryPendingRequestID string
	err := pgx.BeginFunc(ctx, source.pool, func(tx pgx.Tx) error {
		existing, found, err := loadExistingMutationClaim(ctx, tx, mutation)
		if err != nil {
			return err
		}
		if found && (existing.State == dnsproviderremote.MutationSucceeded ||
			existing.State == dnsproviderremote.MutationConflict) {
			result = existing
			return nil
		}

		claim, operation, keyID, ciphertext, err := loadMutationClaimAuthority(ctx, tx, mutation)
		if err != nil {
			return err
		}
		defer clear(ciphertext)
		if operation != mutation.Operation ||
			claim.Revision != mutation.ExpectedRevision && claim.Revision != mutation.ExpectedRevision+1 {
			return dnscheck.ErrProviderRevisionConflict
		}
		claim.Config.TenantID = mutation.TenantID
		claim.Config.ScopeID = claim.Config.TenantScopeID
		decryptor := boundCredentialDecryptor{cipher: boundCipher, binding: dnsacme.CredentialBinding{
			TenantID: mutation.TenantID, ScopeID: claim.Config.ScopeID, ProviderID: claim.Config.ProviderID,
		}}
		plaintext, err := decryptor.Decrypt(keyID, ciphertext)
		if err != nil || len(plaintext) == 0 {
			clear(plaintext)
			return ErrUnavailable
		}
		defer clear(plaintext)
		claim.Config.Credentials, err = decodeCredentials(claim.Config.ProviderType, plaintext)
		if err != nil {
			return ErrUnavailable
		}

		claimID, err := uuid.NewV7()
		if err != nil {
			return err
		}
		claim.ClaimID = claimID
		claim.State = dnsproviderremote.MutationClaimed
		claim.ProviderRequestID = dnsproviderremote.ProviderMutationRequestID(mutation.ClientRequestID)
		if !found {
			err = tx.QueryRow(ctx, `INSERT INTO dns_reconcile_provider_mutation_claims(
				tenant_id,client_request_id,job_id,phase,operation_ordinal,site_id,stream_id,zone_id,provider_id,
				claim_id,lease_expires_at,state,expected_site_revision,expected_zone_revision,
				expected_provider_revision,site_config_digest,operation_digest,authority_digest,
				provider_config_digest,credential_digest,provider_request_id,claimed_at
			) SELECT $1,$2,$3,$4,$5,task.site_id,task.stream_id,$7,$8,$9,
				statement_timestamp()+make_interval(secs => $10::double precision),'claimed',$11,$12,$13,$14,$15,$16,$17,$18,$19,
				statement_timestamp()
			-- The claim carries its task's anchor (migration 507); $6 is that anchor's ID.
			FROM dns_reconcile_tasks task WHERE task.tenant_id=$1 AND task.job_id=$3
			  AND COALESCE(task.site_id,task.stream_id)=$6
			RETURNING lease_expires_at`,
				mutation.TenantID, mutation.ClientRequestID, claim.JobID, claim.Phase,
				claim.OperationOrdinal, mutation.SiteID, mutation.ZoneID, claim.Config.ProviderID,
				claim.ClaimID, int64(mutationClaimLease/time.Second), claim.SiteRevision, claim.Revision,
				claim.ProviderRevision, claim.SiteConfigDigest[:], claim.OperationDigest[:], claim.AuthorityDigest[:],
				claim.ProviderConfigDigest[:], claim.CredentialDigest[:], claim.ProviderRequestID).Scan(&claim.LeaseExpiresAt)
			if err != nil {
				return err
			}
			result = claim
			return nil
		}
		if !sameMutationClaimAuthority(existing, claim) || existing.ClaimID == uuid.Nil {
			return dnscheck.ErrProviderRevisionConflict
		}
		if existing.State != dnsproviderremote.MutationNotApplied &&
			existing.State != dnsproviderremote.MutationClaimed && existing.State != dnsproviderremote.MutationUncertain {
			return dnscheck.ErrProviderRevisionConflict
		}
		if existing.State == dnsproviderremote.MutationClaimed {
			var recoveryNotBefore time.Time
			err = tx.QueryRow(ctx, `UPDATE dns_reconcile_provider_mutation_claims
				SET state='uncertain'
				WHERE tenant_id=$1 AND client_request_id=$2 AND claim_id=$3
				  AND state='claimed' AND lease_expires_at<=statement_timestamp()
				RETURNING lease_expires_at,recovery_not_before`, mutation.TenantID,
				mutation.ClientRequestID, existing.ClaimID).Scan(&claim.LeaseExpiresAt, &recoveryNotBefore)
			if errors.Is(err, pgx.ErrNoRows) {
				claim.ClaimID = existing.ClaimID
				result = claim
				recoveryPendingRequestID = existing.ProviderRequestID
				return nil
			}
			if err != nil {
				return firstClaimError(err)
			}
			claim.ClaimID = existing.ClaimID
			claim.State = dnsproviderremote.MutationUncertain
			claim.RecoveryNotBefore = recoveryNotBefore
			claim.RecoveryReady = false
			result = claim
			return nil
		}
		if existing.State == dnsproviderremote.MutationUncertain && !existing.RecoveryReady {
			claim.ClaimID = existing.ClaimID
			claim.State = existing.State
			claim.LeaseExpiresAt = existing.LeaseExpiresAt
			claim.RecoveryNotBefore = existing.RecoveryNotBefore
			claim.RecoveryReady = false
			result = claim
			return nil
		}
		state := existing.State
		if state == dnsproviderremote.MutationNotApplied {
			state = dnsproviderremote.MutationClaimed
			claim.RecoveryNotBefore = time.Time{}
			claim.RecoveryReady = false
		} else {
			claim.RecoveryNotBefore = existing.RecoveryNotBefore
			claim.RecoveryReady = existing.RecoveryReady
		}
		err = tx.QueryRow(ctx, `UPDATE dns_reconcile_provider_mutation_claims
			SET claim_id=$3,
			    lease_expires_at=statement_timestamp()+make_interval(secs => $4::double precision),
			    claimed_at=statement_timestamp(),state=$5,provider_record_id=NULL,
			    final_zone_revision=NULL,finalized_at=NULL,
			    recovery_not_before=CASE WHEN $5='claimed' THEN NULL ELSE recovery_not_before END
			WHERE tenant_id=$1 AND client_request_id=$2 AND claim_id=$6
			  AND lease_expires_at<=statement_timestamp()
			RETURNING lease_expires_at`, mutation.TenantID, mutation.ClientRequestID, claim.ClaimID,
			int64(mutationClaimLease/time.Second), state, existing.ClaimID).Scan(&claim.LeaseExpiresAt)
		if errors.Is(err, pgx.ErrNoRows) {
			result = claim
			recoveryPendingRequestID = existing.ProviderRequestID
			return nil
		}
		if err != nil {
			return firstClaimError(err)
		}
		claim.State = state
		result = claim
		return nil
	})
	if err != nil {
		clearCredentials(result.Config.Credentials)
		// The claim row is held by the worker whose credential fence spans the provider
		// call (AcquireMutationCredentialLease); waiting would park this worker for the
		// whole bounded provider I/O, so back off like any other active claim.
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "55P03" {
			return dnsproviderremote.MutationClaim{}, &dnscheck.ProviderError{
				Class: dnscheck.ProviderErrorTransient, Code: "provider_recovery_pending", RetryAfter: time.Second,
				ProviderRequestID: dnsproviderremote.ProviderMutationRequestID(mutation.ClientRequestID),
			}
		}
		return dnsproviderremote.MutationClaim{}, mapClaimError(err)
	}
	if result.Config.Credentials != nil && result.Config.ProviderZoneName == "" {
		// A zone saved before migration 473: look its apex up outside the
		// claim transaction (no provider I/O under the row locks).
		result.Config.ProviderZoneName, err = source.zoneApex(ctx, nil, result.Config.ScopeID, result.Config.ZoneID,
			result.Config.ProviderType, result.Config.Credentials, result.Config.ZoneName, "")
		if err != nil {
			clearCredentials(result.Config.Credentials)
			return dnsproviderremote.MutationClaim{}, zoneApexClaimError(err)
		}
	}
	if recoveryPendingRequestID != "" {
		clearCredentials(result.Config.Credentials)
		return dnsproviderremote.MutationClaim{}, &dnscheck.ProviderError{
			Class: dnscheck.ProviderErrorTransient, Code: "provider_recovery_pending",
			RetryAfter: time.Second, ProviderRequestID: recoveryPendingRequestID,
		}
	}
	return result, nil
}

func (source *Source) ValidateMutationClaim(ctx context.Context, mutation dnscheck.ProviderMutation,
	claim dnsproviderremote.MutationClaim) error {
	lease, err := source.AcquireMutationCredentialLease(ctx, mutation, claim)
	if err != nil {
		return mapClaimError(err)
	}
	if lease == nil {
		return ErrUnavailable
	}
	releaseCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return mapClaimError(lease(releaseCtx))
}

func (source *Source) AcquireMutationCredentialLease(ctx context.Context, mutation dnscheck.ProviderMutation,
	claim dnsproviderremote.MutationClaim) (dnsproviderremote.MutationCredentialLease, error) {
	if !validMutationClaimCall(source, ctx, mutation, claim) {
		return nil, ErrUnavailable
	}
	tx, err := source.pool.Begin(ctx)
	if err != nil {
		return nil, mapClaimError(err)
	}
	keepOpen := false
	defer func() {
		if !keepOpen {
			rollbackCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = tx.Rollback(rollbackCtx)
		}
	}()
	current, _, _, ciphertext, err := loadMutationClaimAuthority(ctx, tx, mutation)
	clear(ciphertext)
	if err != nil {
		return nil, mapClaimError(err)
	}
	if !sameMutationClaimAuthority(claim, current) {
		return nil, dnscheck.ErrProviderRevisionConflict
	}
	var leaseExpiresAt, serverNow time.Time
	err = tx.QueryRow(ctx, `UPDATE dns_reconcile_provider_mutation_claims
		SET lease_expires_at=GREATEST(lease_expires_at,
		    statement_timestamp()+make_interval(secs => $5::double precision))
		WHERE tenant_id=$1 AND client_request_id=$2 AND claim_id=$3 AND state='claimed'
		  AND provider_request_id=$4 AND lease_expires_at>statement_timestamp()
		RETURNING lease_expires_at,statement_timestamp()`, mutation.TenantID, mutation.ClientRequestID,
		claim.ClaimID, claim.ProviderRequestID,
		int64(dnsproviderremote.MutationClaimLeaseMinimum/time.Second)).Scan(&leaseExpiresAt, &serverNow)
	if err != nil || leaseExpiresAt.Sub(serverNow) < dnsproviderremote.MutationClaimLeaseMinimum {
		return nil, mapClaimError(firstClaimError(err))
	}
	keepOpen = true
	released := false
	return func(releaseCtx context.Context) error {
		if released {
			return ErrUnavailable
		}
		released = true
		if releaseCtx == nil {
			rollbackCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = tx.Rollback(rollbackCtx)
			return ErrUnavailable
		}
		if err := tx.Commit(releaseCtx); err != nil {
			rollbackCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = tx.Rollback(rollbackCtx)
			return err
		}
		return nil
	}, nil
}

func (source *Source) MarkMutationUncertain(ctx context.Context, mutation dnscheck.ProviderMutation,
	claim dnsproviderremote.MutationClaim, providerRequestID string) error {
	if !validMutationClaimCall(source, ctx, mutation, claim) || providerRequestID != claim.ProviderRequestID {
		return ErrUnavailable
	}
	command, err := source.pool.Exec(ctx, `UPDATE dns_reconcile_provider_mutation_claims
		SET state='uncertain',lease_expires_at=clock_timestamp()
		WHERE tenant_id=$1 AND client_request_id=$2 AND claim_id=$3 AND state='claimed'
		  AND provider_request_id=$4`,
		mutation.TenantID, mutation.ClientRequestID, claim.ClaimID, providerRequestID)
	if err != nil || command.RowsAffected() != 1 {
		return mapClaimError(firstClaimError(err))
	}
	return nil
}

func (source *Source) FinalizeMutationClaim(ctx context.Context, mutation dnscheck.ProviderMutation,
	claim dnsproviderremote.MutationClaim, outcome dnsproviderremote.MutationClaimState,
	providerRequestID, providerRecordID string) (int64, error) {
	if !validMutationClaimCall(source, ctx, mutation, claim) || providerRequestID != claim.ProviderRequestID ||
		outcome != dnsproviderremote.MutationSucceeded && outcome != dnsproviderremote.MutationNotApplied &&
			outcome != dnsproviderremote.MutationConflict {
		return 0, ErrUnavailable
	}
	var finalRevision int64
	err := pgx.BeginFunc(ctx, source.pool, func(tx pgx.Tx) error {
		current, _, _, _, err := loadMutationClaimAuthority(ctx, tx, mutation)
		if err != nil {
			return err
		}
		if !sameMutationClaimAuthority(claim, current) {
			return dnscheck.ErrProviderRevisionConflict
		}
		var state string
		if err := tx.QueryRow(ctx, `SELECT state FROM dns_reconcile_provider_mutation_claims
			WHERE tenant_id=$1 AND client_request_id=$2 AND claim_id=$3
			FOR UPDATE`, mutation.TenantID, mutation.ClientRequestID, claim.ClaimID).Scan(&state); err != nil {
			return err
		}
		if state != string(dnsproviderremote.MutationClaimed) && state != string(dnsproviderremote.MutationUncertain) {
			return dnscheck.ErrProviderRevisionConflict
		}
		finalRevision = current.Revision
		if outcome == dnsproviderremote.MutationSucceeded {
			if providerRequestID == "" || providerRecordID == "" ||
				current.Revision != mutation.ExpectedRevision && current.Revision != mutation.ExpectedRevision+1 {
				return dnscheck.ErrProviderRevisionConflict
			}
			finalRevision = mutation.ExpectedRevision + 1
		} else if current.Revision != claim.Revision {
			return dnscheck.ErrProviderRevisionConflict
		}
		command, err := tx.Exec(ctx, `UPDATE dns_reconcile_provider_mutation_claims
			SET state=$4,provider_record_id=NULLIF($6,''),
			    final_zone_revision=$7,finalized_at=clock_timestamp(),
			    lease_expires_at=CASE WHEN $4='not_applied' THEN statement_timestamp() ELSE lease_expires_at END
			WHERE tenant_id=$1 AND client_request_id=$2 AND claim_id=$3
			  AND state IN ('claimed','uncertain') AND provider_request_id=$5
				  AND ($4<>'not_applied' OR state<>'uncertain' OR recovery_not_before<=clock_timestamp())`,
			mutation.TenantID, mutation.ClientRequestID,
			claim.ClaimID, outcome, providerRequestID, providerRecordID, finalRevision)
		if err != nil || command.RowsAffected() != 1 {
			return firstClaimError(err)
		}
		if outcome == dnsproviderremote.MutationSucceeded && current.Revision == mutation.ExpectedRevision {
			command, err = tx.Exec(ctx, `UPDATE dns_zones SET revision=revision+1,updated_at=clock_timestamp()
				WHERE scope_id=$1 AND id=$2 AND revision=$3`, current.Config.TenantScopeID,
				mutation.ZoneID, mutation.ExpectedRevision)
			if err != nil || command.RowsAffected() != 1 {
				return firstClaimError(err)
			}
		}
		return nil
	})
	if err != nil {
		return 0, mapClaimError(err)
	}
	return finalRevision, nil
}

func loadExistingMutationClaim(ctx context.Context, tx pgx.Tx,
	mutation dnscheck.ProviderMutation) (dnsproviderremote.MutationClaim, bool, error) {
	var claim dnsproviderremote.MutationClaim
	var state string
	var claimSiteID, taskSiteID uuid.UUID
	var recoveryNotBefore *time.Time
	var liveSiteRevision, taskSiteRevision, liveZoneRevision, liveProviderRevision int64
	var operationJSON []byte
	var operationDigest, boundOperationDigest, authorityDigest, siteConfigDigest, taskSiteConfigDigest []byte
	var configDigest, credentialDigest, liveSiteConfigDigest, liveConfigDigest, liveCredentialDigest []byte
	err := tx.QueryRow(ctx, `SELECT claim.job_id,claim.phase,claim.operation_ordinal,claim.claim_id,
		claim.state,claim.lease_expires_at,claim.recovery_not_before,
			COALESCE(claim.recovery_not_before<=clock_timestamp(),false),
		claim.expected_site_revision,claim.expected_zone_revision,claim.expected_provider_revision,
		claim.site_config_digest,claim.operation_digest,claim.authority_digest,
		claim.provider_config_digest,claim.credential_digest,
		COALESCE(claim.provider_request_id,''),COALESCE(claim.provider_record_id,''),
		COALESCE(claim.final_zone_revision,0),task.tenant_scope_id,claim.provider_id,
		provider.provider_type,claim.zone_id,zone.name,COALESCE(claim.site_id,claim.stream_id),
		COALESCE(task.site_id,task.stream_id),operation.operation,
		dns_reconcile_operation_digest_089(operation.operation),anchor.revision,
		task.provider_mutation_site_revision,task.provider_mutation_site_config_digest,
		anchor.config_digest,zone.revision,provider.revision,
		dns_reconcile_provider_config_digest_089(zone,provider),
		dns_reconcile_credential_digest_089(provider.credential_key_id,provider.credential_ciphertext)
	FROM dns_reconcile_provider_mutation_claims claim
	JOIN dns_reconcile_operations operation
	  ON operation.tenant_id=claim.tenant_id AND operation.job_id=claim.job_id
	 AND operation.phase=claim.phase AND operation.ordinal=claim.operation_ordinal
	JOIN dns_reconcile_tasks task
	  ON task.tenant_id=operation.tenant_id AND task.job_id=operation.job_id
	JOIN dns_zones zone
	  ON zone.scope_id=task.tenant_scope_id AND zone.id=task.zone_id AND zone.id=claim.zone_id
	JOIN dns_providers provider
	  ON provider.scope_id=zone.scope_id AND provider.id=zone.provider_id AND provider.id=claim.provider_id
	-- The task's anchor (migration 507): its site, or its stream.
	CROSS JOIN LATERAL dns_reconcile_anchor_507(task.tenant_scope_id,task.site_id,task.stream_id,zone,provider) anchor
	WHERE claim.tenant_id=$1 AND claim.client_request_id=$2
	  AND claim.site_id IS NOT DISTINCT FROM task.site_id AND claim.stream_id IS NOT DISTINCT FROM task.stream_id
	FOR UPDATE OF claim,operation,task NOWAIT`, mutation.TenantID, mutation.ClientRequestID).Scan(
		&claim.JobID, &claim.Phase, &claim.OperationOrdinal, &claim.ClaimID, &state,
		&claim.LeaseExpiresAt, &recoveryNotBefore, &claim.RecoveryReady, &claim.SiteRevision,
		&claim.Revision, &claim.ProviderRevision, &siteConfigDigest, &operationDigest,
		&authorityDigest, &configDigest, &credentialDigest, &claim.ProviderRequestID,
		&claim.ProviderRecordID, &claim.FinalRevision, &claim.Config.TenantScopeID,
		&claim.Config.ProviderID, &claim.Config.ProviderType, &claim.Config.ZoneID,
		&claim.Config.ZoneName, &claimSiteID, &taskSiteID, &operationJSON, &boundOperationDigest,
		&liveSiteRevision, &taskSiteRevision, &taskSiteConfigDigest, &liveSiteConfigDigest,
		&liveZoneRevision, &liveProviderRevision, &liveConfigDigest, &liveCredentialDigest,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return dnsproviderremote.MutationClaim{}, false, nil
	}
	if err != nil {
		return dnsproviderremote.MutationClaim{}, false, err
	}
	claim.State = dnsproviderremote.MutationClaimState(state)
	if recoveryNotBefore != nil {
		claim.RecoveryNotBefore = *recoveryNotBefore
	}
	if !copyClaimDigest(&claim.SiteConfigDigest, siteConfigDigest) ||
		!copyClaimDigest(&claim.OperationDigest, operationDigest) ||
		!copyClaimDigest(&claim.AuthorityDigest, authorityDigest) ||
		!copyClaimDigest(&claim.ProviderConfigDigest, configDigest) ||
		!copyClaimDigest(&claim.CredentialDigest, credentialDigest) {
		return dnsproviderremote.MutationClaim{}, false, dnscheck.ErrProviderRevisionConflict
	}
	var operation dnscheck.ProviderOperation
	if json.Unmarshal(operationJSON, &operation) != nil || operation != mutation.Operation ||
		claimSiteID != mutation.SiteID || taskSiteID != mutation.SiteID ||
		claim.Config.ZoneID != mutation.ZoneID || claim.Revision != mutation.ExpectedRevision ||
		claim.SiteRevision != taskSiteRevision || claim.SiteRevision != liveSiteRevision ||
		claim.ProviderRevision != liveProviderRevision ||
		claim.ProviderRequestID != dnsproviderremote.ProviderMutationRequestID(mutation.ClientRequestID) ||
		len(boundOperationDigest) != sha256.Size || subtle.ConstantTimeCompare(
		claim.OperationDigest[:], boundOperationDigest) != 1 ||
		subtle.ConstantTimeCompare(claim.SiteConfigDigest[:], taskSiteConfigDigest) != 1 ||
		subtle.ConstantTimeCompare(claim.SiteConfigDigest[:], liveSiteConfigDigest) != 1 ||
		subtle.ConstantTimeCompare(claim.ProviderConfigDigest[:], liveConfigDigest) != 1 ||
		subtle.ConstantTimeCompare(claim.CredentialDigest[:], liveCredentialDigest) != 1 {
		return dnsproviderremote.MutationClaim{}, false, dnscheck.ErrProviderRevisionConflict
	}
	if claim.State == dnsproviderremote.MutationSucceeded {
		if claim.ProviderRecordID == "" || claim.FinalRevision != claim.Revision+1 ||
			liveZoneRevision != claim.FinalRevision {
			return dnsproviderremote.MutationClaim{}, false, dnscheck.ErrProviderRevisionConflict
		}
	} else if liveZoneRevision != claim.Revision ||
		(claim.State == dnsproviderremote.MutationConflict && claim.FinalRevision != claim.Revision) {
		return dnsproviderremote.MutationClaim{}, false, dnscheck.ErrProviderRevisionConflict
	}
	return claim, true, nil
}

func loadMutationClaimAuthority(ctx context.Context, tx pgx.Tx,
	mutation dnscheck.ProviderMutation) (dnsproviderremote.MutationClaim, dnscheck.ProviderOperation, string, []byte, error) {
	var claim dnsproviderremote.MutationClaim
	var operation dnscheck.ProviderOperation
	var operationJSON []byte
	var keyID string
	var ciphertext []byte
	var siteConfigDigest, operationDigest, authorityDigest, configDigest, credentialDigest []byte
	err := tx.QueryRow(ctx, `SELECT zone.revision,anchor.revision,provider.revision,scope.id,provider.id,
		provider.provider_type,zone.id,zone.name,COALESCE(zone.provider_zone_apex,''),provider.credential_key_id,
		provider.credential_ciphertext,operation.job_id,operation.phase,operation.ordinal,
		operation.operation,dns_reconcile_operation_digest_089(operation.operation),
		anchor.config_digest,anchor.authority_digest,
		dns_reconcile_provider_config_digest_089(zone,provider),
		dns_reconcile_credential_digest_089(provider.credential_key_id,provider.credential_ciphertext)
	FROM dns_reconcile_operations operation
	JOIN dns_reconcile_tasks task
	  ON task.tenant_id=operation.tenant_id AND task.job_id=operation.job_id
	JOIN access_scopes scope
	  ON scope.id=task.tenant_scope_id AND scope.kind='tenant' AND scope.tenant_id=task.tenant_id
	JOIN tenants tenant ON tenant.id=scope.tenant_id AND tenant.status='active'
	JOIN dns_zones zone ON zone.scope_id=scope.id AND zone.id=task.zone_id AND zone.id=$4
	JOIN dns_providers provider
	  ON provider.scope_id=zone.scope_id AND provider.id=zone.provider_id AND provider.status='verified'
	 AND provider.credential_revoked=false AND provider.credential_version>0
	JOIN users creator ON creator.id=provider.created_by_user_id AND creator.status='active'
	 AND `+tenantaccess.ActorOnTenantSQL("creator.id", "scope.id")+`
	-- The task's anchor (migration 507): a live site, or a live stream with its own CNAME.
	CROSS JOIN LATERAL dns_reconcile_anchor_507(task.tenant_scope_id,task.site_id,task.stream_id,zone,provider) anchor
	WHERE operation.tenant_id=$1 AND operation.client_request_id=$2
	  AND COALESCE(task.site_id,task.stream_id)=$3
	  AND anchor.revision=task.provider_mutation_site_revision
	  AND anchor.config_digest=task.provider_mutation_site_config_digest
	FOR UPDATE OF operation,task,zone,provider`, mutation.TenantID, mutation.ClientRequestID,
		mutation.SiteID, mutation.ZoneID).Scan(
		&claim.Revision, &claim.SiteRevision, &claim.ProviderRevision, &claim.Config.TenantScopeID,
		&claim.Config.ProviderID, &claim.Config.ProviderType, &claim.Config.ZoneID,
		&claim.Config.ZoneName, &claim.Config.ProviderZoneName, &keyID, &ciphertext, &claim.JobID, &claim.Phase,
		&claim.OperationOrdinal, &operationJSON, &operationDigest, &siteConfigDigest, &authorityDigest,
		&configDigest, &credentialDigest,
	)
	if err != nil || json.Unmarshal(operationJSON, &operation) != nil ||
		!copyClaimDigest(&claim.SiteConfigDigest, siteConfigDigest) ||
		!copyClaimDigest(&claim.OperationDigest, operationDigest) ||
		!copyClaimDigest(&claim.AuthorityDigest, authorityDigest) ||
		!copyClaimDigest(&claim.ProviderConfigDigest, configDigest) ||
		!copyClaimDigest(&claim.CredentialDigest, credentialDigest) {
		clear(ciphertext)
		return dnsproviderremote.MutationClaim{}, dnscheck.ProviderOperation{}, "", nil,
			firstClaimError(err)
	}
	return claim, operation, keyID, ciphertext, nil
}

func sameMutationClaimAuthority(left, right dnsproviderremote.MutationClaim) bool {
	return left.JobID == right.JobID && left.Phase == right.Phase &&
		left.OperationOrdinal == right.OperationOrdinal && left.Revision == right.Revision &&
		left.SiteRevision == right.SiteRevision && left.ProviderRevision == right.ProviderRevision &&
		left.Config.TenantScopeID == right.Config.TenantScopeID &&
		left.Config.ProviderID == right.Config.ProviderID && left.Config.ProviderType == right.Config.ProviderType &&
		left.Config.ZoneID == right.Config.ZoneID && left.Config.ZoneName == right.Config.ZoneName &&
		subtle.ConstantTimeCompare(left.OperationDigest[:], right.OperationDigest[:]) == 1 &&
		subtle.ConstantTimeCompare(left.SiteConfigDigest[:], right.SiteConfigDigest[:]) == 1 &&
		subtle.ConstantTimeCompare(left.AuthorityDigest[:], right.AuthorityDigest[:]) == 1 &&
		subtle.ConstantTimeCompare(left.ProviderConfigDigest[:], right.ProviderConfigDigest[:]) == 1 &&
		subtle.ConstantTimeCompare(left.CredentialDigest[:], right.CredentialDigest[:]) == 1
}

func copyClaimDigest(target *[sha256.Size]byte, source []byte) bool {
	if len(source) != sha256.Size {
		return false
	}
	copy(target[:], source)
	return true
}

func validMutationClaimCall(source *Source, ctx context.Context, mutation dnscheck.ProviderMutation,
	claim dnsproviderremote.MutationClaim) bool {
	return source != nil && source.pool != nil && ctx != nil && mutation.TenantID != uuid.Nil &&
		mutation.SiteID != uuid.Nil && mutation.ZoneID != uuid.Nil && mutation.ClientRequestID != "" &&
		claim.ClaimID != uuid.Nil && claim.Config.ZoneID == mutation.ZoneID &&
		claim.SiteRevision > 0 && claim.Revision == mutation.ExpectedRevision &&
		claim.ProviderRequestID == dnsproviderremote.ProviderMutationRequestID(mutation.ClientRequestID) &&
		sameMutationClaimAuthority(claim, claim)
}

func firstClaimError(err error) error {
	if err != nil {
		return err
	}
	return dnscheck.ErrProviderRevisionConflict
}

func mapClaimError(err error) error {
	if err == nil || errors.Is(err, dnscheck.ErrProviderRevisionConflict) {
		return err
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && (pgErr.Code == "P8902" || pgErr.Code == "P8903" || pgErr.Code == "23505") {
		return dnscheck.ErrProviderRevisionConflict
	}
	return ErrUnavailable
}

func reconcileScopeQuery(lock bool) string {
	query := `
		SELECT zone.revision,scope.id,provider.id,provider.provider_type,zone.name,
		       provider.credential_key_id,provider.credential_ciphertext,COALESCE(zone.provider_zone_apex,'')
		FROM dns_zones zone
		JOIN dns_providers provider ON provider.scope_id=zone.scope_id AND provider.id=zone.provider_id
		JOIN access_scopes scope ON scope.id=zone.scope_id AND scope.kind='tenant'
		JOIN tenants tenant ON tenant.id=scope.tenant_id AND tenant.status='active'
		-- $2 is the anchor (migration 507): a live site or a live stream of the scope.
		JOIN LATERAL (SELECT 1 FROM sites site WHERE site.scope_id=scope.id AND site.id=$2 AND site.deleted_at IS NULL
			UNION ALL SELECT 1 FROM l4_forwards forward WHERE forward.scope_id=scope.id AND forward.id=$2
			AND forward.deleted_at IS NULL LIMIT 1) anchor ON true
		JOIN users creator ON creator.id=provider.created_by_user_id AND creator.status='active'
		 AND ` + tenantaccess.ActorOnTenantSQL("creator.id", "scope.id") + `
		WHERE scope.tenant_id=$1 AND zone.id=$3 AND provider.status='verified'
		  AND provider.credential_revoked=false AND provider.credential_version>0`
	if lock {
		query += " FOR UPDATE OF zone"
	}
	return query
}

// zoneApexClaimError keeps a not-hosted zone a permanent provider failure
// (dns_zone_not_hosted on the job); anything else is retried.
func zoneApexClaimError(err error) error {
	if dnsproviderremote.ErrorCodeOf(err) == dnsproviderremote.CodeZoneNotHosted {
		return &dnscheck.ProviderError{Class: dnscheck.ProviderErrorPermanent, Code: string(dnsproviderremote.CodeZoneNotHosted)}
	}
	return ErrUnavailable
}

func clearCredentials(credentials map[string]string) {
	for key := range credentials {
		credentials[key] = ""
		delete(credentials, key)
	}
}

var _ dnsproviderremote.RevisionAuthority = (*Source)(nil)
var _ dnsproviderremote.MutationCredentialLeaseAuthority = (*Source)(nil)
