//go:build integration

package main

import (
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/dnscheck"
	"github.com/cdnca/cdnca/services/control-api/internal/dnsreconcile"
	"github.com/cdnca/cdnca/services/control-api/internal/jobstate"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
)

// (N8): a DNS reconcile task that failed for good (N5: the
// provider's answer could not be decoded, operation permanent_failed) left its
// apply claim uncertain, and 089 then refused every change of the site. While
// the claim is held, 475 only refuses changes of the claim's binding
// (revision, digest columns); once the job is terminal and nothing recovers
// the claim, the recovery runner finalizes it (conflict) and the site is
// writable again.
func TestDNSReconcileRuntimeFinalizesAbandonedUncertainClaim(t *testing.T) {
	pool := newDashboardCompositionTestPool(t)
	fixture := seedDNSRuntimeRecovery(t, pool, 1)
	claimID := uuid.New()
	if _, err := pool.Exec(t.Context(), `INSERT INTO dns_reconcile_provider_mutation_claims(
		tenant_id,client_request_id,job_id,phase,operation_ordinal,site_id,zone_id,provider_id,
		claim_id,lease_expires_at,state,expected_site_revision,expected_zone_revision,
		expected_provider_revision,site_config_digest,operation_digest,authority_digest,
		provider_config_digest,credential_digest,provider_request_id,claimed_at
	) SELECT operation.tenant_id,operation.client_request_id,operation.job_id,operation.phase,
		operation.ordinal,task.site_id,task.zone_id,provider.id,$1,statement_timestamp()+interval '2 minutes',
		'claimed',site.revision,zone.revision,provider.revision,
		dns_reconcile_site_config_digest_089(site),dns_reconcile_operation_digest_089(operation.operation),
		dns_reconcile_authority_digest_089(task.tenant_scope_id,site,zone,provider),
		dns_reconcile_provider_config_digest_089(zone,provider),
		dns_reconcile_credential_digest_089(provider.credential_key_id,provider.credential_ciphertext),
		$4,statement_timestamp()
	FROM dns_reconcile_operations operation
	JOIN dns_reconcile_tasks task ON task.tenant_id=operation.tenant_id AND task.job_id=operation.job_id
	JOIN sites site ON site.scope_id=task.tenant_scope_id AND site.id=task.site_id
	JOIN dns_zones zone ON zone.scope_id=task.tenant_scope_id AND zone.id=task.zone_id
	JOIN dns_providers provider ON provider.scope_id=zone.scope_id AND provider.id=zone.provider_id
	WHERE operation.tenant_id=$2 AND operation.client_request_id=$3`, claimID,
		fixture.tenantID, fixture.clientRequestID, fixture.providerRequestID); err != nil {
		t.Fatal(err)
	}
	// The mutation outcome became unknown (MarkMutationUncertain).
	if _, err := pool.Exec(t.Context(), `UPDATE dns_reconcile_provider_mutation_claims
		SET state='uncertain',lease_expires_at=clock_timestamp()
		WHERE tenant_id=$1 AND client_request_id=$2 AND claim_id=$3`,
		fixture.tenantID, fixture.clientRequestID, claimID); err != nil {
		t.Fatal(err)
	}

	assertCode := func(err error, want string) {
		t.Helper()
		var pgErr *pgconn.PgError
		if !errors.As(err, &pgErr) || pgErr.Code != want {
			t.Fatalf("error=%v, want SQLSTATE %s", err, want)
		}
	}
	// 475 while the claim is held: the binding is pinned, runtime columns are not.
	_, err := pool.Exec(t.Context(), `UPDATE sites SET cache_status_header=false,revision=revision+1 WHERE id=$1`, fixture.siteID)
	assertCode(err, "P8903")
	_, err = pool.Exec(t.Context(), `UPDATE sites SET domain='changed.example.test' WHERE id=$1`, fixture.siteID)
	assertCode(err, "P8903")
	_, err = pool.Exec(t.Context(), `DELETE FROM sites WHERE id=$1`, fixture.siteID)
	assertCode(err, "P8903")
	if _, err := pool.Exec(t.Context(), `UPDATE sites SET ipv6_runtime_state='failed',updated_at=clock_timestamp()
		WHERE id=$1`, fixture.siteID); err != nil {
		t.Fatalf("runtime projection under an active claim: %v", err)
	}

	// The job fails for good; the operation is permanent_failed (N5).
	jobs, err := jobstate.NewStore(pool, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	claims, err := jobs.Claim(t.Context(), jobstate.ClaimInput{
		TenantID: fixture.tenantID, Kind: dnsreconcile.JobKind, WorkerID: "dns-abandoned-test",
		Limit: 1, LeaseDuration: time.Minute,
	})
	if err != nil || len(claims) != 1 {
		t.Fatalf("claim job=(%+v,%v)", claims, err)
	}
	if _, err := jobs.Report(t.Context(), jobstate.ReportInput{
		TenantID: fixture.tenantID, JobID: fixture.jobID, WorkerID: claims[0].WorkerID,
		LeaseID: claims[0].LeaseID, Report: jobstate.Report{
			ItemID: dnsreconcile.JobItemID, State: jobstate.ItemFailed,
			Code: "all_items_failed", Attempt: claims[0].Job.Attempt, Sequence: 1,
		},
	}); err != nil {
		t.Fatal(err)
	}
	operation := dnscheck.ProviderOperation{
		Sequence: 1, Action: dnscheck.ProviderCreate, Name: "www.example.test.",
		Type: dnscheck.RecordA, Value: "192.0.2.10", TTL: 300, Reason: "missing_record",
	}
	resultJSON, err := json.Marshal(dnscheck.ReconcileResult{
		TenantID: fixture.tenantID, SiteID: fixture.siteID, ZoneID: fixture.zoneID,
		Status: dnscheck.TaskFailed, InitialRevision: 1, ProviderRevision: 1,
		ErrorClass: dnscheck.ProviderErrorPermanent, ErrorCode: "dns_provider_remote_invalid_response",
		Operations: []dnscheck.OperationResult{{
			SourceSequence: 1, Operation: operation, ClientRequestID: fixture.clientRequestID,
			ProviderRequestID: fixture.providerRequestID, Status: dnscheck.OperationPermanentFailed,
			ErrorClass: dnscheck.ProviderErrorPermanent, ErrorCode: "dns_provider_remote_invalid_response",
			ReportSequence: 2, Attempts: 2,
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO dns_reconcile_task_events(
		tenant_id,job_id,event_sequence,source,status,provider_revision,result_snapshot,
		compensation_plan,error_class,error_code,occurred_at
	) VALUES($1,$2,1,'control','failed',1,$3,'[]'::jsonb,'permanent',
		'dns_provider_remote_invalid_response',clock_timestamp())`, fixture.tenantID, fixture.jobID, resultJSON); err != nil {
		t.Fatal(err)
	}

	pending, err := dnsreconcile.NewPostgresTenantSource(pool)
	if err != nil {
		t.Fatal(err)
	}
	source := &dnsReconcileRecoveryTenantSource{pool: pool, pending: pending}
	tenants, err := source.PendingTenants(t.Context(), 100)
	if err != nil || !containsDNSRuntimeTenant(tenants, fixture.tenantID) {
		t.Fatalf("pending tenants=%v err=%v, want the tenant with the abandoned claim", tenants, err)
	}
	runner := &dnsReconcileRecoveryRunner{source: source, providers: fixedDNSRecoveryProviderResolver{}}
	if err := runner.recoverDueUncertain(t.Context(), fixture.tenantID, 10); err != nil {
		t.Fatal(err)
	}
	var state string
	var finalized bool
	if err := pool.QueryRow(t.Context(), `SELECT state,finalized_at IS NOT NULL
		FROM dns_reconcile_provider_mutation_claims WHERE tenant_id=$1 AND client_request_id=$2`,
		fixture.tenantID, fixture.clientRequestID).Scan(&state, &finalized); err != nil {
		t.Fatal(err)
	}
	if state != "conflict" || !finalized {
		t.Fatalf("claim state=%s finalized=%v, want conflict/true", state, finalized)
	}
	if _, err := pool.Exec(t.Context(), `UPDATE sites SET cache_status_header=false,revision=revision+1 WHERE id=$1`,
		fixture.siteID); err != nil {
		t.Fatalf("site update after the abandoned claim was finalized: %v", err)
	}
	// Idempotent: a second pass finds nothing to finalize.
	if err := runner.recoverDueUncertain(t.Context(), fixture.tenantID, 10); err != nil {
		t.Fatal(err)
	}
}
