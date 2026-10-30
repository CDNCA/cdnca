//go:build integration

package migrations_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/dnscheck"
	"github.com/cdnca/cdnca/services/control-api/internal/dnsproviderremote"
	"github.com/cdnca/cdnca/services/control-api/internal/dnsreconcile"
	"github.com/cdnca/cdnca/services/control-api/internal/jobstate"
	controlmigrations "github.com/cdnca/cdnca/services/control-api/migrations"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

const dnsProviderClaims089ID = "089_dns_reconcile_provider_mutation_claims"

func TestDNSReconcileProviderMutationClaims089PinsApproved088(t *testing.T) {
	for _, test := range []struct {
		name, file, want string
	}{
		{name: "up", file: "088_security_policy_activation.up.sql", want: "8cf9d78bbbb8156315b0b4dcd3ec2be0bd6c679dc65ee7c404447a1f7bdd5109"},
		{name: "down", file: "088_security_policy_activation.down.sql", want: "45597d926740c8ccadb059fbefcc97837df4d462f33e3123b37c5f5ec38b9132"},
	} {
		t.Run(test.name, func(t *testing.T) {
			value, err := fs.ReadFile(controlmigrations.FS, test.file)
			if err != nil {
				t.Fatal(err)
			}
			if got := fmt.Sprintf("%x", sha256.Sum256(value)); got != test.want {
				t.Fatalf("088 %s sha256=%s, want %s", test.name, got, test.want)
			}
		})
	}
}

func TestDNSReconcileProviderMutationClaims089MigrationContract(t *testing.T) {
	up, err := fs.ReadFile(controlmigrations.FS, dnsProviderClaims089ID+".up.sql")
	if err != nil {
		t.Fatal(err)
	}
	down, err := fs.ReadFile(controlmigrations.FS, dnsProviderClaims089ID+".down.sql")
	if err != nil {
		t.Fatal(err)
	}
	upText, downText := string(up), string(down)
	for _, required := range []string{
		"dns_reconcile_provider_mutation_claims", "tenant_id", "client_request_id", "job_id",
		"phase", "operation_ordinal", "site_id", "zone_id", "provider_id", "claim_id",
		"lease_expires_at", "recovery_not_before", "state", "expected_site_revision",
		"expected_zone_revision", "expected_provider_revision", "site_config_digest",
		"operation_digest", "authority_digest", "provider_config_digest", "credential_digest",
		"provider_request_id", "provider_record_id", "final_zone_revision", "claimed_at", "finalized_at",
		"claimed", "uncertain", "succeeded", "not_applied", "conflict",
		"P8900", "P8902", "P8903", "CREATE UNIQUE INDEX", "WHERE state IN ('claimed','uncertain')",
		"provider_mutation_site_revision", "provider_mutation_site_config_digest",
		"dns_reconcile_site_config_digest_089", "sites_provider_mutation_claim_guard_089",
		"cdnca:dns-reconcile:site-authority:v1",
		"OLD.state='uncertain' AND NEW.state='not_applied'",
		"NEW.recovery_not_before:=clock_timestamp()+interval'2 minutes'",
		"OLD.recovery_not_before<=clock_timestamp()",
		"DEFERRABLE INITIALLY DEFERRED", "final_zone_revision=NEW.expected_zone_revision+1",
		"provider_request_id IS DISTINCT FROM OLD.provider_request_id",
		"REFERENCES dns_reconcile_operations(tenant_id,job_id,phase,ordinal)",
		"BEFORE UPDATE OR DELETE ON dns_zones", "BEFORE UPDATE OR DELETE ON dns_providers",
		"BEFORE INSERT OR UPDATE OR DELETE ON dns_reconcile_provider_mutation_claims",
		"BEFORE TRUNCATE ON dns_reconcile_provider_mutation_claims",
		"dns_reconcile_background_job_recovery_retry_089", "previous_job.max_attempts+1",
		"WHEN (NOT dns_reconcile_background_job_recovery_retry_089(OLD,NEW))",
		"dns_reconcile_provider_recovery_continuations", "continuation_attempt",
		"previous_item_attempt", "previous_item_sequence", "result_attempts",
		"recovery_event_sequence", "recovery_result_digest",
		"dns_reconcile_provider_recovery_leases", "recovery_lease_id",
		"dns_reconcile_background_job_item_recovery_retry_089",
	} {
		if !strings.Contains(strings.ReplaceAll(upText, " ", ""), strings.ReplaceAll(required, " ", "")) {
			t.Errorf("089 up missing %q", required)
		}
	}
	if strings.Contains(upText, "to_jsonb(checked_site)") {
		t.Error("089 site authority digest still depends on the sites composite layout")
	}
	for _, required := range []string{
		"migration 089 rollback requires the verified 089 head", "P8900",
		"migration 089 rollback would discard DNS provider mutation claim facts", "P8901",
		"LOCK TABLE", "dns_reconcile_provider_mutation_claims", "DROP TABLE dns_reconcile_provider_mutation_claims",
		"DROP FUNCTION dns_reconcile_background_job_recovery_retry_089(background_jobs,background_jobs)",
		"DROP TABLE dns_reconcile_provider_recovery_continuations",
		"DROP TABLE dns_reconcile_provider_recovery_leases",
		"DROP FUNCTION dns_reconcile_background_job_item_recovery_retry_089(background_job_items,background_job_items)",
		"FOR EACH ROW EXECUTE FUNCTION protect_background_job()",
	} {
		if !strings.Contains(downText, required) {
			t.Errorf("089 down missing %q", required)
		}
	}
}

func TestDNSReconcileProviderMutationClaims089ContinuationRejectsDirectAbuse(t *testing.T) {
	pool := releaseHeadMigrationPool(t)
	fixture := seedDNSProviderClaim089WithAttempts(t, pool, "continuation-abuse", 1)
	jobs, err := jobstate.NewStore(pool, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	claimed, err := jobs.Claim(t.Context(), jobstate.ClaimInput{
		TenantID: fixture.tenantID, Kind: dnsreconcile.JobKind, WorkerID: "dns089-continuation",
		Limit: 1, LeaseDuration: time.Minute,
	})
	if err != nil || len(claimed) != 1 {
		t.Fatalf("claim job=(%+v,%v)", claimed, err)
	}
	if _, err := jobs.Report(t.Context(), jobstate.ReportInput{
		TenantID: fixture.tenantID, JobID: fixture.jobID, WorkerID: claimed[0].WorkerID,
		LeaseID: claimed[0].LeaseID, Report: jobstate.Report{
			ItemID: dnsreconcile.JobItemID, State: jobstate.ItemFailed,
			Code: "provider_recovery_pending", Attempt: 1, Sequence: 7,
		},
	}); err != nil {
		t.Fatal(err)
	}
	operation := dnscheck.ProviderOperation{
		Sequence: 1, Action: dnscheck.ProviderCreate, Name: "www.example.test.",
		Type: dnscheck.RecordA, Value: "192.0.2.10", TTL: 300, Reason: "missing_record",
	}
	result := dnscheck.ReconcileResult{
		TenantID: fixture.tenantID, SiteID: fixture.siteID, ZoneID: fixture.zoneID,
		Status: dnscheck.TaskFailed, InitialRevision: 1, ProviderRevision: 1,
		ErrorClass: dnscheck.ProviderErrorTransient, ErrorCode: "provider_recovery_pending",
		Operations: []dnscheck.OperationResult{{
			SourceSequence: 1, Operation: operation, ClientRequestID: fixture.clientRequestID,
			ProviderRequestID: dnsproviderremote.ProviderMutationRequestID(fixture.clientRequestID),
			Status:            dnscheck.OperationTransientFailed, ErrorClass: dnscheck.ProviderErrorTransient,
			ErrorCode: "provider_recovery_pending", ReportSequence: 7, Attempts: 3,
		}},
	}
	resultJSON, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO dns_reconcile_task_events(
		tenant_id,job_id,event_sequence,source,status,provider_revision,result_snapshot,
		compensation_plan,error_class,error_code,occurred_at)
		VALUES($1,$2,1,'control','failed',1,$3,'[]'::jsonb,'transient',
		'provider_recovery_pending',clock_timestamp())`, fixture.tenantID, fixture.jobID, resultJSON); err != nil {
		t.Fatal(err)
	}
	claimID := insertDNSProviderClaim089(t, pool, fixture)
	if _, err := pool.Exec(t.Context(), `UPDATE dns_reconcile_provider_mutation_claims
		SET state='conflict',lease_expires_at=clock_timestamp(),final_zone_revision=expected_zone_revision,
		    finalized_at=clock_timestamp()
		WHERE tenant_id=$1 AND client_request_id=$2 AND claim_id=$3`,
		fixture.tenantID, fixture.clientRequestID, claimID); err != nil {
		t.Fatal(err)
	}

	for _, test := range []struct {
		name  string
		query string
		args  []any
	}{
		{name: "job update without fact", query: `UPDATE background_jobs SET state='queued',
			max_attempts=max_attempts+1,completed_count=succeeded_count,failed_count=0,
			lease_id=NULL,lease_owner=NULL,lease_expires_at=NULL,claimable_at=clock_timestamp(),
			last_error_code=NULL,completed_at=NULL,updated_at=clock_timestamp()
			WHERE tenant_id=$1 AND id=$2`, args: []any{fixture.tenantID, fixture.jobID}},
		{name: "cross job fact", query: `INSERT INTO dns_reconcile_provider_recovery_continuations(
			tenant_id,client_request_id,claim_id,job_id,continuation_attempt,
			previous_item_attempt,previous_item_sequence,result_attempts,event_sequence,
			recovery_event_sequence,recovery_result_digest,granted_at)
			VALUES($1,$2,$3,$4,2,1,7,3,1,2,decode(repeat('0',64),'hex'),clock_timestamp())`,
			args: []any{fixture.tenantID, fixture.clientRequestID, claimID, uuid.New()}},
		{name: "cross tenant fact", query: `INSERT INTO dns_reconcile_provider_recovery_continuations(
			tenant_id,client_request_id,claim_id,job_id,continuation_attempt,
			previous_item_attempt,previous_item_sequence,result_attempts,event_sequence,
			recovery_event_sequence,recovery_result_digest,granted_at)
			VALUES($1,$2,$3,$4,2,1,7,3,1,2,decode(repeat('0',64),'hex'),clock_timestamp())`,
			args: []any{uuid.New(), fixture.clientRequestID, claimID, fixture.jobID}},
	} {
		t.Run(test.name, func(t *testing.T) {
			tx, err := pool.Begin(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback(context.Background())
			_, err = tx.Exec(t.Context(), test.query, test.args...)
			assertDNSProviderClaimCode089(t, err, "P8902")
		})
	}
	insertContinuation := `INSERT INTO dns_reconcile_provider_recovery_continuations(
		tenant_id,client_request_id,claim_id,job_id,continuation_attempt,
		previous_item_attempt,previous_item_sequence,result_attempts,event_sequence,
		recovery_event_sequence,recovery_result_digest,granted_at)
		VALUES($1,$2,$3,$4,2,1,7,3,1,2,decode(repeat('0',64),'hex'),clock_timestamp())`
	repeatTx, err := pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repeatTx.Exec(t.Context(), insertContinuation,
		fixture.tenantID, fixture.clientRequestID, claimID, fixture.jobID); err != nil {
		t.Fatal(err)
	}
	_, err = repeatTx.Exec(t.Context(), insertContinuation,
		fixture.tenantID, fixture.clientRequestID, claimID, fixture.jobID)
	assertDNSProviderClaimCode089(t, err, "P8902")
	_ = repeatTx.Rollback(context.Background())

	nonterminal := seedDNSProviderClaim089WithAttempts(t, pool, "continuation-nonterminal", 1)
	nonterminalClaimID := insertDNSProviderClaim089(t, pool, nonterminal)
	_, err = pool.Exec(t.Context(), insertContinuation, nonterminal.tenantID, nonterminal.clientRequestID,
		nonterminalClaimID, nonterminal.jobID)
	assertDNSProviderClaimCode089(t, err, "P8902")

	revisionTx, err := pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := revisionTx.Exec(t.Context(), `UPDATE dns_zones SET revision=revision+1 WHERE id=$1`,
		fixture.zoneID); err != nil {
		t.Fatal(err)
	}
	_, err = revisionTx.Exec(t.Context(), insertContinuation,
		fixture.tenantID, fixture.clientRequestID, claimID, fixture.jobID)
	assertDNSProviderClaimCode089(t, err, "P8902")
	_ = revisionTx.Rollback(context.Background())

	tx, err := pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(context.Background())
	if _, err := tx.Exec(t.Context(), `INSERT INTO dns_reconcile_provider_recovery_continuations(
		tenant_id,client_request_id,claim_id,job_id,continuation_attempt,
		previous_item_attempt,previous_item_sequence,result_attempts,event_sequence,
		recovery_event_sequence,recovery_result_digest,granted_at)
		VALUES($1,$2,$3,$4,2,1,7,3,1,2,decode(repeat('0',64),'hex'),clock_timestamp())`,
		fixture.tenantID, fixture.clientRequestID, claimID, fixture.jobID); err != nil {
		t.Fatal(err)
	}
	_, err = tx.Exec(t.Context(), `UPDATE background_jobs SET state='queued',max_attempts=max_attempts+1,
		completed_count=succeeded_count,failed_count=0,lease_id=NULL,lease_owner=NULL,lease_expires_at=NULL,
		claimable_at=clock_timestamp()+interval '1 minute',last_error_code=NULL,completed_at=NULL,
		updated_at=clock_timestamp()+interval '1 minute' WHERE tenant_id=$1 AND id=$2`,
		fixture.tenantID, fixture.jobID)
	assertDNSProviderClaimCode089(t, err, "P8902")
}

func TestDNSReconcileProviderMutationClaims089ContinuationRequiresRecoveryEvent(t *testing.T) {
	pool := releaseHeadMigrationPool(t)
	fixture := seedDNSProviderClaim089WithAttempts(t, pool, "continuation-event", 1)
	jobs, err := jobstate.NewStore(pool, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	claimed, err := jobs.Claim(t.Context(), jobstate.ClaimInput{
		TenantID: fixture.tenantID, Kind: dnsreconcile.JobKind,
		WorkerID: "dns089-continuation-event", Limit: 1, LeaseDuration: time.Minute,
	})
	if err != nil || len(claimed) != 1 {
		t.Fatalf("claim job=(%+v,%v)", claimed, err)
	}
	if _, err := jobs.Report(t.Context(), jobstate.ReportInput{
		TenantID: fixture.tenantID, JobID: fixture.jobID, WorkerID: claimed[0].WorkerID,
		LeaseID: claimed[0].LeaseID, Report: jobstate.Report{
			ItemID: dnsreconcile.JobItemID, State: jobstate.ItemFailed,
			Code: "provider_recovery_pending", Attempt: 1, Sequence: 7,
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
		ErrorClass: dnscheck.ProviderErrorTransient, ErrorCode: "provider_recovery_pending",
		Operations: []dnscheck.OperationResult{{
			SourceSequence: 1, Operation: operation, ClientRequestID: fixture.clientRequestID,
			ProviderRequestID: dnsproviderremote.ProviderMutationRequestID(fixture.clientRequestID),
			Status:            dnscheck.OperationTransientFailed, ErrorClass: dnscheck.ProviderErrorTransient,
			ErrorCode: "provider_recovery_pending", ReportSequence: 7, Attempts: 3,
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO dns_reconcile_task_events(
		tenant_id,job_id,event_sequence,source,status,provider_revision,result_snapshot,
		compensation_plan,error_class,error_code,occurred_at)
		VALUES($1,$2,1,'control','failed',1,$3,'[]'::jsonb,'transient',
		'provider_recovery_pending',clock_timestamp())`, fixture.tenantID, fixture.jobID, resultJSON); err != nil {
		t.Fatal(err)
	}
	claimID := insertDNSProviderClaim089(t, pool, fixture)
	if _, err := pool.Exec(t.Context(), `UPDATE dns_reconcile_provider_mutation_claims
		SET state='conflict',final_zone_revision=expected_zone_revision,finalized_at=statement_timestamp()
		WHERE tenant_id=$1 AND client_request_id=$2 AND claim_id=$3`,
		fixture.tenantID, fixture.clientRequestID, claimID); err != nil {
		t.Fatal(err)
	}

	tx, err := pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	var grantedAt time.Time
	err = tx.QueryRow(t.Context(), `INSERT INTO dns_reconcile_provider_recovery_continuations(
		tenant_id,client_request_id,claim_id,job_id,continuation_attempt,
		previous_item_attempt,previous_item_sequence,result_attempts,event_sequence,granted_at)
		VALUES($1,$2,$3,$4,2,1,7,3,1,clock_timestamp()) RETURNING granted_at`,
		fixture.tenantID, fixture.clientRequestID, claimID, fixture.jobID).Scan(&grantedAt)
	if err == nil {
		_, err = tx.Exec(t.Context(), `UPDATE background_jobs
			SET state='queued',max_attempts=2,completed_count=succeeded_count,failed_count=0,
			lease_id=NULL,lease_owner=NULL,lease_expires_at=NULL,claimable_at=$3,last_error_code=NULL,
			completed_at=NULL,updated_at=$3 WHERE tenant_id=$1 AND id=$2`,
			fixture.tenantID, fixture.jobID, grantedAt)
	}
	if err == nil {
		_, err = tx.Exec(t.Context(), `UPDATE background_job_items
			SET state='pending',error_code=NULL,completed_at=NULL
			WHERE tenant_id=$1 AND job_id=$2 AND item_id='reconcile'`, fixture.tenantID, fixture.jobID)
	}
	if err == nil {
		_, err = tx.Exec(t.Context(), `UPDATE dns_reconcile_provider_recovery_continuations
			SET consumed_at=clock_timestamp() WHERE tenant_id=$1 AND job_id=$2`,
			fixture.tenantID, fixture.jobID)
	}
	if err == nil {
		err = tx.Commit(t.Context())
	} else {
		_ = tx.Rollback(context.Background())
	}
	assertDNSProviderClaimCode089(t, err, "P8902")
}

func TestDNSReconcileProviderMutationClaims089ContinuationLocksLiveZoneRevisionAtCommit(t *testing.T) {
	pool := releaseHeadMigrationPool(t)
	for _, test := range []struct {
		name             string
		concurrentChange bool
	}{
		{name: "legitimate"},
		{name: "concurrent zone revision", concurrentChange: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := seedDNSProviderClaim089WithAttempts(t, pool,
				"continuation-zone-"+strings.ReplaceAll(test.name, " ", "-"), 1)
			jobs, err := jobstate.NewStore(pool, time.Now)
			if err != nil {
				t.Fatal(err)
			}
			claimed, err := jobs.Claim(t.Context(), jobstate.ClaimInput{
				TenantID: fixture.tenantID, Kind: dnsreconcile.JobKind,
				WorkerID: "dns089-zone-commit", Limit: 1, LeaseDuration: time.Minute,
			})
			if err != nil || len(claimed) != 1 {
				t.Fatalf("claim job=(%+v,%v)", claimed, err)
			}
			if _, err := jobs.Report(t.Context(), jobstate.ReportInput{
				TenantID: fixture.tenantID, JobID: fixture.jobID, WorkerID: claimed[0].WorkerID,
				LeaseID: claimed[0].LeaseID, Report: jobstate.Report{
					ItemID: dnsreconcile.JobItemID, State: jobstate.ItemFailed,
					Code: "provider_recovery_pending", Attempt: 1, Sequence: 7,
				},
			}); err != nil {
				t.Fatal(err)
			}
			operation := dnscheck.ProviderOperation{
				Sequence: 1, Action: dnscheck.ProviderCreate, Name: "www.example.test.",
				Type: dnscheck.RecordA, Value: "192.0.2.10", TTL: 300, Reason: "missing_record",
			}
			operationJSON, err := json.Marshal(operation)
			if err != nil {
				t.Fatal(err)
			}
			connection, err := pool.Acquire(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			if _, err := connection.Exec(t.Context(), `ALTER TABLE dns_reconcile_operations
				DISABLE TRIGGER dns_reconcile_operations_append_only_076`); err != nil {
				connection.Release()
				t.Fatal(err)
			}
			_, updateErr := connection.Exec(t.Context(), `UPDATE dns_reconcile_operations SET operation=$3::jsonb
				WHERE tenant_id=$1 AND job_id=$2 AND phase='apply' AND ordinal=1`,
				fixture.tenantID, fixture.jobID, operationJSON)
			_, resetErr := connection.Exec(t.Context(), `ALTER TABLE dns_reconcile_operations
				ENABLE ALWAYS TRIGGER dns_reconcile_operations_append_only_076`)
			connection.Release()
			if updateErr != nil || resetErr != nil {
				t.Fatalf("prepare continuation operation=(%v,%v)", updateErr, resetErr)
			}
			pendingResult := dnscheck.ReconcileResult{
				TenantID: fixture.tenantID, SiteID: fixture.siteID, ZoneID: fixture.zoneID,
				Status: dnscheck.TaskFailed, InitialRevision: 1, ProviderRevision: 1,
				ErrorClass: dnscheck.ProviderErrorTransient, ErrorCode: "provider_recovery_pending",
				CompensationPlan: []dnscheck.ProviderOperation{},
				Operations: []dnscheck.OperationResult{{
					SourceSequence: 1, Operation: operation, ClientRequestID: fixture.clientRequestID,
					ProviderRequestID: dnsproviderremote.ProviderMutationRequestID(fixture.clientRequestID),
					Status:            dnscheck.OperationTransientFailed, ErrorClass: dnscheck.ProviderErrorTransient,
					ErrorCode: "provider_recovery_pending", ReportSequence: 7, Attempts: 3,
				}},
			}
			pendingJSON, err := json.Marshal(pendingResult)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := pool.Exec(t.Context(), `INSERT INTO dns_reconcile_task_events(
				tenant_id,job_id,event_sequence,source,status,provider_revision,result_snapshot,
				compensation_plan,error_class,error_code,occurred_at)
				VALUES($1,$2,1,'control','failed',1,$3,'[]'::jsonb,'transient',
				'provider_recovery_pending',clock_timestamp())`, fixture.tenantID, fixture.jobID,
				pendingJSON); err != nil {
				t.Fatal(err)
			}
			claimID := insertDNSProviderClaim089(t, pool, fixture)
			if _, err := pool.Exec(t.Context(), `UPDATE dns_reconcile_provider_mutation_claims
				SET state='conflict',final_zone_revision=expected_zone_revision,
				    finalized_at=statement_timestamp()
				WHERE tenant_id=$1 AND client_request_id=$2 AND claim_id=$3`,
				fixture.tenantID, fixture.clientRequestID, claimID); err != nil {
				t.Fatal(err)
			}
			recoveredResult := pendingResult
			recoveredResult.Operations = append([]dnscheck.OperationResult(nil), pendingResult.Operations...)
			recoveredResult.Status = dnscheck.TaskApplying
			recoveredResult.ErrorClass = dnscheck.ProviderErrorNone
			recoveredResult.ErrorCode = ""
			recoveredResult.Operations[0].Status = dnscheck.OperationPlanned
			recoveredResult.Operations[0].ErrorClass = dnscheck.ProviderErrorNone
			recoveredResult.Operations[0].ErrorCode = ""
			recoveredJSON, err := json.Marshal(recoveredResult)
			if err != nil {
				t.Fatal(err)
			}
			tx, err := pool.Begin(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback(context.Background())
			var grantedAt time.Time
			err = tx.QueryRow(t.Context(), `INSERT INTO dns_reconcile_provider_recovery_continuations(
				tenant_id,client_request_id,claim_id,job_id,continuation_attempt,
				previous_item_attempt,previous_item_sequence,result_attempts,event_sequence,
				recovery_event_sequence,recovery_result_digest,granted_at)
				VALUES($1,$2,$3,$4,2,1,7,3,1,2,
				sha256(convert_to($5::jsonb::text,'UTF8')),clock_timestamp()) RETURNING granted_at`,
				fixture.tenantID, fixture.clientRequestID, claimID, fixture.jobID, recoveredJSON).
				Scan(&grantedAt)
			if err == nil {
				_, err = tx.Exec(t.Context(), `UPDATE background_jobs
					SET state='queued',max_attempts=2,completed_count=succeeded_count,failed_count=0,
					lease_id=NULL,lease_owner=NULL,lease_expires_at=NULL,claimable_at=$3,
					last_error_code=NULL,completed_at=NULL,updated_at=$3
					WHERE tenant_id=$1 AND id=$2`, fixture.tenantID, fixture.jobID, grantedAt)
			}
			if err == nil {
				_, err = tx.Exec(t.Context(), `UPDATE background_job_items
					SET state='pending',error_code=NULL,completed_at=NULL
					WHERE tenant_id=$1 AND job_id=$2 AND item_id='reconcile'`,
					fixture.tenantID, fixture.jobID)
			}
			if err == nil {
				_, err = tx.Exec(t.Context(), `INSERT INTO dns_reconcile_task_events(
					tenant_id,job_id,event_sequence,source,status,provider_revision,result_snapshot,
					compensation_plan,error_class,error_code,occurred_at)
					VALUES($1,$2,2,'control','applying',1,$3,'[]'::jsonb,'',NULL,clock_timestamp())`,
					fixture.tenantID, fixture.jobID, recoveredJSON)
			}
			if err == nil {
				_, err = tx.Exec(t.Context(), `UPDATE dns_reconcile_provider_recovery_continuations
					SET consumed_at=clock_timestamp()
					WHERE tenant_id=$1 AND job_id=$2`, fixture.tenantID, fixture.jobID)
			}
			if err != nil {
				_ = tx.Rollback(context.Background())
				t.Fatal(err)
			}
			if test.concurrentChange {
				if _, err := pool.Exec(t.Context(), `UPDATE dns_zones SET revision=revision+1
					WHERE id=$1`, fixture.zoneID); err != nil {
					_ = tx.Rollback(context.Background())
					t.Fatal(err)
				}
			}
			err = tx.Commit(t.Context())
			if !test.concurrentChange {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			assertDNSProviderClaimCode089(t, err, "P8902")
			var jobState, itemState string
			var maxAttempts, eventCount, continuationCount int
			if err := pool.QueryRow(t.Context(), `SELECT job.state,job.max_attempts,item.state,
				(SELECT count(*) FROM dns_reconcile_task_events event
				 WHERE event.tenant_id=job.tenant_id AND event.job_id=job.id),
				(SELECT count(*) FROM dns_reconcile_provider_recovery_continuations continuation
				 WHERE continuation.tenant_id=job.tenant_id AND continuation.job_id=job.id)
				FROM background_jobs job JOIN background_job_items item
				  ON item.tenant_id=job.tenant_id AND item.job_id=job.id AND item.item_id='reconcile'
				WHERE job.tenant_id=$1 AND job.id=$2`, fixture.tenantID, fixture.jobID).
				Scan(&jobState, &maxAttempts, &itemState, &eventCount, &continuationCount); err != nil {
				t.Fatal(err)
			}
			if jobState != "failed" || maxAttempts != 1 || itemState != "failed" ||
				eventCount != 1 || continuationCount != 0 {
				t.Fatalf("rollback job=%s/%d item=%s events=%d continuations=%d",
					jobState, maxAttempts, itemState, eventCount, continuationCount)
			}
		})
	}
}

func TestDNSReconcileProviderMutationClaims089UsesBoundedServerClock(t *testing.T) {
	pool := packageCommerceRBAC079Pool(t, 89)
	const (
		initialLeaseMicros = int64((2 * time.Minute) / time.Microsecond)
		renewalLeaseMicros = int64((17*time.Minute + 30*time.Second) / time.Microsecond)
	)

	t.Run("initial exact", func(t *testing.T) {
		fixture := seedDNSProviderClaim089(t, pool, "clock-initial-exact")
		claimID := uuid.New()
		if err := insertDNSProviderClaim089WithLeaseMicros(t.Context(), pool, fixture, claimID,
			initialLeaseMicros); err != nil {
			t.Fatal(err)
		}
		var leaseMicros int64
		if err := pool.QueryRow(t.Context(), `SELECT extract(epoch FROM lease_expires_at-claimed_at)*1000000
			FROM dns_reconcile_provider_mutation_claims
			WHERE tenant_id=$1 AND client_request_id=$2`, fixture.tenantID, fixture.clientRequestID).
			Scan(&leaseMicros); err != nil || leaseMicros != initialLeaseMicros {
			t.Fatalf("initial lease micros=(%d,%v)", leaseMicros, err)
		}
	})
	for _, test := range []struct {
		name   string
		micros int64
	}{
		{name: "initial lower", micros: initialLeaseMicros - 1},
		{name: "initial upper", micros: initialLeaseMicros + 1},
		{name: "initial future", micros: int64((100 * 365 * 24 * time.Hour) / time.Microsecond)},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := seedDNSProviderClaim089(t, pool, "clock-"+strings.ReplaceAll(test.name, " ", "-"))
			err := insertDNSProviderClaim089WithLeaseMicros(t.Context(), pool, fixture, uuid.New(), test.micros)
			assertDNSProviderClaimCode089(t, err, "P8902")
		})
	}

	for _, test := range []struct {
		name    string
		micros  int64
		wantErr bool
	}{
		{name: "renewal exact", micros: renewalLeaseMicros},
		{name: "renewal lower", micros: renewalLeaseMicros - 1, wantErr: true},
		{name: "renewal upper", micros: renewalLeaseMicros + 1, wantErr: true},
		{name: "renewal future", micros: int64((100 * 365 * 24 * time.Hour) / time.Microsecond), wantErr: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := seedDNSProviderClaim089(t, pool, "clock-"+strings.ReplaceAll(test.name, " ", "-"))
			claimID := insertDNSProviderClaim089(t, pool, fixture)
			_, err := pool.Exec(t.Context(), `UPDATE dns_reconcile_provider_mutation_claims
				SET lease_expires_at=statement_timestamp()+($4::bigint*interval '1 microsecond')
				WHERE tenant_id=$1 AND client_request_id=$2 AND claim_id=$3`, fixture.tenantID,
				fixture.clientRequestID, claimID, test.micros)
			if test.wantErr {
				assertDNSProviderClaimCode089(t, err, "P8902")
			} else if err != nil {
				t.Fatal(err)
			}
		})
	}

	for _, test := range []struct {
		name         string
		offsetMicros int64
		wantErr      bool
	}{
		{name: "terminal exact"},
		{name: "terminal past", offsetMicros: -int64(time.Second / time.Microsecond), wantErr: true},
		{name: "terminal future", offsetMicros: int64(time.Second / time.Microsecond), wantErr: true},
		{name: "terminal far future", offsetMicros: int64((100 * 365 * 24 * time.Hour) / time.Microsecond), wantErr: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := seedDNSProviderClaim089(t, pool, "clock-"+strings.ReplaceAll(test.name, " ", "-"))
			claimID := insertDNSProviderClaim089(t, pool, fixture)
			_, err := pool.Exec(t.Context(), `UPDATE dns_reconcile_provider_mutation_claims
				SET state='conflict',final_zone_revision=expected_zone_revision,
				    finalized_at=statement_timestamp()+($4::bigint*interval '1 microsecond')
				WHERE tenant_id=$1 AND client_request_id=$2 AND claim_id=$3`, fixture.tenantID,
				fixture.clientRequestID, claimID, test.offsetMicros)
			if test.wantErr {
				assertDNSProviderClaimCode089(t, err, "P8902")
			} else if err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestDNSReconcileProviderMutationClaims089RecoveryLeaseSurvivesClaimRotation(t *testing.T) {
	pool := packageCommerceRBAC079Pool(t, 89)
	forceDue := func(fixture dnsProviderClaimFixture089, claimID uuid.UUID) {
		t.Helper()
		if _, err := pool.Exec(t.Context(), `UPDATE dns_reconcile_provider_mutation_claims
			SET state='uncertain',lease_expires_at=clock_timestamp()
			WHERE tenant_id=$1 AND client_request_id=$2 AND claim_id=$3`,
			fixture.tenantID, fixture.clientRequestID, claimID); err != nil {
			t.Fatal(err)
		}
		connection, err := pool.Acquire(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		if _, err := connection.Exec(t.Context(), `SET session_replication_role=replica`); err != nil {
			connection.Release()
			t.Fatal(err)
		}
		_, updateErr := connection.Exec(t.Context(), `UPDATE dns_reconcile_provider_mutation_claims
			SET lease_expires_at=GREATEST(claimed_at,clock_timestamp()-interval '1 microsecond'),
			    recovery_not_before=clock_timestamp()-interval '1 microsecond'
			WHERE tenant_id=$1 AND client_request_id=$2 AND claim_id=$3`,
			fixture.tenantID, fixture.clientRequestID, claimID)
		_, resetErr := connection.Exec(t.Context(), `SET session_replication_role=origin`)
		connection.Release()
		if updateErr != nil || resetErr != nil {
			t.Fatalf("force recovery claim due=(%v,%v)", updateErr, resetErr)
		}
	}
	insertLease := func(fixture dnsProviderClaimFixture089, claimID uuid.UUID) uuid.UUID {
		t.Helper()
		leaseID := uuid.New()
		if _, err := pool.Exec(t.Context(), `INSERT INTO dns_reconcile_provider_recovery_leases(
			tenant_id,client_request_id,claim_id,job_id,recovery_lease_id,
			lease_expires_at,state,claimed_at,released_at)
			VALUES($1,$2,$3,$4,$5,statement_timestamp()+interval '16 minutes',
			'active',statement_timestamp(),NULL)`, fixture.tenantID, fixture.clientRequestID,
			claimID, fixture.jobID, leaseID); err != nil {
			t.Fatal(err)
		}
		return leaseID
	}

	fixture := seedDNSProviderClaim089(t, pool, "stable-recovery-lease")
	oldClaimID := insertDNSProviderClaim089(t, pool, fixture)
	forceDue(fixture, oldClaimID)
	leaseID := insertLease(fixture, oldClaimID)
	newClaimID := uuid.New()
	if _, err := pool.Exec(t.Context(), `UPDATE dns_reconcile_provider_mutation_claims
		SET claim_id=$3,lease_expires_at=statement_timestamp()+interval '2 minutes',
		    claimed_at=statement_timestamp()
		WHERE tenant_id=$1 AND client_request_id=$2 AND claim_id=$4`, fixture.tenantID,
		fixture.clientRequestID, newClaimID, oldClaimID); err != nil {
		t.Fatal(err)
	}
	if err := pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(t.Context(), `INSERT INTO dns_reconcile_provider_recovery_failures(
			tenant_id,client_request_id,claim_id,job_id,recovery_lease_id,reason_code,
			disposition,failure_count,retry_not_before,first_failed_at,last_failed_at)
			VALUES($1,$2,$3,$4,$5,'provider_recovery_lookup_failed','backoff',1,
			clock_timestamp(),clock_timestamp(),clock_timestamp())`, fixture.tenantID,
			fixture.clientRequestID, oldClaimID, fixture.jobID, leaseID); err != nil {
			return err
		}
		command, err := tx.Exec(t.Context(), `UPDATE dns_reconcile_provider_recovery_leases
			SET state='released'
			WHERE tenant_id=$1 AND client_request_id=$2 AND job_id=$3
			  AND recovery_lease_id=$4 AND state='active'`, fixture.tenantID,
			fixture.clientRequestID, fixture.jobID, leaseID)
		if err != nil || command.RowsAffected() != 1 {
			return errors.New("stable recovery lease was not released")
		}
		return nil
	}); err != nil {
		t.Fatalf("stable lease after claim rotation: %v", err)
	}
	var storedClaimID, storedLeaseID uuid.UUID
	var leaseState string
	if err := pool.QueryRow(t.Context(), `SELECT failure.claim_id,failure.recovery_lease_id,lease.state
		FROM dns_reconcile_provider_recovery_failures failure
		JOIN dns_reconcile_provider_recovery_leases lease
		  ON lease.tenant_id=failure.tenant_id
		 AND lease.client_request_id=failure.client_request_id
		 AND lease.recovery_lease_id=failure.recovery_lease_id
		WHERE failure.tenant_id=$1 AND failure.client_request_id=$2`,
		fixture.tenantID, fixture.clientRequestID).
		Scan(&storedClaimID, &storedLeaseID, &leaseState); err != nil {
		t.Fatal(err)
	}
	if storedClaimID != oldClaimID || storedLeaseID != leaseID || leaseState != "released" {
		t.Fatalf("stable failure binding claim=%s lease=%s state=%s",
			storedClaimID, storedLeaseID, leaseState)
	}

	invalid := seedDNSProviderClaim089(t, pool, "invalid-recovery-lease")
	invalidClaimID := insertDNSProviderClaim089(t, pool, invalid)
	forceDue(invalid, invalidClaimID)
	invalidLeaseID := insertLease(invalid, invalidClaimID)
	insertFailure := `INSERT INTO dns_reconcile_provider_recovery_failures(
		tenant_id,client_request_id,claim_id,job_id,recovery_lease_id,reason_code,
		disposition,failure_count,retry_not_before,first_failed_at,last_failed_at)
		VALUES($1,$2,$3,$4,$5,'provider_recovery_lookup_failed','backoff',1,
		clock_timestamp(),clock_timestamp(),clock_timestamp())`
	for _, test := range []struct {
		name             string
		claimID, leaseID uuid.UUID
		jobID            uuid.UUID
	}{
		{name: "wrong lease", claimID: invalidClaimID, leaseID: uuid.New(), jobID: invalid.jobID},
		{name: "wrong claim", claimID: uuid.New(), leaseID: invalidLeaseID, jobID: invalid.jobID},
		{name: "cross job", claimID: invalidClaimID, leaseID: invalidLeaseID, jobID: uuid.New()},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := pool.Exec(t.Context(), insertFailure, invalid.tenantID, invalid.clientRequestID,
				test.claimID, test.jobID, test.leaseID)
			assertDNSProviderClaimCode089(t, err, "P8902")
		})
	}
	_, err := pool.Exec(t.Context(), `UPDATE dns_reconcile_provider_recovery_leases
		SET recovery_lease_id=$4,state='released'
		WHERE tenant_id=$1 AND client_request_id=$2 AND recovery_lease_id=$3`,
		invalid.tenantID, invalid.clientRequestID, invalidLeaseID, uuid.New())
	assertDNSProviderClaimCode089(t, err, "P8902")
}

func TestDNSReconcileProviderMutationClaims089RoundTripAndHeadGuard(t *testing.T) {
	pool := packageCommerceRBAC079Pool(t, 88)
	assertPackageCommerceRBAC079Ledger(t, pool, 88)
	if err := migrateVersionIsolated(t.Context(), pool, "up", 89); err != nil {
		t.Fatal(err)
	}
	assertPackageCommerceRBAC079Ledger(t, pool, 89)
	if err := migrateVersionIsolated(t.Context(), pool, "down", 89); err != nil {
		t.Fatal(err)
	}
	assertPackageCommerceRBAC079Ledger(t, pool, 88)
	if err := migrateVersionIsolated(t.Context(), pool, "up", 89); err != nil {
		t.Fatal(err)
	}
	assertPackageCommerceRBAC079Ledger(t, pool, 89)

	script, err := fs.ReadFile(controlmigrations.FS, dnsProviderClaims089ID+".up.sql")
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name    string
		maximum int64
		tamper  bool
	}{
		{name: "missing 088", maximum: 87},
		{name: "tampered 088", maximum: 88, tamper: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			candidate := packageCommerceRBAC079Pool(t, test.maximum)
			if test.tamper {
				_, err := candidate.Exec(t.Context(), `UPDATE schema_migrations SET checksum_sha256=repeat('a',64) WHERE version=88`)
				if err != nil {
					t.Fatal(err)
				}
			}
			_, err := candidate.Exec(t.Context(), string(script))
			assertDNSProviderClaimCode089(t, err, "P8900")
		})
	}
}

func TestDNSReconcileProviderMutationClaims089IdentityTransitionsAndAuthorityGuards(t *testing.T) {
	pool := packageCommerceRBAC079Pool(t, 89)
	fixture := seedDNSProviderClaim089(t, pool, "identity")
	claimID := insertDNSProviderClaim089(t, pool, fixture)
	requestID := "dns-reconcile-" + strings.Repeat("b", 32)

	for _, query := range []string{
		`UPDATE sites SET revision=revision+1 WHERE id=$1`,
		`UPDATE sites SET domain='changed.example.test',revision=revision+1 WHERE id=$1`,
		`DELETE FROM sites WHERE id=$1`,
	} {
		_, err := pool.Exec(t.Context(), query, fixture.siteID)
		assertDNSProviderClaimCode089(t, err, "P8903")
	}
	for _, query := range []string{
		`UPDATE dns_zones SET revision=revision+1 WHERE id=$1`,
		`UPDATE dns_zones SET name='other.example.test' WHERE id=$1`,
		`DELETE FROM dns_zones WHERE id=$1`,
	} {
		_, err := pool.Exec(t.Context(), query, fixture.zoneID)
		assertDNSProviderClaimCode089(t, err, "P8903")
	}
	for _, query := range []string{
		`UPDATE dns_providers SET revision=revision+1 WHERE id=$1`,
		`UPDATE dns_providers SET credential_key_id='rotated' WHERE id=$1`,
		`UPDATE dns_providers SET credential_ciphertext=credential_ciphertext||decode('00','hex') WHERE id=$1`,
		`DELETE FROM dns_providers WHERE id=$1`,
	} {
		_, err := pool.Exec(t.Context(), query, fixture.providerID)
		assertDNSProviderClaimCode089(t, err, "P8903")
	}

	for _, statement := range []struct {
		query string
		args  []any
	}{
		{query: `UPDATE dns_reconcile_provider_mutation_claims SET provider_id=$2 WHERE tenant_id=$1 AND client_request_id=$3`, args: []any{fixture.tenantID, uuid.New(), fixture.clientRequestID}},
		{query: `UPDATE dns_reconcile_provider_mutation_claims SET authority_digest=$2 WHERE tenant_id=$1 AND client_request_id=$3`, args: []any{fixture.tenantID, make([]byte, sha256.Size), fixture.clientRequestID}},
		{query: `UPDATE dns_reconcile_provider_mutation_claims SET state='succeeded',claim_id=$2 WHERE tenant_id=$1 AND client_request_id=$3`, args: []any{fixture.tenantID, uuid.New(), fixture.clientRequestID}},
		{query: `DELETE FROM dns_reconcile_provider_mutation_claims WHERE tenant_id=$1 AND client_request_id=$2`, args: []any{fixture.tenantID, fixture.clientRequestID}},
	} {
		_, err := pool.Exec(t.Context(), statement.query, statement.args...)
		assertDNSProviderClaimCode089(t, err, "P8902")
	}

	_, err := pool.Exec(t.Context(), `UPDATE dns_reconcile_provider_mutation_claims
		SET state='uncertain',provider_request_id=$3,lease_expires_at=statement_timestamp()
		WHERE tenant_id=$1 AND client_request_id=$2 AND claim_id=$4`,
		fixture.tenantID, fixture.clientRequestID, "dns-reconcile-"+strings.Repeat("c", 32), claimID)
	assertDNSProviderClaimCode089(t, err, "P8902")
	if _, err := pool.Exec(t.Context(), `UPDATE dns_reconcile_provider_mutation_claims
		SET state='uncertain',provider_request_id=$3,lease_expires_at=clock_timestamp()
		WHERE tenant_id=$1 AND client_request_id=$2 AND claim_id=$4`,
		fixture.tenantID, fixture.clientRequestID, requestID, claimID); err != nil {
		t.Fatal(err)
	}
	_, err = pool.Exec(t.Context(), `UPDATE dns_reconcile_provider_mutation_claims
		SET state='not_applied',final_zone_revision=expected_zone_revision,
		    finalized_at=statement_timestamp()
		WHERE tenant_id=$1 AND client_request_id=$2 AND claim_id=$3`,
		fixture.tenantID, fixture.clientRequestID, claimID)
	assertDNSProviderClaimCode089(t, err, "P8902")
	_, err = pool.Exec(t.Context(), `UPDATE dns_reconcile_provider_mutation_claims
		SET state='succeeded',provider_request_id=$3,provider_record_id='record-1',
		    final_zone_revision=expected_zone_revision+1,finalized_at=statement_timestamp()
		WHERE tenant_id=$1 AND client_request_id=$2 AND claim_id=$4`,
		fixture.tenantID, fixture.clientRequestID, "dns-reconcile-"+strings.Repeat("d", 32), claimID)
	assertDNSProviderClaimCode089(t, err, "P8902")
	takeoverID := uuid.New()
	_, err = pool.Exec(t.Context(), `UPDATE dns_reconcile_provider_mutation_claims
		SET claim_id=$3,provider_request_id=$4,lease_expires_at=statement_timestamp()+interval '2 minutes',
		    claimed_at=statement_timestamp()
		WHERE tenant_id=$1 AND client_request_id=$2 AND claim_id=$5`, fixture.tenantID,
		fixture.clientRequestID, takeoverID, "dns-reconcile-"+strings.Repeat("e", 32), claimID)
	assertDNSProviderClaimCode089(t, err, "P8902")
	_, err = pool.Exec(t.Context(), `UPDATE dns_reconcile_provider_mutation_claims SET state='claimed'
		WHERE tenant_id=$1 AND client_request_id=$2`, fixture.tenantID, fixture.clientRequestID)
	assertDNSProviderClaimCode089(t, err, "P8902")
	_, err = pool.Exec(t.Context(), `TRUNCATE dns_reconcile_provider_mutation_claims`)
	assertDNSProviderClaimCode089(t, err, "P8902")
}

func TestDNSReconcileProviderMutationClaims089CanonicalSiteDigest(t *testing.T) {
	pool := packageCommerceRBAC079Pool(t, 89)
	fixture := seedDNSProviderClaim089(t, pool, "canonical-site-digest")
	connection, err := pool.Acquire(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Release()
	digest := func() []byte {
		var value []byte
		if err := connection.QueryRow(t.Context(), `SELECT dns_reconcile_site_config_digest_089(site)
			FROM sites site WHERE id=$1`, fixture.siteID).Scan(&value); err != nil {
			t.Fatal(err)
		}
		return value
	}
	if _, err := connection.Exec(t.Context(), `SET TIME ZONE 'UTC'`); err != nil {
		t.Fatal(err)
	}
	baseline := digest()
	if _, err := connection.Exec(t.Context(), `SET TIME ZONE 'America/Los_Angeles'`); err != nil {
		t.Fatal(err)
	}
	if shifted := digest(); !bytes.Equal(shifted, baseline) {
		t.Fatalf("site authority digest changed across session time zones: %x != %x", shifted, baseline)
	}
	if _, err := connection.Exec(t.Context(), `ALTER TABLE sites ADD COLUMN dns089_layout_probe text`); err != nil {
		t.Fatal(err)
	}
	if layoutChanged := digest(); !bytes.Equal(layoutChanged, baseline) {
		t.Fatalf("site authority digest changed with composite layout: %x != %x", layoutChanged, baseline)
	}
	mutations := []struct {
		name  string
		query string
		args  []any
	}{
		{name: "http ports", query: `UPDATE sites SET http_ports=ARRAY['8080'] WHERE id=$1`},
		{name: "https ports and capability", query: `UPDATE sites SET https_ports=ARRAY['443'],https_enabled=true WHERE id=$1`},
		{name: "origins", query: `UPDATE sites SET origins=ARRAY['192.0.2.44:8080'],origin_hosts=ARRAY['origin-v2.example.test'] WHERE id=$1`},
		{name: "cname", query: `UPDATE sites SET cname='edge.example.test' WHERE id=$1`},
		{name: "enabled status", query: `UPDATE sites SET enabled=false,status='disabled' WHERE id=$1`},
		{name: "sync status", query: `UPDATE sites SET sync_status='pending' WHERE id=$1`},
		{name: "default capability", query: `UPDATE sites SET is_default=true WHERE id=$1`},
		{name: "package", query: `UPDATE sites SET package_id=$2,package_name='package-v2' WHERE id=$1`, args: []any{uuid.New()}},
		{name: "group", query: `UPDATE sites SET group_id=$2,group_name='group-v2',group_active=true WHERE id=$1`, args: []any{uuid.New()}},
		{name: "region", query: `UPDATE sites SET region_id=$2,region_name='region-v2' WHERE id=$1`, args: []any{uuid.New()}},
		{name: "node group", query: `UPDATE sites SET node_group_id=$2,node_group_name='nodes-v2' WHERE id=$1`, args: []any{uuid.New()}},
		{name: "lock", query: `UPDATE sites SET lock_reason='dns authority lock',locked_at=clock_timestamp(),locked_by_user_id=$2 WHERE id=$1`, args: []any{fixture.userID}},
	}
	for _, mutation := range mutations {
		t.Run(mutation.name, func(t *testing.T) {
			tx, err := connection.Begin(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback(context.Background())
			if mutation.name == "group" {
				if _, err := tx.Exec(t.Context(), `INSERT INTO site_groups(id,scope_id,name,active)
					VALUES($1,$2,'group-v2',true)`, mutation.args[0], fixture.scopeID); err != nil {
					t.Fatal(err)
				}
			}
			args := append([]any{fixture.siteID}, mutation.args...)
			if _, err := tx.Exec(t.Context(), mutation.query, args...); err != nil {
				t.Fatal(err)
			}
			var changed []byte
			if err := tx.QueryRow(t.Context(), `SELECT dns_reconcile_site_config_digest_089(site)
				FROM sites site WHERE id=$1`, fixture.siteID).Scan(&changed); err != nil {
				t.Fatal(err)
			}
			if bytes.Equal(changed, baseline) {
				t.Fatalf("site authority digest did not discriminate %s mutation: %x", mutation.name, changed)
			}
		})
	}

	volatileActor := uuid.New()
	if _, err := connection.Exec(t.Context(), `INSERT INTO users(id,username,display_name,password_hash)
		VALUES($1,$2,'DNS 089 volatile actor','hash')`, volatileActor,
		"dns089volatile"+strings.ReplaceAll(volatileActor.String(), "-", "")[:16]); err != nil {
		t.Fatal(err)
	}
	tx, err := connection.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(context.Background())
	if _, err := tx.Exec(t.Context(), `UPDATE sites SET revision=revision+1,
		created_at=created_at-interval '1 second',updated_at=clock_timestamp(),
		created_by_user_id=$2,updated_by_user_id=$2 WHERE id=$1`, fixture.siteID, volatileActor); err != nil {
		t.Fatal(err)
	}
	var volatile []byte
	if err := tx.QueryRow(t.Context(), `SELECT dns_reconcile_site_config_digest_089(site)
		FROM sites site WHERE id=$1`, fixture.siteID).Scan(&volatile); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(volatile, baseline) {
		t.Fatalf("site configuration digest bound volatile revision/audit fields: %x != %x", volatile, baseline)
	}
}

func TestDNSReconcileProviderMutationClaims089CanonicalSiteDigestFixedOracle(t *testing.T) {
	pool := packageCommerceRBAC079Pool(t, 89)
	tx, err := pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(context.Background())
	tenantID := uuid.MustParse("11111111-1111-4111-8111-111111111111")
	scopeID := uuid.MustParse("22222222-2222-4222-8222-222222222222")
	ownerID := uuid.MustParse("33333333-3333-4333-8333-333333333333")
	siteID := uuid.MustParse("44444444-4444-4444-8444-444444444444")
	for _, statement := range []struct {
		query string
		args  []any
	}{
		{`INSERT INTO tenants(id,display_name) VALUES($1,'DNS 089 oracle')`, []any{tenantID}},
		{`INSERT INTO access_scopes(id,kind,tenant_id) VALUES($1,'tenant',$2)`, []any{scopeID, tenantID}},
		{`INSERT INTO users(id,username,display_name,password_hash)
		 VALUES($1,'dns089oracle','DNS 089 oracle','hash')`, []any{ownerID}},
		{`INSERT INTO memberships(scope_id,user_id) VALUES($1,$2)`, []any{scopeID, ownerID}},
		{`INSERT INTO sites(id,scope_id,owner_user_id,domain,origins,origin_hosts,
			 created_by_user_id,updated_by_user_id)
			 VALUES($1,$2,$3,'oracle.example.test',ARRAY['origin.example.test:80'],
			 ARRAY['origin.example.test'],$3,$3)`, []any{siteID, scopeID, ownerID}},
		{`INSERT INTO site_origin_pools(site_id) VALUES($1)`, []any{siteID}},
	} {
		if _, err := tx.Exec(t.Context(), statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	canonical := []byte(`["cdnca:dns-reconcile:site-authority:v1", "44444444-4444-4444-8444-444444444444", "22222222-2222-4222-8222-222222222222", "33333333-3333-4333-8333-333333333333", "oracle.example.test", ["80"], [], ["origin.example.test:80"], ["origin.example.test"], "", false, true, "active", "synced", false, null, null, null, null, null, null, null, null, null, null, null, false, false]`)
	oracle := sha256.Sum256(canonical)
	const want = "ec7b6c5634a78b63e865aa3cb810c8156997a9552aafa3b8bd85f603ad4ae982"
	if got := fmt.Sprintf("%x", oracle); got != want {
		t.Fatalf("independent canonical vector=%s, want %s", got, want)
	}
	var production []byte
	if err := tx.QueryRow(t.Context(), `SELECT dns_reconcile_site_config_digest_089(site)
		FROM sites site WHERE id=$1`, siteID).Scan(&production); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(production, oracle[:]) {
		t.Fatalf("production site digest=%x, independent oracle=%x bytes=%q", production, oracle, canonical)
	}
}

func TestDNSReconcileProviderMutationClaims089RecoveryTimeIsPhysicalServerAuthority(t *testing.T) {
	pool := packageCommerceRBAC079Pool(t, 89)
	fixture := seedDNSProviderClaim089(t, pool, "server-recovery-time")
	claimID := insertDNSProviderClaim089(t, pool, fixture)
	_, err := pool.Exec(t.Context(), `UPDATE dns_reconcile_provider_mutation_claims
		SET state='uncertain',lease_expires_at=clock_timestamp(),
		    recovery_not_before=statement_timestamp()+interval '1 microsecond'
		WHERE tenant_id=$1 AND client_request_id=$2 AND claim_id=$3`,
		fixture.tenantID, fixture.clientRequestID, claimID)
	assertDNSProviderClaimCode089(t, err, "P8902")

	tx, err := pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(context.Background())
	if _, err := tx.Exec(t.Context(), `UPDATE dns_reconcile_provider_mutation_claims
		SET state='uncertain',lease_expires_at=clock_timestamp()
		WHERE tenant_id=$1 AND client_request_id=$2 AND claim_id=$3`,
		fixture.tenantID, fixture.clientRequestID, claimID); err != nil {
		t.Fatal(err)
	}
	var remaining float64
	if err := tx.QueryRow(t.Context(), `SELECT extract(epoch FROM recovery_not_before-clock_timestamp())
		FROM dns_reconcile_provider_mutation_claims
		WHERE tenant_id=$1 AND client_request_id=$2`, fixture.tenantID, fixture.clientRequestID).Scan(&remaining); err != nil {
		t.Fatal(err)
	}
	if remaining < 119 || remaining > 121 {
		t.Fatalf("server-assigned recovery window remaining=%f seconds", remaining)
	}
	_, err = tx.Exec(t.Context(), `UPDATE dns_reconcile_provider_mutation_claims
		SET state='not_applied',final_zone_revision=expected_zone_revision,finalized_at=clock_timestamp()
		WHERE tenant_id=$1 AND client_request_id=$2 AND claim_id=$3`,
		fixture.tenantID, fixture.clientRequestID, claimID)
	assertDNSProviderClaimCode089(t, err, "P8902")
}

func TestDNSReconcileProviderMutationClaims089RejectsQueuedSiteDriftAndFakeSuccess(t *testing.T) {
	pool := packageCommerceRBAC079Pool(t, 89)
	stale := seedDNSProviderClaim089(t, pool, "stale-site")
	if _, err := pool.Exec(t.Context(), `UPDATE sites
		SET domain='changed.example.test',revision=revision+1,updated_at=statement_timestamp()
		WHERE id=$1`, stale.siteID); err != nil {
		t.Fatal(err)
	}
	err := insertDNSProviderClaim089Tx(t.Context(), pool, stale, uuid.New())
	assertDNSProviderClaimCode089(t, err, "P8902")

	fixture := seedDNSProviderClaim089(t, pool, "fake-success")
	claimID := insertDNSProviderClaim089(t, pool, fixture)
	requestID := "dns-reconcile-" + strings.Repeat("b", 32)
	tx, err := pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	_, err = tx.Exec(t.Context(), `UPDATE dns_reconcile_provider_mutation_claims
		SET state='succeeded',provider_record_id='record-forged',final_zone_revision=expected_zone_revision+1,
		    finalized_at=statement_timestamp()
		WHERE tenant_id=$1 AND client_request_id=$2 AND claim_id=$3 AND provider_request_id=$4`,
		fixture.tenantID, fixture.clientRequestID, claimID, requestID)
	if err == nil {
		err = tx.Commit(t.Context())
	} else {
		_ = tx.Rollback(t.Context())
	}
	assertDNSProviderClaimCode089(t, err, "P8902")
	var state string
	var zoneRevision int64
	if err := pool.QueryRow(t.Context(), `SELECT claim.state,zone.revision
		FROM dns_reconcile_provider_mutation_claims claim
		JOIN dns_zones zone ON zone.id=claim.zone_id
		WHERE claim.tenant_id=$1 AND claim.client_request_id=$2`,
		fixture.tenantID, fixture.clientRequestID).Scan(&state, &zoneRevision); err != nil {
		t.Fatal(err)
	}
	if state != "claimed" || zoneRevision != 1 {
		t.Fatalf("failed fake-success transaction left state=%s zone_revision=%d", state, zoneRevision)
	}
}

func TestDNSReconcileProviderMutationClaims089ClaimLinearizesBeforeRotation(t *testing.T) {
	pool := packageCommerceRBAC079Pool(t, 89)
	fixture := seedDNSProviderClaim089(t, pool, "linearize")
	tx, err := pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(context.Background())
	claimID := uuid.New()
	if err := insertDNSProviderClaim089Tx(t.Context(), tx, fixture, claimID); err != nil {
		t.Fatal(err)
	}
	result := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_, updateErr := pool.Exec(ctx, `UPDATE dns_providers SET revision=revision+1 WHERE id=$1`, fixture.providerID)
		result <- updateErr
	}()
	select {
	case err := <-result:
		t.Fatalf("provider rotation did not serialize behind claim: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	if err := tx.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
	assertDNSProviderClaimCode089(t, <-result, "P8903")
}

func TestDNSReconcileProviderMutationClaims089DownRejectsFacts(t *testing.T) {
	empty := packageCommerceRBAC079Pool(t, 89)
	if err := migrateVersionIsolated(t.Context(), empty, "down", 89); err != nil {
		t.Fatal(err)
	}
	assertPackageCommerceRBAC079Ledger(t, empty, 88)

	withFact := packageCommerceRBAC079Pool(t, 89)
	fixture := seedDNSProviderClaim089(t, withFact, "down")
	insertDNSProviderClaim089(t, withFact, fixture)
	assertDNSProviderClaimCode089(t, migrateVersionIsolated(t.Context(), withFact, "down", 89), "P8901")
	assertPackageCommerceRBAC079Ledger(t, withFact, 89)
}

type dnsProviderClaimFixture089 struct {
	tenantID, scopeID, userID, siteID, zoneID, providerID, jobID uuid.UUID
	clientRequestID                                              string
}

func seedDNSProviderClaim089(t *testing.T, pool *pgxpool.Pool, suffix string) dnsProviderClaimFixture089 {
	return seedDNSProviderClaim089WithAttempts(t, pool, suffix, 20)
}

func seedDNSProviderClaim089WithAttempts(t *testing.T, pool *pgxpool.Pool, suffix string,
	maxAttempts int,
) dnsProviderClaimFixture089 {
	t.Helper()
	if maxAttempts < 1 {
		t.Fatalf("invalid max attempts %d", maxAttempts)
	}
	fixture := dnsProviderClaimFixture089{
		tenantID: uuid.New(), scopeID: uuid.New(), userID: uuid.New(), siteID: uuid.New(),
		zoneID: uuid.New(), providerID: uuid.New(), jobID: uuid.New(), clientRequestID: "claim-" + suffix,
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	username := "dns089" + strings.ReplaceAll(fixture.userID.String(), "-", "")[:20]
	digest := make([]byte, sha256.Size)
	operation := `{"Sequence":1,"Action":"create","RecordID":"","Name":"www.example.test.","Type":"A","Value":"192.0.2.10","TTL":300,"PreviousValue":"","PreviousTTL":0,"Reason":"missing_record"}`
	// The same seed serves early-prefix schemas and the release head (migration 210 made
	// sites.display_id mandatory); each fixture owns its scope, so display_id 1 is unique.
	var siteDisplayID bool
	if err := pool.QueryRow(t.Context(), `SELECT EXISTS(SELECT 1 FROM information_schema.columns
		WHERE table_schema=current_schema() AND table_name='sites' AND column_name='display_id')`).
		Scan(&siteDisplayID); err != nil {
		t.Fatal(err)
	}
	siteColumns, siteValues := "", ""
	if siteDisplayID {
		siteColumns, siteValues = ",display_id", ",1"
	}
	err := pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
		statements := []struct {
			query string
			args  []any
		}{
			{`INSERT INTO tenants(id,display_name) VALUES($1,$2)`, []any{fixture.tenantID, "DNS claim " + suffix}},
			{`INSERT INTO access_scopes(id,kind,tenant_id) VALUES($1,'tenant',$2)`, []any{fixture.scopeID, fixture.tenantID}},
			{`INSERT INTO users(id,username,display_name,password_hash) VALUES($1,$2,$3,'hash')`, []any{fixture.userID, username, "DNS claim " + suffix}},
			{`INSERT INTO memberships(scope_id,user_id) VALUES($1,$2)`, []any{fixture.scopeID, fixture.userID}},
			{`INSERT INTO sites(id,scope_id,owner_user_id,domain,origins,origin_hosts,created_by_user_id,updated_by_user_id` + siteColumns + `)
			 VALUES($1,$2,$3,'www.example.test',ARRAY['origin.example.test:80'],ARRAY['origin.example.test'],$3,$3` + siteValues + `)`, []any{fixture.siteID, fixture.scopeID, fixture.userID}},
			{`INSERT INTO site_origin_pools(site_id) VALUES($1)`, []any{fixture.siteID}},
			{`INSERT INTO site_origins(site_id,position,host,port) VALUES($1,1,'origin.example.test',80)`, []any{fixture.siteID}},
			{`INSERT INTO dns_providers(id,scope_id,name,provider_type,credential_key_id,credential_ciphertext,status,
			 created_by_user_id,updated_by_user_id) VALUES($1,$2,'claim-provider','cloudflare','claim-key',$3,'verified',$4,$4)`, []any{fixture.providerID, fixture.scopeID, append(make([]byte, 29), 1), fixture.userID}},
			{`INSERT INTO dns_zones(id,scope_id,provider_id,name,status,created_by_user_id,updated_by_user_id)
			 VALUES($1,$2,$3,'example.test','draft',$4,$4)`, []any{fixture.zoneID, fixture.scopeID, fixture.providerID, fixture.userID}},
			{`INSERT INTO background_jobs(id,tenant_id,kind,subject,idempotency_key,request_digest,request_id,trace_id,
			 state,attempt,max_attempts,claimable_at,total_count,created_at,updated_at)
			 VALUES($1,$2,'dns_reconcile','dns_reconcile/site',$3,$4,'request-089','','queued',0,$6,$5,1,$5,$5)`, []any{fixture.jobID, fixture.tenantID, "job-" + suffix, digest, now, maxAttempts}},
			{`INSERT INTO background_job_items(tenant_id,job_id,ordinal,item_id,state) VALUES($1,$2,1,'reconcile','pending')`, []any{fixture.tenantID, fixture.jobID}},
			{`INSERT INTO dns_reconcile_tasks(tenant_id,tenant_scope_id,job_id,site_id,zone_id,idempotency_key,
			 job_idempotency_key,payload_digest,job_request_digest,canonical_request,plan_digest,deterministic_plan,
			 initial_provider_revision,required_consecutive,created_at)
			 VALUES($1,$2,$3,$4,$5,$6,$7,$8,$8,'{}'::jsonb,$8,'{}'::jsonb,1,3,$9)`, []any{fixture.tenantID, fixture.scopeID, fixture.jobID, fixture.siteID, fixture.zoneID, "raw-" + suffix, "job-" + suffix, digest, now}},
			{`INSERT INTO dns_reconcile_operations(tenant_id,job_id,phase,ordinal,source_sequence,action,
			 client_request_id,operation,created_at) VALUES($1,$2,'apply',1,1,'create',$3,$4::jsonb,$5)`, []any{fixture.tenantID, fixture.jobID, fixture.clientRequestID, operation, now}},
		}
		for _, statement := range statements {
			if _, err := tx.Exec(t.Context(), statement.query, statement.args...); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return fixture
}

func insertDNSProviderClaim089(t *testing.T, pool *pgxpool.Pool, fixture dnsProviderClaimFixture089) uuid.UUID {
	t.Helper()
	claimID := uuid.New()
	if err := insertDNSProviderClaim089Tx(t.Context(), pool, fixture, claimID); err != nil {
		t.Fatal(err)
	}
	return claimID
}

type dnsProviderClaimExecutor089 interface {
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
}

func insertDNSProviderClaim089Tx(ctx context.Context, executor dnsProviderClaimExecutor089,
	fixture dnsProviderClaimFixture089, claimID uuid.UUID,
) error {
	return insertDNSProviderClaim089WithLeaseMicros(ctx, executor, fixture, claimID,
		int64((2*time.Minute)/time.Microsecond))
}

func insertDNSProviderClaim089WithLeaseMicros(ctx context.Context, executor dnsProviderClaimExecutor089,
	fixture dnsProviderClaimFixture089, claimID uuid.UUID, leaseMicros int64,
) error {
	_, err := executor.Exec(ctx, `INSERT INTO dns_reconcile_provider_mutation_claims(
		tenant_id,client_request_id,job_id,phase,operation_ordinal,site_id,zone_id,provider_id,
		claim_id,lease_expires_at,state,expected_site_revision,expected_zone_revision,expected_provider_revision,
		site_config_digest,operation_digest,authority_digest,provider_config_digest,credential_digest,
		provider_request_id,claimed_at)
		SELECT operation.tenant_id,operation.client_request_id,operation.job_id,operation.phase,operation.ordinal,
			task.site_id,task.zone_id,provider.id,$1,
			statement_timestamp()+($4::bigint*interval '1 microsecond'),'claimed',
			site.revision,zone.revision,provider.revision,dns_reconcile_site_config_digest_089(site),
			dns_reconcile_operation_digest_089(operation.operation),
			dns_reconcile_authority_digest_089(task.tenant_scope_id,site,zone,provider),
			dns_reconcile_provider_config_digest_089(zone,provider),
			dns_reconcile_credential_digest_089(provider.credential_key_id,provider.credential_ciphertext),
			$5,statement_timestamp()
		FROM dns_reconcile_operations operation
		JOIN dns_reconcile_tasks task ON task.tenant_id=operation.tenant_id AND task.job_id=operation.job_id
		JOIN sites site ON site.scope_id=task.tenant_scope_id AND site.id=task.site_id
		JOIN dns_zones zone ON zone.scope_id=task.tenant_scope_id AND zone.id=task.zone_id
		JOIN dns_providers provider ON provider.scope_id=zone.scope_id AND provider.id=zone.provider_id
		WHERE operation.tenant_id=$2 AND operation.client_request_id=$3
		FOR UPDATE OF operation,task,zone,provider`, claimID, fixture.tenantID, fixture.clientRequestID, leaseMicros,
		"dns-reconcile-"+strings.Repeat("b", 32))
	return err
}

func assertDNSProviderClaimCode089(t *testing.T, err error, want string) {
	t.Helper()
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != want {
		t.Fatalf("PostgreSQL error=%v, want SQLSTATE %s", err, want)
	}
}
