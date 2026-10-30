//go:build integration

package migrations_test

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
	"github.com/cdnca/cdnca/services/control-api/internal/dnscheck"
	"github.com/cdnca/cdnca/services/control-api/internal/dnsproviderremote"
	"github.com/cdnca/cdnca/services/control-api/internal/dnsreconcile"
	"github.com/cdnca/cdnca/services/control-api/internal/jobhttp"
	"github.com/cdnca/cdnca/services/control-api/internal/jobstate"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	backgroundJobManage094    = "jobs.manage"
	backgroundJobManageAll094 = "jobs.manage_all"
)

func TestBackgroundJobCommands094MigrationContract(t *testing.T) {
	up := mustReadBackgroundJobCommands094(t, "094_background_job_commands.up.sql")
	down := mustReadBackgroundJobCommands094(t, "094_background_job_commands.down.sql")
	for _, fragment := range []string{
		"migration 094 requires the exact verified 093 release head",
		"3614fd6c9d624f2e75ded822c2de8fe62940267c4a5e9b76340a37e428e319af",
		"522de2c6ff1747157b9b0cce959724f18d9395f1c20638d4bfcbdcafb29b734a",
		"ERRCODE = 'P9400'",
		"CREATE TABLE background_job_command_receipts",
		"ADD COLUMN job_command_operation text",
		"ADD COLUMN job_command_xact_id xid8",
		"ADD COLUMN job_transition_xact_id xid8",
		"CREATE TRIGGER background_jobs_mark_command_mutation_094",
		"CREATE TRIGGER a_dns_reconcile_cancel_facts_transition_094",
		"CREATE TRIGGER a_dns_reconcile_provider_recovery_transition_094",
		"job_command_xact_id xid8 NOT NULL DEFAULT pg_current_xact_id()",
		"UNIQUE (tenant_id, job_id, job_command_xact_id)",
		"CREATE CONSTRAINT TRIGGER background_job_command_receipts_final_094",
		"CREATE CONSTRAINT TRIGGER background_jobs_command_receipt_final_094",
		"CREATE CONSTRAINT TRIGGER dns_reconcile_cancel_transition_final_094",
		"CREATE CONSTRAINT TRIGGER dns_reconcile_provider_recovery_transition_final_094",
		"'dns_cancel'",
		"'dns_recovery'",
		"audit_event_id uuid NOT NULL UNIQUE",
		"UNIQUE (actor_scope_id, actor_user_id, idempotency_key)",
		"result_failure_code text",
		"result_started_at timestamptz",
		"result_completed_at timestamptz",
		"completed_at timestamptz NOT NULL",
		"CREATE UNIQUE INDEX audit_events_job_command_denied_identity_094",
		"WHERE result='denied'",
		"AND actor_user_id IS NOT NULL",
		"AND action IN ('job.cancel','job.retry')",
		"CREATE CONSTRAINT TRIGGER audit_events_job_command_success_receipt_094",
		"DEFERRABLE INITIALLY DEFERRED",
		"BEFORE UPDATE OR DELETE OR TRUNCATE ON background_job_command_receipts",
		"BEFORE TRUNCATE ON audit_events",
		"background_job_command_rbac_catalog_additions_094",
		"background_job_command_rbac_grant_additions_094",
		"'jobs.manage'",
		"'jobs.manage_all'",
		"ERRCODE = 'P9402'",
		"ERRCODE = 'P9403'",
	} {
		if !strings.Contains(up, fragment) {
			t.Errorf("094 up missing %q", fragment)
		}
	}
	upDigest := sha256.Sum256([]byte(up))
	for _, fragment := range []string{
		"migration 094 rollback requires the exact verified 094 head",
		hex.EncodeToString(upDigest[:]),
		"3614fd6c9d624f2e75ded822c2de8fe62940267c4a5e9b76340a37e428e319af",
		"522de2c6ff1747157b9b0cce959724f18d9395f1c20638d4bfcbdcafb29b734a",
		"migration 094 rollback would discard job command facts",
		"migration 094 rollback found unowned RBAC facts",
		"ERRCODE = 'P9401'",
		"DROP TABLE background_job_command_receipts",
		"DROP COLUMN job_transition_xact_id",
		"DELETE FROM permissions",
	} {
		if !strings.Contains(down, fragment) {
			t.Errorf("094 down missing %q", fragment)
		}
	}
	if strings.Contains(down, "DELETE FROM schema_migrations") {
		t.Fatal("094 down must not delete its own schema_migrations row")
	}
}

func TestBackgroundJobCommands094FreshRoundTripAndRBAC(t *testing.T) {
	t.Run("existing roles and round trip", func(t *testing.T) {
		pool := packageCommerceRBAC079Pool(t, 93)
		roles := seedBackgroundJobCommandRoles094(t, pool, "existing")
		if err := migrateVersionIsolated(t.Context(), pool, "up", 94); err != nil {
			t.Fatalf("fresh 1..94: %v", err)
		}
		assertPackageCommerceRBAC079Ledger(t, pool, 94)
		assertBackgroundJobCommands094Schema(t, pool)
		assertBackgroundJobCommandRole094(t, pool, roles.tenantOwner, backgroundJobManage094, true)
		assertBackgroundJobCommandRole094(t, pool, roles.tenantAdmin, backgroundJobManage094, false)
		assertBackgroundJobCommandRole094(t, pool, roles.tenantOwner, backgroundJobManageAll094, false)
		assertBackgroundJobCommandRole094(t, pool, roles.platformOwner, backgroundJobManageAll094, true)
		assertBackgroundJobCommandRole094(t, pool, roles.platformOther, backgroundJobManageAll094, false)

		if err := migrateVersionIsolated(t.Context(), pool, "down", 94); err != nil {
			t.Fatalf("94 down: %v", err)
		}
		assertPackageCommerceRBAC079Ledger(t, pool, 93)
		for _, relation := range []string{
			"background_job_command_receipts",
			"background_job_command_rbac_catalog_additions_094",
			"background_job_command_rbac_grant_additions_094",
		} {
			var exists bool
			if err := pool.QueryRow(t.Context(), `SELECT to_regclass($1) IS NOT NULL`, relation).Scan(&exists); err != nil || exists {
				t.Fatalf("relation %s exists=%t after down err=%v", relation, exists, err)
			}
		}
		var sourceColumns int
		if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM information_schema.columns
			WHERE table_schema=current_schema() AND column_name='job_transition_xact_id'
			  AND table_name IN ('dns_reconcile_cancel_facts',
			                     'dns_reconcile_provider_recovery_continuations')`).Scan(&sourceColumns); err != nil {
			t.Fatal(err)
		}
		if sourceColumns != 0 {
			t.Fatalf("DNS transition source columns after down=%d want 0", sourceColumns)
		}
		if err := migrateVersionIsolated(t.Context(), pool, "up", 94); err != nil {
			t.Fatalf("94 reapply: %v", err)
		}
		assertPackageCommerceRBAC079Ledger(t, pool, 94)
	})
	t.Run("future roles", func(t *testing.T) {
		pool := packageCommerceRBAC079Pool(t, 94)
		future := seedBackgroundJobCommandRoles094(t, pool, "future")
		assertBackgroundJobCommandRole094(t, pool, future.tenantOwner, backgroundJobManage094, true)
		assertBackgroundJobCommandRole094(t, pool, future.tenantAdmin, backgroundJobManage094, false)
		assertBackgroundJobCommandRole094(t, pool, future.tenantOwner, backgroundJobManageAll094, false)
		assertBackgroundJobCommandRole094(t, pool, future.platformOwner, backgroundJobManageAll094, true)
		assertBackgroundJobCommandRole094(t, pool, future.platformOther, backgroundJobManageAll094, false)
		for _, roleID := range []uuid.UUID{future.tenantOwner, future.platformOther, future.platformPlain} {
			if _, err := pool.Exec(t.Context(), `INSERT INTO role_permissions(role_id,permission_name)
				VALUES($1,$2)`, roleID, backgroundJobManageAll094); err == nil {
				t.Fatalf("role %s accepted jobs.manage_all", roleID)
			}
		}
		if _, err := pool.Exec(t.Context(), `INSERT INTO role_permissions(role_id,permission_name)
				VALUES($1,$2)`, future.tenantAdmin, backgroundJobManage094); err == nil {
			t.Fatal("future tenant_admin accepted default-only jobs.manage")
		} else {
			assertBackgroundJobCommands094Code(t, err, "P9403")
		}
	})
}

func TestBackgroundJobCommands094RejectsWrongHead(t *testing.T) {
	t.Run("wrong 093 checksum on up", func(t *testing.T) {
		pool := packageCommerceRBAC079Pool(t, 93)
		if _, err := pool.Exec(t.Context(), `UPDATE schema_migrations
			SET down_checksum_sha256=repeat('a',64) WHERE version=93`); err != nil {
			t.Fatal(err)
		}
		up := mustReadBackgroundJobCommands094(t, "094_background_job_commands.up.sql")
		_, err := pool.Exec(t.Context(), up)
		assertBackgroundJobCommands094Code(t, err, "P9400")
	})
	t.Run("historical null checksum on up", func(t *testing.T) {
		pool := packageCommerceRBAC079Pool(t, 93)
		if _, err := pool.Exec(t.Context(), `UPDATE schema_migrations
			SET checksum_sha256=NULL WHERE version=92`); err != nil {
			t.Fatal(err)
		}
		up := mustReadBackgroundJobCommands094(t, "094_background_job_commands.up.sql")
		_, err := pool.Exec(t.Context(), up)
		assertBackgroundJobCommands094Code(t, err, "P9400")
	})
	t.Run("historical null integrity on down", func(t *testing.T) {
		pool := packageCommerceRBAC079Pool(t, 94)
		if _, err := pool.Exec(t.Context(), `UPDATE schema_migrations
			SET integrity_state=NULL WHERE version=92`); err != nil {
			t.Fatal(err)
		}
		down := mustReadBackgroundJobCommands094(t, "094_background_job_commands.down.sql")
		_, err := pool.Exec(t.Context(), down)
		assertBackgroundJobCommands094Code(t, err, "P9400")
	})
	t.Run("null 094 down checksum on down", func(t *testing.T) {
		pool := packageCommerceRBAC079Pool(t, 94)
		if _, err := pool.Exec(t.Context(), `UPDATE schema_migrations
			SET down_checksum_sha256=NULL WHERE version=94`); err != nil {
			t.Fatal(err)
		}
		down := mustReadBackgroundJobCommands094(t, "094_background_job_commands.down.sql")
		_, err := pool.Exec(t.Context(), down)
		assertBackgroundJobCommands094Code(t, err, "P9400")
	})
}

func TestBackgroundJobCommands094ReceiptAuditBindingAndImmutability(t *testing.T) {
	pool := packageCommerceRBAC079Pool(t, 94)
	fixture := insertBackgroundJobCommandReceipt094(t, pool)

	for name, statement := range map[string]string{
		"receipt update": `UPDATE background_job_command_receipts SET result_state='queued' WHERE audit_event_id=$1`,
		"receipt delete": `DELETE FROM background_job_command_receipts WHERE audit_event_id=$1`,
	} {
		t.Run(name, func(t *testing.T) {
			_, err := pool.Exec(t.Context(), statement, fixture.auditID)
			assertBackgroundJobCommands094Code(t, err, "P9402")
		})
	}
	for name, statement := range map[string]string{
		"receipt truncate": `TRUNCATE background_job_command_receipts`,
		"audit truncate":   `TRUNCATE audit_events CASCADE`,
	} {
		t.Run(name, func(t *testing.T) {
			_, err := pool.Exec(t.Context(), statement)
			assertBackgroundJobCommands094Code(t, err, "P9402")
		})
	}
	if _, err := pool.Exec(t.Context(), `UPDATE audit_events SET result='failure' WHERE id=$1`, fixture.auditID); err == nil {
		t.Fatal("command audit accepted update")
	}
	if _, err := pool.Exec(t.Context(), `DELETE FROM audit_events WHERE id=$1`, fixture.auditID); err == nil {
		t.Fatal("command audit accepted delete")
	}

	missingReceiptTx, err := pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := missingReceiptTx.Exec(t.Context(), `INSERT INTO audit_events(
		id,scope_id,stream_position,actor_user_id,action,resource_type,resource_id,
		request_id,result,payload,previous_hash,event_hash,occurred_at
	) SELECT $1,scope_id,2,actor_user_id,'job.cancel',resource_type,resource_id,
		'missing-receipt-request','success',payload,event_hash,
		sha256(convert_to('missing-receipt','UTF8')),occurred_at
	  FROM audit_events WHERE id=$2`, uuid.New(), fixture.auditID); err != nil {
		_ = missingReceiptTx.Rollback(t.Context())
		t.Fatal(err)
	}
	assertBackgroundJobCommands094Code(t, missingReceiptTx.Commit(t.Context()), "P9402")

	tx, err := pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(t.Context()) }()
	forgedAudit := uuid.New()
	if _, err := tx.Exec(t.Context(), `INSERT INTO audit_events(
		id,scope_id,stream_position,actor_user_id,action,resource_type,resource_id,
		request_id,result,payload,previous_hash,event_hash,occurred_at
	) SELECT $1,scope_id,2,actor_user_id,'job.retry',resource_type,resource_id,
		'forged-request','success',payload,event_hash,sha256(convert_to('forged','UTF8')),occurred_at
	  FROM audit_events WHERE id=$2`, forgedAudit, fixture.auditID); err != nil {
		t.Fatal(err)
	}
	_, err = tx.Exec(t.Context(), `INSERT INTO background_job_command_receipts(
		actor_scope_id,actor_user_id,idempotency_key,request_digest,audience,tenant_id,job_id,
		operation,request_id,audit_event_id,result_kind,result_subject,result_request_id,
		result_trace_id,result_state,result_attempt,result_max_attempts,result_total_count,
		result_completed_count,result_succeeded_count,result_failed_count,result_cancelled_count,
		result_failure_code,result_created_at,result_started_at,result_updated_at,result_completed_at,
		created_at,completed_at
	) SELECT actor_scope_id,actor_user_id,'forged-binding',request_digest,audience,tenant_id,job_id,
		operation,'forged-request',$1,result_kind,result_subject,result_request_id,result_trace_id,
		result_state,result_attempt,result_max_attempts,result_total_count,result_completed_count,
		result_succeeded_count,result_failed_count,result_cancelled_count,result_failure_code,
		result_created_at,result_started_at,result_updated_at,result_completed_at,created_at,completed_at
	  FROM background_job_command_receipts WHERE audit_event_id=$2`, forgedAudit, fixture.auditID)
	assertBackgroundJobCommands094Code(t, err, "P9402")
}

func TestBackgroundJobCommands094DeniedIdentityIsUnique(t *testing.T) {
	pool := packageCommerceRBAC079Pool(t, 94)
	fixture := insertBackgroundJobCommandReceipt094(t, pool)
	requestID := "denied-command-request"
	for position := int64(2); position <= 3; position++ {
		_, err := pool.Exec(t.Context(), `INSERT INTO audit_events(
			id,scope_id,stream_position,actor_user_id,action,resource_type,resource_id,
			request_id,result,payload,previous_hash,event_hash,occurred_at
			) SELECT $1::uuid,scope_id,$2,actor_user_id,'job.cancel','background_job',resource_id,
			$3,'denied',jsonb_build_object(
				'audience','tenant','operation','cancel','idempotency_key','denied-key',
				'request_digest',repeat('a',64),'reason','permission_denied'
			),event_hash,sha256(convert_to($1::text,'UTF8')),occurred_at
		  FROM audit_events WHERE id=$4`, uuid.New(), position, requestID, fixture.auditID)
		if position == 2 && err != nil {
			t.Fatal(err)
		}
		if position == 3 {
			assertBackgroundJobCommands094Code(t, err, "23505")
		}
	}
}

func TestBackgroundJobCommands094RejectsPriorSnapshotReceiptForgery(t *testing.T) {
	pool := packageCommerceRBAC079Pool(t, 94)
	fixture := insertBackgroundJobCommandReceipt094(t, pool)
	forgedAuditID := uuid.New()
	forgedDigest := sha256.Sum256([]byte("forged-prior-job-command"))
	tx, err := pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(t.Context()) }()
	if _, err := tx.Exec(t.Context(), `INSERT INTO audit_events(
		id,scope_id,stream_position,actor_user_id,action,resource_type,resource_id,
		request_id,result,payload,previous_hash,event_hash,occurred_at
	) SELECT $1,scope_id,2,actor_user_id,action,resource_type,resource_id,
		'forged-prior-request','success',payload || jsonb_build_object(
			'idempotency_key','forged-prior-key','request_digest',$2::text
		),event_hash,sha256(convert_to('forged-prior-audit','UTF8')),occurred_at
	  FROM audit_events WHERE id=$3`, forgedAuditID, hex.EncodeToString(forgedDigest[:]), fixture.auditID); err != nil {
		t.Fatal(err)
	}
	_, insertErr := tx.Exec(t.Context(), `INSERT INTO background_job_command_receipts(
		actor_scope_id,actor_user_id,idempotency_key,request_digest,audience,tenant_id,job_id,
		operation,request_id,audit_event_id,result_kind,result_subject,result_request_id,
		result_trace_id,result_state,result_attempt,result_max_attempts,result_total_count,
		result_completed_count,result_succeeded_count,result_failed_count,result_cancelled_count,
		result_failure_code,result_created_at,result_started_at,result_updated_at,result_completed_at,
		created_at,completed_at
	) SELECT actor_scope_id,actor_user_id,'forged-prior-key',$1,audience,tenant_id,job_id,
		operation,'forged-prior-request',$2,result_kind,result_subject,result_request_id,
		result_trace_id,result_state,result_attempt,result_max_attempts,result_total_count,
		result_completed_count,result_succeeded_count,result_failed_count,result_cancelled_count,
		result_failure_code,result_created_at,result_started_at,result_updated_at,result_completed_at,
		created_at,completed_at
	  FROM background_job_command_receipts WHERE audit_event_id=$3`,
		forgedDigest[:], forgedAuditID, fixture.auditID)
	if insertErr != nil {
		assertBackgroundJobCommands094Code(t, insertErr, "P9402")
		return
	}
	assertBackgroundJobCommands094Code(t, tx.Commit(t.Context()), "P9402")
}

func TestBackgroundJobCommands094RejectsDuplicateReceiptForOneMutation(t *testing.T) {
	pool := packageCommerceRBAC079Pool(t, 94)
	tx, err := pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(t.Context()) }()
	fixture := insertBackgroundJobCommandReceipt094Tx(t, tx)
	secondAuditID := uuid.New()
	secondDigest := sha256.Sum256([]byte("second-receipt-same-mutation"))
	if _, err := tx.Exec(t.Context(), `INSERT INTO audit_events(
		id,scope_id,stream_position,actor_user_id,action,resource_type,resource_id,
		request_id,result,payload,previous_hash,event_hash,occurred_at
	) SELECT $1,scope_id,2,actor_user_id,action,resource_type,resource_id,
		'second-receipt-request','success',payload || jsonb_build_object(
			'idempotency_key','second-receipt','request_digest',$2::text
		),event_hash,sha256(convert_to('second-receipt-audit','UTF8')),occurred_at
	  FROM audit_events WHERE id=$3`, secondAuditID,
		hex.EncodeToString(secondDigest[:]), fixture.auditID); err != nil {
		t.Fatal(err)
	}
	_, insertErr := tx.Exec(t.Context(), `INSERT INTO background_job_command_receipts(
		actor_scope_id,actor_user_id,idempotency_key,request_digest,audience,tenant_id,job_id,
		operation,request_id,audit_event_id,result_kind,result_subject,result_request_id,
		result_trace_id,result_state,result_attempt,result_max_attempts,result_total_count,
		result_completed_count,result_succeeded_count,result_failed_count,result_cancelled_count,
		result_failure_code,result_created_at,result_started_at,result_updated_at,result_completed_at,
		created_at,completed_at
	) SELECT actor_scope_id,actor_user_id,'second-receipt',$1,audience,tenant_id,job_id,
		operation,'second-receipt-request',$2,result_kind,result_subject,result_request_id,
		result_trace_id,result_state,result_attempt,result_max_attempts,result_total_count,
		result_completed_count,result_succeeded_count,result_failed_count,result_cancelled_count,
		result_failure_code,result_created_at,result_started_at,result_updated_at,result_completed_at,
		created_at,completed_at
	  FROM background_job_command_receipts WHERE audit_event_id=$3`,
		secondDigest[:], secondAuditID, fixture.auditID)
	if insertErr != nil {
		assertBackgroundJobCommands094Code(t, insertErr, "P9402")
		return
	}
	assertBackgroundJobCommands094Code(t, tx.Commit(t.Context()), "P9402")
}

func TestBackgroundJobCommands094DeferredReceiptFinalState(t *testing.T) {
	t.Run("post receipt claim", func(t *testing.T) {
		pool := packageCommerceRBAC079Pool(t, 94)
		fixture := seedFailedBackgroundJobCommand094(t, pool, "post-receipt")
		tx, err := pool.Begin(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(t.Context()) }()
		retried, err := jobstate.RetryTx(t.Context(), tx, fixture.tenantID, fixture.jobID, fixture.retryAt)
		if err != nil {
			t.Fatal(err)
		}
		insertBackgroundJobRetryReceipt094Tx(t, tx, fixture, retried)
		constraintNames := "background_job_command_receipts_final_094, " +
			"audit_events_job_command_success_receipt_094"
		var jobConstraintExists bool
		if err := tx.QueryRow(t.Context(), `SELECT EXISTS(SELECT 1 FROM pg_trigger
			WHERE tgrelid='background_jobs'::regclass
			  AND tgname='background_jobs_command_receipt_final_094')`).Scan(&jobConstraintExists); err != nil {
			t.Fatal(err)
		}
		if jobConstraintExists {
			constraintNames += ", background_jobs_command_receipt_final_094"
		}
		if _, err := tx.Exec(t.Context(), `SET CONSTRAINTS `+constraintNames+` IMMEDIATE`); err != nil {
			t.Fatal(err)
		}
		leaseExpiresAt := fixture.retryAt.Add(time.Minute)
		leaseID := uuid.New()
		_, updateErr := tx.Exec(t.Context(), `UPDATE background_jobs SET
			state='running',attempt=attempt+1,lease_id=$3,lease_owner='post-receipt-worker',
			lease_expires_at=$4,claimable_at=$4,updated_at=$2
			WHERE tenant_id=$1 AND id=$5`, fixture.tenantID, fixture.retryAt,
			leaseID, leaseExpiresAt, fixture.jobID)
		if updateErr != nil {
			assertBackgroundJobCommands094Code(t, updateErr, "P9402")
			return
		}
		if _, err := tx.Exec(t.Context(), `INSERT INTO background_job_attempts(
			tenant_id,job_id,attempt,lease_id,worker_id,state,
			started_at,last_heartbeat_at,lease_expires_at
		) VALUES($1,$2,$3,$4,'post-receipt-worker','running',$5,$5,$6)`,
			fixture.tenantID, fixture.jobID, int(retried.Attempt)+1,
			leaseID, fixture.retryAt, leaseExpiresAt); err != nil {
			t.Fatal(err)
		}
		assertBackgroundJobCommands094Code(t, tx.Commit(t.Context()), "P9402")
	})

	t.Run("rolled back marker", func(t *testing.T) {
		pool := packageCommerceRBAC079Pool(t, 94)
		fixture := seedFailedBackgroundJobCommand094(t, pool, "rollback-marker")
		retryTx, err := pool.Begin(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		retried, err := jobstate.RetryTx(t.Context(), retryTx, fixture.tenantID, fixture.jobID, fixture.retryAt)
		if err != nil {
			_ = retryTx.Rollback(t.Context())
			t.Fatal(err)
		}
		if err := retryTx.Rollback(t.Context()); err != nil {
			t.Fatal(err)
		}

		forgedTx, err := pool.Begin(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = forgedTx.Rollback(t.Context()) }()
		insertErr := insertBackgroundJobRetryReceipt094TxError(t, forgedTx, fixture, retried)
		assertBackgroundJobCommands094Code(t, insertErr, "P9402")
	})
}

func TestBackgroundJobCommands094MutationRequiresReceipt(t *testing.T) {
	pool := packageCommerceRBAC079Pool(t, 94)
	fixture := seedFailedBackgroundJobCommand094(t, pool, "missing-receipt")
	tx, err := pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(t.Context()) }()
	if _, err := jobstate.RetryTx(t.Context(), tx, fixture.tenantID, fixture.jobID, fixture.retryAt); err != nil {
		t.Fatal(err)
	}
	assertBackgroundJobCommands094Code(t, tx.Commit(t.Context()), "P9402")
}

func TestBackgroundJobCommands094PreservesSpecializedDNSFlows(t *testing.T) {
	t.Run("existing DNS cancel", func(t *testing.T) {
		pool := packageCommerceRBAC079Pool(t, 94)
		fixture := seedDNSProviderClaim089WithAttempts(t, pool, "094-special-cancel", 1)
		tx, err := pool.Begin(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(t.Context()) }()
		if err := applyDNSCancelTransition094(t, tx, fixture, false); err != nil {
			t.Fatal(err)
		}
		if err := tx.Commit(t.Context()); err != nil {
			t.Fatal(err)
		}
		var operation string
		var sameXID bool
		if err := pool.QueryRow(t.Context(), `SELECT job.job_command_operation,
			job.job_command_xact_id=fact.job_transition_xact_id
			FROM background_jobs job JOIN dns_reconcile_cancel_facts fact
			  ON fact.tenant_id=job.tenant_id AND fact.job_id=job.id
			WHERE job.tenant_id=$1 AND job.id=$2`, fixture.tenantID, fixture.jobID).
			Scan(&operation, &sameXID); err != nil {
			t.Fatal(err)
		}
		if operation != "dns_cancel" || !sameXID {
			t.Fatalf("DNS cancel marker=%q same_xid=%t", operation, sameXID)
		}
	})

	t.Run("089 provider recovery", func(t *testing.T) {
		pool := releaseHeadMigrationPool(t)
		fixture := prepareDNSRecoveryTransition094(t, pool, "094-special-recovery")
		tx, err := pool.Begin(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(t.Context()) }()
		if err := applyDNSRecoveryTransition094(t, tx, fixture); err != nil {
			t.Fatal(err)
		}
		if err := tx.Commit(t.Context()); err != nil {
			t.Fatal(err)
		}
		var operation string
		var sameXID bool
		if err := pool.QueryRow(t.Context(), `SELECT job.job_command_operation,
			job.job_command_xact_id=continuation.job_transition_xact_id
			FROM background_jobs job JOIN dns_reconcile_provider_recovery_continuations continuation
			  ON continuation.tenant_id=job.tenant_id AND continuation.job_id=job.id
			WHERE job.tenant_id=$1 AND job.id=$2`, fixture.fixture.tenantID, fixture.fixture.jobID).
			Scan(&operation, &sameXID); err != nil {
			t.Fatal(err)
		}
		if operation != "dns_recovery" || !sameXID {
			t.Fatalf("DNS recovery marker=%q same_xid=%t", operation, sameXID)
		}
	})
}

func TestBackgroundJobCommands094RejectsSpecializedDNSBypass(t *testing.T) {
	t.Run("orphan cancel fact", func(t *testing.T) {
		pool := packageCommerceRBAC079Pool(t, 94)
		fixture := seedDNSProviderClaim089WithAttempts(t, pool, "094-orphan-cancel", 1)
		tx, err := pool.Begin(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(t.Context()) }()
		if err := insertDNSCancelSource094(t, tx, fixture); err != nil {
			t.Fatal(err)
		}
		assertBackgroundJobCommands094Code(t, tx.Commit(t.Context()), "P9402")
	})

	t.Run("cancel fact old xid", func(t *testing.T) {
		pool := packageCommerceRBAC079Pool(t, 94)
		fixture := seedDNSProviderClaim089WithAttempts(t, pool, "094-old-xid-cancel", 1)
		tx, err := pool.Begin(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(t.Context()) }()
		var occurredAt time.Time
		if err := tx.QueryRow(t.Context(), `INSERT INTO dns_reconcile_task_events(
			tenant_id,job_id,event_sequence,source,status,result_snapshot,compensation_plan,
			error_class,error_code,occurred_at)
			VALUES($1,$2,1,'control','cancelled','{}','[]','cancelled','cancelled',clock_timestamp())
			RETURNING occurred_at`, fixture.tenantID, fixture.jobID).Scan(&occurredAt); err != nil {
			t.Fatal(err)
		}
		_, err = tx.Exec(t.Context(), `INSERT INTO dns_reconcile_cancel_facts(
			tenant_id,job_id,site_id,command_idempotency_key,command_digest,request_id,
			traceparent,expected_task_revision,event_sequence,created_at,job_transition_xact_id)
			VALUES($1,$2,$3,'old-xid-cancel',decode(repeat('a',64),'hex'),'old-xid-request',
			'old-xid-trace',1,1,$4,'1'::xid8)`, fixture.tenantID, fixture.jobID,
			fixture.siteID, occurredAt)
		assertBackgroundJobCommands094Code(t, err, "P9402")
	})

	t.Run("cancel fact immediate before job", func(t *testing.T) {
		pool := packageCommerceRBAC079Pool(t, 94)
		fixture := seedDNSProviderClaim089WithAttempts(t, pool, "094-early-cancel", 1)
		tx, err := pool.Begin(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(t.Context()) }()
		if err := insertDNSCancelSource094(t, tx, fixture); err != nil {
			t.Fatal(err)
		}
		_, err = tx.Exec(t.Context(), `SET CONSTRAINTS dns_reconcile_cancel_transition_final_094 IMMEDIATE`)
		assertBackgroundJobCommands094Code(t, err, "P9402")
	})

	t.Run("cancel fact time mismatch", func(t *testing.T) {
		pool := packageCommerceRBAC079Pool(t, 94)
		fixture := seedDNSProviderClaim089WithAttempts(t, pool, "094-cancel-time", 1)
		tx, err := pool.Begin(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(t.Context()) }()
		if err := applyDNSCancelTransition094(t, tx, fixture, true); err != nil {
			t.Fatal(err)
		}
		assertBackgroundJobCommands094Code(t, tx.Commit(t.Context()), "P9402")
	})

	t.Run("recovery immediate before job", func(t *testing.T) {
		pool := releaseHeadMigrationPool(t)
		fixture := prepareDNSRecoveryTransition094(t, pool, "094-early-recovery")
		tx, err := pool.Begin(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(t.Context()) }()
		if err := insertDNSRecoverySource094(t, tx, fixture); err != nil {
			t.Fatal(err)
		}
		_, err = tx.Exec(t.Context(), `SET CONSTRAINTS dns_reconcile_provider_recovery_transition_final_094 IMMEDIATE`)
		assertBackgroundJobCommands094Code(t, err, "P9402")
	})

	t.Run("recovery xid mutation", func(t *testing.T) {
		pool := releaseHeadMigrationPool(t)
		fixture := prepareDNSRecoveryTransition094(t, pool, "094-recovery-xid")
		tx, err := pool.Begin(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(t.Context()) }()
		if err := insertDNSRecoverySource094(t, tx, fixture); err != nil {
			t.Fatal(err)
		}
		_, err = tx.Exec(t.Context(), `UPDATE dns_reconcile_provider_recovery_continuations
			SET job_transition_xact_id='1'::xid8
			WHERE tenant_id=$1 AND job_id=$2`, fixture.fixture.tenantID, fixture.fixture.jobID)
		assertBackgroundJobCommands094Code(t, err, "P9402")
	})

	t.Run("recovery then claim in same transaction", func(t *testing.T) {
		pool := releaseHeadMigrationPool(t)
		fixture := prepareDNSRecoveryTransition094(t, pool, "094-recovery-claim")
		tx, err := pool.Begin(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(t.Context()) }()
		if err := applyDNSRecoveryTransition094(t, tx, fixture); err != nil {
			t.Fatal(err)
		}
		leaseID := uuid.New()
		claimAt := time.Now().UTC()
		leaseExpiresAt := claimAt.Add(time.Minute)
		if _, err := tx.Exec(t.Context(), `UPDATE background_jobs
			SET state='running',attempt=2,lease_id=$3,lease_owner='same-xid-worker',
				lease_expires_at=$4,claimable_at=$4,updated_at=$5
			WHERE tenant_id=$1 AND id=$2`, fixture.fixture.tenantID, fixture.fixture.jobID,
			leaseID, leaseExpiresAt, claimAt); err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(t.Context(), `INSERT INTO background_job_attempts(
			tenant_id,job_id,attempt,lease_id,worker_id,state,
			started_at,last_heartbeat_at,lease_expires_at)
			VALUES($1,$2,2,$3,'same-xid-worker','running',$4,$4,$5)`,
			fixture.fixture.tenantID, fixture.fixture.jobID, leaseID, claimAt,
			leaseExpiresAt); err != nil {
			t.Fatal(err)
		}
		assertBackgroundJobCommands094Code(t, tx.Commit(t.Context()), "P9402")
	})

	t.Run("generic DNS cancel still needs receipt", func(t *testing.T) {
		pool := packageCommerceRBAC079Pool(t, 94)
		fixture := seedDNSProviderClaim089WithAttempts(t, pool, "094-generic-dns", 1)
		tx, err := pool.Begin(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(t.Context()) }()
		if _, err := jobstate.CancelTx(t.Context(), tx, fixture.tenantID, fixture.jobID,
			time.Now().UTC()); err != nil {
			t.Fatal(err)
		}
		assertBackgroundJobCommands094Code(t, tx.Commit(t.Context()), "P9402")
	})

	t.Run("generic DNS retry still needs receipt", func(t *testing.T) {
		pool := packageCommerceRBAC079Pool(t, 94)
		fixture := seedDNSProviderClaim089WithAttempts(t, pool, "094-generic-dns-retry", 2)
		jobs, err := jobstate.NewStore(pool, time.Now)
		if err != nil {
			t.Fatal(err)
		}
		claimed, err := jobs.Claim(t.Context(), jobstate.ClaimInput{
			TenantID: fixture.tenantID, Kind: dnsreconcile.JobKind,
			WorkerID: "dns094-generic-retry", Limit: 1, LeaseDuration: time.Minute,
		})
		if err != nil || len(claimed) != 1 {
			t.Fatalf("claim generic DNS retry job=(%+v,%v)", claimed, err)
		}
		if _, err := jobs.Report(t.Context(), jobstate.ReportInput{
			TenantID: fixture.tenantID, JobID: fixture.jobID, WorkerID: claimed[0].WorkerID,
			LeaseID: claimed[0].LeaseID, Report: jobstate.Report{
				ItemID: dnsreconcile.JobItemID, State: jobstate.ItemFailed,
				Code: "provider_failed", Attempt: 1, Sequence: 1,
			},
		}); err != nil {
			t.Fatal(err)
		}
		tx, err := pool.Begin(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(t.Context()) }()
		if _, err := jobstate.RetryTx(t.Context(), tx, fixture.tenantID, fixture.jobID,
			time.Now().UTC()); err != nil {
			t.Fatal(err)
		}
		var operation string
		if err := tx.QueryRow(t.Context(), `SELECT job_command_operation FROM background_jobs
			WHERE tenant_id=$1 AND id=$2`, fixture.tenantID, fixture.jobID).Scan(&operation); err != nil {
			t.Fatal(err)
		}
		if operation != "retry" {
			t.Fatalf("generic DNS retry marker=%q want retry", operation)
		}
		assertBackgroundJobCommands094Code(t, tx.Commit(t.Context()), "P9402")
	})
}

func TestBackgroundJobCommands094RejectsSecondMutationInTransaction(t *testing.T) {
	t.Run("retry then cancel", func(t *testing.T) {
		pool := packageCommerceRBAC079Pool(t, 94)
		fixture := seedFailedBackgroundJobCommand094(t, pool, "retry-cancel")
		tx, err := pool.Begin(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(t.Context()) }()
		if _, err := jobstate.RetryTx(t.Context(), tx, fixture.tenantID, fixture.jobID, fixture.retryAt); err != nil {
			t.Fatal(err)
		}
		_, err = jobstate.CancelTx(t.Context(), tx, fixture.tenantID, fixture.jobID, fixture.retryAt.Add(time.Second))
		assertBackgroundJobCommands094Code(t, err, "P9402")
	})

	t.Run("double retry", func(t *testing.T) {
		pool := packageCommerceRBAC079Pool(t, 94)
		fixture := seedFailedBackgroundJobCommand094(t, pool, "double-retry")
		tx, err := pool.Begin(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(t.Context()) }()
		retried, err := jobstate.RetryTx(t.Context(), tx, fixture.tenantID, fixture.jobID, fixture.retryAt)
		if err != nil {
			t.Fatal(err)
		}
		failRetriedBackgroundJob094(t, tx, fixture, retried)
		_, err = jobstate.RetryTx(t.Context(), tx, fixture.tenantID, fixture.jobID, fixture.retryAt.Add(3*time.Second))
		assertBackgroundJobCommands094Code(t, err, "P9402")
	})
}

func TestBackgroundJobCommands094AllowsMultipleJobsPerTransaction(t *testing.T) {
	pool := packageCommerceRBAC079Pool(t, 94)
	tx, err := pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(t.Context()) }()
	insertBackgroundJobCommandReceipt094Tx(t, tx)
	insertBackgroundJobCommandReceipt094Tx(t, tx)
	if err := tx.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
}

func TestBackgroundJobCommands094RejectsManualMarkersAndTenantForgery(t *testing.T) {
	for _, marker := range []string{"42", "current"} {
		t.Run("insert marker "+marker, func(t *testing.T) {
			pool := packageCommerceRBAC079Pool(t, 94)
			tenantID, jobID := uuid.New(), uuid.New()
			digest := sha256.Sum256([]byte("manual-marker-" + marker))
			now := time.Date(2026, 8, 4, 12, 0, 0, 0, time.UTC)
			if _, err := pool.Exec(t.Context(), `INSERT INTO tenants(id,display_name)
				VALUES($1,'Manual marker tenant')`, tenantID); err != nil {
				t.Fatal(err)
			}
			xidExpression := `$5::xid8`
			arguments := []any{jobID, tenantID, digest[:], now, "42"}
			if marker == "current" {
				xidExpression = `pg_current_xact_id()`
				arguments = arguments[:4]
			}
			statement := `INSERT INTO background_jobs(
				id,tenant_id,kind,subject,idempotency_key,request_digest,request_id,state,
				attempt,max_attempts,claimable_at,total_count,created_at,updated_at,
				job_command_operation,job_command_xact_id
			) VALUES($1,$2,'cache.purge','manual/marker','manual-marker',$3,'manual-marker',
				'queued',0,3,$4,1,$4,$4,'retry',` + xidExpression + `)`
			_, err := pool.Exec(t.Context(), statement, arguments...)
			assertBackgroundJobCommands094Code(t, err, "P9402")
		})
	}

	t.Run("update marker", func(t *testing.T) {
		pool := packageCommerceRBAC079Pool(t, 94)
		fixture := seedFailedBackgroundJobCommand094(t, pool, "manual-update")
		_, err := pool.Exec(t.Context(), `UPDATE background_jobs
			SET job_command_operation='retry',job_command_xact_id=pg_current_xact_id()
			WHERE tenant_id=$1 AND id=$2`, fixture.tenantID, fixture.jobID)
		assertBackgroundJobCommands094Code(t, err, "P9402")
	})

	for _, tenant := range []struct {
		name  string
		value any
	}{{name: "forged tenant", value: uuid.New()}, {name: "null tenant", value: nil}} {
		t.Run(tenant.name, func(t *testing.T) {
			pool := packageCommerceRBAC079Pool(t, 94)
			fixture := insertBackgroundJobCommandReceipt094(t, pool)
			_, err := pool.Exec(t.Context(), `INSERT INTO background_job_command_receipts(
				actor_scope_id,actor_user_id,idempotency_key,request_digest,audience,tenant_id,job_id,
				operation,request_id,audit_event_id,result_kind,result_subject,result_request_id,
				result_trace_id,result_state,result_attempt,result_max_attempts,result_total_count,
				result_completed_count,result_succeeded_count,result_failed_count,result_cancelled_count,
				result_failure_code,result_created_at,result_started_at,result_updated_at,result_completed_at,
				created_at,completed_at
			) SELECT actor_scope_id,actor_user_id,$1,request_digest,audience,$2::uuid,job_id,
				operation,request_id,audit_event_id,result_kind,result_subject,result_request_id,
				result_trace_id,result_state,result_attempt,result_max_attempts,result_total_count,
				result_completed_count,result_succeeded_count,result_failed_count,result_cancelled_count,
				result_failure_code,result_created_at,result_started_at,result_updated_at,result_completed_at,
				created_at,completed_at FROM background_job_command_receipts WHERE audit_event_id=$3`,
				strings.ReplaceAll(tenant.name, " ", "-"), tenant.value, fixture.auditID)
			assertBackgroundJobCommands094Code(t, err, "P9402")
		})
	}
}

func TestBackgroundJobCommands094DownSerializesCommandAndCustomRoleWrites(t *testing.T) {
	t.Run("command audit receipt", func(t *testing.T) {
		pool := packageCommerceRBAC079Pool(t, 94)
		commandTx, err := pool.Begin(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = commandTx.Rollback(t.Context()) }()
		fixture := insertBackgroundJobCommandReceipt094Tx(t, commandTx)
		var commandPID int32
		if err := commandTx.QueryRow(t.Context(), `SELECT pg_backend_pid()`).Scan(&commandPID); err != nil {
			t.Fatal(err)
		}
		downConn, err := pool.Acquire(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		defer downConn.Release()
		var downPID int32
		if err := downConn.QueryRow(t.Context(), `SELECT pg_backend_pid()`).Scan(&downPID); err != nil {
			t.Fatal(err)
		}
		downResult := make(chan error, 1)
		go func() {
			_, downErr := downConn.Exec(context.Background(),
				mustReadBackgroundJobCommands094(t, "094_background_job_commands.down.sql"))
			downResult <- downErr
		}()
		waitForBackgroundJobCommandBlock094(t, pool, downPID, commandPID)
		if err := commandTx.Commit(t.Context()); err != nil {
			t.Fatal(err)
		}
		assertBackgroundJobCommands094Code(t, <-downResult, "P9401")
		var receipts int
		if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM background_job_command_receipts
			WHERE audit_event_id=$1`, fixture.auditID).Scan(&receipts); err != nil || receipts != 1 {
			t.Fatalf("committed command receipts=%d err=%v", receipts, err)
		}
	})

	t.Run("custom role revision", func(t *testing.T) {
		pool := packageCommerceRBAC079Pool(t, 94)
		tenantID, scopeID, actorID, customRoleID := uuid.New(), uuid.New(), uuid.New(), uuid.New()
		now := time.Date(2026, 8, 4, 9, 30, 0, 0, time.UTC)
		if _, err := pool.Exec(t.Context(), `
			INSERT INTO tenants(id,display_name) VALUES($1,'Job command serialized custom role');
			INSERT INTO access_scopes(id,kind,tenant_id) VALUES($2,'tenant',$1);
			INSERT INTO users(id,username,display_name,password_hash) VALUES($3,$4,'Job role actor','test-only');
			INSERT INTO memberships(scope_id,user_id) VALUES($2,$3);
			INSERT INTO custom_roles(
				id,tenant_id,tenant_scope_id,current_name,created_by_user_id,created_by_scope_id,
				created_at,updated_at
			) VALUES($5,$1,$2,'job-operator',$3,$2,$6,$6)`, pgx.QueryExecModeSimpleProtocol,
			tenantID, scopeID, actorID, "job-role-"+strings.ReplaceAll(actorID.String(), "-", ""),
			customRoleID, now); err != nil {
			t.Fatal(err)
		}
		blocker, err := pool.Begin(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = blocker.Rollback(t.Context()) }()
		if _, err := blocker.Exec(t.Context(), `LOCK TABLE audit_events IN ACCESS SHARE MODE`); err != nil {
			t.Fatal(err)
		}
		var blockerPID int32
		if err := blocker.QueryRow(t.Context(), `SELECT pg_backend_pid()`).Scan(&blockerPID); err != nil {
			t.Fatal(err)
		}
		downConn, err := pool.Acquire(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		defer downConn.Release()
		var downPID int32
		if err := downConn.QueryRow(t.Context(), `SELECT pg_backend_pid()`).Scan(&downPID); err != nil {
			t.Fatal(err)
		}
		downResult := make(chan error, 1)
		go func() {
			_, downErr := downConn.Exec(context.Background(),
				mustReadBackgroundJobCommands094(t, "094_background_job_commands.down.sql"))
			downResult <- downErr
		}()
		waitForBackgroundJobCommandBlock094(t, pool, downPID, blockerPID)

		writerConn, err := pool.Acquire(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		defer writerConn.Release()
		var writerPID int32
		if err := writerConn.QueryRow(t.Context(), `SELECT pg_backend_pid()`).Scan(&writerPID); err != nil {
			t.Fatal(err)
		}
		writerResult := make(chan error, 1)
		go func() {
			_, writerErr := writerConn.Exec(context.Background(), `INSERT INTO custom_role_revisions(
				role_id,tenant_id,tenant_scope_id,revision,name,permissions,action,
				created_by_user_id,created_by_scope_id,created_at
			) VALUES($1,$2,$3,1,'job-operator',ARRAY[$4]::text[],
				'identity.custom_role.create',$5,$3,$6)`,
				customRoleID, tenantID, scopeID, backgroundJobManage094, actorID, now)
			writerResult <- writerErr
		}()
		waitForBackgroundJobCommandBlock094(t, pool, writerPID, downPID)
		if err := blocker.Commit(t.Context()); err != nil {
			t.Fatal(err)
		}
		if err := <-downResult; err != nil {
			t.Fatalf("serialized 094 down: %v", err)
		}
		if err := <-writerResult; err == nil {
			t.Fatal("custom role write survived removal of jobs.manage")
		}
	})
}

func TestBackgroundJobCommands094ConcurrentRetrySingleWinnerReplay(t *testing.T) {
	pool := packageCommerceRBAC079Pool(t, 94)
	// The job command audit.Append writes the columns of migration 361 (unified log).
	databasetest.AddUnifiedAuditColumns(t, pool)
	tenantID, scopeID, actorID, roleID := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	if _, err := pool.Exec(t.Context(), `
		INSERT INTO tenants(id,display_name) VALUES($1,'Job command retry tenant');
		INSERT INTO access_scopes(id,kind,tenant_id) VALUES($2,'tenant',$1);
		INSERT INTO users(id,username,display_name,password_hash) VALUES($3,$4,'Job retry actor','test-only');
		INSERT INTO memberships(scope_id,user_id) VALUES($2,$3);
		INSERT INTO roles(id,scope_id,name,description,system_role)
		VALUES($5,$2,'tenant_owner','Job retry owner',true);
		INSERT INTO role_assignments(scope_id,user_id,role_id) VALUES($2,$3,$5)`,
		pgx.QueryExecModeSimpleProtocol, tenantID, scopeID, actorID,
		"job-retry-"+strings.ReplaceAll(actorID.String(), "-", ""), roleID); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 4, 10, 0, 0, 0, time.UTC)
	store, err := jobstate.NewStore(pool, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	created, err := store.Create(t.Context(), jobstate.CreateInput{
		TenantID: tenantID, Kind: "cache.purge", Subject: "site/retry-race",
		IdempotencyKey: "retry-race-create", Payload: []byte(`{"resource":"site/retry-race"}`),
		Items: []jobstate.CreateItem{{ItemID: "item-a"}}, MaxAttempts: 2,
		RequestID: "retry-race-create", TraceID: "retry-race-trace",
	})
	if err != nil {
		t.Fatal(err)
	}
	claims, err := store.Claim(t.Context(), jobstate.ClaimInput{
		TenantID: tenantID, Kind: "cache.purge", WorkerID: "retry-race-worker",
		Limit: 1, LeaseDuration: 30 * time.Second,
	})
	if err != nil || len(claims) != 1 {
		t.Fatalf("retry race claims=%+v err=%v", claims, err)
	}
	now = now.Add(time.Second)
	reported, err := store.Report(t.Context(), jobstate.ReportInput{
		TenantID: tenantID, JobID: created.Job.ID, WorkerID: claims[0].WorkerID, LeaseID: claims[0].LeaseID,
		Report: jobstate.Report{ItemID: "item-a", State: jobstate.ItemFailed,
			Code: "origin_timeout", Attempt: claims[0].Job.Attempt, Sequence: 1},
	})
	if err != nil || !reported.Applied || reported.Job.State != jobstate.StateFailed {
		t.Fatalf("retry race failed job=%+v err=%v", reported, err)
	}
	reader, err := jobhttp.NewPostgresReader(pool)
	if err != nil {
		t.Fatal(err)
	}
	service, err := jobhttp.NewService(reader, jobhttp.ServiceConfig{
		ActiveCursorKeyID: "retry-race", CursorKeys: map[string][]byte{
			"retry-race": []byte("0123456789abcdef0123456789abcdef"),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	principal := jobhttp.Principal{
		UserID: actorID, ScopeID: scopeID, ScopeKind: jobhttp.ScopeTenant,
		Permissions: map[string]struct{}{jobhttp.PermissionManage: {}},
	}
	input := jobhttp.CommandRequest{
		Audience: jobhttp.AudienceTenant, TaskID: created.Job.ID,
		Operation: jobhttp.CommandRetry, IdempotencyKey: "retry-race-command",
	}
	lockDigest := sha256.Sum256([]byte(scopeID.String() + "\x00" + actorID.String() + "\x00" + input.IdempotencyKey))
	lockKey := int64(binary.BigEndian.Uint64(lockDigest[:8]))
	gate, err := pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = gate.Rollback(t.Context()) }()
	if _, err := gate.Exec(t.Context(), `SELECT pg_advisory_xact_lock($1)`, lockKey); err != nil {
		t.Fatal(err)
	}
	var gatePID int32
	if err := gate.QueryRow(t.Context(), `SELECT pg_backend_pid()`).Scan(&gatePID); err != nil {
		t.Fatal(err)
	}
	type retryResult struct {
		result jobhttp.CommandResult
		err    error
	}
	results := make(chan retryResult, 2)
	start := make(chan struct{})
	for range 2 {
		go func() {
			<-start
			result, commandErr := service.Command(context.Background(), principal, input)
			results <- retryResult{result: result, err: commandErr}
		}()
	}
	close(start)
	waitForBackgroundJobCommandBlockerCount094(t, pool, gatePID, 2)
	if err := gate.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
	first, second := <-results, <-results
	if first.err != nil || second.err != nil || first.result.Replayed == second.result.Replayed ||
		!reflect.DeepEqual(first.result.Data, second.result.Data) {
		t.Fatalf("concurrent retry first=%+v second=%+v", first, second)
	}
	stored, err := store.Get(t.Context(), tenantID, created.Job.ID)
	if err != nil || stored.State != jobstate.StateQueued || stored.Attempt != 1 {
		t.Fatalf("concurrent retry stored=%+v err=%v", stored, err)
	}
	var receipts, audits int
	if err := pool.QueryRow(t.Context(), `SELECT
		(SELECT count(*) FROM background_job_command_receipts WHERE job_id=$1 AND operation='retry'),
		(SELECT count(*) FROM audit_events WHERE resource_id=$1::text AND action='job.retry' AND result='success')`,
		created.Job.ID).Scan(&receipts, &audits); err != nil || receipts != 1 || audits != 1 {
		t.Fatalf("concurrent retry receipts/audits=%d/%d err=%v", receipts, audits, err)
	}
}

func TestBackgroundJobCommands094DownGuards(t *testing.T) {
	t.Run("facts", func(t *testing.T) {
		pool := packageCommerceRBAC079Pool(t, 94)
		insertBackgroundJobCommandReceipt094(t, pool)
		err := migrateVersionIsolated(t.Context(), pool, "down", 94)
		assertBackgroundJobCommands094Code(t, err, "P9401")
	})
	t.Run("unowned grant", func(t *testing.T) {
		pool := packageCommerceRBAC079Pool(t, 94)
		tenantID, scopeID, actorID, ownerRoleID, customRoleID :=
			uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
		now := time.Date(2026, 8, 4, 9, 0, 0, 0, time.UTC)
		if _, err := pool.Exec(t.Context(), `
				INSERT INTO tenants(id,display_name) VALUES($1,'Job command down tenant');
				INSERT INTO access_scopes(id,kind,tenant_id) VALUES($2,'tenant',$1);
				INSERT INTO users(id,username,display_name,password_hash)
				VALUES($3,$4,'Job command down actor','test-only');
				INSERT INTO memberships(scope_id,user_id) VALUES($2,$3);
				INSERT INTO roles(id,scope_id,name,description,system_role)
				VALUES($5,$2,'tenant_owner','Job command down owner',true);
				INSERT INTO role_assignments(scope_id,user_id,role_id,assigned_at)
				VALUES($2,$3,$5,$6);
				INSERT INTO custom_roles(
					id,tenant_id,tenant_scope_id,current_name,created_by_user_id,
					created_by_scope_id,created_at,updated_at
				) VALUES($7,$1,$2,'job-operator',$3,$2,$6,$6);
				INSERT INTO custom_role_revisions(
					role_id,tenant_id,tenant_scope_id,revision,name,permissions,action,
					created_by_user_id,created_by_scope_id,created_at
				) VALUES($7,$1,$2,1,'job-operator',ARRAY[$8]::text[],
					'identity.custom_role.create',$3,$2,$6);
				UPDATE custom_roles SET current_revision=1,updated_at=$6 WHERE id=$7`,
			pgx.QueryExecModeSimpleProtocol,
			tenantID, scopeID, actorID,
			"job-command-down-"+strings.ReplaceAll(actorID.String(), "-", ""),
			ownerRoleID, now, customRoleID, backgroundJobManage094); err != nil {
			t.Fatal(err)
		}
		err := migrateVersionIsolated(t.Context(), pool, "down", 94)
		assertBackgroundJobCommands094Code(t, err, "P9401")
	})
	t.Run("tampered head", func(t *testing.T) {
		pool := packageCommerceRBAC079Pool(t, 94)
		if _, err := pool.Exec(t.Context(), `UPDATE schema_migrations
			SET checksum_sha256=repeat('b',64) WHERE version=94`); err != nil {
			t.Fatal(err)
		}
		down := mustReadBackgroundJobCommands094(t, "094_background_job_commands.down.sql")
		_, err := pool.Exec(t.Context(), down)
		assertBackgroundJobCommands094Code(t, err, "P9400")
	})
}

type backgroundJobCommandRoles094 struct {
	tenantOwner   uuid.UUID
	tenantAdmin   uuid.UUID
	platformOwner uuid.UUID
	platformOther uuid.UUID
	platformPlain uuid.UUID
}

func seedBackgroundJobCommandRoles094(t *testing.T, pool *pgxpool.Pool, suffix string) backgroundJobCommandRoles094 {
	t.Helper()
	tenantID, tenantScope, platformScope := uuid.New(), uuid.New(), uuid.New()
	roles := backgroundJobCommandRoles094{
		tenantOwner: uuid.New(), tenantAdmin: uuid.New(), platformOwner: uuid.New(),
		platformOther: uuid.New(), platformPlain: uuid.New(),
	}
	if _, err := pool.Exec(t.Context(), `
		INSERT INTO tenants(id,display_name) VALUES($1,$2);
		INSERT INTO access_scopes(id,kind,tenant_id) VALUES($3,'tenant',$1),($4,'platform',NULL);
		INSERT INTO roles(id,scope_id,name,description,system_role) VALUES
			($5,$3,'tenant_owner','Tenant owner',true),
			($6,$3,'tenant_admin','Tenant admin',true),
			($7,$4,'platform_owner','Platform owner',true),
				($8,$4,'platform_operator','Platform operator',true),
				($9,$4,'platform_plain','Platform plain',true)`,
		pgx.QueryExecModeSimpleProtocol,
		tenantID, "Job command "+suffix, tenantScope, platformScope,
		roles.tenantOwner, roles.tenantAdmin, roles.platformOwner, roles.platformOther, roles.platformPlain); err != nil {
		t.Fatal(err)
	}
	return roles
}

func assertBackgroundJobCommands094Schema(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	var columns, nullable, permissionCount int
	var tenantCatalog, platformCatalog, publicAccess bool
	var markerColumns, sourceColumns int
	if err := pool.QueryRow(t.Context(), `SELECT count(*),count(*) FILTER (WHERE is_nullable='YES')
		FROM information_schema.columns WHERE table_schema=current_schema()
		  AND table_name='background_job_command_receipts'`).Scan(&columns, &nullable); err != nil {
		t.Fatal(err)
	}
	if columns != 30 || nullable != 3 {
		t.Fatalf("receipt columns/nullable=%d/%d want 30/3", columns, nullable)
	}
	if err := pool.QueryRow(t.Context(), `SELECT count(*)
		FROM information_schema.columns WHERE table_schema=current_schema()
		  AND table_name='background_jobs' AND is_nullable='YES' AND (
			(column_name='job_command_operation' AND data_type='text') OR
			(column_name='job_command_xact_id' AND data_type='xid8')
		  )`).Scan(&markerColumns); err != nil {
		t.Fatal(err)
	}
	if markerColumns != 2 {
		t.Fatalf("background job command marker columns=%d want 2", markerColumns)
	}
	if err := pool.QueryRow(t.Context(), `SELECT count(*)
		FROM information_schema.columns WHERE table_schema=current_schema()
		  AND column_name='job_transition_xact_id' AND data_type='xid8' AND is_nullable='YES'
		  AND table_name IN ('dns_reconcile_cancel_facts',
		                     'dns_reconcile_provider_recovery_continuations')`).Scan(&sourceColumns); err != nil {
		t.Fatal(err)
	}
	if sourceColumns != 2 {
		t.Fatalf("DNS transition source columns=%d want 2", sourceColumns)
	}
	if err := pool.QueryRow(t.Context(), `SELECT
		count(*) FILTER (WHERE name IN ($1,$2)),
		EXISTS(SELECT 1 FROM custom_rbac_permission_catalog WHERE permission_name=$1),
		EXISTS(SELECT 1 FROM custom_rbac_permission_catalog WHERE permission_name=$2),
		has_table_privilege('public','background_job_command_receipts','SELECT')
		FROM permissions`, backgroundJobManage094, backgroundJobManageAll094).Scan(
		&permissionCount, &tenantCatalog, &platformCatalog, &publicAccess); err != nil {
		t.Fatal(err)
	}
	if permissionCount != 2 || !tenantCatalog || platformCatalog || publicAccess {
		t.Fatalf("permission count/manage catalog/manage-all catalog/public=%d/%t/%t/%t",
			permissionCount, tenantCatalog, platformCatalog, publicAccess)
	}
}

func assertBackgroundJobCommandRole094(t *testing.T, pool *pgxpool.Pool, roleID uuid.UUID,
	permission string, want bool) {
	t.Helper()
	var got bool
	if err := pool.QueryRow(t.Context(), `SELECT EXISTS(SELECT 1 FROM role_permissions
		WHERE role_id=$1 AND permission_name=$2)`, roleID, permission).Scan(&got); err != nil || got != want {
		t.Fatalf("role=%s permission=%s got=%t want=%t err=%v", roleID, permission, got, want, err)
	}
}

func insertDNSCancelSource094(t *testing.T, tx pgx.Tx, fixture dnsProviderClaimFixture089) error {
	t.Helper()
	var occurredAt time.Time
	if err := tx.QueryRow(t.Context(), `INSERT INTO dns_reconcile_task_events(
		tenant_id,job_id,event_sequence,source,status,result_snapshot,compensation_plan,
		error_class,error_code,occurred_at)
		VALUES($1,$2,1,'control','cancelled','{}','[]','cancelled','cancelled',clock_timestamp())
		RETURNING occurred_at`, fixture.tenantID, fixture.jobID).Scan(&occurredAt); err != nil {
		return err
	}
	_, err := tx.Exec(t.Context(), `INSERT INTO dns_reconcile_cancel_facts(
		tenant_id,job_id,site_id,command_idempotency_key,command_digest,request_id,
		traceparent,expected_task_revision,event_sequence,created_at)
		VALUES($1,$2,$3,'dns-cancel-094',decode(repeat('a',64),'hex'),'dns-cancel-request',
		'dns-cancel-trace',1,1,$4)`, fixture.tenantID, fixture.jobID, fixture.siteID, occurredAt)
	return err
}

func applyDNSCancelTransition094(t *testing.T, tx pgx.Tx, fixture dnsProviderClaimFixture089,
	forgeFinalTime bool,
) error {
	t.Helper()
	if err := insertDNSCancelSource094(t, tx, fixture); err != nil {
		return err
	}
	var transitionAt time.Time
	if err := tx.QueryRow(t.Context(), `SELECT created_at FROM dns_reconcile_cancel_facts
		WHERE tenant_id=$1 AND job_id=$2`, fixture.tenantID, fixture.jobID).Scan(&transitionAt); err != nil {
		return err
	}
	if forgeFinalTime {
		transitionAt = transitionAt.Add(time.Second)
	}
	if _, err := tx.Exec(t.Context(), `UPDATE background_jobs
		SET state='cancelled',cancel_requested_at=$3,completed_count=1,
			succeeded_count=0,failed_count=0,cancelled_count=1,
			lease_id=NULL,lease_owner=NULL,lease_expires_at=NULL,claimable_at=NULL,
			last_error_code='cancelled',completed_at=$3,updated_at=$3
		WHERE tenant_id=$1 AND id=$2`, fixture.tenantID, fixture.jobID, transitionAt); err != nil {
		return err
	}
	_, err := tx.Exec(t.Context(), `UPDATE background_job_items
		SET state='cancelled',attempt=0,sequence=0,error_code='cancelled',completed_at=$3
		WHERE tenant_id=$1 AND job_id=$2 AND state='pending'`, fixture.tenantID, fixture.jobID,
		transitionAt)
	return err
}

type dnsRecoveryTransition094 struct {
	fixture       dnsProviderClaimFixture089
	claimID       uuid.UUID
	recoveredJSON []byte
}

func prepareDNSRecoveryTransition094(t *testing.T, pool *pgxpool.Pool,
	suffix string,
) dnsRecoveryTransition094 {
	t.Helper()
	fixture := seedDNSProviderClaim089WithAttempts(t, pool, suffix, 1)
	jobs, err := jobstate.NewStore(pool, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	claimed, err := jobs.Claim(t.Context(), jobstate.ClaimInput{
		TenantID: fixture.tenantID, Kind: dnsreconcile.JobKind,
		WorkerID: "dns094-recovery", Limit: 1, LeaseDuration: time.Minute,
	})
	if err != nil || len(claimed) != 1 {
		t.Fatalf("claim DNS recovery job=(%+v,%v)", claimed, err)
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
		t.Fatalf("prepare DNS recovery operation=(%v,%v)", updateErr, resetErr)
	}
	pending := dnscheck.ReconcileResult{
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
	pendingJSON, err := json.Marshal(pending)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO dns_reconcile_task_events(
		tenant_id,job_id,event_sequence,source,status,provider_revision,result_snapshot,
		compensation_plan,error_class,error_code,occurred_at)
		VALUES($1,$2,1,'control','failed',1,$3,'[]','transient',
		'provider_recovery_pending',clock_timestamp())`, fixture.tenantID, fixture.jobID,
		pendingJSON); err != nil {
		t.Fatal(err)
	}
	claimID := insertDNSProviderClaim089(t, pool, fixture)
	if _, err := pool.Exec(t.Context(), `UPDATE dns_reconcile_provider_mutation_claims
		SET state='conflict',final_zone_revision=expected_zone_revision,finalized_at=statement_timestamp()
		WHERE tenant_id=$1 AND client_request_id=$2 AND claim_id=$3`,
		fixture.tenantID, fixture.clientRequestID, claimID); err != nil {
		t.Fatal(err)
	}
	recovered := pending
	recovered.Operations = append([]dnscheck.OperationResult(nil), pending.Operations...)
	recovered.Status = dnscheck.TaskApplying
	recovered.ErrorClass = dnscheck.ProviderErrorNone
	recovered.ErrorCode = ""
	recovered.Operations[0].Status = dnscheck.OperationPlanned
	recovered.Operations[0].ErrorClass = dnscheck.ProviderErrorNone
	recovered.Operations[0].ErrorCode = ""
	recoveredJSON, err := json.Marshal(recovered)
	if err != nil {
		t.Fatal(err)
	}
	return dnsRecoveryTransition094{fixture: fixture, claimID: claimID, recoveredJSON: recoveredJSON}
}

func insertDNSRecoverySource094(t *testing.T, tx pgx.Tx, fixture dnsRecoveryTransition094) error {
	t.Helper()
	_, err := tx.Exec(t.Context(), `INSERT INTO dns_reconcile_provider_recovery_continuations(
		tenant_id,client_request_id,claim_id,job_id,continuation_attempt,
		previous_item_attempt,previous_item_sequence,result_attempts,event_sequence,
		recovery_event_sequence,recovery_result_digest,granted_at)
		VALUES($1,$2,$3,$4,2,1,7,3,1,2,
		sha256(convert_to($5::jsonb::text,'UTF8')),clock_timestamp())`,
		fixture.fixture.tenantID, fixture.fixture.clientRequestID, fixture.claimID,
		fixture.fixture.jobID, fixture.recoveredJSON)
	return err
}

func applyDNSRecoveryTransition094(t *testing.T, tx pgx.Tx, fixture dnsRecoveryTransition094) error {
	t.Helper()
	if err := insertDNSRecoverySource094(t, tx, fixture); err != nil {
		return err
	}
	var grantedAt time.Time
	if err := tx.QueryRow(t.Context(), `SELECT granted_at
		FROM dns_reconcile_provider_recovery_continuations
		WHERE tenant_id=$1 AND job_id=$2`, fixture.fixture.tenantID, fixture.fixture.jobID).
		Scan(&grantedAt); err != nil {
		return err
	}
	if _, err := tx.Exec(t.Context(), `UPDATE background_jobs
		SET state='queued',max_attempts=2,completed_count=succeeded_count,failed_count=0,
			lease_id=NULL,lease_owner=NULL,lease_expires_at=NULL,claimable_at=$3,
			last_error_code=NULL,completed_at=NULL,updated_at=$3
		WHERE tenant_id=$1 AND id=$2`, fixture.fixture.tenantID, fixture.fixture.jobID,
		grantedAt); err != nil {
		return err
	}
	if _, err := tx.Exec(t.Context(), `UPDATE background_job_items
		SET state='pending',error_code=NULL,completed_at=NULL
		WHERE tenant_id=$1 AND job_id=$2 AND item_id='reconcile'`,
		fixture.fixture.tenantID, fixture.fixture.jobID); err != nil {
		return err
	}
	if _, err := tx.Exec(t.Context(), `INSERT INTO dns_reconcile_task_events(
		tenant_id,job_id,event_sequence,source,status,provider_revision,result_snapshot,
		compensation_plan,error_class,error_code,occurred_at)
		VALUES($1,$2,2,'control','applying',1,$3,'[]','',NULL,clock_timestamp())`,
		fixture.fixture.tenantID, fixture.fixture.jobID, fixture.recoveredJSON); err != nil {
		return err
	}
	_, err := tx.Exec(t.Context(), `UPDATE dns_reconcile_provider_recovery_continuations
		SET consumed_at=clock_timestamp()
		WHERE tenant_id=$1 AND job_id=$2 AND consumed_at IS NULL`,
		fixture.fixture.tenantID, fixture.fixture.jobID)
	return err
}

type backgroundJobCommandFixture094 struct {
	auditID uuid.UUID
}

type backgroundJobRetryFixture094 struct {
	tenantID uuid.UUID
	scopeID  uuid.UUID
	userID   uuid.UUID
	jobID    uuid.UUID
	retryAt  time.Time
}

func seedFailedBackgroundJobCommand094(t *testing.T, pool *pgxpool.Pool, suffix string) backgroundJobRetryFixture094 {
	t.Helper()
	tenantID, scopeID, userID := uuid.New(), uuid.New(), uuid.New()
	if _, err := pool.Exec(t.Context(), `
		INSERT INTO tenants(id,display_name) VALUES($1,$2);
		INSERT INTO access_scopes(id,kind,tenant_id) VALUES($3,'tenant',$1);
		INSERT INTO users(id,username,display_name,password_hash)
		VALUES($4,$5,'Job command retry actor','test-only');
		INSERT INTO memberships(scope_id,user_id) VALUES($3,$4)`, pgx.QueryExecModeSimpleProtocol,
		tenantID, "Job command "+suffix, scopeID, userID,
		"job-command-retry-"+strings.ReplaceAll(userID.String(), "-", "")); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 4, 11, 0, 0, 0, time.UTC)
	store, err := jobstate.NewStore(pool, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	created, err := store.Create(t.Context(), jobstate.CreateInput{
		TenantID: tenantID, Kind: "cache.purge", Subject: "site/" + suffix,
		IdempotencyKey: "create-" + suffix,
		Payload:        []byte(`{"resource":"site/` + suffix + `"}`),
		Items:          []jobstate.CreateItem{{ItemID: "item-a"}}, MaxAttempts: 3,
		RequestID: "create-" + suffix, TraceID: "trace-" + suffix,
	})
	if err != nil {
		t.Fatal(err)
	}
	claims, err := store.Claim(t.Context(), jobstate.ClaimInput{
		TenantID: tenantID, Kind: "cache.purge", WorkerID: "worker-" + suffix,
		Limit: 1, LeaseDuration: time.Minute,
	})
	if err != nil || len(claims) != 1 {
		t.Fatalf("seed failed job claims=%+v err=%v", claims, err)
	}
	now = now.Add(time.Second)
	reported, err := store.Report(t.Context(), jobstate.ReportInput{
		TenantID: tenantID, JobID: created.Job.ID,
		WorkerID: claims[0].WorkerID, LeaseID: claims[0].LeaseID,
		Report: jobstate.Report{ItemID: "item-a", State: jobstate.ItemFailed,
			Code: "origin_timeout", Attempt: claims[0].Job.Attempt, Sequence: 1},
	})
	if err != nil || !reported.Applied || reported.Job.State != jobstate.StateFailed {
		t.Fatalf("seed failed job report=%+v err=%v", reported, err)
	}
	return backgroundJobRetryFixture094{
		tenantID: tenantID, scopeID: scopeID, userID: userID,
		jobID: created.Job.ID, retryAt: now.Add(time.Second),
	}
}

func failRetriedBackgroundJob094(t *testing.T, tx pgx.Tx,
	fixture backgroundJobRetryFixture094, retried jobstate.StoredJob) {
	t.Helper()
	claimAt := fixture.retryAt.Add(time.Second)
	failedAt := fixture.retryAt.Add(2 * time.Second)
	leaseExpiresAt := claimAt.Add(time.Minute)
	leaseID := uuid.New()
	attempt := int(retried.Attempt) + 1
	if _, err := tx.Exec(t.Context(), `UPDATE background_jobs SET
		state='running',attempt=$3,lease_id=$4,lease_owner='double-retry-worker',
		lease_expires_at=$5,claimable_at=$5,updated_at=$6
		WHERE tenant_id=$1 AND id=$2`, fixture.tenantID, fixture.jobID,
		attempt, leaseID, leaseExpiresAt, claimAt); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(t.Context(), `INSERT INTO background_job_attempts(
		tenant_id,job_id,attempt,lease_id,worker_id,state,
		started_at,last_heartbeat_at,lease_expires_at
	) VALUES($1,$2,$3,$4,'double-retry-worker','running',$5,$5,$6)`,
		fixture.tenantID, fixture.jobID, attempt, leaseID, claimAt, leaseExpiresAt); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(t.Context(), `INSERT INTO background_job_results(
		id,tenant_id,job_id,item_id,attempt,sequence,state,error_code,source,reported_at
	) VALUES($1,$2,$3,'item-a',$4,1,'failed','origin_timeout','worker',$5)`,
		uuid.New(), fixture.tenantID, fixture.jobID, attempt, failedAt); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(t.Context(), `UPDATE background_jobs SET
		state='failed',completed_count=1,succeeded_count=0,failed_count=1,cancelled_count=0,
		lease_id=NULL,lease_owner=NULL,lease_expires_at=NULL,claimable_at=NULL,
		last_error_code='all_items_failed',completed_at=$3,updated_at=$3
		WHERE tenant_id=$1 AND id=$2`, fixture.tenantID, fixture.jobID, failedAt); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(t.Context(), `UPDATE background_job_items SET
		state='failed',attempt=$3,sequence=1,error_code='origin_timeout',completed_at=$4
		WHERE tenant_id=$1 AND job_id=$2 AND item_id='item-a'`,
		fixture.tenantID, fixture.jobID, attempt, failedAt); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(t.Context(), `UPDATE background_job_attempts SET
		state='failed',completed_at=$4,error_code='all_items_failed'
		WHERE tenant_id=$1 AND job_id=$2 AND attempt=$3`,
		fixture.tenantID, fixture.jobID, attempt, failedAt); err != nil {
		t.Fatal(err)
	}
}

func insertBackgroundJobRetryReceipt094Tx(t *testing.T, tx pgx.Tx,
	fixture backgroundJobRetryFixture094, retried jobstate.StoredJob) {
	t.Helper()
	if err := insertBackgroundJobRetryReceipt094TxError(t, tx, fixture, retried); err != nil {
		t.Fatal(err)
	}
}

func insertBackgroundJobRetryReceipt094TxError(t *testing.T, tx pgx.Tx,
	fixture backgroundJobRetryFixture094, retried jobstate.StoredJob) error {
	t.Helper()
	auditID := uuid.New()
	requestDigest := sha256.Sum256([]byte("retry-command-" + fixture.jobID.String()))
	payload := map[string]any{
		"audience": "tenant", "operation": "retry", "idempotency_key": "retry-command",
		"request_digest": hex.EncodeToString(requestDigest[:]), "tenant_id": fixture.tenantID.String(),
		"result_data": map[string]any{
			"task_id": retried.ID.String(), "tenant_id": retried.TenantID.String(),
			"kind": retried.Kind, "subject": retried.Subject, "request_id": retried.RequestID,
			"trace_id": retried.TraceID, "state": string(retried.State), "attempt": retried.Attempt,
			"max_attempts": retried.MaxAttempts, "total_count": retried.Progress.Total,
			"completed_count": retried.Progress.Completed, "succeeded_count": retried.Progress.Succeeded,
			"failed_count": retried.Progress.Failed, "cancelled_count": retried.Progress.Cancelled,
			"failure_code": nil, "created_at": retried.CreatedAt, "started_at": retried.StartedAt,
			"updated_at": retried.UpdatedAt, "completed_at": nil,
		},
	}
	if _, err := tx.Exec(t.Context(), `INSERT INTO audit_events(
		id,scope_id,stream_position,actor_user_id,action,resource_type,resource_id,
		request_id,result,payload,previous_hash,event_hash,occurred_at
	) VALUES($1,$2,1,$3,'job.retry','background_job',$4,'retry-command-request','success',$5,
		NULL,sha256(convert_to('retry-command-audit','UTF8')),$6)`,
		auditID, fixture.scopeID, fixture.userID, fixture.jobID.String(), payload, fixture.retryAt); err != nil {
		return err
	}
	_, err := tx.Exec(t.Context(), `INSERT INTO background_job_command_receipts(
		actor_scope_id,actor_user_id,idempotency_key,request_digest,audience,tenant_id,job_id,
		operation,request_id,audit_event_id,result_kind,result_subject,result_request_id,
		result_trace_id,result_state,result_attempt,result_max_attempts,result_total_count,
		result_completed_count,result_succeeded_count,result_failed_count,result_cancelled_count,
		result_failure_code,result_created_at,result_started_at,result_updated_at,result_completed_at,
		created_at,completed_at
	) VALUES($1,$2,'retry-command',$3,'tenant',$4,$5,'retry','retry-command-request',$6,
		$7,$8,$9,$10,'queued',$11,$12,$13,$14,$15,$16,$17,NULL,$18,$19,$20,NULL,$20,$20)`,
		fixture.scopeID, fixture.userID, requestDigest[:], fixture.tenantID, fixture.jobID, auditID,
		retried.Kind, retried.Subject, retried.RequestID, retried.TraceID,
		int(retried.Attempt), int(retried.MaxAttempts), retried.Progress.Total,
		retried.Progress.Completed, retried.Progress.Succeeded, retried.Progress.Failed,
		retried.Progress.Cancelled, retried.CreatedAt, retried.StartedAt, retried.UpdatedAt)
	return err
}

func insertBackgroundJobCommandReceipt094(t *testing.T, pool *pgxpool.Pool) backgroundJobCommandFixture094 {
	t.Helper()
	tx, err := pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(t.Context()) }()
	fixture := insertBackgroundJobCommandReceipt094Tx(t, tx)
	if err := tx.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
	return fixture
}

func insertBackgroundJobCommandReceipt094Tx(t *testing.T, tx pgx.Tx) backgroundJobCommandFixture094 {
	t.Helper()
	tenantID, scopeID, userID, jobID, auditID := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	requestDigest := sha256.Sum256([]byte("job-command-request"))
	jobDigest := sha256.Sum256([]byte("background-job"))
	now := time.Date(2026, 8, 4, 8, 0, 0, 123000000, time.UTC)
	if _, err := tx.Exec(t.Context(), `
		INSERT INTO tenants(id,display_name) VALUES($1,'Job command receipt tenant');
		INSERT INTO access_scopes(id,kind,tenant_id) VALUES($2,'tenant',$1);
		INSERT INTO users(id,username,display_name,password_hash) VALUES($3,$4,'Job command actor','test-only');
		INSERT INTO memberships(scope_id,user_id) VALUES($2,$3);
		INSERT INTO background_jobs(
			id,tenant_id,kind,subject,idempotency_key,request_digest,request_id,trace_id,state,
			attempt,max_attempts,claimable_at,total_count,created_at,updated_at
		) VALUES($5,$1,'cache.purge','site/command','job-create',$6,'job-request','trace-job',
			'queued',0,3,$7,1,$7,$7);
		INSERT INTO background_job_items(tenant_id,job_id,ordinal,item_id,state)
		VALUES($1,$5,1,'item-a','pending')`, pgx.QueryExecModeSimpleProtocol,
		tenantID, scopeID, userID,
		"job-command-"+strings.ReplaceAll(userID.String(), "-", ""), jobID, jobDigest[:], now); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(t.Context(), `UPDATE background_jobs SET
		state='cancelled',cancel_requested_at=$2,claimable_at=NULL,completed_count=1,
		cancelled_count=1,last_error_code='cancelled',updated_at=$2,completed_at=$2
		WHERE id=$1`, jobID, now); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(t.Context(), `UPDATE background_job_items SET
		state='cancelled',error_code='cancelled',completed_at=$2 WHERE job_id=$1`, jobID, now); err != nil {
		t.Fatal(err)
	}
	payload := map[string]any{
		"audience": "tenant", "operation": "cancel", "idempotency_key": "cancel-command",
		"request_digest": hex.EncodeToString(requestDigest[:]), "tenant_id": tenantID.String(),
		"result_data": map[string]any{
			"task_id": jobID.String(), "tenant_id": tenantID.String(), "kind": "cache.purge",
			"subject": "site/command", "request_id": "job-request", "trace_id": "trace-job",
			"state": "cancelled", "attempt": 0, "max_attempts": 3, "total_count": 1,
			"completed_count": 1, "succeeded_count": 0, "failed_count": 0,
			"cancelled_count": 1, "failure_code": "cancelled", "created_at": now,
			"started_at": nil, "updated_at": now, "completed_at": now,
		},
	}
	if _, err := tx.Exec(t.Context(), `INSERT INTO audit_events(
		id,scope_id,stream_position,actor_user_id,action,resource_type,resource_id,
		request_id,result,payload,previous_hash,event_hash,occurred_at
	) VALUES($1,$2,1,$3,'job.cancel','background_job',$4,'cancel-request','success',$5,
		NULL,sha256(convert_to('command-audit','UTF8')),$6)`,
		auditID, scopeID, userID, jobID.String(), payload, now); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(t.Context(), `INSERT INTO background_job_command_receipts(
		actor_scope_id,actor_user_id,idempotency_key,request_digest,audience,tenant_id,job_id,
		operation,request_id,audit_event_id,result_kind,result_subject,result_request_id,
		result_trace_id,result_state,result_attempt,result_max_attempts,result_total_count,
		result_completed_count,result_succeeded_count,result_failed_count,result_cancelled_count,
		result_failure_code,result_created_at,result_started_at,result_updated_at,result_completed_at,
		created_at,completed_at
	) VALUES($1,$2,'cancel-command',$3,'tenant',$4,$5,'cancel','cancel-request',$6,
		'cache.purge','site/command','job-request','trace-job','cancelled',0,3,1,1,0,0,1,
		'cancelled',$7,NULL,$7,$7,$7,$7)`, scopeID, userID, requestDigest[:], tenantID, jobID, auditID, now); err != nil {
		t.Fatal(err)
	}
	return backgroundJobCommandFixture094{auditID: auditID}
}

func waitForBackgroundJobCommandBlock094(t *testing.T, pool *pgxpool.Pool, blockedPID, blockerPID int32) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		var blocked bool
		if err := pool.QueryRow(ctx, `SELECT $2::integer=ANY(pg_blocking_pids($1::integer))`,
			blockedPID, blockerPID).Scan(&blocked); err != nil {
			t.Fatal(err)
		}
		if blocked {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatalf("backend %d was not blocked by %d", blockedPID, blockerPID)
		case <-ticker.C:
		}
	}
}

func waitForBackgroundJobCommandBlockerCount094(t *testing.T, pool *pgxpool.Pool, blockerPID int32, want int) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		var blocked int
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM pg_stat_activity activity
			WHERE activity.pid<>pg_backend_pid() AND activity.wait_event_type='Lock'
			  AND $1::integer=ANY(pg_blocking_pids(activity.pid))`, blockerPID).Scan(&blocked); err != nil {
			t.Fatal(err)
		}
		if blocked == want {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatalf("backend %d blocked %d commands, want %d", blockerPID, blocked, want)
		case <-ticker.C:
		}
	}
}

func mustReadBackgroundJobCommands094(t *testing.T, name string) string {
	t.Helper()
	value, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	return string(value)
}

func assertBackgroundJobCommands094Code(t *testing.T, err error, code string) {
	t.Helper()
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != code {
		t.Fatalf("error = %v, want SQLSTATE %s", err, code)
	}
}
