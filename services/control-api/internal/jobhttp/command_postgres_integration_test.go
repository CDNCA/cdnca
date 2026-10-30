//go:build integration

package jobhttp

import (
	"context"
	"errors"
	"fmt"
	"os"
	"reflect"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/database"
	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
	"github.com/cdnca/cdnca/services/control-api/internal/jobstate"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestJobCommandPostgresFixtureExternalRoleSafety(t *testing.T) {
	fixture := openJobCommandRoleFixture(t)
	if err := verifyJobCommandExternalRoleBaseline(t.Context(), fixture.connection, fixture.schema); err != nil {
		t.Fatal(err)
	}

	assertRejected := func(t *testing.T, statement string) {
		t.Helper()
		tx, err := fixture.connection.Begin(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(context.Background()) }()
		if _, err := tx.Exec(t.Context(), statement); err != nil {
			t.Fatal(err)
		}
		if err := verifyJobCommandExternalRoleBaseline(t.Context(), tx, fixture.schema); err == nil {
			t.Fatalf("unsafe external-role prerequisite accepted after %s", statement)
		}
	}

	for _, check := range []struct {
		name      string
		statement string
	}{
		{"schema CREATE", "GRANT CREATE ON SCHEMA " + fixture.identifier + " TO cdnca_control_app"},
		{"schema direct ACL", "GRANT USAGE ON SCHEMA " + fixture.identifier + " TO cdnca_control_app"},
		{"schema PUBLIC USAGE", "GRANT USAGE ON SCHEMA " + fixture.identifier + " TO PUBLIC"},
		{"schema owner", "ALTER SCHEMA " + fixture.identifier + " OWNER TO cdnca_control_app"},
		{"schema default ACL", "ALTER DEFAULT PRIVILEGES IN SCHEMA " + fixture.identifier +
			" GRANT SELECT ON TABLES TO cdnca_control_app"},
		{"global default ACL", "ALTER DEFAULT PRIVILEGES GRANT SELECT ON TABLES TO cdnca_control_app"},
	} {
		t.Run(check.name, func(t *testing.T) { assertRejected(t, check.statement) })
	}

	if _, created := fixture.createdRoleOIDs["cdnca_control_app"]; !created {
		t.Log("ambient safe control role retained; fixture-created role mutation checks skipped")
		return
	}
	for _, check := range []struct {
		name      string
		statement string
	}{
		{"LOGIN", "ALTER ROLE cdnca_control_app LOGIN"},
		{"SUPERUSER", "ALTER ROLE cdnca_control_app SUPERUSER"},
		{"CREATEDB", "ALTER ROLE cdnca_control_app CREATEDB"},
		{"CREATEROLE", "ALTER ROLE cdnca_control_app CREATEROLE"},
		{"REPLICATION", "ALTER ROLE cdnca_control_app REPLICATION"},
		{"BYPASSRLS", "ALTER ROLE cdnca_control_app BYPASSRLS"},
		{"database CREATE", "GRANT CREATE ON DATABASE " + pgx.Identifier{fixture.database}.Sanitize() +
			" TO cdnca_control_app"},
	} {
		t.Run(check.name, func(t *testing.T) { assertRejected(t, check.statement) })
	}
	if _, created := fixture.createdRoleOIDs["cdnca_plugin_webhook_runtime"]; created {
		t.Run("mutual membership", func(t *testing.T) {
			assertRejected(t, "GRANT cdnca_plugin_webhook_runtime TO cdnca_control_app")
		})
	}
}

func TestBackgroundJobCommandsRequireMigration094Facts(t *testing.T) {
	if os.Getenv("TEST_DATABASE_URL") == "" {
		t.Fatal("TEST_DATABASE_URL is required; command migration evidence must not be skipped")
	}
	pool := openJobCommandTestDatabase(t)
	for _, permission := range []string{PermissionManage, PermissionManageAll} {
		var present bool
		if err := pool.QueryRow(t.Context(), `SELECT EXISTS(SELECT 1 FROM permissions WHERE name=$1)`, permission).Scan(&present); err != nil {
			t.Fatal(err)
		}
		if !present {
			t.Fatalf("migration 094 is missing permission %q", permission)
		}
	}
	var relation string
	if err := pool.QueryRow(t.Context(), `SELECT to_regclass('background_job_command_receipts')::text`).Scan(&relation); err != nil {
		t.Fatal(err)
	}
	if relation != "background_job_command_receipts" {
		t.Fatalf("migration 094 is missing background_job_command_receipts")
	}
	var resultCompletedNullable, commandCompletedRequired bool
	if err := pool.QueryRow(t.Context(), `
		SELECT
			(SELECT is_nullable='YES' FROM information_schema.columns
			 WHERE table_schema=current_schema() AND table_name='background_job_command_receipts'
			   AND column_name='result_completed_at'),
			(SELECT is_nullable='NO' FROM information_schema.columns
			 WHERE table_schema=current_schema() AND table_name='background_job_command_receipts'
			   AND column_name='completed_at')`).Scan(&resultCompletedNullable, &commandCompletedRequired); err != nil {
		t.Fatal(err)
	}
	if !resultCompletedNullable || !commandCompletedRequired {
		t.Fatalf("receipt completion columns result_nullable=%t command_required=%t",
			resultCompletedNullable, commandCompletedRequired)
	}
	var auditEventUnique, auditEventRequired bool
	if err := pool.QueryRow(t.Context(), `
		SELECT
			EXISTS (
				SELECT 1
				FROM pg_index index
				WHERE index.indrelid='background_job_command_receipts'::regclass
				  AND index.indisunique AND index.indisvalid AND index.indpred IS NULL
				  AND index.indnkeyatts=1
				  AND (SELECT attribute.attname
				       FROM unnest(index.indkey) key(attnum)
				       JOIN pg_attribute attribute
				         ON attribute.attrelid=index.indrelid AND attribute.attnum=key.attnum
				       LIMIT 1)='audit_event_id'
			),
			EXISTS (
				SELECT 1 FROM information_schema.columns
				WHERE table_schema=current_schema()
				  AND table_name='background_job_command_receipts'
				  AND column_name='audit_event_id' AND is_nullable='NO'
			)`).Scan(&auditEventUnique, &auditEventRequired); err != nil {
		t.Fatal(err)
	}
	if !auditEventUnique || !auditEventRequired {
		t.Fatalf("receipt audit_event_id unique=%t required=%t", auditEventUnique, auditEventRequired)
	}
	// The fixture applies through 104, which extends the 094 index to cover replay.
	const deniedCommandPredicate = "((result = 'denied'::text) AND (actor_user_id IS NOT NULL) AND (action = ANY (ARRAY['job.cancel'::text, 'job.retry'::text, 'job.replay'::text])))"
	var deniedAuditUnique bool
	if err := pool.QueryRow(t.Context(), `
		SELECT EXISTS (
			SELECT 1
			FROM pg_index index
			WHERE index.indrelid='audit_events'::regclass
			  AND index.indisunique AND index.indisvalid AND index.indpred IS NOT NULL
			  AND index.indnkeyatts=4 AND index.indnatts=4
			  AND ARRAY(
				SELECT attribute.attname::text
				FROM unnest(index.indkey) WITH ORDINALITY key(attnum, ordinal)
				JOIN pg_attribute attribute
				  ON attribute.attrelid=index.indrelid AND attribute.attnum=key.attnum
				ORDER BY key.ordinal
			  )=ARRAY['scope_id','actor_user_id','action','request_id']::text[]
			  AND pg_get_expr(index.indpred,index.indrelid,false)=$1
		)`, deniedCommandPredicate).Scan(&deniedAuditUnique); err != nil {
		t.Fatal(err)
	}
	if !deniedAuditUnique {
		t.Fatal("migrations 094/104 are missing the exact denied job-command audit identity index")
	}
	var tenantManageCatalog, platformManageAllCatalog bool
	if err := pool.QueryRow(t.Context(), `
		SELECT
			EXISTS(SELECT 1 FROM custom_rbac_permission_catalog WHERE permission_name=$1),
			EXISTS(SELECT 1 FROM custom_rbac_permission_catalog WHERE permission_name=$2)`,
		PermissionManage, PermissionManageAll).Scan(&tenantManageCatalog, &platformManageAllCatalog); err != nil {
		t.Fatal(err)
	}
	if !tenantManageCatalog || platformManageAllCatalog {
		t.Fatalf("custom role catalog jobs.manage=%t jobs.manage_all=%t",
			tenantManageCatalog, platformManageAllCatalog)
	}
	tenantID, tenantScope := seedJobHTTPTenant(t, pool, "Command RBAC Contract Tenant")
	tenantOwnerRole := uuid.New()
	if _, err := pool.Exec(t.Context(), `INSERT INTO roles(
		id,scope_id,name,description,system_role
	) VALUES($1,$2,'tenant_owner','Job command RBAC contract owner',true)`,
		tenantOwnerRole, tenantScope); err != nil {
		t.Fatal(err)
	}
	var tenantOwnerManageAllBefore bool
	if err := pool.QueryRow(t.Context(), `SELECT EXISTS(SELECT 1 FROM role_permissions
		WHERE role_id=$1 AND permission_name=$2)`, tenantOwnerRole, PermissionManageAll).Scan(
		&tenantOwnerManageAllBefore); err != nil {
		t.Fatal(err)
	}
	if tenantOwnerManageAllBefore {
		t.Fatal("future tenant system role received jobs.manage_all")
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO role_permissions(role_id,permission_name)
		VALUES($1,$2)`, tenantOwnerRole, PermissionManageAll); err == nil {
		t.Fatal("future tenant system role accepted jobs.manage_all")
	}

	platformScope, platformOwnerRole, platformOtherRole := uuid.New(), uuid.New(), uuid.New()
	if _, err := pool.Exec(t.Context(), `
		INSERT INTO access_scopes(id,kind) VALUES($1,'platform');
			INSERT INTO roles(id,scope_id,name,description,system_role) VALUES
				($2,$1,'platform_owner','Job command platform owner',true),
				($3,$1,'platform_operator','Job command platform operator',true)`,
		pgx.QueryExecModeSimpleProtocol,
		platformScope, platformOwnerRole, platformOtherRole); err != nil {
		t.Fatal(err)
	}
	var futurePlatformOwnerManageAll, futurePlatformOtherManageAll bool
	if err := pool.QueryRow(t.Context(), `SELECT
		EXISTS(SELECT 1 FROM role_permissions WHERE role_id=$1 AND permission_name=$3),
		EXISTS(SELECT 1 FROM role_permissions WHERE role_id=$2 AND permission_name=$3)`,
		platformOwnerRole, platformOtherRole, PermissionManageAll).Scan(
		&futurePlatformOwnerManageAll, &futurePlatformOtherManageAll); err != nil {
		t.Fatal(err)
	}
	if !futurePlatformOwnerManageAll || futurePlatformOtherManageAll {
		t.Fatalf("future platform grants owner=%t other=%t",
			futurePlatformOwnerManageAll, futurePlatformOtherManageAll)
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO role_permissions(role_id,permission_name)
		VALUES($1,$2)`, platformOtherRole, PermissionManageAll); err == nil {
		t.Fatal("future non-owner platform system role accepted jobs.manage_all")
	}

	customActor, _ := seedCommandActor(t, pool, tenantScope, ScopeTenant, "identity.roles.manage")
	customRoleID := uuid.New()
	if _, err := pool.Exec(t.Context(), `INSERT INTO custom_roles(
		id,tenant_id,tenant_scope_id,current_name,created_by_user_id,created_by_scope_id,
		created_at,updated_at
	) VALUES($1,$2,$3,'job-command-custom',$4,$3,$5,$5)`,
		customRoleID, tenantID, tenantScope, customActor.UserID, fixtureNow); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO custom_role_revisions(
		role_id,tenant_id,tenant_scope_id,revision,name,permissions,action,
		created_by_user_id,created_by_scope_id,created_at
	) VALUES($1,$2,$3,1,'job-command-custom',$4,'identity.custom_role.create',$5,$3,$6)`,
		customRoleID, tenantID, tenantScope, []string{PermissionManageAll},
		customActor.UserID, fixtureNow); err == nil {
		t.Fatal("future tenant custom role accepted jobs.manage_all")
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO custom_role_revisions(
		role_id,tenant_id,tenant_scope_id,revision,name,permissions,action,
		created_by_user_id,created_by_scope_id,created_at
	) VALUES($1,$2,$3,1,'job-command-custom',$4,'identity.custom_role.create',$5,$3,$6)`,
		customRoleID, tenantID, tenantScope, []string{PermissionManage},
		customActor.UserID, fixtureNow); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `UPDATE custom_roles
		SET current_revision=1,updated_at=$2 WHERE id=$1`, customRoleID, fixtureNow); err != nil {
		t.Fatal(err)
	}
	var customManage, customManageAll bool
	if err := pool.QueryRow(t.Context(), `SELECT
		EXISTS(SELECT 1 FROM role_permissions WHERE role_id=$1 AND permission_name=$2),
		EXISTS(SELECT 1 FROM role_permissions WHERE role_id=$1 AND permission_name=$3)`,
		customRoleID, PermissionManage, PermissionManageAll).Scan(&customManage, &customManageAll); err != nil {
		t.Fatal(err)
	}
	if !customManage || customManageAll {
		t.Fatalf("future custom role jobs.manage=%t jobs.manage_all=%t", customManage, customManageAll)
	}

	var tenantOwnerManage, tenantManageAll, platformOwnerManageAll, foreignManageAll bool
	if err := pool.QueryRow(t.Context(), `
		SELECT
			EXISTS(
				SELECT 1 FROM role_permissions permission
				JOIN roles role ON role.id=permission.role_id
				WHERE role.scope_id=$1 AND role.system_role AND role.name='tenant_owner'
				  AND permission.permission_name=$2
			),
			EXISTS(
				SELECT 1 FROM role_permissions permission
				JOIN roles role ON role.id=permission.role_id
				JOIN access_scopes scope ON scope.id=role.scope_id
				WHERE scope.kind='tenant' AND permission.permission_name=$3
			),
			EXISTS(
				SELECT 1 FROM role_permissions permission
				JOIN roles role ON role.id=permission.role_id
				JOIN access_scopes scope ON scope.id=role.scope_id
				WHERE scope.kind='platform' AND role.system_role AND role.name='platform_owner'
				  AND permission.permission_name=$3
			),
			EXISTS(
				SELECT 1 FROM role_permissions permission
				JOIN roles role ON role.id=permission.role_id
				JOIN access_scopes scope ON scope.id=role.scope_id
				WHERE permission.permission_name=$3
				  AND (scope.kind<>'platform' OR NOT role.system_role OR role.name<>'platform_owner')
			)`, tenantScope, PermissionManage, PermissionManageAll).Scan(
		&tenantOwnerManage, &tenantManageAll, &platformOwnerManageAll, &foreignManageAll); err != nil {
		t.Fatal(err)
	}
	if !tenantOwnerManage || tenantManageAll || !platformOwnerManageAll || foreignManageAll {
		t.Fatalf("RBAC grants tenant_owner_manage=%t tenant_manage_all=%t platform_owner_manage_all=%t foreign_manage_all=%t",
			tenantOwnerManage, tenantManageAll, platformOwnerManageAll, foreignManageAll)
	}
}

func TestPostgresCommandsRBACIdempotencyAndReadback(t *testing.T) {
	pool := openJobCommandTestDatabase(t)
	now := fixtureNow
	store, err := jobstate.NewStore(pool, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	tenantA, scopeA := seedJobHTTPTenant(t, pool, "Command Tenant A")
	tenantB, scopeB := seedJobHTTPTenant(t, pool, "Command Tenant B")
	actorA, roleA := seedCommandActor(t, pool, scopeA, ScopeTenant, PermissionManage, PermissionRead)
	viewerA, _ := seedCommandActor(t, pool, scopeA, ScopeTenant)
	platformScope := uuid.New()
	if _, err := pool.Exec(t.Context(), `INSERT INTO access_scopes(id,kind) VALUES($1,'platform')`, platformScope); err != nil {
		t.Fatal(err)
	}
	platform, _ := seedCommandActor(t, pool, platformScope, ScopePlatform, PermissionManageAll)
	platformAdmin, platformAdminRole := seedCommandActor(t, pool, platformScope, ScopePlatform, PermissionAdmin)
	var platformAdminPermissionCount int
	var platformAdminPermission, platformAdminManageAll bool
	if err := pool.QueryRow(t.Context(), `SELECT
		count(*),
		EXISTS(SELECT 1 FROM role_permissions WHERE role_id=$1 AND permission_name=$2),
		EXISTS(SELECT 1 FROM role_permissions WHERE role_id=$1 AND permission_name=$3)
		FROM role_permissions WHERE role_id=$1`, platformAdminRole, PermissionAdmin, PermissionManageAll).Scan(
		&platformAdminPermissionCount, &platformAdminPermission, &platformAdminManageAll); err != nil {
		t.Fatal(err)
	}
	if platformAdminPermissionCount != 1 || !platformAdminPermission ||
		platformAdminManageAll || len(platformAdmin.Permissions) != 1 {
		t.Fatalf("platform.admin live facts count=%d admin=%t manage_all=%t claims=%v",
			platformAdminPermissionCount, platformAdminPermission,
			platformAdminManageAll, platformAdmin.Permissions)
	}

	queuedA := createIntegrationJob(t, store, tenantA, "cache.purge", "site/command-a", uuid.Nil)
	failedA := createFailedCommandJob(t, store, tenantA, "dns.repair", "site/failed-a")
	queuedB := createIntegrationJob(t, store, tenantB, "edge.publish", "site/command-b", uuid.Nil)
	queuedPlatformAdmin := createIntegrationJob(t, store, tenantB, "cache.purge", "site/platform-admin", uuid.Nil)
	reader, err := NewPostgresReader(pool)
	if err != nil {
		t.Fatal(err)
	}
	reader.now = func() time.Time { return now }
	reader.auditor = audit.NewWithClock(pool, reader.now)
	service, err := NewService(reader, fixtureServiceConfig())
	if err != nil {
		t.Fatal(err)
	}
	ctx := withRequestID(t.Context(), "job-command-integration-success")

	cancelInput := CommandRequest{
		Audience: AudienceTenant, TaskID: queuedA.ID, Operation: CommandCancel, IdempotencyKey: "cancel-a",
	}
	cancelled, err := service.Command(ctx, actorA, cancelInput)
	if err != nil || cancelled.Replayed || cancelled.Data.Status != StateCancelled {
		t.Fatalf("cancel = %+v, err=%v", cancelled, err)
	}
	replayed, err := service.Command(ctx, actorA, cancelInput)
	if err != nil || !replayed.Replayed || replayed.Data.Status != StateCancelled {
		t.Fatalf("cancel replay = %+v, err=%v", replayed, err)
	}
	var receiptState, auditState string
	var receiptAttempt int
	var resultCompleted, receiptCompleted, auditBinding bool
	if err := pool.QueryRow(ctx, `
		SELECT receipt.result_state,receipt.result_attempt,
		       receipt.result_completed_at IS NOT NULL,receipt.completed_at IS NOT NULL,
		       audit.payload#>>'{result_data,state}',
		       audit.scope_id=receipt.actor_scope_id
		       AND audit.actor_user_id=receipt.actor_user_id
		       AND audit.action='job.'||receipt.operation
		       AND audit.resource_type='background_job'
		       AND audit.resource_id=receipt.job_id::text
		       AND audit.request_id=receipt.request_id
		       AND audit.result='success'
		       AND audit.payload->>'audience'=receipt.audience
		       AND audit.payload->>'operation'=receipt.operation
		       AND audit.payload->>'idempotency_key'=receipt.idempotency_key
		       AND decode(audit.payload->>'request_digest','hex')=receipt.request_digest
		       AND audit.payload->>'tenant_id'=receipt.tenant_id::text
		       AND audit.payload#>>'{result_data,task_id}'=receipt.job_id::text
		       AND audit.payload#>>'{result_data,tenant_id}'=receipt.tenant_id::text
		       AND audit.payload#>>'{result_data,kind}'=receipt.result_kind
		       AND audit.payload#>>'{result_data,subject}'=receipt.result_subject
		       AND audit.payload#>>'{result_data,request_id}'=receipt.result_request_id
		       AND audit.payload#>>'{result_data,trace_id}'=receipt.result_trace_id
		       AND audit.payload#>>'{result_data,state}'=receipt.result_state
		       AND (audit.payload#>>'{result_data,attempt}')::integer=receipt.result_attempt
		       AND (audit.payload#>>'{result_data,max_attempts}')::integer=receipt.result_max_attempts
		       AND (audit.payload#>>'{result_data,total_count}')::integer=receipt.result_total_count
		       AND (audit.payload#>>'{result_data,completed_count}')::integer=receipt.result_completed_count
		       AND (audit.payload#>>'{result_data,succeeded_count}')::integer=receipt.result_succeeded_count
		       AND (audit.payload#>>'{result_data,failed_count}')::integer=receipt.result_failed_count
		       AND (audit.payload#>>'{result_data,cancelled_count}')::integer=receipt.result_cancelled_count
		       AND NULLIF(audit.payload#>>'{result_data,failure_code}','')
		           IS NOT DISTINCT FROM receipt.result_failure_code
		       AND (audit.payload#>>'{result_data,created_at}')::timestamptz=receipt.result_created_at
		       AND NULLIF(audit.payload#>>'{result_data,started_at}','')::timestamptz
		           IS NOT DISTINCT FROM receipt.result_started_at
		       AND (audit.payload#>>'{result_data,updated_at}')::timestamptz=receipt.result_updated_at
		       AND NULLIF(audit.payload#>>'{result_data,completed_at}','')::timestamptz
		           IS NOT DISTINCT FROM receipt.result_completed_at
		FROM background_job_command_receipts receipt
		JOIN audit_events audit ON audit.id=receipt.audit_event_id
		WHERE receipt.actor_scope_id=$1 AND receipt.actor_user_id=$2
		  AND receipt.idempotency_key='cancel-a'`, scopeA, actorA.UserID).Scan(
		&receiptState, &receiptAttempt, &resultCompleted, &receiptCompleted,
		&auditState, &auditBinding); err != nil {
		t.Fatal(err)
	}
	if receiptState != "cancelled" || receiptAttempt != int(cancelled.Data.Attempt) ||
		!resultCompleted || !receiptCompleted || auditState != receiptState || !auditBinding {
		t.Fatalf("cancel receipt state=%q attempt=%d result_completed=%t completed=%t audit_state=%q binding=%t",
			receiptState, receiptAttempt, resultCompleted, receiptCompleted, auditState, auditBinding)
	}
	if _, err := service.Command(withRequestID(t.Context(), "job-command-initial-invalid"), actorA, CommandRequest{
		Audience: AudienceTenant, TaskID: queuedA.ID, Operation: CommandCancel, IdempotencyKey: "cancel-invalid",
	}); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("initial invalid transition error = %v", err)
	}
	var invalidReason string
	if err := pool.QueryRow(ctx, `SELECT payload->>'reason' FROM audit_events
		WHERE scope_id=$1 AND actor_user_id=$2 AND action='job.cancel'
		  AND request_id='job-command-initial-invalid' AND result='denied'`,
		scopeA, actorA.UserID).Scan(&invalidReason); err != nil {
		t.Fatal(err)
	}
	if invalidReason != "invalid_transition" {
		t.Fatalf("initial invalid transition audit reason = %q", invalidReason)
	}
	if _, err := pool.Exec(ctx, `UPDATE background_job_command_receipts
		SET result_state='queued'
		WHERE actor_scope_id=$1 AND actor_user_id=$2 AND idempotency_key='cancel-a'`, scopeA, actorA.UserID); err == nil {
		t.Fatal("command receipt accepted result mutation")
	}
	if _, err := pool.Exec(ctx, `UPDATE background_job_command_receipts
		SET request_digest=decode(repeat('00',32),'hex')
		WHERE actor_scope_id=$1 AND actor_user_id=$2 AND idempotency_key='cancel-a'`, scopeA, actorA.UserID); err == nil {
		t.Fatal("command receipt accepted mutation")
	}
	if _, err := pool.Exec(ctx, `DELETE FROM background_job_command_receipts
		WHERE actor_scope_id=$1 AND actor_user_id=$2 AND idempotency_key='cancel-a'`, scopeA, actorA.UserID); err == nil {
		t.Fatal("command receipt accepted deletion")
	}
	if _, err := pool.Exec(ctx, `TRUNCATE background_job_command_receipts`); err == nil {
		t.Fatal("command receipt accepted truncation")
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO background_job_command_receipts(
			actor_scope_id,actor_user_id,idempotency_key,request_digest,audience,
			tenant_id,job_id,operation,request_id,audit_event_id,
			result_kind,result_subject,result_request_id,result_trace_id,
			result_state,result_attempt,result_max_attempts,
			result_total_count,result_completed_count,result_succeeded_count,
			result_failed_count,result_cancelled_count,result_failure_code,
			result_created_at,result_started_at,result_updated_at,result_completed_at,
			created_at,completed_at)
		SELECT $1,$2,'forged-binding',decode(repeat('00',32),'hex'),'tenant',
		       $3,$4,'retry','forged-binding',audit.id,
		       job.kind,job.subject,job.request_id,job.trace_id,
		       'queued',job.attempt,job.max_attempts,
		       job.total_count,job.completed_count,job.succeeded_count,
		       0,0,NULL,job.created_at,job.started_at,$5,NULL,$5,$5
		FROM audit_events audit
		JOIN background_jobs job ON job.id=$4
		WHERE audit.scope_id=$1 AND audit.actor_user_id=$2 AND audit.action='job.cancel'
		ORDER BY audit.stream_position DESC LIMIT 1`,
		scopeA, actorA.UserID, tenantA, failedA.ID, now); err == nil {
		t.Fatal("command receipt accepted forged audit binding")
	}
	if _, err := service.Command(withRequestID(t.Context(), "job-command-digest-conflict"), actorA, CommandRequest{
		Audience: AudienceTenant, TaskID: failedA.ID, Operation: CommandRetry, IdempotencyKey: "cancel-a",
	}); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("digest conflict error = %v", err)
	}
	if _, err := service.Command(withRequestID(t.Context(), "job-command-viewer-denied"), viewerA, CommandRequest{
		Audience: AudienceTenant, TaskID: failedA.ID, Operation: CommandRetry, IdempotencyKey: "viewer-denied",
	}); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("viewer command error = %v", err)
	}
	// API-JOBS-01：actorA 的实时角色有 jobs.manage，但本次凭据（如只读 API 密钥）有效权限只有 jobs.read，
	// 必须在进入 PG 前拒绝，不写回执、不改任务。待出包前全量跑（PG 集成）。
	readOnlyCredential := actorA
	readOnlyCredential.Permissions = map[string]struct{}{PermissionRead: {}}
	for _, operation := range []CommandOperation{CommandCancel, CommandRetry} {
		if _, err := service.Command(withRequestID(t.Context(), "job-command-readonly-key-"+string(operation)),
			readOnlyCredential, CommandRequest{
				Audience: AudienceTenant, TaskID: failedA.ID, Operation: operation,
				IdempotencyKey: "readonly-key-" + string(operation),
			}); !errors.Is(err, ErrPermissionDenied) {
			t.Fatalf("read-only credential %s error = %v", operation, err)
		}
	}
	assertCommandFactCount(t, pool, `SELECT count(*) FROM background_job_command_receipts
		WHERE actor_user_id=$1 AND idempotency_key LIKE 'readonly-key-%'`, 0, actorA.UserID)
	assertCommandFactCount(t, pool, `SELECT count(*) FROM audit_events
		WHERE actor_user_id=$1 AND request_id LIKE 'job-command-readonly-key-%'`, 0, actorA.UserID)
	if _, err := service.Command(withRequestID(t.Context(), "job-command-foreign-denied"), actorA, CommandRequest{
		Audience: AudienceTenant, TaskID: queuedB.ID, Operation: CommandCancel, IdempotencyKey: "foreign-denied",
	}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("foreign command error = %v", err)
	}
	platformCancelled, err := service.Command(ctx, platform, CommandRequest{
		Audience: AudiencePlatform, TaskID: queuedB.ID, Operation: CommandCancel, IdempotencyKey: "platform-cancel",
	})
	if err != nil || platformCancelled.Data.Status != StateCancelled {
		t.Fatalf("platform cancel = %+v, err=%v", platformCancelled, err)
	}
	platformAdminCancelled, err := service.Command(
		withRequestID(t.Context(), "job-command-platform-admin"), platformAdmin, CommandRequest{
			Audience: AudiencePlatform, TaskID: queuedPlatformAdmin.ID,
			Operation: CommandCancel, IdempotencyKey: "platform-admin-cancel",
		})
	if err != nil || platformAdminCancelled.Data.Status != StateCancelled {
		t.Fatalf("platform.admin cancel = %+v, err=%v", platformAdminCancelled, err)
	}

	attemptsBefore, err := service.Attempts(ctx, actorA, ChildPageRequest{
		Audience: AudienceTenant, TaskID: failedA.ID, Limit: 10,
	})
	if err != nil || len(attemptsBefore.Data) != 1 || attemptsBefore.Data[0].Number != 1 {
		t.Fatalf("attempts before retry = %+v, err=%v", attemptsBefore, err)
	}
	retried, err := service.Command(ctx, actorA, CommandRequest{
		Audience: AudienceTenant, TaskID: failedA.ID, Operation: CommandRetry, IdempotencyKey: "retry-a",
	})
	if err != nil || retried.Data.Status != StateQueued || retried.Data.Attempt != 1 {
		t.Fatalf("retry = %+v, err=%v", retried, err)
	}
	if err := pool.QueryRow(ctx, `SELECT result_state,result_attempt,
		result_completed_at IS NOT NULL,completed_at IS NOT NULL
		FROM background_job_command_receipts
		WHERE actor_scope_id=$1 AND actor_user_id=$2 AND idempotency_key='retry-a'`,
		scopeA, actorA.UserID).Scan(&receiptState, &receiptAttempt, &resultCompleted, &receiptCompleted); err != nil {
		t.Fatal(err)
	}
	if receiptState != "queued" || receiptAttempt != 1 || resultCompleted || !receiptCompleted {
		t.Fatalf("retry receipt state=%q attempt=%d result_completed=%t completed=%t",
			receiptState, receiptAttempt, resultCompleted, receiptCompleted)
	}
	attemptsQueued, err := service.Attempts(ctx, actorA, ChildPageRequest{
		Audience: AudienceTenant, TaskID: failedA.ID, Limit: 10,
	})
	if err != nil || len(attemptsQueued.Data) != 1 {
		t.Fatalf("retry created an attempt early: %+v, err=%v", attemptsQueued, err)
	}
	now = now.Add(5 * time.Second)
	claim := claimIntegrationJob(t, store, tenantA, "dns.repair", "command-worker-2")
	if claim.Job.ID != failedA.ID || claim.Job.Attempt != 2 {
		t.Fatalf("retry claim = %+v", claim.Job)
	}
	detail, err := service.Get(ctx, actorA, AudienceTenant, failedA.ID)
	if err != nil || detail.Status != StateRunning || detail.Attempt != 2 {
		t.Fatalf("detail after claim = %+v, err=%v", detail, err)
	}
	results, err := service.Results(ctx, actorA, ChildPageRequest{
		Audience: AudienceTenant, TaskID: failedA.ID, Limit: 10,
	})
	if err != nil || len(results.Data) != 2 || results.Data[0].Status != ResultPending || results.Data[1].Status != ResultPending {
		t.Fatalf("results after retry claim = %+v, err=%v", results, err)
	}
	retryReplay, err := service.Command(ctx, actorA, CommandRequest{
		Audience: AudienceTenant, TaskID: failedA.ID, Operation: CommandRetry, IdempotencyKey: "retry-a",
	})
	if err != nil || !retryReplay.Replayed || !reflect.DeepEqual(retryReplay.Data, retried.Data) {
		t.Fatalf("retry replay after claim = %+v, err=%v, want immutable %+v", retryReplay, err, retried.Data)
	}

	grantID := uuid.New()
	if err := pool.QueryRow(ctx, `SELECT id FROM custom_role_grants
		WHERE tenant_scope_id=$1 AND role_id=$2 AND subject_user_id=$3
		  AND NOT EXISTS(SELECT 1 FROM custom_role_grant_revocations WHERE grant_id=custom_role_grants.id)`,
		scopeA, roleA, actorA.UserID).Scan(&grantID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO custom_role_grant_revocations(
		id,grant_id,tenant_id,tenant_scope_id,role_id,role_revision,subject_user_id,
		revoked_by_user_id,revoked_by_scope_id,revoked_at
	) SELECT $1,grant_row.id,grant_row.tenant_id,grant_row.tenant_scope_id,grant_row.role_id,
		grant_row.role_revision,grant_row.subject_user_id,role.created_by_user_id,
		grant_row.tenant_scope_id,$2
	  FROM custom_role_grants grant_row JOIN custom_roles role ON role.id=grant_row.role_id
	  WHERE grant_row.id=$3`, uuid.New(), now.Add(2*time.Second), grantID); err != nil {
		t.Fatal(err)
	}
	actorA.Permissions = map[string]struct{}{PermissionManage: {}}
	if _, err := service.Command(withRequestID(t.Context(), "job-command-revoked-denied"), actorA, cancelInput); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("revoked replay error = %v", err)
	}
	assertCommandFactCount(t, pool, `SELECT count(*) FROM background_job_command_receipts
		WHERE actor_scope_id=$1 AND actor_user_id=$2 AND idempotency_key='cancel-a'`, 1, scopeA, actorA.UserID)
	assertCommandFactCount(t, pool, `SELECT count(*) FROM audit_events
		WHERE scope_id=$1 AND actor_user_id=$2 AND action='job.cancel' AND result='denied'`, 3, scopeA, actorA.UserID)
	if _, err := pool.Exec(ctx, `INSERT INTO custom_role_grants(
		id,tenant_id,tenant_scope_id,role_id,role_revision,subject_user_id,
		granted_by_user_id,granted_by_scope_id,granted_at
	) SELECT $1,grant_row.tenant_id,grant_row.tenant_scope_id,grant_row.role_id,
		grant_row.role_revision,grant_row.subject_user_id,role.created_by_user_id,
		grant_row.tenant_scope_id,$2
	  FROM custom_role_grants grant_row JOIN custom_roles role ON role.id=grant_row.role_id
	  WHERE grant_row.id=$3`, uuid.New(), now.Add(3*time.Second), grantID); err != nil {
		t.Fatal(err)
	}

	staleActor := Principal{
		UserID: uuid.New(), ScopeID: scopeA, ScopeKind: ScopeTenant,
		Permissions: map[string]struct{}{PermissionManage: {}},
	}
	if _, err := pool.Exec(ctx, `INSERT INTO users(id,username,display_name,password_hash)
		VALUES($1,$2,'Stale Job Command Actor','hash')`,
		staleActor.UserID, "stale-job-command-"+staleActor.UserID.String()); err != nil {
		t.Fatal(err)
	}
	staleInput := CommandRequest{
		Audience: AudienceTenant, TaskID: queuedA.ID, Operation: CommandCancel, IdempotencyKey: "stale-membership",
	}
	staleRequest := withRequestID(t.Context(), "job-command-membership-denied")
	staleStart := make(chan struct{})
	staleErrors := make(chan error, 2)
	var staleWait sync.WaitGroup
	for range 2 {
		staleWait.Add(1)
		go func() {
			defer staleWait.Done()
			<-staleStart
			_, err := service.Command(staleRequest, staleActor, staleInput)
			staleErrors <- err
		}()
	}
	close(staleStart)
	staleWait.Wait()
	close(staleErrors)
	for err := range staleErrors {
		if !errors.Is(err, ErrPermissionDenied) {
			t.Fatalf("stale membership replay error = %v", err)
		}
	}
	assertCommandFactCount(t, pool, `SELECT count(*) FROM audit_events
		WHERE scope_id=$1 AND actor_user_id=$2 AND action='job.cancel'
		  AND request_id='job-command-membership-denied' AND result='denied'`, 1, scopeA, staleActor.UserID)
	if _, err := service.Command(staleRequest, staleActor, CommandRequest{
		Audience: AudienceTenant, TaskID: queuedB.ID, Operation: CommandCancel,
		IdempotencyKey: "stale-membership-different",
	}); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("mismatched stale membership replay error = %v", err)
	}
	assertCommandFactCount(t, pool, `SELECT count(*) FROM audit_events
		WHERE scope_id=$1 AND actor_user_id=$2 AND action='job.cancel'
		  AND request_id='job-command-membership-denied' AND result='denied'`, 1, scopeA, staleActor.UserID)
	if _, err := service.Command(withRequestID(t.Context(), "job-command-membership-denied-second"),
		staleActor, staleInput); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("distinct stale membership request error = %v", err)
	}
	assertCommandFactCount(t, pool, `SELECT count(*) FROM audit_events
		WHERE scope_id=$1 AND actor_user_id=$2 AND action='job.cancel' AND result='denied'`,
		2, scopeA, staleActor.UserID)

	_ = scopeB
}

func TestPostgresCommandsConcurrentSingleWinnerAndReplay(t *testing.T) {
	pool := openJobCommandTestDatabase(t)
	now := fixtureNow
	store, err := jobstate.NewStore(pool, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	tenantID, scopeID := seedJobHTTPTenant(t, pool, "Command Race Tenant")
	actor, _ := seedCommandActor(t, pool, scopeID, ScopeTenant, PermissionManage)
	reader, err := NewPostgresReader(pool)
	if err != nil {
		t.Fatal(err)
	}
	reader.now = func() time.Time { return now }
	reader.auditor = audit.NewWithClock(pool, reader.now)
	service, err := NewService(reader, fixtureServiceConfig())
	if err != nil {
		t.Fatal(err)
	}

	differentKeyJob := createIntegrationJob(t, store, tenantID, "cache.purge", "site/race-different", uuid.Nil)
	blocker, err := pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = blocker.Rollback(context.Background()) })
	if _, err := blocker.Exec(t.Context(), `SELECT 1 FROM background_jobs WHERE id=$1 FOR UPDATE`, differentKeyJob.ID); err != nil {
		t.Fatal(err)
	}
	results := runConcurrentCommands(service, actor, differentKeyJob.ID, []string{"race-a", "race-b"}, func() {
		waitForCommandJobLockWaiters(t, pool, 2)
		if err := blocker.Commit(t.Context()); err != nil {
			t.Fatal(err)
		}
	})
	success, rejected := 0, 0
	for _, result := range results {
		switch {
		case result.err == nil:
			success++
		case errors.Is(result.err, ErrInvalidTransition):
			rejected++
		default:
			t.Fatalf("different-key result = %+v", result)
		}
	}
	if success != 1 || rejected != 1 {
		t.Fatalf("different-key race success=%d rejected=%d", success, rejected)
	}
	assertCommandFactCount(t, pool, `SELECT count(*) FROM background_job_command_receipts WHERE job_id=$1`, 1, differentKeyJob.ID)
	assertCommandFactCount(t, pool, `SELECT count(*) FROM audit_events WHERE resource_id=$1 AND action='job.cancel'`, 2, differentKeyJob.ID.String())
	var concurrentReason string
	if err := pool.QueryRow(t.Context(), `SELECT payload->>'reason' FROM audit_events
		WHERE resource_id=$1 AND action='job.cancel' AND result='denied'`,
		differentKeyJob.ID.String()).Scan(&concurrentReason); err != nil {
		t.Fatal(err)
	}
	if concurrentReason != "concurrent_state_changed" {
		t.Fatalf("different-key loser audit reason = %q", concurrentReason)
	}

	sameKeyJob := createIntegrationJob(t, store, tenantID, "cache.purge", "site/race-same", uuid.Nil)
	results = runConcurrentCommands(service, actor, sameKeyJob.ID, []string{"race-same", "race-same"}, nil)
	replayed := 0
	for _, result := range results {
		if result.err != nil {
			t.Fatalf("same-key result = %+v", result)
		}
		if result.result.Replayed {
			replayed++
		}
	}
	if replayed != 1 {
		t.Fatalf("same-key replayed=%d, want 1", replayed)
	}
	if len(results) != 2 || !reflect.DeepEqual(results[0].result.Data, results[1].result.Data) {
		t.Fatalf("same-key data differs: %+v", results)
	}
	assertCommandFactCount(t, pool, `SELECT count(*) FROM background_job_command_receipts WHERE job_id=$1`, 1, sameKeyJob.ID)
	assertCommandFactCount(t, pool, `SELECT count(*) FROM audit_events WHERE resource_id=$1 AND action='job.cancel'`, 1, sameKeyJob.ID.String())
}

func TestPostgresSettlementBackoffDLQAndOperatorReplay(t *testing.T) {
	pool := openJobCommandTestDatabase(t)
	now := fixtureNow
	store, err := jobstate.NewStore(pool, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	tenantID, tenantScope := seedJobHTTPTenant(t, pool, "Settlement Tenant")
	tenantActor, _ := seedCommandActor(t, pool, tenantScope, ScopeTenant, PermissionManage, PermissionRead)
	platformScope := uuid.New()
	if _, err := pool.Exec(t.Context(), `INSERT INTO access_scopes(id,kind) VALUES($1,'platform')`, platformScope); err != nil {
		t.Fatal(err)
	}
	platformActor, _ := seedCommandActor(t, pool, platformScope, ScopePlatform, PermissionManageAll, PermissionReadAll)
	reader, err := NewPostgresReader(pool)
	if err != nil {
		t.Fatal(err)
	}
	reader.now = func() time.Time { return now }
	reader.auditor = audit.NewWithClock(pool, reader.now)
	service, err := NewService(reader, fixtureServiceConfig())
	if err != nil {
		t.Fatal(err)
	}

	job := createFailedCommandJob(t, store, tenantID, "cache.purge", "site/settlement")
	retryAt := now.Add(5 * time.Second)
	retried, err := service.Command(withRequestID(t.Context(), "settlement-retry"), tenantActor, CommandRequest{
		Audience: AudienceTenant, TaskID: job.ID, Operation: CommandRetry, IdempotencyKey: "settlement-retry",
	})
	if err != nil || retried.Data.Status != StateQueued {
		t.Fatalf("retry = %+v, err=%v", retried, err)
	}
	var claimableAt time.Time
	if err := pool.QueryRow(t.Context(), `SELECT claimable_at FROM background_jobs WHERE id=$1`, job.ID).Scan(&claimableAt); err != nil {
		t.Fatal(err)
	}
	if !claimableAt.Equal(retryAt) {
		t.Fatalf("claimable_at=%s, want bounded backoff %s", claimableAt, retryAt)
	}
	now = retryAt.Add(-time.Microsecond)
	claims, err := store.Claim(t.Context(), jobstate.ClaimInput{
		TenantID: tenantID, Kind: job.Kind, WorkerID: "settlement-worker", Limit: 1, LeaseDuration: time.Minute,
	})
	if err != nil || len(claims) != 0 {
		t.Fatalf("early claims=%+v, err=%v", claims, err)
	}
	now = retryAt
	claim := claimIntegrationJob(t, store, tenantID, job.Kind, "settlement-worker")
	reportIntegrationResult(t, store, claim, "node-a", jobstate.ItemFailed, "node_offline", 1)
	reportIntegrationResult(t, store, claim, "item-b", jobstate.ItemFailed, "origin_timeout", 1)

	var dlqReason string
	var dlqAttempt, receiptCount int
	if err := pool.QueryRow(t.Context(), `SELECT attempt,reason_code FROM background_job_dead_letters
		WHERE tenant_id=$1 AND job_id=$2`, tenantID, job.ID).Scan(&dlqAttempt, &dlqReason); err != nil {
		t.Fatal(err)
	}
	if dlqAttempt != 2 || dlqReason != jobstate.CodeAllItemsFailed {
		t.Fatalf("DLQ attempt=%d reason=%q", dlqAttempt, dlqReason)
	}
	if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM background_job_results WHERE job_id=$1`, job.ID).Scan(&receiptCount); err != nil {
		t.Fatal(err)
	}
	if receiptCount != 4 {
		t.Fatalf("immutable receipt count=%d, want 4", receiptCount)
	}
	receipts, err := service.Receipts(t.Context(), tenantActor, ChildPageRequest{
		Audience: AudienceTenant, TaskID: job.ID, Limit: 10,
	})
	if err != nil || len(receipts.Data) != 4 || receipts.Data[0].Attempt != 2 ||
		receipts.Data[0].Ordinal != 1 || receipts.Data[1].Attempt != 2 ||
		receipts.Data[1].Ordinal != 2 || receipts.Data[2].Attempt != 1 {
		t.Fatalf("settlement receipts=%+v, err=%v", receipts, err)
	}
	letters, err := service.DeadLetters(t.Context(), platformActor, ChildPageRequest{
		Audience: AudiencePlatform, TaskID: job.ID, Limit: 10,
	})
	if err != nil || len(letters.Data) != 1 || letters.Data[0].Attempt != 2 ||
		letters.Data[0].FailedItemCount != 2 || letters.Data[0].Source != "worker" {
		t.Fatalf("dead letters=%+v, err=%v", letters, err)
	}
	if _, err := pool.Exec(t.Context(), `UPDATE background_job_dead_letters
		SET reason_code='item_failed' WHERE job_id=$1`, job.ID); err == nil {
		t.Fatal("dead letter accepted mutation")
	}
	if _, err := pool.Exec(t.Context(), `DELETE FROM background_job_dead_letters WHERE job_id=$1`, job.ID); err == nil {
		t.Fatal("dead letter accepted deletion")
	}

	tenantBefore := retried.Data
	if _, err := service.Command(withRequestID(t.Context(), "tenant-replay"), tenantActor, CommandRequest{
		Audience: AudienceTenant, TaskID: job.ID,
		Operation: CommandOperation("replay"), IdempotencyKey: "tenant-replay",
	}); !errors.Is(err, ErrScopeForbidden) {
		t.Fatalf("tenant replay error=%v, want scope forbidden", err)
	}
	assertCommandFactCount(t, pool, `SELECT count(*) FROM background_job_replay_facts WHERE job_id=$1`, 0, job.ID)
	assertCommandFactCount(t, pool, `SELECT count(*) FROM background_job_command_receipts
		WHERE job_id=$1 AND operation='replay'`, 0, job.ID)
	assertCommandFactCount(t, pool, `SELECT count(*) FROM audit_events
		WHERE resource_id=$1 AND action='job.replay' AND result='denied'`, 1, job.ID.String())

	replayed, err := service.Command(withRequestID(t.Context(), "operator-replay"), platformActor, CommandRequest{
		Audience: AudiencePlatform, TaskID: job.ID,
		Operation: CommandOperation("replay"), IdempotencyKey: "operator-replay",
	})
	if err != nil || replayed.Replayed || replayed.Data.Status != StateQueued ||
		replayed.Data.MaxAttempts != 3 || replayed.Data.Attempt != 2 {
		t.Fatalf("operator replay=%+v, err=%v", replayed, err)
	}
	replayAgain, err := service.Command(withRequestID(t.Context(), "operator-replay"), platformActor, CommandRequest{
		Audience: AudiencePlatform, TaskID: job.ID,
		Operation: CommandOperation("replay"), IdempotencyKey: "operator-replay",
	})
	if err != nil || !replayAgain.Replayed || !reflect.DeepEqual(replayAgain.Data, replayed.Data) {
		t.Fatalf("operator replay repeat=%+v, err=%v", replayAgain, err)
	}
	assertCommandFactCount(t, pool, `SELECT count(*) FROM background_job_replay_facts WHERE job_id=$1`, 1, job.ID)
	assertCommandFactCount(t, pool, `SELECT count(*) FROM audit_events
		WHERE resource_id=$1 AND action='job.replay' AND result='success'`, 1, job.ID.String())
	retryAgain, err := service.Command(withRequestID(t.Context(), "settlement-retry"), tenantActor, CommandRequest{
		Audience: AudienceTenant, TaskID: job.ID, Operation: CommandRetry, IdempotencyKey: "settlement-retry",
	})
	if err != nil || !retryAgain.Replayed || !reflect.DeepEqual(retryAgain.Data, tenantBefore) {
		t.Fatalf("retry receipt after operator replay=%+v, err=%v, want immutable %+v", retryAgain, err, tenantBefore)
	}
}

func TestPostgresCommandFailuresRollbackQueueReceiptAndAudit(t *testing.T) {
	pool := openJobCommandTestDatabase(t)
	now := fixtureNow
	store, err := jobstate.NewStore(pool, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	tenantID, scopeID := seedJobHTTPTenant(t, pool, "Command Rollback Tenant")
	actor, _ := seedCommandActor(t, pool, scopeID, ScopeTenant, PermissionManage)
	ctx := withRequestID(t.Context(), "job-command-rollback")

	auditFailureJob := createIntegrationJob(t, store, tenantID, "cache.purge", "site/audit-failure", uuid.Nil)
	reader, err := NewPostgresReader(pool)
	if err != nil {
		t.Fatal(err)
	}
	reader.now = func() time.Time { return now }
	reader.auditor = failingCommandAuditor{}
	service, err := NewService(reader, fixtureServiceConfig())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Command(ctx, actor, CommandRequest{
		Audience: AudienceTenant, TaskID: auditFailureJob.ID,
		Operation: CommandCancel, IdempotencyKey: "audit-failure",
	}); !errors.Is(err, ErrStoreUnavailable) {
		t.Fatalf("audit failure error = %v", err)
	}
	assertStoredCommandState(t, store, tenantID, auditFailureJob.ID, jobstate.StateQueued)
	assertCommandFactCount(t, pool, `SELECT count(*) FROM background_job_command_receipts WHERE job_id=$1`, 0, auditFailureJob.ID)
	assertCommandFactCount(t, pool, `SELECT count(*) FROM audit_events WHERE resource_id=$1`, 0, auditFailureJob.ID.String())

	reader.auditor = audit.NewWithClock(pool, reader.now)
	receiptFailureJob := createIntegrationJob(t, store, tenantID, "cache.purge", "site/receipt-failure", uuid.Nil)
	if _, err := pool.Exec(ctx, `
		CREATE FUNCTION fail_job_command_receipt_insert() RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN
			IF NEW.idempotency_key='receipt-failure' THEN
				RAISE EXCEPTION 'injected receipt failure';
			END IF;
			RETURN NEW;
		END $$;
			CREATE TRIGGER job_command_receipt_failure
			BEFORE INSERT ON background_job_command_receipts
			FOR EACH ROW EXECUTE FUNCTION fail_job_command_receipt_insert()`,
		pgx.QueryExecModeSimpleProtocol); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Command(ctx, actor, CommandRequest{
		Audience: AudienceTenant, TaskID: receiptFailureJob.ID,
		Operation: CommandCancel, IdempotencyKey: "receipt-failure",
	}); !errors.Is(err, ErrStoreUnavailable) {
		t.Fatalf("receipt failure error = %v", err)
	}
	assertStoredCommandState(t, store, tenantID, receiptFailureJob.ID, jobstate.StateQueued)
	assertCommandFactCount(t, pool, `SELECT count(*) FROM background_job_command_receipts WHERE job_id=$1`, 0, receiptFailureJob.ID)
	assertCommandFactCount(t, pool, `SELECT count(*) FROM audit_events WHERE resource_id=$1`, 0, receiptFailureJob.ID.String())

	queueFailureJob := createFailedCommandJob(t, store, tenantID, "dns.repair", "site/queue-failure")
	if _, err := pool.Exec(ctx, `
		CREATE TABLE job_command_test_failures(job_id uuid PRIMARY KEY);
		INSERT INTO job_command_test_failures(job_id) VALUES($1);
		CREATE FUNCTION fail_job_command_queue_update() RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN
			IF EXISTS(SELECT 1 FROM job_command_test_failures WHERE job_id=NEW.id) THEN
				RAISE EXCEPTION 'injected queue failure';
			END IF;
			RETURN NEW;
		END $$;
			CREATE TRIGGER job_command_queue_failure
			BEFORE UPDATE ON background_jobs
			FOR EACH ROW EXECUTE FUNCTION fail_job_command_queue_update()`,
		pgx.QueryExecModeSimpleProtocol, queueFailureJob.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Command(ctx, actor, CommandRequest{
		Audience: AudienceTenant, TaskID: queueFailureJob.ID,
		Operation: CommandRetry, IdempotencyKey: "queue-failure",
	}); !errors.Is(err, ErrStoreUnavailable) {
		t.Fatalf("queue failure error = %v", err)
	}
	assertStoredCommandState(t, store, tenantID, queueFailureJob.ID, jobstate.StateFailed)
	assertCommandFactCount(t, pool, `SELECT count(*) FROM background_job_command_receipts WHERE job_id=$1`, 0, queueFailureJob.ID)
	assertCommandFactCount(t, pool, `SELECT count(*) FROM audit_events WHERE resource_id=$1`, 0, queueFailureJob.ID.String())
}

type commandRaceResult struct {
	result CommandResult
	err    error
}

func runConcurrentCommands(
	service *Service,
	actor Principal,
	taskID uuid.UUID,
	keys []string,
	afterStart func(),
) []commandRaceResult {
	start := make(chan struct{})
	results := make(chan commandRaceResult, len(keys))
	var workers sync.WaitGroup
	for _, key := range keys {
		key := key
		workers.Add(1)
		go func() {
			defer workers.Done()
			<-start
			result, err := service.Command(context.Background(), actor, CommandRequest{
				Audience: AudienceTenant, TaskID: taskID, Operation: CommandCancel, IdempotencyKey: key,
			})
			results <- commandRaceResult{result: result, err: err}
		}()
	}
	close(start)
	if afterStart != nil {
		afterStart()
	}
	workers.Wait()
	close(results)
	collected := make([]commandRaceResult, 0, len(keys))
	for result := range results {
		collected = append(collected, result)
	}
	return collected
}

func waitForCommandJobLockWaiters(t *testing.T, pool *pgxpool.Pool, want int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		var waiters int
		if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM pg_stat_activity
			WHERE pid<>pg_backend_pid() AND wait_event_type='Lock'
			  AND query LIKE '%FROM background_jobs job%'
			  AND query LIKE '%FOR UPDATE%'`).Scan(&waiters); err != nil {
			t.Fatal(err)
		}
		if waiters >= want {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %d job command row-lock waiters", want)
}

type failingCommandAuditor struct{}

func (failingCommandAuditor) Append(context.Context, pgx.Tx, audit.Event) error {
	return errors.New("injected audit failure")
}

const (
	jobCommandControlRole = "cdnca_control_app"
	jobCommandRuntimeRole = "cdnca_plugin_webhook_runtime"
)

type jobCommandRowQuerier interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

type jobCommandRoleFixture struct {
	admin           *pgxpool.Pool
	connection      *pgxpool.Conn
	databaseURL     string
	database        string
	schema          string
	identifier      string
	createdRoleOIDs map[string]uint32
	schemaCreated   bool
}

func openJobCommandRoleFixture(t *testing.T) *jobCommandRoleFixture {
	t.Helper()
	databaseURL := strings.TrimSpace(os.Getenv("TEST_DATABASE_URL"))
	if databaseURL == "" {
		t.Fatal("TEST_DATABASE_URL is required; command integration evidence must not be skipped")
	}
	admin, err := pgxpool.New(t.Context(), databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	if err := admin.Ping(t.Context()); err != nil {
		admin.Close()
		t.Fatal(err)
	}
	connection, err := admin.Acquire(t.Context())
	if err != nil {
		admin.Close()
		t.Fatal(err)
	}
	if _, err := connection.Exec(t.Context(), `SELECT pg_advisory_lock(
		hashtextextended('cdnca-jobhttp-command-external-roles',0))`); err != nil {
		connection.Release()
		admin.Close()
		t.Fatal(err)
	}
	schema := "jobcommand_test_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if !regexp.MustCompile(`^jobcommand_test_[a-f0-9]{32}$`).MatchString(schema) {
		t.Fatalf("unsafe schema %q", schema)
	}
	fixture := &jobCommandRoleFixture{
		admin: admin, connection: connection, databaseURL: databaseURL,
		schema: schema, identifier: pgx.Identifier{schema}.Sanitize(),
		createdRoleOIDs: make(map[string]uint32),
	}
	t.Cleanup(func() {
		ctx, cancel := databasetest.CleanupContext()
		defer cancel()
		schemaRemoved := !fixture.schemaCreated
		if fixture.schemaCreated {
			if _, err := fixture.connection.Exec(ctx, "DROP SCHEMA "+fixture.identifier+" CASCADE"); err != nil {
				t.Errorf("drop job command schema: %v", err)
			} else {
				schemaRemoved = true
			}
		}
		if schemaRemoved {
			if err := cleanupJobCommandExternalRoles(ctx, fixture.connection, fixture.createdRoleOIDs); err != nil {
				t.Errorf("drop job command external roles: %v", err)
			}
		}
		var unlocked bool
		if err := fixture.connection.QueryRow(ctx, `SELECT pg_advisory_unlock(
			hashtextextended('cdnca-jobhttp-command-external-roles',0))`).Scan(&unlocked); err != nil {
			t.Errorf("unlock job command external roles: %v", err)
		} else if !unlocked {
			t.Error("job command external-role advisory lock was not held")
		}
		fixture.connection.Release()
		fixture.admin.Close()
	})
	if err := fixture.connection.QueryRow(t.Context(), `SELECT current_database()`).Scan(&fixture.database); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.connection.Exec(t.Context(), "CREATE SCHEMA "+fixture.identifier); err != nil {
		t.Fatal(err)
	}
	fixture.schemaCreated = true
	if _, err := fixture.connection.Exec(t.Context(), "ALTER SCHEMA "+fixture.identifier+" OWNER TO CURRENT_USER"); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.connection.Exec(t.Context(), "REVOKE USAGE ON SCHEMA "+fixture.identifier+" FROM PUBLIC"); err != nil {
		t.Fatal(err)
	}
	createdRoleOIDs, err := prepareJobCommandExternalRoles(t.Context(), fixture.connection, fixture.schema)
	if err != nil {
		t.Fatal(err)
	}
	fixture.createdRoleOIDs = createdRoleOIDs
	return fixture
}

func openJobCommandTestDatabase(t *testing.T) *pgxpool.Pool {
	t.Helper()
	fixture := openJobCommandRoleFixture(t)
	config, err := pgxpool.ParseConfig(fixture.databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	config.ConnConfig.RuntimeParams["search_path"] = fixture.schema
	pool, err := pgxpool.NewWithConfig(t.Context(), config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	// The command store and audit log under test run against the release head
	// (a replay stopped at 104 lacks the unified-log audit columns of 361).
	if err := database.Migrate(t.Context(), pool, "up"); err != nil {
		t.Fatalf("migrate job command schema: %v", err)
	}
	return pool
}

func prepareJobCommandExternalRoles(
	ctx context.Context,
	connection *pgxpool.Conn,
	schema string,
) (map[string]uint32, error) {
	tx, err := connection.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	var currentUser string
	if err := tx.QueryRow(ctx, `SELECT current_user`).Scan(&currentUser); err != nil {
		return nil, err
	}
	if currentUser == jobCommandControlRole || currentUser == jobCommandRuntimeRole {
		return nil, errors.New("job command fixture user conflicts with an external role")
	}
	existing := make(map[string]uint32, 2)
	rows, err := tx.Query(ctx, `SELECT rolname,oid FROM pg_roles
		WHERE rolname IN ($1,$2)`, jobCommandControlRole, jobCommandRuntimeRole)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var name string
		var oid uint32
		if err := rows.Scan(&name, &oid); err != nil {
			rows.Close()
			return nil, err
		}
		existing[name] = oid
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}
	rows.Close()
	created := make(map[string]uint32, 2)
	for _, role := range []string{jobCommandControlRole, jobCommandRuntimeRole} {
		if _, ok := existing[role]; ok {
			continue
		}
		statement := "CREATE ROLE " + pgx.Identifier{role}.Sanitize() +
			" NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS"
		if _, err := tx.Exec(ctx, statement); err != nil {
			return nil, err
		}
		var oid uint32
		if err := tx.QueryRow(ctx, `SELECT oid FROM pg_roles WHERE rolname=$1`, role).Scan(&oid); err != nil {
			return nil, err
		}
		created[role] = oid
	}
	if err := verifyJobCommandExternalRoleBaseline(ctx, tx, schema); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return created, nil
}

func verifyJobCommandExternalRoleBaseline(
	ctx context.Context,
	querier jobCommandRowQuerier,
	schema string,
) error {
	var safe bool
	if err := querier.QueryRow(ctx, `
		WITH target AS (
			SELECT
				(SELECT oid FROM pg_roles WHERE rolname=$2) AS control_role,
				(SELECT oid FROM pg_roles WHERE rolname=$3) AS runtime_role
		), namespace AS (
			SELECT oid,nspowner,nspacl FROM pg_namespace WHERE oid=to_regnamespace($1)
		)
		SELECT target.control_role IS NOT NULL AND target.runtime_role IS NOT NULL
		  AND current_user <> $2 AND current_user <> $3
		  AND NOT EXISTS (
			SELECT 1 FROM pg_roles role
			WHERE role.oid IN (target.control_role,target.runtime_role) AND (
				role.rolcanlogin OR role.rolsuper OR role.rolcreatedb OR role.rolcreaterole OR
				role.rolreplication OR role.rolbypassrls
			)
		  )
		  AND NOT COALESCE(pg_has_role(target.control_role,target.runtime_role,'MEMBER'),true)
		  AND NOT COALESCE(pg_has_role(target.runtime_role,target.control_role,'MEMBER'),true)
		  AND NOT COALESCE(has_database_privilege(target.control_role,current_database(),'CREATE'),true)
		  AND NOT COALESCE(has_database_privilege(target.runtime_role,current_database(),'CREATE'),true)
		  AND namespace.nspowner=current_user::regrole
		  AND COALESCE(namespace.nspacl,acldefault('n',namespace.nspowner))
			IS NOT DISTINCT FROM acldefault('n',namespace.nspowner)
		  AND NOT has_schema_privilege('public',$1,'USAGE')
		  AND NOT COALESCE(has_schema_privilege(target.control_role,$1,'CREATE'),true)
		  AND NOT COALESCE(has_schema_privilege(target.runtime_role,$1,'CREATE'),true)
		  AND NOT EXISTS (
			SELECT 1 FROM aclexplode(namespace.nspacl) acl
			WHERE acl.grantee IN (target.control_role,target.runtime_role)
		  )
		  AND NOT EXISTS (
			SELECT 1 FROM pg_default_acl default_acl
			WHERE default_acl.defaclrole=current_user::regrole
			  AND default_acl.defaclnamespace IN (0,namespace.oid)
			  AND default_acl.defaclobjtype IN ('r','S','f','T')
		  )
		FROM target CROSS JOIN namespace`, schema, jobCommandControlRole, jobCommandRuntimeRole).Scan(&safe); err != nil {
		return err
	}
	if !safe {
		return errors.New("job command external-role baseline is unavailable or unsafe")
	}
	return nil
}

func cleanupJobCommandExternalRoles(
	ctx context.Context,
	connection *pgxpool.Conn,
	createdRoleOIDs map[string]uint32,
) error {
	var cleanupErrors []error
	var rolesToDrop []string
	for _, role := range []string{jobCommandControlRole, jobCommandRuntimeRole} {
		expectedOID, created := createdRoleOIDs[role]
		if !created {
			continue
		}
		var oid uint32
		var unsafe bool
		err := connection.QueryRow(ctx, `SELECT oid,
			rolcanlogin OR rolsuper OR rolcreatedb OR rolcreaterole OR rolreplication OR rolbypassrls
			FROM pg_roles WHERE rolname=$1`, role).Scan(&oid, &unsafe)
		if errors.Is(err, pgx.ErrNoRows) {
			continue
		}
		if err != nil {
			cleanupErrors = append(cleanupErrors, err)
			continue
		}
		if oid != expectedOID || unsafe {
			cleanupErrors = append(cleanupErrors,
				fmt.Errorf("refusing to drop changed external role %s", role))
			continue
		}
		var linked bool
		if err := connection.QueryRow(ctx, `SELECT
			COALESCE(pg_has_role(to_regrole($1),to_regrole($2),'MEMBER'),true) OR
			COALESCE(pg_has_role(to_regrole($2),to_regrole($1),'MEMBER'),true) OR
			COALESCE(has_database_privilege(to_regrole($1),current_database(),'CREATE'),true)`,
			role, map[string]string{
				jobCommandControlRole: jobCommandRuntimeRole,
				jobCommandRuntimeRole: jobCommandControlRole,
			}[role]).Scan(&linked); err != nil {
			cleanupErrors = append(cleanupErrors, err)
			continue
		}
		if linked {
			cleanupErrors = append(cleanupErrors,
				fmt.Errorf("refusing to drop linked external role %s", role))
			continue
		}
		rolesToDrop = append(rolesToDrop, role)
	}
	if len(cleanupErrors) > 0 {
		return errors.Join(cleanupErrors...)
	}
	for _, role := range rolesToDrop {
		if _, err := connection.Exec(ctx, "DROP ROLE "+pgx.Identifier{role}.Sanitize()); err != nil {
			cleanupErrors = append(cleanupErrors, err)
		}
	}
	return errors.Join(cleanupErrors...)
}

func seedCommandActor(
	t *testing.T,
	pool *pgxpool.Pool,
	scopeID uuid.UUID,
	scopeKind ScopeKind,
	permissions ...string,
) (Principal, uuid.UUID) {
	t.Helper()
	userID := uuid.New()
	username := "job-command-" + userID.String()
	if _, err := pool.Exec(t.Context(), `INSERT INTO users(id,username,display_name,password_hash)
		VALUES($1,$2,'Job Command Actor','hash')`, userID, username); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO memberships(scope_id,user_id) VALUES($1,$2)`,
		scopeID, userID); err != nil {
		t.Fatal(err)
	}

	claims := make(map[string]struct{}, len(permissions))
	for _, permission := range permissions {
		claims[permission] = struct{}{}
	}
	if scopeKind == ScopePlatform {
		roleID := uuid.New()
		roleName := "platform_operator"
		for _, permission := range permissions {
			if permission == PermissionManageAll {
				roleName = "platform_owner"
			}
		}
		if _, err := pool.Exec(t.Context(), `INSERT INTO roles(
			id,scope_id,name,description,system_role
		) VALUES($1,$2,$3,'job command integration',true)`, roleID, scopeID, roleName); err != nil {
			t.Fatal(err)
		}
		for _, permission := range permissions {
			if _, err := pool.Exec(t.Context(), `INSERT INTO role_permissions(role_id,permission_name)
				VALUES($1,$2) ON CONFLICT DO NOTHING`, roleID, permission); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := pool.Exec(t.Context(), `INSERT INTO role_assignments(scope_id,user_id,role_id)
			VALUES($1,$2,$3)`, scopeID, userID, roleID); err != nil {
			t.Fatal(err)
		}
		return Principal{UserID: userID, ScopeID: scopeID, ScopeKind: scopeKind, Permissions: claims}, roleID
	}

	ownerRoleID := uuid.New()
	err := pool.QueryRow(t.Context(), `SELECT id FROM roles
		WHERE scope_id=$1 AND system_role AND name='tenant_owner'`, scopeID).Scan(&ownerRoleID)
	if errors.Is(err, pgx.ErrNoRows) {
		if _, err := pool.Exec(t.Context(), `INSERT INTO roles(
			id,scope_id,name,description,system_role
		) VALUES($1,$2,'tenant_owner','job command integration owner',true)`,
			ownerRoleID, scopeID); err != nil {
			t.Fatal(err)
		}
	} else if err != nil {
		t.Fatal(err)
	}
	if len(permissions) == 1 && permissions[0] == "identity.roles.manage" {
		if _, err := pool.Exec(t.Context(), `INSERT INTO role_assignments(scope_id,user_id,role_id)
			VALUES($1,$2,$3)`, scopeID, userID, ownerRoleID); err != nil {
			t.Fatal(err)
		}
		return Principal{UserID: userID, ScopeID: scopeID, ScopeKind: scopeKind, Permissions: claims}, ownerRoleID
	}

	managerID, roleID, grantID := uuid.New(), uuid.New(), uuid.New()
	managerName := "job-command-manager-" + managerID.String()
	roleName := "job-command-" + strings.ReplaceAll(roleID.String(), "-", "")
	rolePermissions := permissions
	if len(rolePermissions) == 0 {
		rolePermissions = []string{"plugin_webhooks.read"}
	}
	if _, err := pool.Exec(t.Context(), `
		INSERT INTO users(id,username,display_name,password_hash)
		VALUES($1,$2,'Job Command Manager','hash');
		INSERT INTO memberships(scope_id,user_id) VALUES($3,$1);
		INSERT INTO role_assignments(scope_id,user_id,role_id) VALUES($3,$1,$4)`,
		pgx.QueryExecModeSimpleProtocol, managerID, managerName, scopeID, ownerRoleID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO custom_roles(
		id,tenant_id,tenant_scope_id,current_name,created_by_user_id,created_by_scope_id,
		created_at,updated_at
	) SELECT $1,tenant_id,id,$2,$3,id,$4,$4 FROM access_scopes WHERE id=$5`,
		roleID, roleName, managerID, fixtureNow, scopeID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO custom_role_revisions(
		role_id,tenant_id,tenant_scope_id,revision,name,permissions,action,
		created_by_user_id,created_by_scope_id,created_at
	) SELECT id,tenant_id,tenant_scope_id,1,current_name,$2,
		'identity.custom_role.create',$3,tenant_scope_id,$4
	  FROM custom_roles WHERE id=$1`, roleID, rolePermissions, managerID, fixtureNow); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `UPDATE custom_roles
		SET current_revision=1,updated_at=$2 WHERE id=$1`, roleID, fixtureNow.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO custom_role_grants(
		id,tenant_id,tenant_scope_id,role_id,role_revision,subject_user_id,
		granted_by_user_id,granted_by_scope_id,granted_at
	) SELECT $1,tenant_id,tenant_scope_id,id,1,$2,$3,tenant_scope_id,$4
	  FROM custom_roles WHERE id=$5`,
		grantID, userID, managerID, fixtureNow.Add(time.Second), roleID); err != nil {
		t.Fatal(err)
	}
	return Principal{UserID: userID, ScopeID: scopeID, ScopeKind: scopeKind, Permissions: claims}, roleID
}

func createFailedCommandJob(
	t *testing.T,
	store *jobstate.Store,
	tenantID uuid.UUID,
	kind, subject string,
) jobstate.StoredJob {
	t.Helper()
	job := createIntegrationJob(t, store, tenantID, kind, subject, uuid.Nil)
	claim := claimIntegrationJob(t, store, tenantID, kind, "command-worker-1")
	reportIntegrationResult(t, store, claim, "node-a", jobstate.ItemFailed, "node_offline", 1)
	reportIntegrationResult(t, store, claim, "item-b", jobstate.ItemFailed, "origin_timeout", 1)
	failed, err := store.Get(t.Context(), tenantID, job.ID)
	if err != nil || failed.State != jobstate.StateFailed {
		t.Fatalf("failed job = %+v, err=%v", failed, err)
	}
	return failed
}

func assertStoredCommandState(
	t *testing.T,
	store *jobstate.Store,
	tenantID, jobID uuid.UUID,
	want jobstate.State,
) {
	t.Helper()
	job, err := store.Get(t.Context(), tenantID, jobID)
	if err != nil || job.State != want {
		t.Fatalf("stored job = %+v, err=%v, want state %s", job, err, want)
	}
}

func assertCommandFactCount(t *testing.T, pool *pgxpool.Pool, query string, want int, arguments ...any) {
	t.Helper()
	var count int
	if err := pool.QueryRow(t.Context(), query, arguments...).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != want {
		t.Fatalf("fact count = %d, want %d for %s", count, want, query)
	}
}

// CACHE-ADD-05 (P15/P16): the generic cancel/retry of a cache operation is
// refused with a denied audit and leaves the job untouched.
// Without a registered cache.operation ProducerCommandRouter (cache control
// disabled) the generic path still refuses; with one, Service.Command routes
// cancel/retry to the cache module (fix-cacheflow2, producer_command_test.go).
func TestPostgresCommandsRefuseCacheOperationGenericCommands(t *testing.T) {
	pool := openJobCommandTestDatabase(t)
	now := fixtureNow
	store, err := jobstate.NewStore(pool, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	tenantID, scopeID := seedJobHTTPTenant(t, pool, "Cache Command Tenant")
	actor, _ := seedCommandActor(t, pool, scopeID, ScopeTenant, PermissionManage, PermissionRead)
	// The failed one first: its claim takes the oldest queued job of the kind.
	failed := createFailedCommandJob(t, store, tenantID, "cache.operation", "site/cache-command-failed")
	queued := createIntegrationJob(t, store, tenantID, "cache.operation", "site/cache-command", uuid.Nil)
	reader, err := NewPostgresReader(pool)
	if err != nil {
		t.Fatal(err)
	}
	reader.now = func() time.Time { return now }
	reader.auditor = audit.NewWithClock(pool, reader.now)
	service, err := NewService(reader, fixtureServiceConfig())
	if err != nil {
		t.Fatal(err)
	}
	ctx := withRequestID(t.Context(), "job-command-cache-producer")
	for _, test := range []struct {
		job       jobstate.StoredJob
		operation CommandOperation
		want      jobstate.State
	}{{queued, CommandCancel, jobstate.StateQueued}, {failed, CommandRetry, jobstate.StateFailed}} {
		_, err := service.Command(ctx, actor, CommandRequest{Audience: AudienceTenant, TaskID: test.job.ID,
			Operation: test.operation, IdempotencyKey: "cache-" + string(test.operation)})
		if !errors.Is(err, ErrProducerCommand) {
			t.Fatalf("%s err=%v, want ErrProducerCommand", test.operation, err)
		}
		assertStoredCommandState(t, store, tenantID, test.job.ID, test.want)
		var denied int
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE resource_type='background_job'
			AND resource_id=$1 AND result='denied' AND payload->>'reason'='producer_command'`,
			test.job.ID.String()).Scan(&denied); err != nil || denied != 1 {
			t.Fatalf("%s denied audits=%d err=%v", test.operation, denied, err)
		}
	}
}
