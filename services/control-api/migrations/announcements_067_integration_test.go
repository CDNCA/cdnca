package migrations_test

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io/fs"
	"strings"
	"sync"
	"testing"
	"time"

	controlmigrations "github.com/cdnca/cdnca/services/control-api/migrations"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestAnnouncements067MigrationChainRoundTripAndChecksums(t *testing.T) {
	pool, cleanup := new043Pool(t)
	defer cleanup()
	migrate067(t, pool, "up")

	var serverVersion string
	if err := pool.QueryRow(t.Context(), `SHOW server_version`).Scan(&serverVersion); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(serverVersion, "17.") {
		t.Fatalf("PostgreSQL server version = %q, want major 17", serverVersion)
	}
	assert067Ledger(t, pool, 67)
	assert067Checksums(t, pool)

	migrate067(t, pool, "down")
	assert067Ledger(t, pool, 66)
	assert067Installed(t, pool, false)
	assert043AnnouncementCatalog(t, pool)

	migrate067(t, pool, "up")
	assert067Ledger(t, pool, 67)
	assert067Installed(t, pool, true)
}

func TestAnnouncements067UpRejectsMissingLedgerVersion(t *testing.T) {
	pool, cleanup := new043Pool(t)
	defer cleanup()
	migrate067(t, pool, "up")
	migrate067(t, pool, "down")

	if _, err := pool.Exec(t.Context(), `DELETE FROM schema_migrations WHERE version=42`); err != nil {
		t.Fatal(err)
	}
	if err := migrate067Error(t.Context(), pool, "up"); err == nil {
		t.Fatal("067 up accepted ledger missing version 42")
	}
	assert067Installed(t, pool, false)
	var count, version067 int64
	if err := pool.QueryRow(t.Context(), `SELECT count(*),count(*) FILTER (WHERE version=67)
		FROM schema_migrations`).Scan(&count, &version067); err != nil {
		t.Fatal(err)
	}
	if count != 65 || version067 != 0 {
		t.Fatalf("ledger after rejected 067 up = count:%d version067:%d, want 65/0", count, version067)
	}
}

func TestAnnouncements067UpRejectsForgedLedgerMetadata(t *testing.T) {
	pool, cleanup := new043Pool(t)
	defer cleanup()
	migrate067(t, pool, "up")
	migrate067(t, pool, "down")

	const forged = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
	if _, err := pool.Exec(t.Context(), `UPDATE schema_migrations SET
		migration_id='042_forged',checksum_sha256=$1,down_checksum_sha256=$1
		WHERE version=42`, forged); err != nil {
		t.Fatal(err)
	}
	if err := migrate067Error(t.Context(), pool, "up"); err == nil {
		t.Fatal("067 up accepted forged version 42 ledger metadata")
	}
	assert067Installed(t, pool, false)
	var identifier, upChecksum, downChecksum string
	var version067 int64
	if err := pool.QueryRow(t.Context(), `SELECT migration_id,checksum_sha256,down_checksum_sha256,
		(SELECT count(*) FROM schema_migrations WHERE version=67)
		FROM schema_migrations WHERE version=42`).Scan(
		&identifier, &upChecksum, &downChecksum, &version067); err != nil {
		t.Fatal(err)
	}
	if identifier != "042_forged" || upChecksum != forged || downChecksum != forged || version067 != 0 {
		t.Fatalf("ledger after rejected 067 up = %q/%q/%q version067:%d",
			identifier, upChecksum, downChecksum, version067)
	}
}

func TestAnnouncements067DownRejectsFutureHeadAtomically(t *testing.T) {
	pool, cleanup := new043Pool(t)
	defer cleanup()
	migrate067(t, pool, "up")

	const checksum = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
	if _, err := pool.Exec(t.Context(), `INSERT INTO schema_migrations(
		version,migration_id,checksum_sha256,down_checksum_sha256,integrity_state,metadata_recorded_at
	) VALUES(75,'075_future',$1,$1,'verified',now())`, checksum); err != nil {
		t.Fatal(err)
	}
	if err := migrate067Error(t.Context(), pool, "down"); err == nil {
		t.Fatal("067 down accepted future migration head 75")
	}
	assert067Installed(t, pool, true)
	var count, version067, version075 int64
	if err := pool.QueryRow(t.Context(), `SELECT count(*),
		count(*) FILTER (WHERE version=67),count(*) FILTER (WHERE version=75)
		FROM schema_migrations`).Scan(&count, &version067, &version075); err != nil {
		t.Fatal(err)
	}
	if count != 68 || version067 != 1 || version075 != 1 {
		t.Fatalf("ledger after rejected 067 down = count:%d version067:%d version075:%d, want 68/1/1",
			count, version067, version075)
	}
}

func TestAnnouncements067ExistingAndFutureSystemRoleProjection(t *testing.T) {
	pool, cleanup := new043Pool(t)
	defer cleanup()
	migrate067(t, pool, "up")
	migrate067(t, pool, "down")

	platformScopeID := uuid.New()
	platformRoleID := uuid.New()
	if _, err := pool.Exec(t.Context(), `
		INSERT INTO access_scopes(id,kind) VALUES($1,'platform')`, platformScopeID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `
		INSERT INTO roles(id,scope_id,name,description,system_role)
		VALUES($2,$1,'platform_owner','067 platform owner',true)`,
		platformScopeID, platformRoleID); err != nil {
		t.Fatal(err)
	}
	existing := seed067Tenant(t, pool, "existing", true)
	future := seed067Tenant(t, pool, "future", false)

	migrate067(t, pool, "up")
	assert067RolePermissions(t, pool, platformRoleID, nil)
	assert067RolePermissions(t, pool, existing.ownerRoleID,
		[]string{"announcements.manage", "announcements.read"})
	assert067RolePermissions(t, pool, existing.viewerRoleID,
		[]string{"announcements.read"})
	if _, err := pool.Exec(t.Context(), `
		INSERT INTO role_permissions(role_id,permission_name)
		VALUES($1,'announcements.manage')`, existing.viewerRoleID); err == nil ||
		!strings.Contains(err.Error(), "invalid tenant system role permission") {
		t.Fatalf("tenant_viewer manage grant error = %v", err)
	}
	assert067EffectivePermissions(t, pool, existing.scopeID, existing.ownerUserID,
		[]string{"announcements.manage", "announcements.read"})
	assert067EffectivePermissions(t, pool, existing.scopeID, existing.viewerUserID,
		[]string{"announcements.read"})
	assert067EffectivePermissions(t, pool, future.scopeID, existing.ownerUserID, nil)

	start := make(chan struct{})
	errorsByRole := make(chan error, 2)
	var writers sync.WaitGroup
	future.ownerRoleID, future.viewerRoleID = uuid.New(), uuid.New()
	for _, role := range []struct {
		id   uuid.UUID
		name string
	}{
		{id: future.ownerRoleID, name: "tenant_owner"},
		{id: future.viewerRoleID, name: "tenant_viewer"},
	} {
		writers.Add(1)
		go func(roleID uuid.UUID, roleName string) {
			defer writers.Done()
			<-start
			_, err := pool.Exec(t.Context(), `
				INSERT INTO roles(id,scope_id,name,description,system_role)
				VALUES($1,$2,$3,'067 future role',true)`, roleID, future.scopeID, roleName)
			errorsByRole <- err
		}(role.id, role.name)
	}
	close(start)
	writers.Wait()
	close(errorsByRole)
	for err := range errorsByRole {
		if err != nil {
			t.Fatalf("concurrent future system role projection: %v", err)
		}
	}
	if _, err := pool.Exec(t.Context(), `
		INSERT INTO role_assignments(scope_id,user_id,role_id) VALUES
			($1,$2,$3),($1,$4,$5)`, future.scopeID, future.ownerUserID,
		future.ownerRoleID, future.viewerUserID, future.viewerRoleID); err != nil {
		t.Fatal(err)
	}
	assert067RolePermissions(t, pool, future.ownerRoleID,
		[]string{"announcements.manage", "announcements.read"})
	assert067RolePermissions(t, pool, future.viewerRoleID,
		[]string{"announcements.read"})
	assert067EffectivePermissions(t, pool, future.scopeID, future.viewerUserID,
		[]string{"announcements.read"})

	customRoleID := seed067CustomRoleRoot(t, pool, existing, "no-defaults")
	assert067RolePermissions(t, pool, customRoleID, nil)

	migrate067(t, pool, "down")
	assert067Installed(t, pool, false)
	assert043AnnouncementCatalog(t, pool)
	var remaining int
	if err := pool.QueryRow(t.Context(), `
		SELECT count(*) FROM role_permissions
		WHERE permission_name IN ('announcements.read','announcements.manage')`).Scan(&remaining); err != nil {
		t.Fatal(err)
	}
	if remaining != 0 {
		t.Fatalf("announcement grants after 067 down = %d, want 0", remaining)
	}

	migrate067(t, pool, "up")
	assert067RolePermissions(t, pool, existing.ownerRoleID,
		[]string{"announcements.manage", "announcements.read"})
	assert067RolePermissions(t, pool, customRoleID, nil)
}

func TestAnnouncements067UpRequires043Catalog(t *testing.T) {
	pool, cleanup := new043Pool(t)
	defer cleanup()
	migrate067(t, pool, "up")
	migrate067(t, pool, "down")
	if _, err := pool.Exec(t.Context(), `
		DELETE FROM custom_rbac_permission_catalog
		WHERE permission_name='announcements.manage'`); err != nil {
		t.Fatal(err)
	}
	err := migrate067Error(t.Context(), pool, "up")
	assert067PGError(t, err, "55000")
	assert067Ledger(t, pool, 66)
	assert067Installed(t, pool, false)
}

func TestAnnouncements067DownFailsClosedForUnprovenAndBusinessFacts(t *testing.T) {
	t.Run("unproven existing system grant", func(t *testing.T) {
		pool, cleanup := new043Pool(t)
		defer cleanup()
		migrate067(t, pool, "up")
		migrate067(t, pool, "down")
		tenant := seed067Tenant(t, pool, "unproven", true)
		if _, err := pool.Exec(t.Context(), `
			INSERT INTO role_permissions(role_id,permission_name)
			VALUES($1,'announcements.read')`, tenant.ownerRoleID); err != nil {
			t.Fatal(err)
		}
		migrate067(t, pool, "up")
		if _, err := pool.Exec(t.Context(), `
			UPDATE access_scopes SET kind='platform',tenant_id=NULL WHERE id=$1`,
			tenant.scopeID); err == nil ||
			!strings.Contains(err.Error(), "scope classification with announcement RBAC grants is immutable") {
			t.Fatalf("unproven grant scope mutation error = %v", err)
		}
		assert067DownRejected(t, pool)
		assert067RolePermissions(t, pool, tenant.ownerRoleID,
			[]string{"announcements.manage", "announcements.read"})
		var provenance int
		if err := pool.QueryRow(t.Context(), `
			SELECT count(*) FROM announcement_rbac_system_role_grant_additions
			WHERE role_id=$1`, tenant.ownerRoleID).Scan(&provenance); err != nil {
			t.Fatal(err)
		}
		if provenance != 1 {
			t.Fatalf("067 provenance rows = %d, want only newly-added manage grant", provenance)
		}
	})

	t.Run("custom role revision and non-system reference", func(t *testing.T) {
		pool, cleanup := new043Pool(t)
		defer cleanup()
		migrate067(t, pool, "up")
		tenant := seed067Tenant(t, pool, "customfact", true)
		customRoleID := seed067CustomRoleRoot(t, pool, tenant, "announcement-reader")
		publish067CustomRoleRevision(t, pool, tenant, customRoleID,
			[]string{"announcements.read"})
		assert067RolePermissions(t, pool, customRoleID, []string{"announcements.read"})
		assert067DownRejected(t, pool)
	})

	t.Run("announcement write fact", func(t *testing.T) {
		pool, cleanup := new043Pool(t)
		defer cleanup()
		migrate067(t, pool, "up")
		tenant := seed067Tenant(t, pool, "domainfact", true)
		if _, err := pool.Exec(t.Context(), `
			INSERT INTO announcement_write_requests(
				id,tenant_scope_id,actor_user_id,operation,idempotency_key,request_digest,created_at
			) VALUES($1,$2,$3,'announcement.create','067-domain-fact',decode(repeat('ab',32),'hex'),$4)`,
			uuid.New(), tenant.scopeID, tenant.ownerUserID, time.Now().UTC()); err != nil {
			t.Fatal(err)
		}
		assert067DownRejected(t, pool)
	})

	t.Run("announcement audit fact", func(t *testing.T) {
		pool, cleanup := new043Pool(t)
		defer cleanup()
		migrate067(t, pool, "up")
		tenant := seed067Tenant(t, pool, "auditfact", true)
		seed067AnnouncementAudit(t, pool, tenant)
		assert067DownRejected(t, pool)
	})
}

func TestAnnouncements067DirectSQLProtection(t *testing.T) {
	pool, cleanup := new043Pool(t)
	defer cleanup()
	migrate067(t, pool, "up")
	tenant := seed067Tenant(t, pool, "guards", true)
	operatorRoleID := uuid.New()
	if _, err := pool.Exec(t.Context(), `
		INSERT INTO roles(id,scope_id,name,description,system_role)
		VALUES($1,$2,'tenant_operator','067 guard role',true)`,
		operatorRoleID, tenant.scopeID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `
		INSERT INTO role_permissions(role_id,permission_name)
		VALUES($1,'announcements.read')`, operatorRoleID); err != nil {
		t.Fatal(err)
	}

	statements := []string{
		`UPDATE announcement_rbac_system_role_grant_additions SET source_migration=67`,
		fmt.Sprintf(`DELETE FROM announcement_rbac_system_role_grant_additions WHERE role_id='%s'`, tenant.ownerRoleID),
		`TRUNCATE announcement_rbac_system_role_grant_additions`,
		fmt.Sprintf(`INSERT INTO announcement_rbac_system_role_grant_additions(role_id,permission_name) VALUES('%s','announcements.read')`, operatorRoleID),
		`DELETE FROM custom_rbac_permission_catalog WHERE permission_name='announcements.manage'`,
		fmt.Sprintf(`UPDATE role_permissions SET permission_name='announcements.manage' WHERE role_id='%s' AND permission_name='announcements.read'`, tenant.viewerRoleID),
		fmt.Sprintf(`DELETE FROM role_permissions WHERE role_id='%s' AND permission_name='announcements.read'`, tenant.ownerRoleID),
		`TRUNCATE role_permissions, announcement_rbac_system_role_grant_additions CASCADE`,
		fmt.Sprintf(`UPDATE access_scopes SET kind='platform',tenant_id=NULL WHERE id='%s'`, tenant.scopeID),
	}
	for _, statement := range statements {
		if _, err := pool.Exec(t.Context(), statement); err == nil {
			t.Errorf("direct SQL unexpectedly succeeded: %s", statement)
		}
	}

	seed067AnnouncementAudit(t, pool, tenant)
	for _, statement := range []string{
		`UPDATE audit_events SET action='tampered' WHERE action='announcement.test'`,
		`DELETE FROM audit_events WHERE action='announcement.test'`,
		`TRUNCATE audit_events`,
	} {
		if _, err := pool.Exec(t.Context(), statement); err == nil {
			t.Errorf("audit SQL unexpectedly succeeded: %s", statement)
		}
	}

	var alwaysCount int
	if err := pool.QueryRow(t.Context(), `
		SELECT count(*) FROM pg_trigger
		WHERE tgrelid='announcement_rbac_system_role_grant_additions'::regclass
		  AND tgname IN ('announcement_rbac_grant_additions_protect',
		                 'announcement_rbac_grant_additions_no_truncate')
		  AND tgenabled='A'`).Scan(&alwaysCount); err != nil {
		t.Fatal(err)
	}
	if alwaysCount != 2 {
		t.Fatalf("ALWAYS provenance guards = %d, want 2", alwaysCount)
	}
	if err := pool.QueryRow(t.Context(), `
		SELECT count(*) FROM pg_trigger
		WHERE tgrelid='custom_rbac_permission_catalog'::regclass
		  AND tgname='announcement_rbac_catalog_delete_guard_067'
		  AND tgenabled='A'`).Scan(&alwaysCount); err != nil {
		t.Fatal(err)
	}
	if alwaysCount != 1 {
		t.Fatalf("ALWAYS announcement catalog guards = %d, want 1", alwaysCount)
	}

	if _, err := pool.Exec(t.Context(), `
		INSERT INTO permissions(name,description)
		VALUES('test.067.unrelated','067 unrelated catalog permission');
		INSERT INTO custom_rbac_permission_catalog(permission_name,step_up_required)
		VALUES('test.067.unrelated',false);
		DELETE FROM custom_rbac_permission_catalog
		WHERE permission_name='test.067.unrelated'`); err != nil {
		t.Fatalf("unrelated catalog row should retain migration 042 delete semantics: %v", err)
	}
}

func TestAnnouncements067ScopeClassificationSerializesWithFutureRoleProjection(t *testing.T) {
	t.Run("scope update wins", func(t *testing.T) {
		pool, cleanup := new043Pool(t)
		defer cleanup()
		migrate067(t, pool, "up")
		tenant := seed067Tenant(t, pool, "scopewins", false)

		scopeTx, err := pool.Begin(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		defer scopeTx.Rollback(t.Context())
		set067TransactionTimeouts(t, scopeTx)
		if _, err := scopeTx.Exec(t.Context(), `
			UPDATE access_scopes SET kind='platform',tenant_id=NULL WHERE id=$1`,
			tenant.scopeID); err != nil {
			t.Fatal(err)
		}

		roleConn, err := pool.Acquire(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		defer roleConn.Release()
		set067ConnectionTimeouts(t, roleConn)
		var rolePID int
		if err := roleConn.QueryRow(t.Context(), `SELECT pg_backend_pid()`).Scan(&rolePID); err != nil {
			t.Fatal(err)
		}
		roleID := uuid.New()
		roleResult := make(chan error, 1)
		go func() {
			_, err := roleConn.Exec(t.Context(), `
				INSERT INTO roles(id,scope_id,name,description,system_role)
				VALUES($1,$2,'tenant_owner','067 scope race',true)`, roleID, tenant.scopeID)
			roleResult <- err
		}()
		wait067Blocked(t, pool, rolePID)
		if err := scopeTx.Commit(t.Context()); err != nil {
			t.Fatal(err)
		}
		if err := <-roleResult; err != nil {
			t.Fatal(err)
		}
		assert067RolePermissions(t, pool, roleID, nil)
		var kind string
		if err := pool.QueryRow(t.Context(), `SELECT kind FROM access_scopes WHERE id=$1`,
			tenant.scopeID).Scan(&kind); err != nil || kind != "platform" {
			t.Fatalf("scope kind after serialized role insert = %q, %v", kind, err)
		}
	})

	t.Run("role projection wins", func(t *testing.T) {
		pool, cleanup := new043Pool(t)
		defer cleanup()
		migrate067(t, pool, "up")
		tenant := seed067Tenant(t, pool, "rolewins", false)

		roleTx, err := pool.Begin(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		defer roleTx.Rollback(t.Context())
		set067TransactionTimeouts(t, roleTx)
		roleID := uuid.New()
		if _, err := roleTx.Exec(t.Context(), `
			INSERT INTO roles(id,scope_id,name,description,system_role)
			VALUES($1,$2,'tenant_owner','067 scope race',true)`, roleID, tenant.scopeID); err != nil {
			t.Fatal(err)
		}

		updateConn, err := pool.Acquire(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		defer updateConn.Release()
		set067ConnectionTimeouts(t, updateConn)
		var updatePID int
		if err := updateConn.QueryRow(t.Context(), `SELECT pg_backend_pid()`).Scan(&updatePID); err != nil {
			t.Fatal(err)
		}
		updateResult := make(chan error, 1)
		go func() {
			_, err := updateConn.Exec(t.Context(), `
				UPDATE access_scopes SET kind='platform',tenant_id=NULL WHERE id=$1`, tenant.scopeID)
			updateResult <- err
		}()
		wait067Blocked(t, pool, updatePID)
		if err := roleTx.Commit(t.Context()); err != nil {
			t.Fatal(err)
		}
		if err := <-updateResult; err == nil ||
			!strings.Contains(err.Error(), "scope classification with announcement RBAC grants is immutable") {
			t.Fatalf("concurrent scope update error = %v", err)
		}
		assert067RolePermissions(t, pool, roleID,
			[]string{"announcements.manage", "announcements.read"})
	})
}

func TestAnnouncements067MigrationLockOrderSerializesRBACMutations(t *testing.T) {
	t.Run("up waits for permission insert", func(t *testing.T) {
		pool, cleanup := new043Pool(t)
		defer cleanup()
		migrate067(t, pool, "up")
		migrate067(t, pool, "down")
		tenant := seed067Tenant(t, pool, "permission-insert", true)

		mutationErr, commitErr, migrationErr := run067MigrationBehindScopeLock(
			t, pool, tenant.scopeID, "up", func(tx pgx.Tx) error {
				_, err := tx.Exec(t.Context(), `
					INSERT INTO role_permissions(role_id,permission_name)
					VALUES($1,'announcements.read')`, tenant.ownerRoleID)
				return err
			})
		assert067ConcurrentSuccess(t, mutationErr, commitErr, migrationErr)
		assert067RolePermissions(t, pool, tenant.ownerRoleID,
			[]string{"announcements.manage", "announcements.read"})
	})

	t.Run("down waits for permission insert and delete", func(t *testing.T) {
		pool, cleanup := new043Pool(t)
		defer cleanup()
		migrate067(t, pool, "up")
		migrate067(t, pool, "down")
		tenant := seed067Tenant(t, pool, "permission-delete", true)
		if _, err := pool.Exec(t.Context(), `INSERT INTO permissions(name,description)
			VALUES('test.067.transient','067 transient permission')`); err != nil {
			t.Fatal(err)
		}
		migrate067(t, pool, "up")

		mutationErr, commitErr, migrationErr := run067MigrationBehindScopeLock(
			t, pool, tenant.scopeID, "down", func(tx pgx.Tx) error {
				if _, err := tx.Exec(t.Context(), `
					INSERT INTO role_permissions(role_id,permission_name)
					VALUES($1,'test.067.transient')`, tenant.ownerRoleID); err != nil {
					return err
				}
				_, err := tx.Exec(t.Context(), `DELETE FROM role_permissions
					WHERE role_id=$1 AND permission_name='test.067.transient'`, tenant.ownerRoleID)
				return err
			})
		assert067ConcurrentSuccess(t, mutationErr, commitErr, migrationErr)
		assert067Ledger(t, pool, 66)
	})

	t.Run("up waits for assignment mutation", func(t *testing.T) {
		pool, cleanup := new043Pool(t)
		defer cleanup()
		migrate067(t, pool, "up")
		migrate067(t, pool, "down")
		tenant := seed067Tenant(t, pool, "assignment", true)

		mutationErr, commitErr, migrationErr := run067MigrationBehindScopeLock(
			t, pool, tenant.scopeID, "up", func(tx pgx.Tx) error {
				if _, err := tx.Exec(t.Context(), `DELETE FROM role_assignments
					WHERE scope_id=$1 AND user_id=$2 AND role_id=$3`, tenant.scopeID,
					tenant.viewerUserID, tenant.viewerRoleID); err != nil {
					return err
				}
				_, err := tx.Exec(t.Context(), `
					INSERT INTO role_assignments(scope_id,user_id,role_id)
					VALUES($1,$2,$3)`, tenant.scopeID, tenant.viewerUserID, tenant.viewerRoleID)
				return err
			})
		assert067ConcurrentSuccess(t, mutationErr, commitErr, migrationErr)
	})

	t.Run("down waits then rejects custom role announcement revision", func(t *testing.T) {
		pool, cleanup := new043Pool(t)
		defer cleanup()
		migrate067(t, pool, "up")
		tenant := seed067Tenant(t, pool, "custom-role", true)
		roleID := seed067CustomRoleRoot(t, pool, tenant, "concurrent-reader")
		now := time.Date(2026, 7, 23, 11, 0, 0, 0, time.UTC)

		mutationErr, commitErr, migrationErr := run067MigrationBehindScopeLock(
			t, pool, tenant.scopeID, "down", func(tx pgx.Tx) error {
				if _, err := tx.Exec(t.Context(), `
					INSERT INTO custom_role_revisions(
						role_id,tenant_id,tenant_scope_id,revision,name,permissions,action,
						created_by_user_id,created_by_scope_id,created_at
					) SELECT id,tenant_id,tenant_scope_id,1,current_name,$2,
						'identity.custom_role.create',$3,tenant_scope_id,$4
					FROM custom_roles WHERE id=$1`, roleID, []string{"announcements.read"},
					tenant.ownerUserID, now); err != nil {
					return err
				}
				_, err := tx.Exec(t.Context(), `
					UPDATE custom_roles SET current_revision=1,updated_at=$2 WHERE id=$1`, roleID, now)
				return err
			})
		assert067NoDeadlock(t, mutationErr, commitErr, migrationErr)
		if mutationErr != nil || commitErr != nil {
			t.Fatalf("serialized custom role mutation errors mutation=%v commit=%v",
				mutationErr, commitErr)
		}
		assert067PGError(t, migrationErr, "55000")
		assert067Ledger(t, pool, 67)
		assert067Installed(t, pool, true)
	})

	t.Run("migration first serializes future role", func(t *testing.T) {
		pool, cleanup := new043Pool(t)
		defer cleanup()
		migrate067(t, pool, "up")
		migrate067(t, pool, "down")
		tenant := seed067Tenant(t, pool, "migration-first", false)

		blocker, err := pool.Begin(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		defer blocker.Rollback(t.Context())
		set067TransactionTimeouts(t, blocker)
		if _, err := blocker.Exec(t.Context(), `LOCK TABLE role_permissions IN ACCESS SHARE MODE`); err != nil {
			t.Fatal(err)
		}
		migrationPool, migrationPID := new067MigrationPool(t, pool)
		migrationResult := make(chan error, 1)
		go func() { migrationResult <- migrate067Error(t.Context(), migrationPool, "up") }()
		wait067Blocked(t, pool, migrationPID)

		roleConn, err := pool.Acquire(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		defer roleConn.Release()
		set067ConnectionTimeouts(t, roleConn)
		var rolePID int
		if err := roleConn.QueryRow(t.Context(), `SELECT pg_backend_pid()`).Scan(&rolePID); err != nil {
			t.Fatal(err)
		}
		roleID := uuid.New()
		roleResult := make(chan error, 1)
		go func() {
			_, err := roleConn.Exec(t.Context(), `
				INSERT INTO roles(id,scope_id,name,description,system_role)
				VALUES($1,$2,'tenant_owner','067 migration-first role',true)`,
				roleID, tenant.scopeID)
			roleResult <- err
		}()
		wait067Blocked(t, pool, rolePID)
		commitErr := blocker.Commit(t.Context())
		migrationErr := <-migrationResult
		roleErr := <-roleResult
		assert067ConcurrentSuccess(t, roleErr, commitErr, migrationErr)
		assert067RolePermissions(t, pool, roleID,
			[]string{"announcements.manage", "announcements.read"})
	})
}

func TestAnnouncements067DownRejectsPermissionCatalogDrift(t *testing.T) {
	for _, test := range []struct {
		name             string
		deletePermission bool
		stepUpDrift      bool
	}{
		{name: "catalog row"},
		{name: "permission and catalog rows", deletePermission: true},
		{name: "catalog step-up flag", stepUpDrift: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			pool, cleanup := new043Pool(t)
			defer cleanup()
			migrate067(t, pool, "up")
			if test.stepUpDrift {
				if _, err := pool.Exec(t.Context(), `ALTER TABLE custom_rbac_permission_catalog
					DISABLE TRIGGER custom_rbac_permission_catalog_no_update_or_truncate;
					UPDATE custom_rbac_permission_catalog SET step_up_required=true
					WHERE permission_name='announcements.manage'`); err != nil {
					t.Fatal(err)
				}
			} else {
				if _, err := pool.Exec(t.Context(), `ALTER TABLE custom_rbac_permission_catalog
					DISABLE TRIGGER announcement_rbac_catalog_delete_guard_067;
					DELETE FROM custom_rbac_permission_catalog
					WHERE permission_name='announcements.manage'`); err != nil {
					t.Fatal(err)
				}
				if test.deletePermission {
					if _, err := pool.Exec(t.Context(), `DELETE FROM permissions
						WHERE name='announcements.manage'`); err != nil {
						t.Fatal(err)
					}
				}
			}
			assert067DownRejected(t, pool)
		})
	}
}

type tenant067Fixture struct {
	tenantID, scopeID         uuid.UUID
	ownerUserID, viewerUserID uuid.UUID
	ownerRoleID, viewerRoleID uuid.UUID
}

func seed067Tenant(t *testing.T, pool *pgxpool.Pool, suffix string, withRoles bool) tenant067Fixture {
	t.Helper()
	fixture := tenant067Fixture{
		tenantID: uuid.New(), scopeID: uuid.New(),
		ownerUserID: uuid.New(), viewerUserID: uuid.New(),
		ownerRoleID: uuid.New(), viewerRoleID: uuid.New(),
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO tenants(id,display_name) VALUES($1,$2)`,
		fixture.tenantID, "067 "+suffix); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `
		INSERT INTO access_scopes(id,kind,tenant_id) VALUES($1,'tenant',$2)`,
		fixture.scopeID, fixture.tenantID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `
		INSERT INTO users(id,username,display_name,password_hash) VALUES
			($1,$3,$3,'hash'),($2,$4,$4,'hash')`,
		fixture.ownerUserID, fixture.viewerUserID,
		"owner067"+suffix, "viewer067"+suffix); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `
		INSERT INTO memberships(scope_id,user_id) VALUES($1,$2),($1,$3)`,
		fixture.scopeID, fixture.ownerUserID, fixture.viewerUserID); err != nil {
		t.Fatal(err)
	}
	if withRoles {
		if _, err := pool.Exec(t.Context(), `
			INSERT INTO roles(id,scope_id,name,description,system_role) VALUES
				($1,$3,'tenant_owner','067 tenant owner',true),
				($2,$3,'tenant_viewer','067 tenant viewer',true)`,
			fixture.ownerRoleID, fixture.viewerRoleID, fixture.scopeID); err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(t.Context(), `
			INSERT INTO role_assignments(scope_id,user_id,role_id) VALUES
				($3,$4,$1),($3,$5,$2)`, fixture.ownerRoleID, fixture.viewerRoleID,
			fixture.scopeID, fixture.ownerUserID, fixture.viewerUserID); err != nil {
			t.Fatal(err)
		}
	}
	return fixture
}

func seed067CustomRoleRoot(t *testing.T, pool *pgxpool.Pool, tenant tenant067Fixture, name string) uuid.UUID {
	t.Helper()
	roleID := uuid.New()
	now := time.Date(2026, 7, 23, 10, 0, 0, 0, time.UTC)
	if _, err := pool.Exec(t.Context(), `
		INSERT INTO custom_roles(
			id,tenant_id,tenant_scope_id,current_name,created_by_user_id,
			created_by_scope_id,created_at,updated_at
		) VALUES($1,$2,$3,$4,$5,$3,$6,$6)`,
		roleID, tenant.tenantID, tenant.scopeID, name, tenant.ownerUserID, now); err != nil {
		t.Fatal(err)
	}
	return roleID
}

func publish067CustomRoleRevision(t *testing.T, pool *pgxpool.Pool, tenant tenant067Fixture,
	roleID uuid.UUID, permissions []string,
) {
	t.Helper()
	now := time.Date(2026, 7, 23, 10, 1, 0, 0, time.UTC)
	if _, err := pool.Exec(t.Context(), `
		INSERT INTO custom_role_revisions(
			role_id,tenant_id,tenant_scope_id,revision,name,permissions,action,
			created_by_user_id,created_by_scope_id,created_at
		) SELECT id,tenant_id,tenant_scope_id,1,current_name,$2,
			'identity.custom_role.create',$3,tenant_scope_id,$4
		FROM custom_roles WHERE id=$1`,
		roleID, permissions, tenant.ownerUserID, now); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `
		UPDATE custom_roles SET current_revision=1,updated_at=$2 WHERE id=$1`,
		roleID, now); err != nil {
		t.Fatal(err)
	}
}

func seed067AnnouncementAudit(t *testing.T, pool *pgxpool.Pool, tenant tenant067Fixture) {
	t.Helper()
	if _, err := pool.Exec(t.Context(), `
		INSERT INTO audit_events(
			id,scope_id,stream_position,actor_user_id,action,resource_type,resource_id,
			request_id,result,payload,event_hash,occurred_at
		) VALUES($1,$2,1,$3,'announcement.test','announcement','067-audit',
			'067-audit','denied','{}',decode(repeat('cd',32),'hex'),$4)`,
		uuid.New(), tenant.scopeID, tenant.ownerUserID, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
}

func migrate067(t *testing.T, pool *pgxpool.Pool, direction string) {
	t.Helper()
	if err := migrate067Error(t.Context(), pool, direction); err != nil {
		t.Fatalf("migrate 067 %s: %v", direction, err)
	}
}

func migrate067Error(ctx context.Context, pool *pgxpool.Pool, direction string) error {
	const target int64 = 67
	if direction != "up" && direction != "down" {
		return fmt.Errorf("unsupported 067 migration direction %q", direction)
	}
	if direction == "down" {
		script, err := fs.ReadFile(controlmigrations.FS, "067_announcements_rbac.down.sql")
		if err != nil {
			return err
		}
		if err := pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
			var current int64
			if err := tx.QueryRow(ctx, `SELECT COALESCE(max(version),0) FROM schema_migrations`).Scan(&current); err != nil {
				return err
			}
			if err := validate067Ledger(ctx, tx.QueryRow, current); err != nil {
				return err
			}
			if current != target {
				return fmt.Errorf("migration head = %d, want %d before down", current, target)
			}
			if _, err := tx.Exec(ctx, string(script)); err != nil {
				return err
			}
			command, err := tx.Exec(ctx, `DELETE FROM schema_migrations WHERE version=67`)
			if err == nil && command.RowsAffected() != 1 {
				return fmt.Errorf("delete 067 ledger rows = %d, want 1", command.RowsAffected())
			}
			if err != nil {
				return err
			}
			return validate067Ledger(ctx, tx.QueryRow, target-1)
		}); err != nil {
			return fmt.Errorf("migrate 067 down: %w", err)
		}
		return nil
	}

	if _, err := pool.Exec(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
		version bigint PRIMARY KEY,
		migration_id text,
		checksum_sha256 text,
		down_checksum_sha256 text,
		integrity_state text,
		metadata_recorded_at timestamptz,
		applied_at timestamptz NOT NULL DEFAULT now()
	)`); err != nil {
		return err
	}
	var current int64
	if err := pool.QueryRow(ctx, `SELECT COALESCE(max(version),0) FROM schema_migrations`).Scan(&current); err != nil {
		return err
	}
	if err := validate067Ledger(ctx, pool.QueryRow, current); err != nil {
		return err
	}
	if current > target {
		return fmt.Errorf("migration head = %d, want at most %d", current, target)
	}
	for version := current + 1; version <= target; version++ {
		upMatches, err := fs.Glob(controlmigrations.FS, fmt.Sprintf("%03d_*.up.sql", version))
		if err != nil {
			return fmt.Errorf("resolve migration %03d up: %w", version, err)
		}
		if len(upMatches) != 1 {
			return fmt.Errorf("resolve migration %03d up: matches=%v", version, upMatches)
		}
		downMatches, err := fs.Glob(controlmigrations.FS, fmt.Sprintf("%03d_*.down.sql", version))
		if err != nil {
			return fmt.Errorf("resolve migration %03d down: %w", version, err)
		}
		if len(downMatches) != 1 {
			return fmt.Errorf("resolve migration %03d down: matches=%v", version, downMatches)
		}
		upScript, err := fs.ReadFile(controlmigrations.FS, upMatches[0])
		if err != nil {
			return err
		}
		downScript, err := fs.ReadFile(controlmigrations.FS, downMatches[0])
		if err != nil {
			return err
		}
		identifier := strings.TrimSuffix(upMatches[0], ".up.sql")
		upChecksum := fmt.Sprintf("%x", sha256.Sum256(upScript))
		downChecksum := fmt.Sprintf("%x", sha256.Sum256(downScript))
		if err := pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
			if _, err := tx.Exec(ctx, string(upScript)); err != nil {
				return err
			}
			_, err := tx.Exec(ctx, `INSERT INTO schema_migrations(
				version,migration_id,checksum_sha256,down_checksum_sha256,
				integrity_state,metadata_recorded_at
			) VALUES($1,$2,$3,$4,'verified',now())`,
				version, identifier, upChecksum, downChecksum)
			return err
		}); err != nil {
			return fmt.Errorf("migrate %03d up: %w", version, err)
		}
	}
	return validate067Ledger(ctx, pool.QueryRow, target)
}

func validate067Ledger(
	ctx context.Context,
	queryRow func(context.Context, string, ...any) pgx.Row,
	wantHead int64,
) error {
	var count, minimum, maximum int64
	if err := queryRow(ctx, `SELECT count(*),COALESCE(min(version),0),COALESCE(max(version),0)
		FROM schema_migrations`).Scan(&count, &minimum, &maximum); err != nil {
		return err
	}
	wantMinimum := int64(1)
	if wantHead == 0 {
		wantMinimum = 0
	}
	if count != wantHead || minimum != wantMinimum || maximum != wantHead {
		return fmt.Errorf("migration ledger = count:%d min:%d max:%d, want %d/%d/%d",
			count, minimum, maximum, wantHead, wantMinimum, wantHead)
	}
	for version := int64(1); version <= wantHead; version++ {
		upMatches, err := fs.Glob(controlmigrations.FS, fmt.Sprintf("%03d_*.up.sql", version))
		if err != nil || len(upMatches) != 1 {
			return fmt.Errorf("resolve migration %03d up: matches=%v err=%v", version, upMatches, err)
		}
		downMatches, err := fs.Glob(controlmigrations.FS, fmt.Sprintf("%03d_*.down.sql", version))
		if err != nil || len(downMatches) != 1 {
			return fmt.Errorf("resolve migration %03d down: matches=%v err=%v", version, downMatches, err)
		}
		upScript, err := fs.ReadFile(controlmigrations.FS, upMatches[0])
		if err != nil {
			return err
		}
		downScript, err := fs.ReadFile(controlmigrations.FS, downMatches[0])
		if err != nil {
			return err
		}
		var identifier, upChecksum, downChecksum, integrity string
		var metadataRecorded bool
		if err := queryRow(ctx, `SELECT migration_id,checksum_sha256,down_checksum_sha256,
			integrity_state,metadata_recorded_at IS NOT NULL
			FROM schema_migrations WHERE version=$1`, version).Scan(
			&identifier, &upChecksum, &downChecksum, &integrity, &metadataRecorded); err != nil {
			return err
		}
		if identifier != strings.TrimSuffix(upMatches[0], ".up.sql") ||
			upChecksum != fmt.Sprintf("%x", sha256.Sum256(upScript)) ||
			downChecksum != fmt.Sprintf("%x", sha256.Sum256(downScript)) ||
			integrity != "verified" || !metadataRecorded {
			return fmt.Errorf("migration %03d ledger metadata mismatch", version)
		}
	}
	return nil
}

func wait067Blocked(t *testing.T, pool *pgxpool.Pool, backendPID int) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	for ctx.Err() == nil {
		var blocked bool
		if err := pool.QueryRow(ctx, `SELECT cardinality(pg_blocking_pids($1)) > 0`,
			backendPID).Scan(&blocked); err != nil {
			t.Fatal(err)
		}
		if blocked {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("timed out waiting for PostgreSQL lock serialization")
}

func set067TransactionTimeouts(t *testing.T, tx pgx.Tx) {
	t.Helper()
	if _, err := tx.Exec(t.Context(), `
		SET LOCAL lock_timeout='3s';
		SET LOCAL deadlock_timeout='100ms';
		SET LOCAL statement_timeout='10s'`); err != nil {
		t.Fatal(err)
	}
}

func set067ConnectionTimeouts(t *testing.T, conn *pgxpool.Conn) {
	t.Helper()
	if _, err := conn.Exec(t.Context(), `
		SET lock_timeout='3s';
		SET deadlock_timeout='100ms';
		SET statement_timeout='10s'`); err != nil {
		t.Fatal(err)
	}
}

func new067MigrationPool(t *testing.T, pool *pgxpool.Pool) (*pgxpool.Pool, int) {
	t.Helper()
	config := pool.Config()
	config.MaxConns = 1
	config.MinConns = 0
	originalAfterConnect := config.AfterConnect
	config.AfterConnect = func(ctx context.Context, conn *pgx.Conn) error {
		if originalAfterConnect != nil {
			if err := originalAfterConnect(ctx, conn); err != nil {
				return err
			}
		}
		_, err := conn.Exec(ctx, `
			SET lock_timeout='3s';
			SET deadlock_timeout='100ms';
			SET statement_timeout='10s'`)
		return err
	}
	migrationPool, err := pgxpool.NewWithConfig(t.Context(), config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(migrationPool.Close)
	var backendPID int
	if err := migrationPool.QueryRow(t.Context(), `SELECT pg_backend_pid()`).Scan(&backendPID); err != nil {
		t.Fatal(err)
	}
	return migrationPool, backendPID
}

func assert067NoDeadlock(t *testing.T, errs ...error) {
	t.Helper()
	for _, err := range errs {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "40P01" {
			t.Fatalf("unexpected PostgreSQL deadlock: %v", err)
		}
	}
}

func run067MigrationBehindScopeLock(
	t *testing.T,
	pool *pgxpool.Pool,
	scopeID uuid.UUID,
	direction string,
	mutate func(pgx.Tx) error,
) (mutationErr, commitErr, migrationErr error) {
	t.Helper()
	tx, err := pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(t.Context())
	set067TransactionTimeouts(t, tx)
	if _, err := tx.Exec(t.Context(), `SELECT kind FROM access_scopes WHERE id=$1 FOR SHARE`,
		scopeID); err != nil {
		t.Fatal(err)
	}

	migrationPool, migrationPID := new067MigrationPool(t, pool)
	migrationResult := make(chan error, 1)
	go func() {
		migrationResult <- migrate067Error(t.Context(), migrationPool, direction)
	}()
	wait067Blocked(t, pool, migrationPID)
	mutationErr = mutate(tx)
	if mutationErr == nil {
		commitErr = tx.Commit(t.Context())
	} else {
		_ = tx.Rollback(t.Context())
	}
	migrationErr = <-migrationResult
	return mutationErr, commitErr, migrationErr
}

func assert067ConcurrentSuccess(t *testing.T, mutationErr, commitErr, migrationErr error) {
	t.Helper()
	assert067NoDeadlock(t, mutationErr, commitErr, migrationErr)
	if mutationErr != nil || commitErr != nil || migrationErr != nil {
		t.Fatalf("serialized migration errors mutation=%v commit=%v migration=%v",
			mutationErr, commitErr, migrationErr)
	}
}

func assert067DownRejected(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	err := migrate067Error(t.Context(), pool, "down")
	assert067PGError(t, err, "55000")
	assert067Ledger(t, pool, 67)
	assert067Installed(t, pool, true)
}

func assert067PGError(t *testing.T, err error, code string) {
	t.Helper()
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != code {
		t.Fatalf("PostgreSQL error = %v, want SQLSTATE %s", err, code)
	}
}

func assert067Ledger(t *testing.T, pool *pgxpool.Pool, wantHead int64) {
	t.Helper()
	var count, minimum, maximum, invalid int64
	if err := pool.QueryRow(t.Context(), `
		SELECT count(*),min(version),max(version),count(*) FILTER (WHERE
			migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
			down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR integrity_state <> 'verified' OR
			metadata_recorded_at IS NULL)
		FROM schema_migrations`).Scan(&count, &minimum, &maximum, &invalid); err != nil {
		t.Fatal(err)
	}
	if count != wantHead || minimum != 1 || maximum != wantHead || invalid != 0 {
		t.Fatalf("migration ledger count/min/max/invalid = %d/%d/%d/%d, want %d/1/%d/0",
			count, minimum, maximum, invalid, wantHead, wantHead)
	}
}

func assert067Checksums(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	up, err := controlmigrations.FS.ReadFile("067_announcements_rbac.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	down, err := controlmigrations.FS.ReadFile("067_announcements_rbac.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	var identifier, upChecksum, downChecksum, integrity string
	if err := pool.QueryRow(t.Context(), `
		SELECT migration_id,checksum_sha256,down_checksum_sha256,integrity_state
		FROM schema_migrations WHERE version=67`).Scan(
		&identifier, &upChecksum, &downChecksum, &integrity); err != nil {
		t.Fatal(err)
	}
	if identifier != "067_announcements_rbac" ||
		upChecksum != fmt.Sprintf("%x", sha256.Sum256(up)) ||
		downChecksum != fmt.Sprintf("%x", sha256.Sum256(down)) || integrity != "verified" {
		t.Fatalf("067 ledger metadata = %q/%q/%q/%q", identifier, upChecksum, downChecksum, integrity)
	}
}

func assert067Installed(t *testing.T, pool *pgxpool.Pool, want bool) {
	t.Helper()
	var installed bool
	if err := pool.QueryRow(t.Context(), `
		SELECT to_regclass('announcement_rbac_system_role_grant_additions') IS NOT NULL
		  AND EXISTS(SELECT 1 FROM pg_trigger WHERE tgname='roles_project_announcement_permissions_067')
		  AND EXISTS(SELECT 1 FROM pg_proc WHERE proname='project_announcement_system_role_permissions_067')
		  AND EXISTS(SELECT 1 FROM pg_trigger WHERE tgname='announcement_rbac_catalog_delete_guard_067')
		  AND EXISTS(SELECT 1 FROM pg_proc WHERE proname='protect_announcement_rbac_catalog_delete_067')`).Scan(&installed); err != nil {
		t.Fatal(err)
	}
	if installed != want {
		t.Fatalf("067 installed = %t, want %t", installed, want)
	}
}

func assert043AnnouncementCatalog(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	var permissions, catalog int
	if err := pool.QueryRow(t.Context(), `
		SELECT
			(SELECT count(*) FROM permissions
			 WHERE name IN ('announcements.read','announcements.manage')),
			(SELECT count(*) FROM custom_rbac_permission_catalog
			 WHERE permission_name IN ('announcements.read','announcements.manage')
			   AND NOT step_up_required)`).Scan(&permissions, &catalog); err != nil {
		t.Fatal(err)
	}
	if permissions != 2 || catalog != 2 {
		t.Fatalf("043 announcement permission/catalog counts = %d/%d, want 2/2", permissions, catalog)
	}
}

func assert067RolePermissions(t *testing.T, pool *pgxpool.Pool, roleID uuid.UUID, want []string) {
	t.Helper()
	var got []string
	if err := pool.QueryRow(t.Context(), `
		SELECT coalesce(array_agg(permission_name ORDER BY permission_name),ARRAY[]::text[])
		FROM role_permissions
		WHERE role_id=$1 AND permission_name LIKE 'announcements.%'`, roleID).Scan(&got); err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("role %s announcement permissions = %v, want %v", roleID, got, want)
	}
}

func assert067EffectivePermissions(t *testing.T, pool *pgxpool.Pool, scopeID, userID uuid.UUID, want []string) {
	t.Helper()
	var got []string
	if err := pool.QueryRow(t.Context(), `
		SELECT coalesce(array_agg(permission_name ORDER BY permission_name),ARRAY[]::text[])
		FROM custom_rbac_effective_permissions($1,$2)
		WHERE permission_name LIKE 'announcements.%'`, scopeID, userID).Scan(&got); err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("effective announcements permissions scope=%s user=%s = %v, want %v",
			scopeID, userID, got, want)
	}
}
