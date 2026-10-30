//go:build integration

package identity_test

import (
	"bytes"
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/database"
	"github.com/cdnca/cdnca/services/control-api/internal/iamlock"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestIdentityBootstrapWaitsForGlobalExclusive(t *testing.T) {
	pool := newIdentityAuthorityPool(t)
	holder, err := pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer holder.Rollback(context.Background())
	if err := iamlock.AcquireShared(t.Context(), holder); err != nil {
		t.Fatal(err)
	}

	done := make(chan error, 1)
	go func() {
		_, err := identity.NewStore(pool).BootstrapPlatformUser(context.Background(),
			"stage2-bootstrap", "Stage2 Bootstrap", "unused-hash", "stage2-bootstrap")
		done <- err
	}()
	select {
	case err := <-done:
		t.Fatalf("bootstrap did not wait for global exclusive lock: %v", err)
	case <-time.After(75 * time.Millisecond):
	}
	if err := holder.Rollback(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestIdentityBootstrapPersistsRecoveryEmailAndRejectsInvalidEmail(t *testing.T) {
	pool := newIdentityAuthorityPool(t)
	store := identity.NewStore(pool)
	result, err := store.BootstrapPlatformUserWithEmail(t.Context(),
		"bootstrap-email", "Bootstrap Email", " Admin@Example.Test ", "unused-hash", "bootstrap-email")
	if err != nil {
		t.Fatalf("BootstrapPlatformUserWithEmail() error = %v", err)
	}
	var email string
	if err := pool.QueryRow(t.Context(), `SELECT email FROM users WHERE id=$1`, result.UserID).Scan(&email); err != nil {
		t.Fatal(err)
	}
	if email != "admin@example.test" {
		t.Fatalf("persisted recovery email = %q, want %q", email, "admin@example.test")
	}
	if _, err := store.BootstrapPlatformUserWithEmail(t.Context(),
		"bootstrap-invalid-email", "Bootstrap Invalid Email", "not-an-email", "unused-hash", "bootstrap-invalid-email"); !errors.Is(err, identity.ErrInvalidUserInput) {
		t.Fatalf("invalid recovery email error = %v, want ErrInvalidUserInput", err)
	}
}

func TestIdentityBootstrapReusesExistingImmutablePlatformOwnerRole(t *testing.T) {
	pool := newIdentityAuthorityPool(t)
	store := identity.NewStore(pool)
	first, err := store.BootstrapPlatformUserWithEmail(t.Context(),
		"bootstrap-first", "Bootstrap First", "first@example.test", "unused-hash", "bootstrap-first")
	if err != nil {
		t.Fatalf("first BootstrapPlatformUserWithEmail() error = %v", err)
	}
	second, err := store.BootstrapPlatformUserWithEmail(t.Context(),
		"bootstrap-second", "Bootstrap Second", "second@example.test", "unused-hash", "bootstrap-second")
	if err != nil {
		t.Fatalf("second BootstrapPlatformUserWithEmail() error = %v", err)
	}
	if second.ScopeID != first.ScopeID || second.RoleID != first.RoleID || second.UserID == first.UserID {
		t.Fatalf("second bootstrap result = %+v, first = %+v", second, first)
	}

	var roles, assignments int
	if err := pool.QueryRow(t.Context(), `SELECT
		(SELECT count(*) FROM roles WHERE scope_id=$1 AND name='platform_owner' AND system_role),
		(SELECT count(*) FROM role_assignments WHERE scope_id=$1 AND role_id=$2)`,
		first.ScopeID, first.RoleID).Scan(&roles, &assignments); err != nil {
		t.Fatal(err)
	}
	if roles != 1 || assignments != 2 {
		t.Fatalf("platform_owner roles=%d assignments=%d, want 1 role and 2 assignments", roles, assignments)
	}
}

func TestIdentityBootstrapProjectsPlatformCompatiblePermissions(t *testing.T) {
	pool := newIdentityAuthorityPool(t)
	result, err := identity.NewStore(pool).BootstrapPlatformUser(t.Context(),
		"bootstrap-compatible", "Bootstrap Compatible", "unused-hash", "bootstrap-compatible")
	if err != nil {
		t.Fatalf("BootstrapPlatformUser() error = %v", err)
	}

	var expectedPermissions, actualPermissions int
	var hasManage, hasManageAll bool
	if err := pool.QueryRow(t.Context(), `SELECT
		(SELECT count(*) FROM permissions WHERE name <> 'jobs.manage'),
		(SELECT count(*) FROM role_permissions WHERE role_id=$1),
		EXISTS(SELECT 1 FROM role_permissions WHERE role_id=$1 AND permission_name='jobs.manage'),
		EXISTS(SELECT 1 FROM role_permissions WHERE role_id=$1 AND permission_name='jobs.manage_all')`,
		result.RoleID).Scan(&expectedPermissions, &actualPermissions, &hasManage, &hasManageAll); err != nil {
		t.Fatal(err)
	}
	if actualPermissions != expectedPermissions || hasManage || !hasManageAll {
		t.Fatalf("platform_owner permissions count=%d/%d jobs.manage=%t jobs.manage_all=%t",
			actualPermissions, expectedPermissions, hasManage, hasManageAll)
	}

	tenantID, tenantScopeID, tenantOwnerID := uuid.New(), uuid.New(), uuid.New()
	if _, err := pool.Exec(t.Context(), `INSERT INTO tenants(id,display_name)
		VALUES($1,'Bootstrap tenant')`, tenantID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO access_scopes(id,kind,tenant_id)
		VALUES($1,'tenant',$2)`, tenantScopeID, tenantID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO roles(id,scope_id,name,description,system_role)
		VALUES($1,$2,'tenant_owner','Bootstrap tenant owner',true)`, tenantOwnerID, tenantScopeID); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(t.Context(), `SELECT EXISTS(
		SELECT 1 FROM role_permissions WHERE role_id=$1 AND permission_name='jobs.manage'
	)`, tenantOwnerID).Scan(&hasManage); err != nil {
		t.Fatal(err)
	}
	if !hasManage {
		t.Fatal("future tenant_owner is missing jobs.manage projection")
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO role_permissions(role_id,permission_name)
		VALUES($1,'jobs.manage')`, result.RoleID); identitySQLState(err) != "P9403" {
		t.Fatalf("platform_owner jobs.manage guard error = %v, want P9403", err)
	}
}

func identitySQLState(err error) string {
	var state interface{ SQLState() string }
	if errors.As(err, &state) {
		return state.SQLState()
	}
	return ""
}

func TestIdentitySessionScopeHintDriftHasNoMutationSideEffects(t *testing.T) {
	for _, operation := range []string{"rotate", "logout"} {
		t.Run(operation, func(t *testing.T) {
			pool := newIdentityAuthorityPool(t)
			fixture := seedIdentityAuthoritySession(t, pool)
			holder, err := pool.Begin(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			defer holder.Rollback(context.Background())
			if err := iamlock.AcquireShared(t.Context(), holder); err != nil {
				t.Fatal(err)
			}

			done := make(chan error, 1)
			store := identity.NewStore(pool)
			go func() {
				switch operation {
				case "rotate":
					_, _, err := store.RotateSession(context.Background(), fixture.tokenHash,
						uuid.New(), bytes.Repeat([]byte{0x72}, 32), time.Now().Add(time.Hour),
						"stage2-hint-drift", "", "")
					done <- err
				case "logout":
					done <- store.RevokeSessionFamily(context.Background(), fixture.tokenHash, "stage2-hint-drift")
				}
			}()
			assertIdentityGlobalExclusiveWaiter(t, pool)
			if _, err := pool.Exec(t.Context(), `UPDATE auth_sessions SET scope_id=$2 WHERE id=$1`,
				fixture.sessionID, fixture.scopeB); err != nil {
				t.Fatal(err)
			}
			if err := holder.Rollback(t.Context()); err != nil {
				t.Fatal(err)
			}
			if err := <-done; !errors.Is(err, identity.ErrInvalidSession) {
				t.Fatalf("%s after scope hint drift = %v, want ErrInvalidSession", operation, err)
			}

			var usedAt, revokedAt *time.Time
			var replacedBy *uuid.UUID
			if err := pool.QueryRow(t.Context(), `SELECT used_at,revoked_at,replaced_by_id
				FROM auth_sessions WHERE id=$1`, fixture.sessionID).Scan(&usedAt, &revokedAt, &replacedBy); err != nil {
				t.Fatal(err)
			}
			if usedAt != nil || revokedAt != nil || replacedBy != nil {
				t.Fatalf("%s drift mutated original session: used=%v revoked=%v replaced=%v",
					operation, usedAt, revokedAt, replacedBy)
			}
			var sessions, audits int
			if err := pool.QueryRow(t.Context(), `SELECT
				(SELECT count(*) FROM auth_sessions WHERE family_id=$1),
				(SELECT count(*) FROM audit_events WHERE request_id='stage2-hint-drift')`,
				fixture.familyID).Scan(&sessions, &audits); err != nil {
				t.Fatal(err)
			}
			if sessions != 1 || audits != 0 {
				t.Fatalf("%s drift side effects = sessions:%d audits:%d, want 1/0", operation, sessions, audits)
			}
		})
	}
}

func TestIdentityMissingSessionTokenUsesSyntheticScopeWithoutSideEffects(t *testing.T) {
	pool := newIdentityAuthorityPool(t)
	store := identity.NewStore(pool)
	missing := bytes.Repeat([]byte{0x6d}, 32)
	if err := store.RevokeSessionFamily(t.Context(), missing, "stage2-missing-logout"); err != nil {
		t.Fatalf("missing logout: %v", err)
	}
	if _, _, err := store.RotateSession(t.Context(), missing, uuid.New(), bytes.Repeat([]byte{0x6e}, 32),
		time.Now().Add(time.Hour), "stage2-missing-rotate", "", ""); !errors.Is(err, identity.ErrInvalidSession) {
		t.Fatalf("missing rotate = %v, want ErrInvalidSession", err)
	}
	var sessions, audits int
	if err := pool.QueryRow(t.Context(), `SELECT
		(SELECT count(*) FROM auth_sessions),
		(SELECT count(*) FROM audit_events WHERE request_id LIKE 'stage2-missing-%')`).Scan(
		&sessions, &audits); err != nil {
		t.Fatal(err)
	}
	if sessions != 0 || audits != 0 {
		t.Fatalf("missing token side effects = sessions:%d audits:%d, want 0/0", sessions, audits)
	}
}

func TestIdentityFamilyMutationLocksEveryScope(t *testing.T) {
	for _, operation := range []string{"rotate", "logout"} {
		t.Run(operation, func(t *testing.T) {
			pool := newIdentityAuthorityPool(t)
			fixture := seedIdentityAuthoritySession(t, pool)
			if _, err := pool.Exec(t.Context(), `INSERT INTO auth_sessions(
				id,family_id,user_id,scope_id,refresh_token_hash,created_at,expires_at
			) VALUES($1,$2,$3,$4,$5,$6,$7)`, uuid.New(), fixture.familyID, fixture.userID,
				fixture.scopeB, bytes.Repeat([]byte{0x73}, 32), time.Now().Add(-time.Hour),
				time.Now().Add(time.Hour)); err != nil {
				t.Fatal(err)
			}

			holder, err := pool.Begin(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			defer holder.Rollback(context.Background())
			for _, key := range []string{
				"iam-authz:v1:" + fixture.scopeB.String(),
				"custom-rbac-tenant:" + fixture.scopeB.String(),
			} {
				if _, err := holder.Exec(t.Context(),
					`SELECT pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended($1,0))`, key); err != nil {
					t.Fatal(err)
				}
			}

			done := make(chan error, 1)
			store := identity.NewStore(pool)
			go func() {
				switch operation {
				case "rotate":
					_, _, err := store.RotateSession(context.Background(), fixture.tokenHash,
						uuid.New(), bytes.Repeat([]byte{0x74}, 32), time.Now().Add(time.Hour),
						"stage2-family-scope", "", "")
					done <- err
				case "logout":
					done <- store.RevokeSessionFamily(context.Background(), fixture.tokenHash, "stage2-family-scope")
				}
			}()
			select {
			case err := <-done:
				t.Fatalf("%s bypassed second family scope legacy locks: %v", operation, err)
			case <-time.After(100 * time.Millisecond):
			}
			if err := holder.Rollback(t.Context()); err != nil {
				t.Fatal(err)
			}
			if err := <-done; err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestIdentityUserMutationRejectsScopeSetDriftWithoutSideEffects(t *testing.T) {
	for _, operation := range []string{"managed", "profile", "password"} {
		t.Run(operation, func(t *testing.T) {
			fixture := seedIdentityUserMutationFixture(t)
			holder, err := fixture.pool.Begin(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			defer holder.Rollback(context.Background())
			if err := iamlock.AcquireShared(t.Context(), holder); err != nil {
				t.Fatal(err)
			}

			done := make(chan error, 1)
			go func() {
				switch operation {
				case "managed":
					_, err := fixture.store.UpdateManagedUser(context.Background(), fixture.manager,
						identity.UpdateUserInput{ID: fixture.userID, ExpectedRevision: fixture.revision,
							Fields: identity.UserFields{DisplayName: "Changed Managed"},
							Status: identity.UserStatusActive, Role: identity.UserRoleOwner,
							IdempotencyKey: "scope-drift-managed", RequestID: "scope-drift-managed"},
						[32]byte{0x31})
					done <- err
				case "profile":
					_, err := fixture.store.UpdateAccountProfile(context.Background(), fixture.actor,
						identity.UpdateProfileInput{ExpectedRevision: fixture.revision,
							Fields:         identity.UserFields{DisplayName: "Changed Profile"},
							IdempotencyKey: "scope-drift-profile", RequestID: "scope-drift-profile"},
						[32]byte{0x32})
					done <- err
				case "password":
					done <- fixture.store.ChangePassword(context.Background(), fixture.actor,
						identity.PasswordCredential{PasswordHash: fixture.passwordHash, Revision: fixture.revision},
						"changed-password-hash", "scope-drift-password")
				}
			}()
			assertIdentityGlobalExclusiveWaiter(t, fixture.pool)
			if _, err := fixture.pool.Exec(t.Context(), `INSERT INTO memberships(scope_id,user_id) VALUES($1,$2)`,
				fixture.scopeB, fixture.userID); err != nil {
				t.Fatal(err)
			}
			if err := holder.Rollback(t.Context()); err != nil {
				t.Fatal(err)
			}
			if err := <-done; !errors.Is(err, identity.ErrConflict) {
				t.Fatalf("%s scope drift error = %v, want ErrConflict", operation, err)
			}
			assertIdentityUserMutationUnchanged(t, fixture, "scope-drift-"+operation)
		})
	}
}

func TestIdentityUserMutationRejectsMoreThan64Scopes(t *testing.T) {
	fixture := seedIdentityUserMutationFixture(t)
	for range 64 {
		tenantID, scopeID := uuid.New(), uuid.New()
		if _, err := fixture.pool.Exec(t.Context(), `INSERT INTO tenants(id,display_name) VALUES($1,$2)`,
			tenantID, "Scope Limit Tenant "+tenantID.String()); err != nil {
			t.Fatal(err)
		}
		if _, err := fixture.pool.Exec(t.Context(), `INSERT INTO access_scopes(id,kind,tenant_id)
			VALUES($1,'tenant',$2)`, scopeID, tenantID); err != nil {
			t.Fatal(err)
		}
		if _, err := fixture.pool.Exec(t.Context(), `INSERT INTO memberships(scope_id,user_id) VALUES($1,$2)`,
			scopeID, fixture.userID); err != nil {
			t.Fatal(err)
		}
	}
	err := fixture.store.ChangePassword(t.Context(), fixture.actor,
		identity.PasswordCredential{PasswordHash: fixture.passwordHash, Revision: fixture.revision},
		"changed-password-hash", "scope-limit-password")
	if !errors.Is(err, iamlock.ErrInvalidInput) {
		t.Fatalf("ChangePassword(65 scopes) = %v, want invalid lock input", err)
	}
	assertIdentityUserMutationUnchanged(t, fixture, "scope-limit-password")
}

func TestUpdateUserAuthorizesLivePlatformManagerPermissions(t *testing.T) {
	for _, permission := range []string{"platform.admin", "identity.users.manage"} {
		t.Run(permission, func(t *testing.T) {
			fixture := seedManagedUserAuthorityFixture(t, permission)
			result, err := fixture.service.UpdateUser(t.Context(), fixture.actor, fixture.input)
			if err != nil {
				t.Fatal(err)
			}
			if result.ID != fixture.targetUserID || result.Status != identity.UserStatusDisabled ||
				result.Role != identity.UserRoleViewer || result.Revision != 2 {
				t.Fatalf("UpdateUser() = %#v", result)
			}
			facts := managedUserAuthorityFactsFor(t, fixture)
			if facts.targetDisplay != fixture.input.Fields.DisplayName ||
				facts.targetStatus != identity.UserStatusDisabled || facts.targetRevision != 2 ||
				facts.tenantDisplay != fixture.input.Fields.DisplayName || facts.tenantRevision != 2 ||
				facts.roleCount != 1 || facts.roleID != fixture.viewerRoleID ||
				facts.sessionCount != 1 || facts.revokedSessionCount != 1 ||
				facts.writeCount != 1 || facts.auditCount != 1 {
				t.Fatalf("authorized UpdateUser facts = %#v", facts)
			}
		})
	}
}

func TestUpdateUserRejectsStaleOrForgedPlatformAuthorityWithoutSideEffects(t *testing.T) {
	tests := map[string]func(*testing.T, *managedUserAuthorityFixture) identity.Actor{
		"forged platform scope kind": func(_ *testing.T, fixture *managedUserAuthorityFixture) identity.Actor {
			return fixture.forgedTenantActor
		},
		"disabled actor": func(t *testing.T, fixture *managedUserAuthorityFixture) identity.Actor {
			command, err := fixture.pool.Exec(t.Context(), `UPDATE users SET status='disabled' WHERE id=$1`,
				fixture.actor.UserID)
			if err != nil {
				t.Fatal(err)
			}
			if command.RowsAffected() != 1 {
				t.Fatalf("disable actor affected %d rows", command.RowsAffected())
			}
			return fixture.actor
		},
		"suspended membership": func(t *testing.T, fixture *managedUserAuthorityFixture) identity.Actor {
			command, err := fixture.pool.Exec(t.Context(), `UPDATE memberships SET status='suspended'
				WHERE scope_id=$1 AND user_id=$2`, fixture.actor.ScopeID, fixture.actor.UserID)
			if err != nil {
				t.Fatal(err)
			}
			if command.RowsAffected() != 1 {
				t.Fatalf("suspend actor membership affected %d rows", command.RowsAffected())
			}
			return fixture.actor
		},
		"permission revoked": func(t *testing.T, fixture *managedUserAuthorityFixture) identity.Actor {
			// 系统角色的权限不可修改（迁移 042/094 的守卫）；撤权改为收回该角色的指派。
			command, err := fixture.pool.Exec(t.Context(), `DELETE FROM role_assignments
				WHERE role_id=$1 AND user_id=$2`, fixture.actorRoleID, fixture.actor.UserID)
			if err != nil {
				t.Fatal(err)
			}
			if command.RowsAffected() != 1 {
				t.Fatalf("revoke actor permission affected %d rows", command.RowsAffected())
			}
			return fixture.actor
		},
	}
	for name, revoke := range tests {
		t.Run(name, func(t *testing.T) {
			fixture := seedManagedUserAuthorityFixture(t, "identity.users.manage")
			actor := revoke(t, &fixture)
			before := managedUserAuthorityFactsFor(t, fixture)
			result, err := fixture.service.UpdateUser(t.Context(), actor, fixture.input)
			if result.ID != uuid.Nil || !errors.Is(err, identity.ErrPermissionDenied) {
				t.Fatalf("UpdateUser() = %#v, %v, want zero result and permission denied", result, err)
			}
			after := managedUserAuthorityFactsFor(t, fixture)
			if after != before {
				t.Fatalf("rejected UpdateUser changed facts: before=%#v after=%#v", before, after)
			}
		})
	}
}

func TestUpdateUserReplayRevalidatesPlatformAuthority(t *testing.T) {
	fixture := seedManagedUserAuthorityFixture(t, "identity.users.manage")
	first, err := fixture.service.UpdateUser(t.Context(), fixture.actor, fixture.input)
	if err != nil || first.ID != fixture.targetUserID {
		t.Fatalf("initial UpdateUser() = %#v, %v", first, err)
	}
	// 系统角色的权限不可修改；撤权改为收回该角色的指派。
	command, err := fixture.pool.Exec(t.Context(), `DELETE FROM role_assignments
		WHERE role_id=$1 AND user_id=$2`, fixture.actorRoleID, fixture.actor.UserID)
	if err != nil {
		t.Fatal(err)
	}
	if command.RowsAffected() != 1 {
		t.Fatalf("revoke replay actor permission affected %d rows", command.RowsAffected())
	}
	before := managedUserAuthorityFactsFor(t, fixture)
	replayed, err := fixture.service.UpdateUser(t.Context(), fixture.actor, fixture.input)
	if replayed.ID != uuid.Nil || !errors.Is(err, identity.ErrPermissionDenied) {
		t.Fatalf("UpdateUser(replay after revoke) = %#v, %v, want zero result and permission denied", replayed, err)
	}
	after := managedUserAuthorityFactsFor(t, fixture)
	if after != before {
		t.Fatalf("rejected replay changed facts: before=%#v after=%#v", before, after)
	}
}

type managedUserAuthorityFixture struct {
	pool              *pgxpool.Pool
	service           *identity.Service
	actor             identity.Actor
	forgedTenantActor identity.Actor
	actorRoleID       uuid.UUID
	targetUserID      uuid.UUID
	targetScopeID     uuid.UUID
	viewerRoleID      uuid.UUID
	targetSession     uuid.UUID
	input             identity.UpdateUserInput
}

type managedUserAuthorityFacts struct {
	targetDisplay       string
	targetStatus        string
	targetRevision      int64
	tenantDisplay       string
	tenantRevision      int64
	roleCount           int
	roleID              uuid.UUID
	sessionCount        int
	revokedSessionCount int
	writeCount          int
	auditCount          int
}

func seedManagedUserAuthorityFixture(t *testing.T, permission string) managedUserAuthorityFixture {
	t.Helper()
	pool := newIdentityAuthorityPool(t)
	tokens, err := identity.NewTokenManager("identity-managed-user-authority-test-secret-2026", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	service, err := identity.NewService(identity.NewStore(pool), tokens, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	platformScopeID, tenantID, tenantScopeID := uuid.New(), uuid.New(), uuid.New()
	actorUserID, actorRoleID := uuid.New(), uuid.New()
	tenantManagerUserID, tenantManagerRoleID := uuid.New(), uuid.New()
	targetUserID, ownerRoleID, viewerRoleID, sessionID := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	if _, err := pool.Exec(t.Context(), `INSERT INTO tenants(id,display_name) VALUES($1,'Managed Target')`,
		tenantID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO access_scopes(id,kind,tenant_id)
		VALUES($1,'platform',NULL),($2,'tenant',$3)`, platformScopeID, tenantScopeID, tenantID); err != nil {
		t.Fatal(err)
	}
	actorUsername := "managed-user-actor-" + uuid.NewString()[:8]
	tenantManagerUsername := "managed-user-tenant-manager-" + uuid.NewString()[:8]
	targetUsername := "managed-user-target-" + uuid.NewString()[:8]
	if _, err := pool.Exec(t.Context(), `INSERT INTO users(id,username,display_name,password_hash) VALUES
		($1,$2,'Managed User Actor','unused'),($3,$4,'Managed Tenant Manager','unused'),
		($5,$6,'Managed Target','unused')`, actorUserID, actorUsername,
		tenantManagerUserID, tenantManagerUsername, targetUserID, targetUsername); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO memberships(scope_id,user_id) VALUES
		($1,$2),($3,$4),($3,$5)`, platformScopeID, actorUserID,
		tenantScopeID, tenantManagerUserID, targetUserID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO roles(id,scope_id,name,description,system_role) VALUES
		($1,$2,$3,'managed user authority actor',true),
		($4,$5,'tenant_owner','managed target owner',true),
		($6,$5,'tenant_viewer','managed target viewer',true),
		($7,$5,$8,'managed tenant manager',true)`,
		actorRoleID, platformScopeID, "managed-user-authority-"+uuid.NewString()[:8],
		ownerRoleID, tenantScopeID, viewerRoleID, tenantManagerRoleID,
		"managed-tenant-manager-"+uuid.NewString()[:8]); err != nil {
		t.Fatal(err)
	}
	command, err := pool.Exec(t.Context(), `INSERT INTO role_permissions(role_id,permission_name)
		SELECT $1,name FROM permissions WHERE name=$2`, actorRoleID, permission)
	if err != nil {
		t.Fatal(err)
	}
	if command.RowsAffected() != 1 {
		t.Fatalf("seed actor permission %q affected %d rows", permission, command.RowsAffected())
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO role_permissions(role_id,permission_name)
		VALUES($1,'identity.users.manage')`, tenantManagerRoleID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO role_assignments(scope_id,user_id,role_id) VALUES
		($1,$2,$3),($4,$5,$6),($4,$7,$8)`, platformScopeID, actorUserID, actorRoleID,
		tenantScopeID, targetUserID, ownerRoleID, tenantManagerUserID, tenantManagerRoleID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO auth_sessions(
		id,family_id,user_id,scope_id,refresh_token_hash,created_at,expires_at
	) VALUES($1,$1,$2,$3,$4,$5,$6)`, sessionID, targetUserID, tenantScopeID,
		bytes.Repeat([]byte{0x7d}, 32), time.Now().Add(-time.Hour), time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	key := "managed-user-authority-" + uuid.NewString()
	return managedUserAuthorityFixture{
		pool: pool, service: service,
		actor: identity.Actor{UserID: actorUserID, ScopeID: platformScopeID, ScopeKind: "platform"},
		forgedTenantActor: identity.Actor{
			UserID: tenantManagerUserID, ScopeID: tenantScopeID, ScopeKind: "platform",
		},
		actorRoleID:   actorRoleID,
		targetUserID:  targetUserID,
		targetScopeID: tenantScopeID,
		viewerRoleID:  viewerRoleID,
		targetSession: sessionID,
		input: identity.UpdateUserInput{
			ID: targetUserID, ExpectedRevision: 1,
			Fields: identity.UserFields{DisplayName: "Managed Target Updated"},
			Status: identity.UserStatusDisabled, Role: identity.UserRoleViewer,
			IdempotencyKey: key, RequestID: key,
		},
	}
}

func managedUserAuthorityFactsFor(t *testing.T, fixture managedUserAuthorityFixture) managedUserAuthorityFacts {
	t.Helper()
	var facts managedUserAuthorityFacts
	if err := fixture.pool.QueryRow(t.Context(), `SELECT display_name,status,revision FROM users WHERE id=$1`,
		fixture.targetUserID).Scan(&facts.targetDisplay, &facts.targetStatus, &facts.targetRevision); err != nil {
		t.Fatal(err)
	}
	if err := fixture.pool.QueryRow(t.Context(), `SELECT display_name,revision FROM tenants
		WHERE id=(SELECT tenant_id FROM access_scopes WHERE id=$1)`, fixture.targetScopeID).
		Scan(&facts.tenantDisplay, &facts.tenantRevision); err != nil {
		t.Fatal(err)
	}
	if err := fixture.pool.QueryRow(t.Context(), `SELECT count(*) FROM role_assignments
		WHERE scope_id=$1 AND user_id=$2`, fixture.targetScopeID, fixture.targetUserID).Scan(&facts.roleCount); err != nil {
		t.Fatal(err)
	}
	if facts.roleCount != 1 {
		t.Fatalf("target role assignment count=%d, want 1", facts.roleCount)
	}
	if err := fixture.pool.QueryRow(t.Context(), `SELECT role_id FROM role_assignments
		WHERE scope_id=$1 AND user_id=$2`, fixture.targetScopeID, fixture.targetUserID).Scan(&facts.roleID); err != nil {
		t.Fatal(err)
	}
	if err := fixture.pool.QueryRow(t.Context(), `SELECT count(*),count(*) FILTER (WHERE revoked_at IS NOT NULL)
		FROM auth_sessions WHERE id=$1 AND user_id=$2`, fixture.targetSession, fixture.targetUserID).
		Scan(&facts.sessionCount, &facts.revokedSessionCount); err != nil {
		t.Fatal(err)
	}
	if err := fixture.pool.QueryRow(t.Context(), `SELECT
		(SELECT count(*) FROM identity_write_requests
		 WHERE operation='identity.user.update' AND idempotency_key=$1),
		(SELECT count(*) FROM audit_events WHERE request_id=$1 AND action='identity.user.update')`,
		fixture.input.IdempotencyKey).Scan(&facts.writeCount, &facts.auditCount); err != nil {
		t.Fatal(err)
	}
	return facts
}

type identityUserMutationFixture struct {
	pool         *pgxpool.Pool
	store        *identity.Store
	actor        identity.Actor
	manager      identity.Actor
	userID       uuid.UUID
	scopeB       uuid.UUID
	sessionID    uuid.UUID
	revision     int64
	displayName  string
	passwordHash string
}

func seedIdentityUserMutationFixture(t *testing.T) identityUserMutationFixture {
	t.Helper()
	pool := newIdentityAuthorityPool(t)
	tenantA, tenantB, scopeA, scopeB, userID := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	platformScopeID, managerUserID, managerRoleID := uuid.New(), uuid.New(), uuid.New()
	fixture := identityUserMutationFixture{
		pool: pool, store: identity.NewStore(pool), actor: identity.Actor{UserID: userID, ScopeID: scopeA, ScopeKind: "tenant"},
		manager: identity.Actor{UserID: managerUserID, ScopeID: platformScopeID, ScopeKind: "platform"},
		userID:  userID, scopeB: scopeB, sessionID: uuid.New(), displayName: "Scope Stable User",
		passwordHash: "scope-stable-password-hash", revision: 1,
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO tenants(id,display_name) VALUES($1,'Scope A'),($2,'Scope B')`,
		tenantA, tenantB); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO access_scopes(id,kind,tenant_id)
		VALUES($1,'tenant',$2),($3,'tenant',$4),($5,'platform',NULL)`,
		scopeA, tenantA, scopeB, tenantB, platformScopeID); err != nil {
		t.Fatal(err)
	}
	username := "scope-" + strings.ReplaceAll(uuid.NewString(), "-", "")
	managerUsername := "scope-manager-" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if _, err := pool.Exec(t.Context(), `INSERT INTO users(id,username,display_name,password_hash) VALUES
		($1,$2,$3,$4),($5,$6,'Scope Manager','unused')`,
		userID, username, fixture.displayName, fixture.passwordHash, managerUserID, managerUsername); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO memberships(scope_id,user_id) VALUES
		($1,$2),($3,$4)`, scopeA, userID, platformScopeID, managerUserID); err != nil {
		t.Fatal(err)
	}
	ownerRoleID, viewerRoleID := uuid.New(), uuid.New()
	if _, err := pool.Exec(t.Context(), `INSERT INTO roles(id,scope_id,name,description,system_role) VALUES
		($1,$3,'tenant_owner','Scope owner',true),($2,$3,'tenant_viewer','Scope viewer',true),
		($4,$5,$6,'Scope manager',true)`, ownerRoleID, viewerRoleID, scopeA,
		managerRoleID, platformScopeID, "scope-manager-"+uuid.NewString()[:8]); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO role_permissions(role_id,permission_name)
		VALUES($1,'identity.users.manage')`, managerRoleID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO role_assignments(scope_id,user_id,role_id) VALUES
		($1,$2,$3),($4,$5,$6)`, scopeA, userID, ownerRoleID,
		platformScopeID, managerUserID, managerRoleID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO auth_sessions(
		id,family_id,user_id,scope_id,refresh_token_hash,created_at,expires_at
	) VALUES($1,$2,$3,$4,$5,$6,$7)`, fixture.sessionID, uuid.New(), userID, scopeA,
		bytes.Repeat([]byte{0x75}, 32), time.Now().Add(-time.Hour), time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	return fixture
}

func assertIdentityUserMutationUnchanged(
	t *testing.T,
	fixture identityUserMutationFixture,
	requestID string,
) {
	t.Helper()
	var displayName, passwordHash string
	var revision int64
	if err := fixture.pool.QueryRow(t.Context(), `SELECT display_name,password_hash,revision FROM users WHERE id=$1`,
		fixture.userID).Scan(&displayName, &passwordHash, &revision); err != nil {
		t.Fatal(err)
	}
	if displayName != fixture.displayName || passwordHash != fixture.passwordHash || revision != fixture.revision {
		t.Fatalf("user changed after rejected scope set: display=%q password=%q revision=%d",
			displayName, passwordHash, revision)
	}
	var revoked, audits, writes int
	if err := fixture.pool.QueryRow(t.Context(), `SELECT
		(SELECT count(*) FROM auth_sessions WHERE user_id=$1 AND revoked_at IS NOT NULL),
		(SELECT count(*) FROM audit_events WHERE request_id=$2),
		(SELECT count(*) FROM identity_write_requests WHERE idempotency_key=$2)`,
		fixture.userID, requestID).Scan(&revoked, &audits, &writes); err != nil {
		t.Fatal(err)
	}
	if revoked != 0 || audits != 0 || writes != 0 {
		t.Fatalf("rejected scope set side effects: revoked=%d audits=%d writes=%d", revoked, audits, writes)
	}
}

type identityAuthoritySession struct {
	sessionID uuid.UUID
	familyID  uuid.UUID
	userID    uuid.UUID
	scopeA    uuid.UUID
	scopeB    uuid.UUID
	tokenHash []byte
}

func seedIdentityAuthoritySession(t *testing.T, pool *pgxpool.Pool) identityAuthoritySession {
	t.Helper()
	fixture := identityAuthoritySession{
		sessionID: uuid.New(), familyID: uuid.New(), scopeB: uuid.New(), tokenHash: bytes.Repeat([]byte{0x71}, 32),
	}
	tenantA, tenantB := uuid.New(), uuid.New()
	fixture.scopeA, fixture.userID = uuid.New(), uuid.New()
	username := "stage2-" + strings.ReplaceAll(uuid.NewString(), "-", "")
	now := time.Now().UTC()
	if _, err := pool.Exec(t.Context(),
		`INSERT INTO tenants(id,display_name) VALUES($1,'Stage2 A'),($2,'Stage2 B')`, tenantA, tenantB); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(),
		`INSERT INTO access_scopes(id,kind,tenant_id) VALUES($1,'tenant',$2),($3,'tenant',$4)`,
		fixture.scopeA, tenantA, fixture.scopeB, tenantB); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(),
		`INSERT INTO users(id,username,display_name,password_hash) VALUES($1,$2,'Stage2 User','unused')`,
		fixture.userID, username); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(),
		`INSERT INTO memberships(scope_id,user_id) VALUES($1,$3),($2,$3)`,
		fixture.scopeA, fixture.scopeB, fixture.userID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `
		INSERT INTO auth_sessions(
			id,family_id,user_id,scope_id,refresh_token_hash,created_at,expires_at
		) VALUES($1,$2,$3,$4,$5,$6,$7)`,
		fixture.sessionID, fixture.familyID, fixture.userID, fixture.scopeA, fixture.tokenHash,
		now.Add(-time.Hour), now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	return fixture
}

func assertIdentityGlobalExclusiveWaiter(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		var waiting bool
		if err := pool.QueryRow(t.Context(), `SELECT EXISTS(
			SELECT 1 FROM pg_catalog.pg_locks
			WHERE locktype='advisory' AND classid=1229016321::oid AND objid=1::oid
			  AND objsubid=2 AND mode='ExclusiveLock' AND NOT granted
		)`).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("identity mutation never waited for global exclusive lock")
}

func newIdentityAuthorityPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	databaseURL := strings.TrimSpace(os.Getenv("TEST_DATABASE_URL"))
	if databaseURL == "" {
		t.Skip("TEST_DATABASE_URL is not set")
	}
	admin, err := pgxpool.New(t.Context(), databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	schema := "identity_stage2a_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	identifier := pgx.Identifier{schema}.Sanitize()
	if _, err := admin.Exec(t.Context(), "CREATE SCHEMA "+identifier); err != nil {
		admin.Close()
		t.Fatal(err)
	}
	config, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		admin.Close()
		t.Fatal(err)
	}
	config.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(t.Context(), config)
	if err != nil {
		admin.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		pool.Close()
		_, _ = admin.Exec(context.Background(), "DROP SCHEMA "+identifier+" CASCADE")
		admin.Close()
	})
	if err := database.Migrate(t.Context(), pool, "up"); err != nil {
		t.Fatal(err)
	}
	return pool
}
