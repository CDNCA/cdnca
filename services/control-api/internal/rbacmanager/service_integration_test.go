//go:build integration

package rbacmanager

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/migrations"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var errInjectedAudit = errors.New("injected custom RBAC audit failure")

type failingAudit struct{}

func (failingAudit) Append(context.Context, pgx.Tx, audit.Event) error {
	return errInjectedAudit
}

type recordingStepUp struct{}

func (recordingStepUp) VerifyAndConsume(
	ctx context.Context,
	tx pgx.Tx,
	_ StepUpProof,
	check StepUpCheck,
) (StepUpEvidence, error) {
	if _, err := tx.Exec(ctx, `INSERT INTO custom_rbac_test_step_up_uses(request_id)
		VALUES($1)`, check.RequestID); err != nil {
		return StepUpEvidence{}, err
	}
	return StepUpEvidence{
		ProofID: uuid.New(), Method: "totp",
		VerifiedAt: time.Date(2026, 7, 22, 7, 59, 0, 0, time.UTC),
	}, nil
}

type acceptingStepUp struct{}

func (acceptingStepUp) VerifyAndConsume(
	_ context.Context,
	tx pgx.Tx,
	proof StepUpProof,
	check StepUpCheck,
) (StepUpEvidence, error) {
	if tx == nil || proof.Token != "verified-token" || check.Audience != "custom-rbac" ||
		check.Actor.SessionID == uuid.Nil || check.TenantID == uuid.Nil || check.Action == "" ||
		check.RequestID == "" || check.TraceID == "" || len(check.MutationDigest) != 32 {
		return StepUpEvidence{}, ErrStepUpRequired
	}
	return StepUpEvidence{ProofID: uuid.New(), Method: "totp", VerifiedAt: check.ActorSessionTime()}, nil
}

func (check StepUpCheck) ActorSessionTime() time.Time {
	return time.Date(2026, 7, 22, 7, 59, 0, 0, time.UTC)
}

type rbacFixture struct {
	pool             *pgxpool.Pool
	service          *Service
	now              time.Time
	tenantID         uuid.UUID
	scopeID          uuid.UUID
	actor            Actor
	actorRoleID      uuid.UUID
	subjectID        uuid.UUID
	subjectSessionID uuid.UUID
	otherTenantID    uuid.UUID
	otherScopeID     uuid.UUID
	otherSubjectID   uuid.UUID
	operatorScopeID  uuid.UUID
	operatorUserID   uuid.UUID
	operatorRoleID   uuid.UUID
}

func TestCustomRBACMigrationRoundTrip(t *testing.T) {
	pool := isolatedRBACPool(t, false)
	migrateRBACTo42(t, pool)
	assertMigrationVersion(t, pool, 42, true)
	assertTable(t, pool, "custom_role_revisions", true)
	applyRBACMigration(t, pool, "042_custom_rbac.down.sql", 42, false)
	assertMigrationVersion(t, pool, 42, false)
	assertTable(t, pool, "custom_role_revisions", false)
	applyRBACMigration(t, pool, "042_custom_rbac.up.sql", 42, true)
	assertMigrationVersion(t, pool, 42, true)
	assertTable(t, pool, "custom_role_grants", true)
}

func TestPermissionSubsetWhitelistSystemRoleAndOperatorBoundaries(t *testing.T) {
	fixture := newRBACFixture(t)
	ctx := t.Context()

	if _, err := fixture.service.CreateRole(ctx, fixture.actor, CreateRoleRequest{
		Name: "escalated", Permissions: []string{"dns.read"},
		Mutation: mutation("subset-denied"),
	}); !errors.Is(err, ErrPermissionEscalation) {
		t.Fatalf("CreateRole(permission escalation) error = %v", err)
	}
	if _, err := fixture.service.CreateRole(ctx, fixture.actor, CreateRoleRequest{
		Name: "unknown", Permissions: []string{"unknown.permission"},
		Mutation: mutation("whitelist-denied"),
	}); !errors.Is(err, ErrPermissionNotAllowed) {
		t.Fatalf("CreateRole(non-whitelisted) error = %v", err)
	}
	if _, err := fixture.service.RenameRole(ctx, fixture.actor, RenameRoleRequest{
		RoleID: fixture.actorRoleID, ExpectedRevision: 1, Name: "rewritten-owner",
		Mutation: mutation("system-role-denied"),
	}); !errors.Is(err, ErrSystemRoleImmutable) {
		t.Fatalf("RenameRole(system role) error = %v", err)
	}

	operator := Actor{
		UserID: fixture.operatorUserID, ScopeID: fixture.operatorScopeID,
		ScopeKind: "platform", IdentityDomain: PlatformOperatorIdentityDomain,
	}
	if _, err := fixture.service.CreateRole(ctx, operator, CreateRoleRequest{
		Name: "operator-injected", Permissions: []string{"sites.read"},
		Mutation: mutation("operator-denied"),
	}); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("CreateRole(platform operator) error = %v", err)
	}

	if _, err := fixture.pool.Exec(ctx, `UPDATE roles SET description='tampered' WHERE id=$1`, fixture.actorRoleID); err == nil {
		t.Fatal("direct system role update succeeded")
	}
	if _, err := fixture.pool.Exec(ctx, `DELETE FROM role_permissions WHERE role_id=$1`, fixture.actorRoleID); err == nil {
		t.Fatal("direct system role permission delete succeeded")
	}
	if _, err := fixture.pool.Exec(ctx, `INSERT INTO role_permissions(role_id,permission_name)
		VALUES($1,'platform.admin')`, fixture.actorRoleID); err == nil {
		t.Fatal("direct tenant system role privilege escalation succeeded")
	}
}

func TestCriticalStepUpSelfGrantCrossTenantAndIdempotency(t *testing.T) {
	fixture := newRBACFixture(t)
	ctx := t.Context()

	criticalRequest := CreateRoleRequest{
		Name: "role-admin", Permissions: []string{"identity.roles.manage"},
		Mutation: mutation("critical-create"),
	}
	if _, err := fixture.service.CreateRole(ctx, fixture.actor, criticalRequest); !errors.Is(err, ErrStepUpRequired) {
		t.Fatalf("CreateRole(without step-up) error = %v", err)
	}
	criticalRequest.Mutation.StepUp = validStepUp(fixture.now)
	criticalRole, err := fixture.service.CreateRole(ctx, fixture.actor, criticalRequest)
	if err != nil {
		t.Fatal(err)
	}
	replayed, err := fixture.service.CreateRole(ctx, fixture.actor, criticalRequest)
	if err != nil || !replayed.Replayed || replayed.ID != criticalRole.ID {
		t.Fatalf("CreateRole(replay) = %#v, %v", replayed, err)
	}
	conflict := criticalRequest
	conflict.Name = "different-payload"
	if _, err := fixture.service.CreateRole(ctx, fixture.actor, conflict); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("CreateRole(same key different payload) error = %v", err)
	}

	if _, err := fixture.service.AssignRole(ctx, fixture.actor, AssignRoleRequest{
		RoleID: criticalRole.ID, ExpectedRoleRevision: criticalRole.CurrentRevision,
		SubjectUserID: fixture.actor.UserID, Mutation: mutationWithStepUp("self-grant", fixture.now),
	}); !errors.Is(err, ErrSelfAssignment) {
		t.Fatalf("AssignRole(self) error = %v", err)
	}
	if _, err := fixture.service.AssignRole(ctx, fixture.actor, AssignRoleRequest{
		RoleID: criticalRole.ID, ExpectedRoleRevision: criticalRole.CurrentRevision,
		SubjectUserID: fixture.otherSubjectID, Mutation: mutationWithStepUp("cross-tenant", fixture.now),
	}); !errors.Is(err, ErrTenantBoundary) {
		t.Fatalf("AssignRole(cross tenant) error = %v", err)
	}
	if _, err := fixture.service.AssignRole(ctx, fixture.actor, AssignRoleRequest{
		RoleID: criticalRole.ID, ExpectedRoleRevision: criticalRole.CurrentRevision,
		SubjectUserID: fixture.subjectID, Mutation: mutation("assign-no-step-up"),
	}); !errors.Is(err, ErrStepUpRequired) {
		t.Fatalf("AssignRole(critical without step-up) error = %v", err)
	}
}

func TestEffectivePermissionsFollowRevisionAndDeactivationImmediately(t *testing.T) {
	fixture := newRBACFixture(t)
	ctx := t.Context()
	role, err := fixture.service.CreateRole(ctx, fixture.actor, CreateRoleRequest{
		Name: "site-reader", Permissions: []string{"sites.read"}, Mutation: mutation("create-reader"),
	})
	if err != nil {
		t.Fatal(err)
	}
	grant, err := fixture.service.AssignRole(ctx, fixture.actor, AssignRoleRequest{
		RoleID: role.ID, ExpectedRoleRevision: role.CurrentRevision,
		SubjectUserID: fixture.subjectID, Mutation: mutation("assign-reader"),
	})
	if err != nil {
		t.Fatal(err)
	}
	assertPermissions(t, fixture.service, fixture.scopeID, fixture.subjectID,
		[]string{"identity.self.read", "sites.read"})
	assertSessionPermission(t, fixture, "sites.read", true)

	updated, err := fixture.service.PublishRevision(ctx, fixture.actor, PublishRevisionRequest{
		RoleID: role.ID, ExpectedRevision: 1, Permissions: []string{"sites.manage"},
		Mutation: mutation("publish-manager"),
	})
	if err != nil || updated.CurrentRevision != 2 {
		t.Fatalf("PublishRevision() = %#v, %v", updated, err)
	}
	assertPermissions(t, fixture.service, fixture.scopeID, fixture.subjectID,
		[]string{"identity.self.read", "sites.manage"})
	assertSessionPermission(t, fixture, "sites.read", false)
	assertSessionPermission(t, fixture, "sites.manage", true)

	if _, err := fixture.service.DeactivateRole(ctx, fixture.actor, DeactivateRoleRequest{
		RoleID: role.ID, ExpectedRevision: 2, Mutation: mutation("deactivate-role"),
	}); err != nil {
		t.Fatal(err)
	}
	assertPermissions(t, fixture.service, fixture.scopeID, fixture.subjectID,
		[]string{"identity.self.read"})
	assertSessionPermission(t, fixture, "sites.manage", false)
	if _, err := fixture.service.AssignRole(ctx, fixture.actor, AssignRoleRequest{
		RoleID: role.ID, ExpectedRoleRevision: 2, SubjectUserID: fixture.subjectID,
		Mutation: mutation("assign-inactive"),
	}); !errors.Is(err, ErrRoleInactive) {
		t.Fatalf("AssignRole(inactive) error = %v", err)
	}

	if _, err := fixture.service.RevokeGrant(ctx, fixture.actor, RevokeGrantRequest{
		GrantID: grant.ID, Mutation: mutation("revoke-after-deactivate"),
	}); err != nil {
		t.Fatal(err)
	}
}

func TestRenameAndPublishCASHaveSingleWinner(t *testing.T) {
	fixture := newRBACFixture(t)
	ctx := t.Context()
	role, err := fixture.service.CreateRole(ctx, fixture.actor, CreateRoleRequest{
		Name: "site-role", Permissions: []string{"sites.read"}, Mutation: mutation("create-cas-role"),
	})
	if err != nil {
		t.Fatal(err)
	}
	renamed, err := fixture.service.RenameRole(ctx, fixture.actor, RenameRoleRequest{
		RoleID: role.ID, ExpectedRevision: 1, Name: "site-observer", Mutation: mutation("rename-role"),
	})
	if err != nil || renamed.Name != "site-observer" || renamed.CurrentRevision != 2 {
		t.Fatalf("RenameRole() = %#v, %v", renamed, err)
	}

	requests := []PublishRevisionRequest{
		{RoleID: role.ID, ExpectedRevision: 2, Permissions: []string{"sites.read", "sites.manage"}, Mutation: mutation("cas-a")},
		{RoleID: role.ID, ExpectedRevision: 2, Permissions: []string{"sites.manage"}, Mutation: mutation("cas-b")},
	}
	errorsCh := make(chan error, len(requests))
	var wg sync.WaitGroup
	for _, request := range requests {
		request := request
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := fixture.service.PublishRevision(context.Background(), fixture.actor, request)
			errorsCh <- err
		}()
	}
	wg.Wait()
	close(errorsCh)
	var successes, conflicts int
	for err := range errorsCh {
		switch {
		case err == nil:
			successes++
		case errors.Is(err, ErrRevisionConflict):
			conflicts++
		default:
			t.Fatalf("unexpected concurrent publish error: %v", err)
		}
	}
	if successes != 1 || conflicts != 1 {
		t.Fatalf("concurrent publish successes=%d conflicts=%d", successes, conflicts)
	}
}

func TestRevocationAndPrincipalChangesAreObservedImmediately(t *testing.T) {
	fixture := newRBACFixture(t)
	ctx := t.Context()
	role, err := fixture.service.CreateRole(ctx, fixture.actor, CreateRoleRequest{
		Name: "live-permissions", Permissions: []string{"sites.manage"}, Mutation: mutation("live-create"),
	})
	if err != nil {
		t.Fatal(err)
	}
	grant, err := fixture.service.AssignRole(ctx, fixture.actor, AssignRoleRequest{
		RoleID: role.ID, ExpectedRoleRevision: 1, SubjectUserID: fixture.subjectID,
		Mutation: mutation("live-assign"),
	})
	if err != nil {
		t.Fatal(err)
	}
	assertPermissions(t, fixture.service, fixture.scopeID, fixture.subjectID,
		[]string{"identity.self.read", "sites.manage"})
	if _, err := fixture.service.RevokeGrant(ctx, fixture.actor, RevokeGrantRequest{
		GrantID: grant.ID, Mutation: mutation("live-revoke"),
	}); err != nil {
		t.Fatal(err)
	}
	assertPermissions(t, fixture.service, fixture.scopeID, fixture.subjectID, []string{"identity.self.read"})

	delegatorRoleID := uuid.New()
	if _, err := fixture.pool.Exec(ctx, `INSERT INTO roles(id,scope_id,name,description,system_role)
		VALUES($1,$2,'tenant_delegator','RBAC test delegator',true)`, delegatorRoleID, fixture.scopeID); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.pool.Exec(ctx, `INSERT INTO role_permissions(role_id,permission_name)
		SELECT $1,unnest($2::text[])`, delegatorRoleID, []string{ManagePermission, "sites.read"}); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.pool.Exec(ctx, `DELETE FROM role_assignments
		WHERE scope_id=$1 AND user_id=$2 AND role_id=$3`, fixture.scopeID, fixture.actor.UserID, fixture.actorRoleID); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.pool.Exec(ctx, `INSERT INTO role_assignments(scope_id,user_id,role_id)
		VALUES($1,$2,$3)`, fixture.scopeID, fixture.actor.UserID, delegatorRoleID); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.service.PublishRevision(ctx, fixture.actor, PublishRevisionRequest{
		RoleID: role.ID, ExpectedRevision: 1, Permissions: []string{"sites.manage"},
		Mutation: mutation("live-escalation-denied"),
	}); !errors.Is(err, ErrPermissionEscalation) {
		t.Fatalf("PublishRevision(after actor permission removal) error = %v", err)
	}

	if _, err := fixture.pool.Exec(ctx, `UPDATE memberships SET status='suspended'
		WHERE scope_id=$1 AND user_id=$2`, fixture.scopeID, fixture.subjectID); err != nil {
		t.Fatal(err)
	}
	assertPermissions(t, fixture.service, fixture.scopeID, fixture.subjectID, nil)
	assertPermissions(t, fixture.service, fixture.operatorScopeID, fixture.operatorUserID, nil)
}

func TestAuthorizeTenantSessionTxSharesCustomPermissionRevocationLock(t *testing.T) {
	fixture := newRBACFixture(t)
	role, err := fixture.service.CreateRole(t.Context(), fixture.actor, CreateRoleRequest{
		Name: "transaction-authorizer", Permissions: []string{"sites.manage"},
		Mutation: mutation("transaction-authorizer-create"),
	})
	if err != nil {
		t.Fatal(err)
	}
	grant, err := fixture.service.AssignRole(t.Context(), fixture.actor, AssignRoleRequest{
		RoleID: role.ID, ExpectedRoleRevision: role.CurrentRevision, SubjectUserID: fixture.subjectID,
		Mutation: mutation("transaction-authorizer-assign"),
	})
	if err != nil {
		t.Fatal(err)
	}

	authorizationTx, err := fixture.pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	session := AuthenticatedSessionReference{
		UserID: fixture.subjectID, ScopeID: fixture.scopeID, SessionID: fixture.subjectSessionID,
	}
	tenantID, err := fixture.service.AuthorizeTenantSessionTx(
		t.Context(), authorizationTx, session, "sites.manage")
	if err != nil || tenantID != fixture.tenantID {
		_ = authorizationTx.Rollback(t.Context())
		t.Fatalf("AuthorizeTenantSessionTx() = (%s,%v), want tenant %s", tenantID, err, fixture.tenantID)
	}

	revocationResult := make(chan error, 1)
	started := make(chan struct{})
	go func() {
		close(started)
		_, err := fixture.service.RevokeGrant(context.Background(), fixture.actor, RevokeGrantRequest{
			GrantID: grant.ID, Mutation: mutation("transaction-authorizer-revoke"),
		})
		revocationResult <- err
	}()
	<-started
	select {
	case err := <-revocationResult:
		_ = authorizationTx.Rollback(t.Context())
		t.Fatalf("permission revocation bypassed authorization transaction lock: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	if err := authorizationTx.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-revocationResult:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("permission revocation remained blocked after authorization commit")
	}

	afterRevocation, err := fixture.pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = afterRevocation.Rollback(context.Background()) }()
	if _, err := fixture.service.AuthorizeTenantSessionTx(
		t.Context(), afterRevocation, session, "sites.manage"); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("authorization after committed revocation error = %v", err)
	}
	if _, err := fixture.service.AuthorizeTenantSessionTx(
		t.Context(), afterRevocation, session, "Sites.Manage"); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("invalid permission name error = %v", err)
	}
}

func TestAuthorizeTenantSessionTxRejectsCommitFirstIdentityRevocation(t *testing.T) {
	for _, test := range []struct {
		name      string
		statement string
		arguments func(*rbacFixture, uuid.UUID) []any
	}{
		{
			name:      "role_assignment",
			statement: `DELETE FROM role_assignments WHERE scope_id=$1 AND user_id=$2 AND role_id=$3`,
			arguments: func(fixture *rbacFixture, roleID uuid.UUID) []any {
				return []any{fixture.scopeID, fixture.subjectID, roleID}
			},
		},
		{
			name:      "role_permission",
			statement: `DELETE FROM role_permissions WHERE role_id=$1 AND permission_name='sites.manage'`,
			arguments: func(_ *rbacFixture, roleID uuid.UUID) []any {
				return []any{roleID}
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newRBACFixtureAt42(t)
			applyRBACMigration(t, fixture.pool, "069_iam_global_lock_protocol.up.sql", 69, true)
			applyRBACMigration(t, fixture.pool, "070_iam_global_lock_stage2_authority.up.sql", 70, true)
			applyRBACMigration(t, fixture.pool, "042_custom_rbac.down.sql", 42, false)
			roleID := uuid.New()
			if _, err := fixture.pool.Exec(t.Context(), `INSERT INTO roles(id,scope_id,name,description,system_role)
				VALUES($1,$2,$3,'commit-first revocation role',false)`,
				roleID, fixture.scopeID, "commit_first_"+test.name); err != nil {
				t.Fatal(err)
			}
			if _, err := fixture.pool.Exec(t.Context(), `INSERT INTO role_permissions(role_id,permission_name)
				VALUES($1,'sites.manage')`, roleID); err != nil {
				t.Fatal(err)
			}
			if _, err := fixture.pool.Exec(t.Context(), `INSERT INTO role_assignments(scope_id,user_id,role_id)
				VALUES($1,$2,$3)`, fixture.scopeID, fixture.subjectID, roleID); err != nil {
				t.Fatal(err)
			}
			applyRBACMigration(t, fixture.pool, "042_custom_rbac.up.sql", 42, true)

			revocationTx, err := fixture.pool.Begin(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = revocationTx.Rollback(context.Background()) }()
			command, err := revocationTx.Exec(t.Context(), test.statement, test.arguments(fixture, roleID)...)
			if err != nil {
				t.Fatal(err)
			}
			if command.RowsAffected() != 1 {
				t.Fatalf("revocation affected %d rows, want 1", command.RowsAffected())
			}

			authorizationTx, err := fixture.pool.Begin(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = authorizationTx.Rollback(context.Background()) }()
			result := make(chan error, 1)
			started := make(chan struct{})
			go func() {
				close(started)
				_, err := fixture.service.AuthorizeTenantSessionTx(context.Background(), authorizationTx,
					AuthenticatedSessionReference{UserID: fixture.subjectID, ScopeID: fixture.scopeID,
						SessionID: fixture.subjectSessionID}, "sites.manage")
				result <- err
			}()
			<-started
			select {
			case err := <-result:
				t.Fatalf("authorization escaped uncommitted %s revocation: %v", test.name, err)
			case <-time.After(100 * time.Millisecond):
			}
			if err := revocationTx.Commit(t.Context()); err != nil {
				t.Fatal(err)
			}
			select {
			case err := <-result:
				if !errors.Is(err, ErrPermissionDenied) {
					t.Fatalf("authorization after committed %s revocation error=%v", test.name, err)
				}
			case <-time.After(5 * time.Second):
				t.Fatalf("authorization remained blocked after committed %s revocation", test.name)
			}
		})
	}
}

func TestAuditFailureRollsBackMutationAndWriteFact(t *testing.T) {
	fixture := newRBACFixture(t)
	if _, err := fixture.pool.Exec(t.Context(), `CREATE TABLE custom_rbac_test_step_up_uses(
		request_id text PRIMARY KEY)`); err != nil {
		t.Fatal(err)
	}
	service, err := NewServiceWithDependencies(fixture.pool, failingAudit{}, recordingStepUp{}, func() time.Time {
		return fixture.now
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = service.CreateRole(t.Context(), fixture.actor, CreateRoleRequest{
		Name: "rolled-back", Permissions: []string{ManagePermission},
		Mutation: mutationWithStepUp("audit-failure", fixture.now),
	})
	if !errors.Is(err, errInjectedAudit) {
		t.Fatalf("CreateRole(audit failure) error = %v", err)
	}
	var roles, revisions, writes, proofUses int
	if err := fixture.pool.QueryRow(t.Context(), `SELECT
		(SELECT count(*) FROM custom_roles WHERE current_name='rolled-back'),
		(SELECT count(*) FROM custom_role_revisions WHERE name='rolled-back'),
		(SELECT count(*) FROM custom_rbac_write_requests WHERE idempotency_key='audit-failure'),
		(SELECT count(*) FROM custom_rbac_test_step_up_uses WHERE request_id='request-audit-failure')`).
		Scan(&roles, &revisions, &writes, &proofUses); err != nil {
		t.Fatal(err)
	}
	if roles != 0 || revisions != 0 || writes != 0 || proofUses != 0 {
		t.Fatalf("rolled-back rows roles=%d revisions=%d writes=%d proof_uses=%d",
			roles, revisions, writes, proofUses)
	}
}

func TestAppendOnlyFactsAndDirectSQLGuards(t *testing.T) {
	fixture := newRBACFixture(t)
	ctx := t.Context()
	role, err := fixture.service.CreateRole(ctx, fixture.actor, CreateRoleRequest{
		Name: "guarded", Permissions: []string{"sites.read"}, Mutation: mutation("guard-create"),
	})
	if err != nil {
		t.Fatal(err)
	}
	grant, err := fixture.service.AssignRole(ctx, fixture.actor, AssignRoleRequest{
		RoleID: role.ID, ExpectedRoleRevision: 1, SubjectUserID: fixture.subjectID,
		Mutation: mutation("guard-grant"),
	})
	if err != nil {
		t.Fatal(err)
	}
	revocation, err := fixture.service.RevokeGrant(ctx, fixture.actor, RevokeGrantRequest{
		GrantID: grant.ID, Mutation: mutation("guard-revoke"),
	})
	if err != nil {
		t.Fatal(err)
	}
	criticalRole, err := fixture.service.CreateRole(ctx, fixture.actor, CreateRoleRequest{
		Name: "guarded-critical", Permissions: []string{"identity.roles.manage"},
		Mutation: mutationWithStepUp("guard-critical-create", fixture.now),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.pool.Exec(ctx, `INSERT INTO custom_role_revisions(
		role_id,tenant_id,tenant_scope_id,revision,name,permissions,action,
		created_by_user_id,created_by_scope_id,created_at
	) VALUES($1,$2,$3,2,$4,$5,'identity.custom_role.publish',$6,$3,$7)`,
		criticalRole.ID, fixture.tenantID, fixture.scopeID, criticalRole.Name,
		[]string{"sites.read"}, fixture.actor.UserID, fixture.now); err == nil {
		t.Fatal("direct critical permission removal without step-up succeeded")
	}

	statements := []string{
		fmt.Sprintf("UPDATE custom_role_revisions SET name='tampered' WHERE role_id='%s' AND revision=1", role.ID),
		fmt.Sprintf("DELETE FROM custom_role_revisions WHERE role_id='%s' AND revision=1", role.ID),
		"TRUNCATE custom_role_revisions",
		fmt.Sprintf("UPDATE custom_role_grants SET role_revision=99 WHERE id='%s'", grant.ID),
		fmt.Sprintf("DELETE FROM custom_role_grants WHERE id='%s'", grant.ID),
		"TRUNCATE custom_role_grants",
		fmt.Sprintf("UPDATE custom_role_grant_revocations SET revoked_at=now() WHERE id='%s'", revocation.ID),
		fmt.Sprintf("DELETE FROM custom_role_grant_revocations WHERE id='%s'", revocation.ID),
		"TRUNCATE custom_role_grant_revocations",
		"UPDATE custom_rbac_write_requests SET request_id='tampered' WHERE idempotency_key='guard-create'",
		"DELETE FROM custom_rbac_write_requests WHERE idempotency_key='guard-create'",
		"TRUNCATE custom_rbac_write_requests",
		"UPDATE audit_events SET action='tampered' WHERE action='identity.custom_role.create'",
		"DELETE FROM audit_events WHERE action='identity.custom_role.create'",
		"TRUNCATE audit_events",
	}
	for _, statement := range statements {
		if _, err := fixture.pool.Exec(ctx, statement); err == nil {
			t.Errorf("direct SQL unexpectedly succeeded: %s", statement)
		}
	}

	permissions := []string{"billing.adjustments.manage"}
	_, err = fixture.pool.Exec(ctx, `INSERT INTO custom_role_revisions(
		role_id,tenant_id,tenant_scope_id,revision,name,permissions,action,created_by_user_id,
		created_by_scope_id,step_up_proof_id,step_up_method,step_up_verified_at,created_at
	) VALUES($1,$2,$3,2,'guarded',$4,'identity.custom_role.publish',$5,$3,$7,'webauthn',$6,$6)`,
		role.ID, fixture.tenantID, fixture.scopeID, permissions, fixture.actor.UserID, fixture.now, uuid.New())
	if err == nil {
		t.Fatal("direct SQL permission escalation revision succeeded")
	}

	_, err = fixture.pool.Exec(ctx, `INSERT INTO custom_role_grants(
		id,tenant_id,tenant_scope_id,role_id,role_revision,subject_user_id,
		granted_by_user_id,granted_by_scope_id,granted_at
	) VALUES($1,$2,$3,$4,1,$5,$6,$3,$7)`, uuid.New(), fixture.tenantID,
		fixture.scopeID, role.ID, fixture.otherSubjectID, fixture.actor.UserID, fixture.now)
	if err == nil {
		t.Fatal("direct SQL cross-tenant grant succeeded")
	}
}

func assertPermissions(t *testing.T, service *Service, scopeID, userID uuid.UUID, want []string) {
	t.Helper()
	got, err := service.EffectivePermissions(t.Context(), scopeID, userID)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(got, want) {
		t.Fatalf("EffectivePermissions() = %v, want %v", got, want)
	}
}

func assertSessionPermission(t *testing.T, fixture *rbacFixture, permission string, want bool) {
	t.Helper()
	principal, err := identity.NewStore(fixture.pool).PrincipalForSession(
		t.Context(), fixture.subjectID, fixture.scopeID, fixture.subjectSessionID,
	)
	if err != nil {
		t.Fatal(err)
	}
	if got := slices.Contains(principal.Permissions, permission); got != want {
		t.Fatalf("session permission %q present = %t, want %t; permissions=%v", permission, got, want, principal.Permissions)
	}
}

func mutation(key string) MutationContext {
	return MutationContext{IdempotencyKey: key, RequestID: "request-" + key, TraceID: "trace-" + key}
}

func mutationWithStepUp(key string, now time.Time) MutationContext {
	result := mutation(key)
	result.StepUp = validStepUp(now)
	return result
}

func validStepUp(now time.Time) StepUpProof {
	_ = now
	return StepUpProof{Token: "verified-token"}
}

// newRBACFixture seeds a schema at the release migration head: the service
// writes today's audit_events columns (361), which a replay stopped at 042/070
// does not have.
func newRBACFixture(t *testing.T) *rbacFixture {
	t.Helper()
	return seedRBACFixture(t, databasetest.MigratedPool(t, nil))
}

// newRBACFixtureAt42 stops at 042 for tests that exercise 042's own down/up
// and then 069/070 by hand; they must not call service mutations that audit.
func newRBACFixtureAt42(t *testing.T) *rbacFixture {
	t.Helper()
	return seedRBACFixture(t, isolatedRBACPool(t, true))
}

func seedRBACFixture(t *testing.T, pool *pgxpool.Pool) *rbacFixture {
	t.Helper()
	now := time.Date(2026, 7, 22, 8, 0, 0, 0, time.UTC)
	fixture := &rbacFixture{
		pool: pool, now: now,
		tenantID: uuid.New(), scopeID: uuid.New(), subjectID: uuid.New(), subjectSessionID: uuid.New(),
		otherTenantID: uuid.New(), otherScopeID: uuid.New(), otherSubjectID: uuid.New(),
		operatorScopeID: uuid.New(), operatorUserID: uuid.New(),
		actorRoleID: uuid.New(), operatorRoleID: uuid.New(),
	}
	fixture.actor = Actor{
		UserID: uuid.New(), ScopeID: fixture.scopeID, SessionID: uuid.New(), ScopeKind: "tenant",
		IdentityDomain: CustomerControlIdentityDomain,
	}
	ctx := t.Context()
	for _, row := range []struct {
		tenantID, scopeID uuid.UUID
		name              string
	}{
		{fixture.tenantID, fixture.scopeID, "Tenant A"},
		{fixture.otherTenantID, fixture.otherScopeID, "Tenant B"},
	} {
		if _, err := pool.Exec(ctx, `INSERT INTO tenants(id,display_name) VALUES($1,$2)`, row.tenantID, row.name); err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(ctx, `INSERT INTO access_scopes(id,kind,tenant_id) VALUES($1,'tenant',$2)`, row.scopeID, row.tenantID); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := pool.Exec(ctx, `INSERT INTO access_scopes(id,kind) VALUES($1,'platform')`, fixture.operatorScopeID); err != nil {
		t.Fatal(err)
	}
	users := []struct {
		id, scopeID uuid.UUID
		username    string
	}{
		{fixture.actor.UserID, fixture.scopeID, "rbac-actor"},
		{fixture.subjectID, fixture.scopeID, "rbac-subject"},
		{fixture.otherSubjectID, fixture.otherScopeID, "rbac-other-subject"},
		{fixture.operatorUserID, fixture.operatorScopeID, "rbac-operator"},
	}
	for _, user := range users {
		if _, err := pool.Exec(ctx, `INSERT INTO users(id,username,display_name,password_hash)
			VALUES($1,$2,$2,'hash')`, user.id, user.username); err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(ctx, `INSERT INTO memberships(scope_id,user_id) VALUES($1,$2)`, user.scopeID, user.id); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := pool.Exec(ctx, `INSERT INTO auth_sessions(
		id,family_id,user_id,scope_id,refresh_token_hash,created_at,expires_at
	) VALUES($1,$2,$3,$4,$5,$6,$7)`, fixture.actor.SessionID, uuid.New(), fixture.actor.UserID,
		fixture.scopeID, bytesOf(32, 0x42), now.Add(-time.Hour), now.Add(10*365*24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO auth_sessions(
		id,family_id,user_id,scope_id,refresh_token_hash,created_at,expires_at
	) VALUES($1,$2,$3,$4,$5,$6,$7)`, fixture.subjectSessionID, uuid.New(), fixture.subjectID,
		fixture.scopeID, bytesOf(32, 0x43), now.Add(-time.Hour), now.Add(10*365*24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO roles(id,scope_id,name,description,system_role)
		VALUES($1,$2,'tenant_owner','RBAC test tenant owner',true)`, fixture.actorRoleID, fixture.scopeID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO role_permissions(role_id,permission_name)
		SELECT $1,unnest($2::text[]) ON CONFLICT DO NOTHING`, fixture.actorRoleID,
		[]string{"identity.roles.manage", "sites.read", "sites.manage"}); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO role_assignments(scope_id,user_id,role_id) VALUES($1,$2,$3)`,
		fixture.scopeID, fixture.actor.UserID, fixture.actorRoleID); err != nil {
		t.Fatal(err)
	}
	viewerRoleID := uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO roles(id,scope_id,name,description,system_role)
		VALUES($1,$2,'rbac_test_viewer','RBAC test viewer',true)`, viewerRoleID, fixture.scopeID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO role_permissions(role_id,permission_name) VALUES($1,'identity.self.read')
		ON CONFLICT DO NOTHING`, viewerRoleID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO role_assignments(scope_id,user_id,role_id) VALUES($1,$2,$3)`,
		fixture.scopeID, fixture.subjectID, viewerRoleID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO roles(id,scope_id,name,description,system_role)
		VALUES($1,$2,'platform_owner','RBAC test platform owner',true)`, fixture.operatorRoleID, fixture.operatorScopeID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO role_permissions(role_id,permission_name)
		SELECT $1,name FROM permissions WHERE name <> 'jobs.manage' -- 094: tenant roles only
		ON CONFLICT DO NOTHING`, fixture.operatorRoleID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO role_assignments(scope_id,user_id,role_id) VALUES($1,$2,$3)`,
		fixture.operatorScopeID, fixture.operatorUserID, fixture.operatorRoleID); err != nil {
		t.Fatal(err)
	}
	service, err := NewServiceWithDependencies(pool, audit.New(pool), acceptingStepUp{}, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	fixture.service = service
	return fixture
}

func bytesOf(length int, value byte) []byte {
	result := make([]byte, length)
	for index := range result {
		result[index] = value
	}
	return result
}

func isolatedRBACPool(t *testing.T, migrate bool) *pgxpool.Pool {
	t.Helper()
	databaseURL := os.Getenv("TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("TEST_DATABASE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	admin, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	schema := "custom_rbac_test_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if !regexp.MustCompile(`^custom_rbac_test_[a-f0-9]{32}$`).MatchString(schema) {
		admin.Close()
		t.Fatalf("unsafe schema name %q", schema)
	}
	identifier := pgx.Identifier{schema}.Sanitize()
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+identifier); err != nil {
		admin.Close()
		t.Fatal(err)
	}
	config, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		admin.Close()
		t.Fatal(err)
	}
	config.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		_, _ = admin.Exec(ctx, "DROP SCHEMA "+identifier+" CASCADE")
		admin.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		pool.Close()
		cleanupCtx, cleanupCancel := databasetest.CleanupContext()
		defer cleanupCancel()
		if _, err := admin.Exec(cleanupCtx, "DROP SCHEMA "+identifier+" CASCADE"); err != nil {
			t.Errorf("drop schema: %v", err)
		}
		admin.Close()
	})
	if migrate {
		migrateRBACTo42(t, pool)
	}
	return pool
}

func assertMigrationVersion(t *testing.T, pool *pgxpool.Pool, version int64, want bool) {
	t.Helper()
	var got bool
	if err := pool.QueryRow(t.Context(), `SELECT EXISTS(
		SELECT 1 FROM schema_migrations WHERE version=$1)`, version).Scan(&got); err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("migration %d applied = %t, want %t", version, got, want)
	}
}

func migrateRBACTo42(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	if _, err := pool.Exec(t.Context(), `CREATE TABLE schema_migrations (
		version bigint PRIMARY KEY,
		applied_at timestamptz NOT NULL DEFAULT now()
	)`); err != nil {
		t.Fatal(err)
	}
	entries, err := fs.ReadDir(migrations.FS, ".")
	if err != nil {
		t.Fatal(err)
	}
	upByVersion := make(map[int]string, 42)
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".up.sql") {
			continue
		}
		prefix, _, found := strings.Cut(entry.Name(), "_")
		if !found {
			continue
		}
		version, err := strconv.Atoi(prefix)
		if err != nil || version < 1 || version > 42 {
			continue
		}
		upByVersion[version] = entry.Name()
	}
	for version := 1; version <= 42; version++ {
		name, ok := upByVersion[version]
		if !ok {
			t.Fatalf("migration %03d is missing from the 001..042 chain", version)
		}
		applyRBACMigration(t, pool, name, version, true)
	}
}

func applyRBACMigration(t *testing.T, pool *pgxpool.Pool, name string, version int, up bool) {
	t.Helper()
	script, err := fs.ReadFile(migrations.FS, name)
	if err != nil {
		t.Fatal(err)
	}
	err = pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(t.Context(), string(script)); err != nil {
			return err
		}
		if up {
			_, err = tx.Exec(t.Context(), `INSERT INTO schema_migrations(version) VALUES($1)`, version)
		} else {
			_, err = tx.Exec(t.Context(), `DELETE FROM schema_migrations WHERE version=$1`, version)
		}
		return err
	})
	if err != nil {
		t.Fatalf("apply %s: %v", name, err)
	}
}

func assertTable(t *testing.T, pool *pgxpool.Pool, table string, want bool) {
	t.Helper()
	var got bool
	if err := pool.QueryRow(t.Context(), `SELECT to_regclass($1) IS NOT NULL`, table).Scan(&got); err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("table %s exists = %t, want %t", table, got, want)
	}
}
