//go:build integration

package identity_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/iamlock"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestSuspendMembershipAllowsPlatformAndSameScopeTenantManagers(t *testing.T) {
	for _, actorKind := range []string{"platform", "tenant"} {
		t.Run(actorKind, func(t *testing.T) {
			fixture := seedMembershipFixture(t)
			actor := fixture.platformActor
			if actorKind == "tenant" {
				actor = fixture.tenantActor
			}
			input := fixture.input("suspend-"+actorKind, "request-"+actorKind)
			result, err := fixture.service.SuspendMembership(t.Context(), actor, input)
			if err != nil {
				t.Fatal(err)
			}
			if result.ScopeID != fixture.targetScope || result.UserID != fixture.targetUser ||
				result.PreviousStatus != identity.MembershipStatusActive ||
				result.Status != identity.MembershipStatusSuspended || result.Replayed ||
				result.ReasonCode != input.ReasonCode || result.SessionsRevoked != 1 || result.SuspendedAt.IsZero() {
				t.Fatalf("SuspendMembership() = %#v", result)
			}
			fixture.assertMutation(t, actor, input, 1, 1)
		})
	}
}

func TestSuspendMembershipAllowsPlatformManagerWithIdentityUsersManageOnly(t *testing.T) {
	fixture := seedMembershipFixture(t)
	// 系统角色权限不可改（迁移 042/094）：把平台管理员换成只有 identity.users.manage 的另一个系统角色。
	usersManageRole := uuid.New()
	if _, err := fixture.pool.Exec(t.Context(), `INSERT INTO roles(id,scope_id,name,description,system_role)
		VALUES($1,$2,'membership_users_manager','Membership users manager',true)`,
		usersManageRole, fixture.platformActor.ScopeID); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.pool.Exec(t.Context(), `INSERT INTO role_permissions(role_id,permission_name)
		VALUES($1,'identity.users.manage')`, usersManageRole); err != nil {
		t.Fatal(err)
	}
	command, err := fixture.pool.Exec(t.Context(), `UPDATE role_assignments SET role_id=$3
		WHERE role_id=$1 AND user_id=$2`, fixture.platformRoleID, fixture.platformActor.UserID, usersManageRole)
	if err != nil {
		t.Fatal(err)
	}
	if command.RowsAffected() != 1 {
		t.Fatalf("replaced platform.admin assignment = %d, want 1", command.RowsAffected())
	}

	input := fixture.input("suspend-platform-users-manage", "request-platform-users-manage")
	result, err := fixture.service.SuspendMembership(t.Context(), fixture.platformActor, input)
	if err != nil {
		t.Fatal(err)
	}
	if result.ScopeID != fixture.targetScope || result.UserID != fixture.targetUser ||
		result.PreviousStatus != identity.MembershipStatusActive ||
		result.Status != identity.MembershipStatusSuspended || result.Replayed ||
		result.ReasonCode != input.ReasonCode || result.SessionsRevoked != 1 || result.SuspendedAt.IsZero() {
		t.Fatalf("SuspendMembership() = %#v", result)
	}
	fixture.assertMutation(t, fixture.platformActor, input, 1, 1)
}

func TestSuspendMembershipRejectsUnauthorizedAndCrossTenantActorsWithoutSideEffects(t *testing.T) {
	for _, test := range []struct {
		name    string
		prepare func(*membershipFixture) identity.Actor
		want    error
	}{
		{
			name: "cross-tenant manager",
			prepare: func(fixture *membershipFixture) identity.Actor {
				return fixture.otherTenantActor
			},
			want: identity.ErrPermissionDenied,
		},
		{
			name: "cross-tenant actor forged as platform",
			prepare: func(fixture *membershipFixture) identity.Actor {
				actor := fixture.otherTenantActor
				actor.ScopeKind = "platform"
				return actor
			},
			want: identity.ErrPermissionDenied,
		},
		{
			name: "platform actor missing both permissions",
			prepare: func(fixture *membershipFixture) identity.Actor {
				if _, err := fixture.pool.Exec(t.Context(), `DELETE FROM role_assignments WHERE role_id=$1`,
					fixture.platformRoleID); err != nil {
					t.Fatal(err)
				}
				return fixture.platformActor
			},
			want: identity.ErrPermissionDenied,
		},
		{
			name: "inactive actor membership",
			prepare: func(fixture *membershipFixture) identity.Actor {
				if _, err := fixture.pool.Exec(t.Context(), `UPDATE memberships SET status='suspended'
					WHERE scope_id=$1 AND user_id=$2`, fixture.platformActor.ScopeID, fixture.platformActor.UserID); err != nil {
					t.Fatal(err)
				}
				return fixture.platformActor
			},
			want: identity.ErrPermissionDenied,
		},
		{
			name: "disabled actor user",
			prepare: func(fixture *membershipFixture) identity.Actor {
				if _, err := fixture.pool.Exec(t.Context(), `UPDATE users SET status='disabled'
					WHERE id=$1`, fixture.platformActor.UserID); err != nil {
					t.Fatal(err)
				}
				return fixture.platformActor
			},
			want: identity.ErrPermissionDenied,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := seedMembershipFixture(t)
			actor := test.prepare(&fixture)
			input := fixture.input("reject-"+strings.ReplaceAll(test.name, " ", "-"), "reject-"+test.name)
			if _, err := fixture.service.SuspendMembership(t.Context(), actor, input); !errors.Is(err, test.want) {
				t.Fatalf("SuspendMembership() error = %v, want %v", err, test.want)
			}
			fixture.assertNoMutation(t, input)
		})
	}
}

func TestSuspendMembershipReturnsNotFoundWithoutSideEffects(t *testing.T) {
	fixture := seedMembershipFixture(t)
	input := fixture.input("membership-not-found", "membership-not-found")
	// auth_sessions 以 (scope_id,user_id) 外键引用成员关系：先删目标在该作用域的会话再删成员关系。
	if _, err := fixture.pool.Exec(t.Context(), `DELETE FROM auth_sessions
		WHERE scope_id=$1 AND user_id=$2`, fixture.targetScope, fixture.targetUser); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.pool.Exec(t.Context(), `DELETE FROM memberships
		WHERE scope_id=$1 AND user_id=$2`, fixture.targetScope, fixture.targetUser); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.service.SuspendMembership(t.Context(), fixture.platformActor, input); !errors.Is(err, identity.ErrMembershipNotFound) {
		t.Fatalf("SuspendMembership() error = %v, want ErrMembershipNotFound", err)
	}
	var memberships, revoked, audits, writes int
	if err := fixture.pool.QueryRow(t.Context(), `SELECT
		(SELECT count(*) FROM memberships WHERE scope_id=$1 AND user_id=$2),
		(SELECT count(*) FROM auth_sessions WHERE id=$3 AND revoked_at IS NOT NULL),
		(SELECT count(*) FROM audit_events WHERE request_id=$4),
		(SELECT count(*) FROM identity_write_requests WHERE idempotency_key=$5)`,
		fixture.targetScope, fixture.targetUser, fixture.targetSession,
		input.RequestID, input.IdempotencyKey,
	).Scan(&memberships, &revoked, &audits, &writes); err != nil {
		t.Fatal(err)
	}
	if memberships != 0 || revoked != 0 || audits != 0 || writes != 0 {
		t.Fatalf("not-found mutation state = memberships:%d revoked:%d audits:%d writes:%d",
			memberships, revoked, audits, writes)
	}
}

func TestSuspendMembershipReplayConflictAndExpectedStatus(t *testing.T) {
	fixture := seedMembershipFixture(t)
	input := fixture.input("membership-replay", "membership-replay-1")
	first, err := fixture.service.SuspendMembership(t.Context(), fixture.platformActor, input)
	if err != nil {
		t.Fatal(err)
	}
	replay := input
	replay.RequestID = "membership-replay-2"
	replay.TraceID = "membership-replay-trace-2"
	second, err := fixture.service.SuspendMembership(t.Context(), fixture.platformActor, replay)
	if err != nil {
		t.Fatal(err)
	}
	if !second.Replayed || second.ScopeID != first.ScopeID || second.UserID != first.UserID ||
		!second.SuspendedAt.Equal(first.SuspendedAt) || second.SessionsRevoked != first.SessionsRevoked {
		t.Fatalf("replay = %#v, first = %#v", second, first)
	}

	changed := replay
	changed.ReasonCode = "policy_violation"
	if _, err := fixture.service.SuspendMembership(t.Context(), fixture.platformActor, changed); !errors.Is(err, identity.ErrIdempotencyConflict) {
		t.Fatalf("changed replay error = %v, want ErrIdempotencyConflict", err)
	}

	differentKey := fixture.input("membership-status-conflict", "membership-status-conflict")
	if _, err := fixture.service.SuspendMembership(t.Context(), fixture.platformActor, differentKey); !errors.Is(err, identity.ErrMembershipStatusConflict) {
		t.Fatalf("second mutation error = %v, want ErrMembershipStatusConflict", err)
	}
	fixture.assertMutation(t, fixture.platformActor, input, 1, 1)
	var rejectedWrites, rejectedAudits int
	if err := fixture.pool.QueryRow(t.Context(), `SELECT
		(SELECT count(*) FROM identity_write_requests WHERE idempotency_key=$1),
		(SELECT count(*) FROM audit_events WHERE request_id=$2)`,
		differentKey.IdempotencyKey, differentKey.RequestID).Scan(&rejectedWrites, &rejectedAudits); err != nil {
		t.Fatal(err)
	}
	if rejectedWrites != 0 || rejectedAudits != 0 {
		t.Fatalf("expected-status failure side effects = writes:%d audits:%d", rejectedWrites, rejectedAudits)
	}
}

func TestSuspendMembershipReplayRevalidatesCurrentPermission(t *testing.T) {
	fixture := seedMembershipFixture(t)
	input := fixture.input("membership-replay-revoked", "membership-replay-revoked")
	if _, err := fixture.service.SuspendMembership(t.Context(), fixture.platformActor, input); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.pool.Exec(t.Context(), `DELETE FROM role_assignments WHERE role_id=$1`,
		fixture.platformRoleID); err != nil {
		t.Fatal(err)
	}
	replay := input
	replay.RequestID = "membership-replay-after-revoke"
	replay.TraceID = "membership-replay-after-revoke"
	if _, err := fixture.service.SuspendMembership(t.Context(), fixture.platformActor, replay); !errors.Is(err, identity.ErrPermissionDenied) {
		t.Fatalf("replay after permission revocation error = %v, want ErrPermissionDenied", err)
	}
	fixture.assertMutation(t, fixture.platformActor, input, 1, 1)
	var replayAudits int
	if err := fixture.pool.QueryRow(t.Context(), `SELECT count(*) FROM audit_events WHERE request_id=$1`,
		replay.RequestID).Scan(&replayAudits); err != nil {
		t.Fatal(err)
	}
	if replayAudits != 0 {
		t.Fatalf("permission-denied replay wrote %d audit events", replayAudits)
	}
}

func TestSuspendMembershipDatabaseFailureRollsBackEverySideEffect(t *testing.T) {
	fixture := seedMembershipFixture(t)
	if _, err := fixture.pool.Exec(t.Context(), `
		CREATE FUNCTION reject_membership_audit_073()
		RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN
			IF NEW.action = 'identity.membership.suspend' THEN
				RAISE EXCEPTION USING ERRCODE='40001', MESSAGE='injected serialization failure';
			END IF;
			RETURN NEW;
		END;
		$$;
		CREATE TRIGGER reject_membership_audit_073
		BEFORE INSERT ON audit_events
		FOR EACH ROW EXECUTE FUNCTION reject_membership_audit_073()`); err != nil {
		t.Fatal(err)
	}
	input := fixture.input("membership-rollback", "membership-rollback")
	if _, err := fixture.service.SuspendMembership(t.Context(), fixture.platformActor, input); !errors.Is(err, identity.ErrMembershipUnavailable) {
		t.Fatalf("SuspendMembership() error = %v, want ErrMembershipUnavailable", err)
	} else if strings.Contains(err.Error(), "40001") || strings.Contains(err.Error(), "serialization") {
		t.Fatalf("database detail leaked: %v", err)
	}
	fixture.assertNoMutation(t, input)
}

func TestSuspendMembershipConcurrentRequestsSerializeWithoutDuplicateFacts(t *testing.T) {
	for _, sameKey := range []bool{true, false} {
		name := "different keys"
		if sameKey {
			name = "same key replay"
		}
		t.Run(name, func(t *testing.T) {
			fixture := seedMembershipFixture(t)
			inputs := []identity.SuspendMembershipInput{
				fixture.input("membership-concurrent-a", "membership-concurrent-a"),
				fixture.input("membership-concurrent-b", "membership-concurrent-b"),
			}
			if sameKey {
				inputs[1].IdempotencyKey = inputs[0].IdempotencyKey
				inputs[1].ReasonCode = inputs[0].ReasonCode
			}
			type outcome struct {
				result identity.MembershipMutationResult
				err    error
			}
			workerContext, cancelWorkers := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancelWorkers()
			outcomes := make(chan outcome, 2)
			for _, input := range inputs {
				input := input
				go func() {
					result, err := fixture.service.SuspendMembership(workerContext, fixture.platformActor, input)
					outcomes <- outcome{result: result, err: err}
				}()
			}
			var successes, replays, statusConflicts int
			for range inputs {
				var outcome outcome
				select {
				case outcome = <-outcomes:
				case <-workerContext.Done():
					t.Fatalf("concurrent membership workers did not finish: %v", workerContext.Err())
				}
				switch {
				case outcome.err == nil:
					successes++
					if outcome.result.Replayed {
						replays++
					}
				case errors.Is(outcome.err, identity.ErrMembershipStatusConflict):
					statusConflicts++
				default:
					t.Fatalf("concurrent outcome error = %v", outcome.err)
				}
			}
			if sameKey && (successes != 2 || replays != 1 || statusConflicts != 0) {
				t.Fatalf("same-key outcomes = success:%d replay:%d conflict:%d", successes, replays, statusConflicts)
			}
			if !sameKey && (successes != 1 || replays != 0 || statusConflicts != 1) {
				t.Fatalf("different-key outcomes = success:%d replay:%d conflict:%d", successes, replays, statusConflicts)
			}
			var audits, writes int
			if err := fixture.pool.QueryRow(t.Context(), `SELECT
				(SELECT count(*) FROM audit_events WHERE action='identity.membership.suspend'),
				(SELECT count(*) FROM identity_write_requests WHERE operation='identity.membership.suspend')`,
			).Scan(&audits, &writes); err != nil {
				t.Fatal(err)
			}
			if audits != 1 || writes != 1 {
				t.Fatalf("concurrent facts = audits:%d writes:%d, want 1/1", audits, writes)
			}
		})
	}
}

func TestSuspendMembershipWaitsForGlobalAndLegacyAuthorityLocks(t *testing.T) {
	for _, lock := range []string{
		"global",
		"iam-authz-actor", "iam-authz-target",
		"custom-rbac-actor", "custom-rbac-target",
	} {
		t.Run(lock, func(t *testing.T) {
			fixture := seedMembershipFixture(t)
			applicationName := "m073-" + lock + "-" + strings.ReplaceAll(uuid.NewString(), "-", "")
			workerService, workerPool, backendPID := newMembershipLockWorker(t, fixture.pool, applicationName)
			holder, err := fixture.pool.Begin(t.Context())
			if err != nil {
				closeMembershipLockWorkerPool(t, workerPool)
				t.Fatal(err)
			}
			workerContext, cancelWorker := context.WithTimeout(t.Context(), 5*time.Second)
			holderReleased := false
			workerFinished := false
			var done chan error
			defer func() {
				if !holderReleased {
					cleanupContext, cancelCleanup := context.WithTimeout(
						context.WithoutCancel(t.Context()), time.Second,
					)
					_ = holder.Rollback(cleanupContext)
					cancelCleanup()
				}
				cancelWorker()
				if done != nil && !workerFinished {
					cleanupContext, cancelCleanup := context.WithTimeout(
						context.WithoutCancel(t.Context()), time.Second,
					)
					select {
					case <-done:
					case <-cleanupContext.Done():
					}
					cancelCleanup()
				}
				closeMembershipLockWorkerPool(t, workerPool)
			}()
			lockKey := ""
			switch lock {
			case "global":
				if err := iamlock.AcquireExclusive(t.Context(), holder); err != nil {
					t.Fatal(err)
				}
			default:
				scopeID := fixture.targetScope
				if strings.HasSuffix(lock, "-actor") {
					scopeID = fixture.platformActor.ScopeID
				}
				key := "iam-authz:v1:" + scopeID.String()
				if strings.HasPrefix(lock, "custom-rbac") {
					key = "custom-rbac-tenant:" + scopeID.String()
				}
				lockKey = key
				if _, err := holder.Exec(t.Context(),
					`SELECT pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended($1,0))`, key); err != nil {
					t.Fatal(err)
				}
			}

			done = make(chan error, 1)
			input := fixture.input("membership-lock-"+lock, "membership-lock-"+lock)
			go func() {
				_, err := workerService.SuspendMembership(workerContext, fixture.platformActor, input)
				done <- err
			}()
			completed, err := waitForMembershipAuthorityLock(
				t, fixture.pool, backendPID, applicationName, lock, lockKey, done,
			)
			if completed {
				workerFinished = true
			}
			if err != nil {
				t.Fatal(err)
			}
			releaseContext, cancelRelease := context.WithTimeout(
				context.WithoutCancel(t.Context()), time.Second,
			)
			err = holder.Rollback(releaseContext)
			cancelRelease()
			if err != nil {
				t.Fatal(err)
			}
			holderReleased = true
			select {
			case err := <-done:
				workerFinished = true
				if err != nil {
					t.Fatal(err)
				}
			case <-workerContext.Done():
				t.Fatalf("membership worker did not finish after %s unlock: %v", lock, workerContext.Err())
			}
		})
	}
}

func newMembershipLockWorker(
	t *testing.T,
	source *pgxpool.Pool,
	applicationName string,
) (*identity.Service, *pgxpool.Pool, int) {
	t.Helper()
	config := source.Config()
	config.ConnConfig.RuntimeParams["application_name"] = applicationName
	config.MaxConns = 1
	config.MinConns = 0
	config.MinIdleConns = 0
	pool, err := pgxpool.NewWithConfig(t.Context(), config)
	if err != nil {
		t.Fatal(err)
	}
	tokens, err := identity.NewTokenManager(strings.Repeat("m", 32), time.Hour)
	if err != nil {
		closeMembershipLockWorkerPool(t, pool)
		t.Fatal(err)
	}
	service, err := identity.NewService(identity.NewStore(pool), tokens, time.Hour)
	if err != nil {
		closeMembershipLockWorkerPool(t, pool)
		t.Fatal(err)
	}
	var backendPID int
	if err := pool.QueryRow(t.Context(), `SELECT pg_catalog.pg_backend_pid()`).Scan(&backendPID); err != nil {
		closeMembershipLockWorkerPool(t, pool)
		t.Fatal(err)
	}
	return service, pool, backendPID
}

func closeMembershipLockWorkerPool(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	closed := make(chan struct{})
	go func() {
		pool.Close()
		close(closed)
	}()
	ctx, cancel := context.WithTimeout(context.WithoutCancel(t.Context()), time.Second)
	defer cancel()
	select {
	case <-closed:
	case <-ctx.Done():
		t.Errorf("membership lock worker pool did not close: %v", ctx.Err())
	}
}

func waitForMembershipAuthorityLock(
	t *testing.T,
	pool *pgxpool.Pool,
	backendPID int,
	applicationName string,
	lock string,
	lockKey string,
	done <-chan error,
) (bool, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case err := <-done:
			return true, fmt.Errorf("membership mutation completed before %s lock wait: %v", lock, err)
		default:
		}
		var waiting bool
		var err error
		if lock == "global" {
			err = pool.QueryRow(ctx, `SELECT EXISTS(
				SELECT 1
				FROM pg_catalog.pg_locks lock_row
				JOIN pg_catalog.pg_stat_activity activity ON activity.pid=lock_row.pid
				WHERE lock_row.pid=$1 AND activity.application_name=$2
				  AND activity.state='active' AND activity.wait_event_type='Lock'
				  AND lock_row.locktype='advisory' AND lock_row.classid=1229016321::oid
				  AND lock_row.objid=1::oid AND lock_row.objsubid=2
				  AND lock_row.mode='ExclusiveLock' AND lock_row.granted=false
			)`, backendPID, applicationName).Scan(&waiting)
		} else {
			err = pool.QueryRow(ctx, `SELECT EXISTS(
				SELECT 1
				FROM pg_catalog.pg_locks lock_row
				JOIN pg_catalog.pg_stat_activity activity ON activity.pid=lock_row.pid
				WHERE lock_row.pid=$1 AND activity.application_name=$2
				  AND activity.state='active' AND activity.wait_event_type='Lock'
				  AND lock_row.locktype='advisory' AND lock_row.objsubid=1
				  AND ((lock_row.classid::bigint << 32) | lock_row.objid::bigint) =
				      pg_catalog.hashtextextended($3,0)
				  AND lock_row.mode='ExclusiveLock' AND lock_row.granted=false
			)`, backendPID, applicationName, lockKey).Scan(&waiting)
		}
		if err != nil {
			return false, fmt.Errorf("observe %s lock wait: %w", lock, err)
		}
		if waiting {
			return false, nil
		}
		select {
		case <-ctx.Done():
			return false, fmt.Errorf("backend %d (%s) did not wait on exact %s lock: %w",
				backendPID, applicationName, lock, ctx.Err())
		case <-ticker.C:
		}
	}
}

type membershipFixture struct {
	pool             *pgxpool.Pool
	service          *identity.Service
	platformActor    identity.Actor
	tenantActor      identity.Actor
	otherTenantActor identity.Actor
	targetUser       uuid.UUID
	targetScope      uuid.UUID
	otherScope       uuid.UUID
	targetSession    uuid.UUID
	otherSession     uuid.UUID
	platformRoleID   uuid.UUID
	tenantRoleID     uuid.UUID
}

func seedMembershipFixture(t *testing.T) membershipFixture {
	t.Helper()
	pool := newIdentityAuthorityPool(t)
	tokens, err := identity.NewTokenManager(strings.Repeat("m", 32), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	service, err := identity.NewService(identity.NewStore(pool), tokens, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	fixture := membershipFixture{
		pool: pool, service: service,
		platformActor:    identity.Actor{UserID: uuid.New(), ScopeID: uuid.New(), ScopeKind: "platform"},
		tenantActor:      identity.Actor{UserID: uuid.New(), ScopeID: uuid.New(), ScopeKind: "tenant"},
		otherTenantActor: identity.Actor{UserID: uuid.New(), ScopeID: uuid.New(), ScopeKind: "tenant"},
		targetUser:       uuid.New(), targetSession: uuid.New(), otherSession: uuid.New(),
		platformRoleID: uuid.New(), tenantRoleID: uuid.New(),
	}
	fixture.targetScope = fixture.tenantActor.ScopeID
	fixture.otherScope = fixture.otherTenantActor.ScopeID
	tenantA, tenantB := uuid.New(), uuid.New()
	if _, err := pool.Exec(t.Context(), `INSERT INTO tenants(id,display_name) VALUES
		($1,'Membership Tenant A'),($2,'Membership Tenant B')`, tenantA, tenantB); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO access_scopes(id,kind,tenant_id) VALUES
		($1,'platform',NULL),($2,'tenant',$3),($4,'tenant',$5)`,
		fixture.platformActor.ScopeID, fixture.targetScope, tenantA, fixture.otherScope, tenantB); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO users(id,username,display_name,password_hash) VALUES
		($1,$2,'Platform Membership Manager','unused'),
		($3,$4,'Tenant Membership Manager','unused'),
		($5,$6,'Other Tenant Manager','unused'),
		($7,$8,'Membership Target','unused')`,
		fixture.platformActor.UserID, membershipUsername("platform"),
		fixture.tenantActor.UserID, membershipUsername("tenant"),
		fixture.otherTenantActor.UserID, membershipUsername("other"),
		fixture.targetUser, membershipUsername("target")); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO memberships(scope_id,user_id) VALUES
		($1,$2),($3,$4),($5,$6),($3,$7),($5,$7)`,
		fixture.platformActor.ScopeID, fixture.platformActor.UserID,
		fixture.targetScope, fixture.tenantActor.UserID,
		fixture.otherScope, fixture.otherTenantActor.UserID, fixture.targetUser); err != nil {
		t.Fatal(err)
	}
	otherTenantRole := uuid.New()
	// 迁移 042 起非系统角色只能经自定义 RBAC 事实创建；这里直接建系统角色作为测试夹具。
	if _, err := pool.Exec(t.Context(), `INSERT INTO roles(id,scope_id,name,description,system_role) VALUES
		($1,$2,'membership_manager','Membership manager',true),
		($3,$4,'membership_manager','Membership manager',true),
		($5,$6,'membership_manager','Membership manager',true)`,
		fixture.platformRoleID, fixture.platformActor.ScopeID,
		fixture.tenantRoleID, fixture.targetScope,
		otherTenantRole, fixture.otherScope); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO role_permissions(role_id,permission_name) VALUES
		($1,'platform.admin'),($2,'identity.users.manage'),($3,'identity.users.manage')`,
		fixture.platformRoleID, fixture.tenantRoleID, otherTenantRole); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO role_assignments(scope_id,user_id,role_id) VALUES
		($1,$2,$3),($4,$5,$6),($7,$8,$9)`,
		fixture.platformActor.ScopeID, fixture.platformActor.UserID, fixture.platformRoleID,
		fixture.targetScope, fixture.tenantActor.UserID, fixture.tenantRoleID,
		fixture.otherScope, fixture.otherTenantActor.UserID, otherTenantRole); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	if _, err := pool.Exec(t.Context(), `INSERT INTO auth_sessions(
		id,family_id,user_id,scope_id,refresh_token_hash,created_at,expires_at
	) VALUES($1,$2,$3,$4,$5,$6,$7),($8,$9,$3,$10,$11,$6,$7)`,
		fixture.targetSession, uuid.New(), fixture.targetUser, fixture.targetScope, bytes.Repeat([]byte{0x73}, 32),
		now.Add(-time.Hour), now.Add(time.Hour), fixture.otherSession, uuid.New(), fixture.otherScope,
		bytes.Repeat([]byte{0x74}, 32)); err != nil {
		t.Fatal(err)
	}
	return fixture
}

func membershipUsername(prefix string) string {
	return prefix + "-" + strings.ReplaceAll(uuid.NewString(), "-", "")
}

func (fixture membershipFixture) input(key, requestID string) identity.SuspendMembershipInput {
	return identity.SuspendMembershipInput{
		ScopeID: fixture.targetScope, UserID: fixture.targetUser,
		ExpectedStatus: identity.MembershipStatusActive, ReasonCode: "security_review",
		IdempotencyKey: key, RequestID: requestID, TraceID: "trace-" + key,
	}
}

func (fixture membershipFixture) assertMutation(
	t *testing.T,
	actor identity.Actor,
	input identity.SuspendMembershipInput,
	wantAudits int,
	wantWrites int,
) {
	t.Helper()
	var status string
	var targetRevoked, otherRevoked bool
	var audits, writes int
	var auditComplete, writeComplete bool
	if err := fixture.pool.QueryRow(t.Context(), `SELECT
		(SELECT status FROM memberships WHERE scope_id=$1 AND user_id=$2),
		(SELECT revoked_at IS NOT NULL FROM auth_sessions WHERE id=$3),
		(SELECT revoked_at IS NOT NULL FROM auth_sessions WHERE id=$4),
		(SELECT count(*) FROM audit_events WHERE scope_id=$5 AND action='identity.membership.suspend'),
		(SELECT count(*) FROM identity_write_requests
		 WHERE actor_user_id=$6 AND operation='identity.membership.suspend' AND idempotency_key=$7),
		EXISTS(SELECT 1 FROM audit_events
		 WHERE scope_id=$5 AND actor_user_id=$6 AND action='identity.membership.suspend'
		   AND resource_type='membership' AND resource_id=$1::text || ':' || $2::text
		   AND request_id=$8 AND payload->>'target_scope_id'=$1::text
		   AND payload->>'target_user_id'=$2::text AND payload->>'reason_code'=$9
		   AND payload->>'trace_id'=$10 AND payload->>'status'='suspended'),
		EXISTS(SELECT 1 FROM identity_write_requests
		 WHERE actor_user_id=$6 AND operation='identity.membership.suspend' AND idempotency_key=$7
		   AND completed_at IS NOT NULL AND response_status=200 AND resource_id=$2
		   AND response_body->>'scope_id'=$1::text AND response_body->>'user_id'=$2::text
		   AND response_body->>'status'='suspended' AND response_body->>'replayed'='false')`,
		fixture.targetScope, fixture.targetUser, fixture.targetSession, fixture.otherSession,
		actor.ScopeID, actor.UserID, input.IdempotencyKey, input.RequestID, input.ReasonCode, input.TraceID,
	).Scan(&status, &targetRevoked, &otherRevoked, &audits, &writes, &auditComplete, &writeComplete); err != nil {
		t.Fatal(err)
	}
	if status != identity.MembershipStatusSuspended || !targetRevoked || otherRevoked ||
		audits != wantAudits || writes != wantWrites || !auditComplete || !writeComplete {
		t.Fatalf("mutation state = status:%s target_revoked:%t other_revoked:%t audits:%d writes:%d audit_complete:%t write_complete:%t",
			status, targetRevoked, otherRevoked, audits, writes, auditComplete, writeComplete)
	}
	var responseBody []byte
	var revokedAt time.Time
	if err := fixture.pool.QueryRow(t.Context(), `SELECT request.response_body, session.revoked_at
		FROM identity_write_requests request
		JOIN auth_sessions session ON session.id=$3
		WHERE request.actor_user_id=$1 AND request.operation='identity.membership.suspend'
		  AND request.idempotency_key=$2`,
		actor.UserID, input.IdempotencyKey, fixture.targetSession,
	).Scan(&responseBody, &revokedAt); err != nil {
		t.Fatal(err)
	}
	var receipt identity.MembershipMutationResult
	if err := json.Unmarshal(responseBody, &receipt); err != nil {
		t.Fatal(err)
	}
	if receipt.ScopeID != fixture.targetScope || receipt.UserID != fixture.targetUser ||
		receipt.PreviousStatus != identity.MembershipStatusActive ||
		receipt.Status != identity.MembershipStatusSuspended || receipt.ReasonCode != input.ReasonCode ||
		receipt.SessionsRevoked != 1 || receipt.SuspendedAt.IsZero() ||
		receipt.SuspendedAt.UnixMicro() != revokedAt.UnixMicro() || receipt.Replayed {
		t.Fatalf("membership receipt = %#v", receipt)
	}
}

func (fixture membershipFixture) assertNoMutation(t *testing.T, input identity.SuspendMembershipInput) {
	t.Helper()
	var status string
	var revoked, audits, writes int
	if err := fixture.pool.QueryRow(t.Context(), `SELECT
		(SELECT status FROM memberships WHERE scope_id=$1 AND user_id=$2),
		(SELECT count(*) FROM auth_sessions WHERE id=$3 AND revoked_at IS NOT NULL),
		(SELECT count(*) FROM audit_events WHERE request_id=$4),
		(SELECT count(*) FROM identity_write_requests WHERE idempotency_key=$5)`,
		fixture.targetScope, fixture.targetUser, fixture.targetSession, input.RequestID, input.IdempotencyKey,
	).Scan(&status, &revoked, &audits, &writes); err != nil {
		t.Fatal(err)
	}
	if status != identity.MembershipStatusActive || revoked != 0 || audits != 0 || writes != 0 {
		t.Fatalf("rejected mutation state = status:%s revoked:%d audits:%d writes:%d",
			status, revoked, audits, writes)
	}
}
