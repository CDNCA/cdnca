package errorpagecontrol

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type testAuthorizationHooks struct {
	entered    chan<- struct{}
	authorized chan<- struct{}
	release    <-chan struct{}
}

type testTxAuthorizer struct {
	hooks *testAuthorizationHooks
}

func (authorizer testTxAuthorizer) Authorize(
	ctx context.Context,
	tx pgx.Tx,
	actor Actor,
	permission string,
) error {
	if authorizer.hooks != nil && authorizer.hooks.entered != nil {
		authorizer.hooks.entered <- struct{}{}
	}
	if validateActor(actor) != nil || (permission != permissionRead && permission != permissionManage) {
		return ErrPermissionDenied
	}
	var scopeKind string
	var tenantID *uuid.UUID
	if err := tx.QueryRow(ctx, `SELECT kind,tenant_id FROM access_scopes WHERE id=$1 FOR SHARE`, actor.ScopeID).
		Scan(&scopeKind, &tenantID); err != nil {
		return authorizationTestError(err)
	}
	if scopeKind != actor.ScopeKind {
		return ErrPermissionDenied
	}
	if tenantID != nil {
		var tenantStatus string
		if err := tx.QueryRow(ctx, `SELECT status FROM tenants WHERE id=$1 FOR SHARE`, *tenantID).Scan(&tenantStatus); err != nil {
			return authorizationTestError(err)
		}
		if tenantStatus != "active" {
			return ErrPermissionDenied
		}
	}
	var accountStatus string
	if err := tx.QueryRow(ctx, `SELECT status FROM users WHERE id=$1 FOR SHARE`, actor.UserID).Scan(&accountStatus); err != nil {
		return authorizationTestError(err)
	}
	if accountStatus != "active" {
		return ErrPermissionDenied
	}
	var membershipStatus string
	if err := tx.QueryRow(ctx, `SELECT status FROM memberships
		WHERE scope_id=$1 AND user_id=$2 FOR SHARE`, actor.ScopeID, actor.UserID).Scan(&membershipStatus); err != nil {
		return authorizationTestError(err)
	}
	if membershipStatus != "active" {
		return ErrPermissionDenied
	}
	var granted string
	if err := tx.QueryRow(ctx, `SELECT permission.permission_name
		FROM role_assignments assignment
		JOIN roles role ON role.id=assignment.role_id AND role.scope_id=assignment.scope_id
		JOIN role_permissions permission ON permission.role_id=role.id
		WHERE assignment.scope_id=$1 AND assignment.user_id=$2 AND permission.permission_name=$3
		ORDER BY role.id LIMIT 1 FOR SHARE OF assignment,role,permission`,
		actor.ScopeID, actor.UserID, permission).Scan(&granted); err != nil {
		return authorizationTestError(err)
	}
	if authorizer.hooks != nil && authorizer.hooks.authorized != nil {
		authorizer.hooks.authorized <- struct{}{}
	}
	if authorizer.hooks != nil && authorizer.hooks.release != nil {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-authorizer.hooks.release:
		}
	}
	return nil
}

func authorizationTestError(err error) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrPermissionDenied
	}
	return err
}

func TestErrorPageWritesAndReplaysReauthorizeAccount(t *testing.T) {
	fixture := openErrorPageDatabase(t)
	identities := seedErrorPageIdentities(t, fixture.pool)
	service, err := NewServiceWithDependencies(
		fixture.pool,
		newMemoryContentStore(),
		&testScanner{name: "authorization-scanner"},
		staticLimits{quota: AssetQuota{MaxAssetBytes: MaxEdgeResourceBytes, MaxAssets: 100, MaxTotalBytes: 8 << 20}},
		audit.New(fixture.pool),
		time.Now,
		testTxAuthorizer{},
	)
	if err != nil {
		t.Fatal(err)
	}

	replayRequest := initiateRequest(identities.tenantScope, "authorization-replay", []byte("safe"), "text/plain")
	if _, err := service.InitiateAsset(t.Context(), identities.tenantOwner, replayRequest); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.pool.Exec(t.Context(), `UPDATE users SET status='disabled' WHERE id=$1`, identities.tenantOwner.UserID); err != nil {
		t.Fatal(err)
	}
	for name, request := range map[string]InitiateAssetRequest{
		"replay": replayRequest,
		"fresh":  initiateRequest(identities.tenantScope, "authorization-fresh", []byte("fresh"), "text/plain"),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := service.InitiateAsset(t.Context(), identities.tenantOwner, request); !errors.Is(err, ErrPermissionDenied) {
				t.Fatalf("error=%v, want ErrPermissionDenied", err)
			}
		})
	}
}

func TestErrorPageCrossTenantAndRevisionRace(t *testing.T) {
	fixture := openErrorPageDatabase(t)
	identities := seedErrorPageIdentities(t, fixture.pool)
	service, err := NewServiceWithDependencies(
		fixture.pool,
		newMemoryContentStore(),
		&testScanner{name: "revision-scanner"},
		staticLimits{quota: AssetQuota{MaxAssetBytes: MaxEdgeResourceBytes, MaxAssets: 100, MaxTotalBytes: 8 << 20}},
		audit.New(fixture.pool),
		time.Now,
		testTxAuthorizer{},
	)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := service.InitiateAsset(t.Context(), identities.tenantOwner,
		initiateRequest(identities.otherTenantScope, "cross-tenant-forged-target", []byte("forged"), "text/plain")); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("cross-tenant target error=%v", err)
	}

	asset := readyAsset(t, service, identities.tenantOwner, identities.tenantScope,
		"revision-race-asset", []byte("safe"), "text/plain")
	created, err := service.CreateRule(t.Context(), identities.tenantOwner, CreateRuleRequest{
		Target: RuleTarget{Kind: ScopeSite, ScopeID: identities.tenantScope, SiteID: &identities.siteID},
		Fields: RuleFields{
			Category: CategoryOriginResponse,
			Match:    StatusSelector{Kind: MatchExact, From: 500},
			AssetID:  asset.ID,
			Enabled:  false,
		},
		WriteMetadata: writeMetadata("revision-race-create"),
	})
	if err != nil {
		t.Fatal(err)
	}

	start := make(chan struct{})
	results := make(chan error, 2)
	var ready sync.WaitGroup
	ready.Add(2)
	for contender := 0; contender < 2; contender++ {
		contender := contender
		go func() {
			ready.Done()
			<-start
			fields := created.Value.Fields
			fields.Match.From = 501 + contender
			fields.Match.To = 501 + contender
			_, err := service.UpdateRule(t.Context(), identities.tenantOwner, UpdateRuleRequest{
				RuleID: created.Value.ID, ExpectedRevision: created.Value.Revision, Fields: fields,
				WriteMetadata: writeMetadata("revision-race-update-" + string(rune('a'+contender))),
			})
			results <- err
		}()
	}
	ready.Wait()
	close(start)
	successes, conflicts := 0, 0
	for range 2 {
		err := <-results
		switch {
		case err == nil:
			successes++
		case errors.Is(err, ErrRevisionConflict):
			conflicts++
		default:
			t.Fatalf("unexpected race error=%v", err)
		}
	}
	if successes != 1 || conflicts != 1 {
		t.Fatalf("successes=%d revision_conflicts=%d", successes, conflicts)
	}
}

func TestErrorPageAuthorizationCommitOrder(t *testing.T) {
	fixture, identities, actor, roleID := openMutableAuthorizationDatabase(t)
	store := newMemoryContentStore()
	service := newAuthorizationService(t, fixture.pool, store, testTxAuthorizer{})
	mutations := authorizationMutations(fixture.pool, actor, roleID)
	sequence := 0
	for _, mutation := range mutations {
		for _, replay := range []bool{false, true} {
			mode := "fresh"
			if replay {
				mode = "replay"
			}
			sequence++
			t.Run(mutation.name+"/business-first/"+mode, func(t *testing.T) {
				request := initiateRequest(identities.tenantScope,
					fmt.Sprintf("auth-order-%d", sequence), []byte(fmt.Sprintf("body-%d", sequence)), "text/plain")
				if replay {
					if _, err := service.InitiateAsset(t.Context(), actor, request); err != nil {
						t.Fatal(err)
					}
				}
				authorized := make(chan struct{}, 1)
				release := make(chan struct{})
				blockedService := newAuthorizationService(t, fixture.pool, store, testTxAuthorizer{
					hooks: &testAuthorizationHooks{authorized: authorized, release: release},
				})
				ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
				defer cancel()
				businessDone := make(chan authorizationWriteOutcome, 1)
				go invokeAuthorizationWrite(ctx, blockedService, actor, request, businessDone)
				waitSignal(t, ctx, authorized, "authorization")
				revocationStarted := make(chan struct{}, 1)
				revocationDone := make(chan error, 1)
				go func() {
					revocationDone <- pgx.BeginFunc(ctx, fixture.pool, func(tx pgx.Tx) error {
						revocationStarted <- struct{}{}
						return mutation.revoke(ctx, tx)
					})
				}()
				waitSignal(t, ctx, revocationStarted, "revocation start")
				select {
				case err := <-revocationDone:
					t.Fatalf("revocation bypassed authorization locks: %v", err)
				case <-time.After(25 * time.Millisecond):
				}
				close(release)
				outcome := waitAuthorizationOutcome(t, ctx, businessDone)
				if outcome.err != nil || outcome.replayed != replay {
					t.Fatalf("business outcome replayed=%t err=%v", outcome.replayed, outcome.err)
				}
				if err := waitError(t, ctx, revocationDone, "revocation"); err != nil {
					t.Fatal(err)
				}
				if _, err := service.InitiateAsset(t.Context(), actor, request); !errors.Is(err, ErrPermissionDenied) {
					t.Fatalf("post-revocation replay error=%v", err)
				}
				if err := mutation.restore(t.Context()); err != nil {
					t.Fatal(err)
				}
			})

			sequence++
			t.Run(mutation.name+"/revocation-first/"+mode, func(t *testing.T) {
				request := initiateRequest(identities.tenantScope,
					fmt.Sprintf("auth-order-%d", sequence), []byte(fmt.Sprintf("body-%d", sequence)), "text/plain")
				if replay {
					if _, err := service.InitiateAsset(t.Context(), actor, request); err != nil {
						t.Fatal(err)
					}
				}
				ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
				defer cancel()
				revocationTx, err := fixture.pool.Begin(ctx)
				if err != nil {
					t.Fatal(err)
				}
				defer func() { _ = revocationTx.Rollback(context.Background()) }()
				if err := mutation.revoke(ctx, revocationTx); err != nil {
					t.Fatal(err)
				}
				entered := make(chan struct{}, 1)
				blockedService := newAuthorizationService(t, fixture.pool, store, testTxAuthorizer{
					hooks: &testAuthorizationHooks{entered: entered},
				})
				businessDone := make(chan authorizationWriteOutcome, 1)
				go invokeAuthorizationWrite(ctx, blockedService, actor, request, businessDone)
				waitSignal(t, ctx, entered, "authorization entry")
				select {
				case outcome := <-businessDone:
					t.Fatalf("business bypassed revocation lock: replayed=%t err=%v", outcome.replayed, outcome.err)
				case <-time.After(25 * time.Millisecond):
				}
				if err := revocationTx.Commit(ctx); err != nil {
					t.Fatal(err)
				}
				outcome := waitAuthorizationOutcome(t, ctx, businessDone)
				if !errors.Is(outcome.err, ErrPermissionDenied) {
					t.Fatalf("business error=%v, want ErrPermissionDenied", outcome.err)
				}
				if err := mutation.restore(t.Context()); err != nil {
					t.Fatal(err)
				}
			})
		}
	}
}

func TestErrorPageAuthorizationDeadlockStress(t *testing.T) {
	fixture, identities, actor, roleID := openMutableAuthorizationDatabase(t)
	store := newMemoryContentStore()
	mutations := authorizationMutations(fixture.pool, actor, roleID)
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	for round := 0; round < 32; round++ {
		mutation := mutations[round%len(mutations)]
		authorized := make(chan struct{}, 1)
		release := make(chan struct{})
		service := newAuthorizationService(t, fixture.pool, store, testTxAuthorizer{
			hooks: &testAuthorizationHooks{authorized: authorized, release: release},
		})
		request := initiateRequest(identities.tenantScope, fmt.Sprintf("auth-stress-%d", round),
			[]byte(fmt.Sprintf("stress-%d", round)), "text/plain")
		businessDone := make(chan authorizationWriteOutcome, 1)
		go invokeAuthorizationWrite(ctx, service, actor, request, businessDone)
		waitSignal(t, ctx, authorized, "stress authorization")
		revocationStarted := make(chan struct{}, 1)
		revocationDone := make(chan error, 1)
		go func() {
			revocationDone <- pgx.BeginFunc(ctx, fixture.pool, func(tx pgx.Tx) error {
				revocationStarted <- struct{}{}
				return mutation.revoke(ctx, tx)
			})
		}()
		waitSignal(t, ctx, revocationStarted, "stress revocation")
		close(release)
		if outcome := waitAuthorizationOutcome(t, ctx, businessDone); outcome.err != nil {
			t.Fatalf("round %d business error=%v", round, outcome.err)
		}
		if err := waitError(t, ctx, revocationDone, "stress revocation"); err != nil {
			t.Fatalf("round %d revocation error=%v", round, err)
		}
		if err := mutation.restore(ctx); err != nil {
			t.Fatalf("round %d restore error=%v", round, err)
		}
	}
}

func TestErrorPageServiceWithoutAuthorizerFailsClosed(t *testing.T) {
	fixture := openErrorPageDatabase(t)
	identities := seedErrorPageIdentities(t, fixture.pool)
	service, err := NewServiceWithDependencies(
		fixture.pool,
		newMemoryContentStore(),
		&testScanner{name: "deny-scanner"},
		staticLimits{quota: AssetQuota{MaxAssetBytes: MaxEdgeResourceBytes, MaxAssets: 100, MaxTotalBytes: 8 << 20}},
		audit.New(fixture.pool),
		time.Now,
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.InitiateAsset(t.Context(), identities.tenantOwner,
		initiateRequest(identities.tenantScope, "deny-default", []byte("safe"), "text/plain")); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("error=%v, want ErrPermissionDenied", err)
	}
}

type authorizationMutation struct {
	name    string
	revoke  func(context.Context, pgx.Tx) error
	restore func(context.Context) error
}

func authorizationMutations(pool *pgxpool.Pool, actor Actor, roleID uuid.UUID) []authorizationMutation {
	execRestore := func(query string, args ...any) func(context.Context) error {
		return func(ctx context.Context) error {
			_, err := pool.Exec(ctx, query, args...)
			return err
		}
	}
	return []authorizationMutation{
		{
			name: "account",
			revoke: func(ctx context.Context, tx pgx.Tx) error {
				_, err := tx.Exec(ctx, `UPDATE users SET status='disabled' WHERE id=$1`, actor.UserID)
				return err
			},
			restore: execRestore(`UPDATE users SET status='active' WHERE id=$1`, actor.UserID),
		},
		{
			name: "membership",
			revoke: func(ctx context.Context, tx pgx.Tx) error {
				_, err := tx.Exec(ctx, `UPDATE memberships SET status='suspended' WHERE scope_id=$1 AND user_id=$2`,
					actor.ScopeID, actor.UserID)
				return err
			},
			restore: execRestore(`UPDATE memberships SET status='active' WHERE scope_id=$1 AND user_id=$2`,
				actor.ScopeID, actor.UserID),
		},
		{
			name: "assignment",
			revoke: func(ctx context.Context, tx pgx.Tx) error {
				_, err := tx.Exec(ctx, `DELETE FROM role_assignments WHERE scope_id=$1 AND user_id=$2 AND role_id=$3`,
					actor.ScopeID, actor.UserID, roleID)
				return err
			},
			restore: execRestore(`INSERT INTO role_assignments(scope_id,user_id,role_id,assigned_at) VALUES($1,$2,$3,$4)`,
				actor.ScopeID, actor.UserID, roleID, time.Now().UTC()),
		},
		{
			name: "role-permission",
			revoke: func(ctx context.Context, tx pgx.Tx) error {
				_, err := tx.Exec(ctx, `DELETE FROM role_permissions WHERE role_id=$1 AND permission_name=$2`,
					roleID, permissionManage)
				return err
			},
			restore: execRestore(`INSERT INTO role_permissions(role_id,permission_name) VALUES($1,$2)`, roleID, permissionManage),
		},
	}
}

func openMutableAuthorizationDatabase(
	t *testing.T,
) (integrationFixture, seededIdentities, Actor, uuid.UUID) {
	t.Helper()
	fixture := openErrorPageDatabase(t)
	identities := seedErrorPageIdentities(t, fixture.pool)
	actor, roleID := seedLegacyAuthorizationRole(t, fixture.pool, identities)
	if _, err := fixture.pool.Exec(t.Context(),
		`INSERT INTO role_permissions(role_id,permission_name) VALUES($1,$2)`, roleID, permissionManage); err != nil {
		t.Fatal(err)
	}
	return fixture, identities, actor, roleID
}

func seedLegacyAuthorizationRole(
	t *testing.T,
	pool *pgxpool.Pool,
	identities seededIdentities,
) (Actor, uuid.UUID) {
	t.Helper()
	roleID := uuid.New()
	now := time.Now().UTC()
	if err := pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
		// The mutations revoke this role's assignment and permission with plain
		// DML, which 042 only allows for a role that is neither a system role nor
		// a custom RBAC projection. Since 042 such a row cannot be inserted
		// directly (custom roles go through custom RBAC facts), so the row alone
		// is written with triggers off; its permission and assignment below go
		// through every trigger.
		if _, err := tx.Exec(t.Context(), `SET LOCAL session_replication_role='replica'`); err != nil {
			return err
		}
		if _, err := tx.Exec(t.Context(), `INSERT INTO roles(id,scope_id,name,description,system_role,created_at)
			VALUES($1,$2,$3,'error page authorization test',false,$4)`, roleID, identities.tenantScope,
			"errorpage_auth_"+roleID.String(), now); err != nil {
			return err
		}
		if _, err := tx.Exec(t.Context(), `SET LOCAL session_replication_role='origin'`); err != nil {
			return err
		}
		_, err := tx.Exec(t.Context(), `INSERT INTO role_assignments(scope_id,user_id,role_id,assigned_at)
			VALUES($1,$2,$3,$4)`, identities.tenantScope, identities.tenantViewer.UserID, roleID, now)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return identities.tenantViewer, roleID
}

type authorizationWriteOutcome struct {
	replayed bool
	err      error
}

func invokeAuthorizationWrite(
	ctx context.Context,
	service *Service,
	actor Actor,
	request InitiateAssetRequest,
	done chan<- authorizationWriteOutcome,
) {
	result, err := service.InitiateAsset(ctx, actor, request)
	done <- authorizationWriteOutcome{replayed: result.Replayed, err: err}
}

func newAuthorizationService(
	t *testing.T,
	pool *pgxpool.Pool,
	store ContentStore,
	authorizer TxAuthorizer,
) *Service {
	t.Helper()
	service, err := NewServiceWithDependencies(
		pool,
		store,
		&testScanner{name: "authorization-scanner"},
		staticLimits{quota: AssetQuota{MaxAssetBytes: MaxEdgeResourceBytes, MaxAssets: 1000, MaxTotalBytes: 64 << 20}},
		audit.New(pool),
		time.Now,
		authorizer,
	)
	if err != nil {
		t.Fatal(err)
	}
	return service
}

func waitSignal(t *testing.T, ctx context.Context, signal <-chan struct{}, label string) {
	t.Helper()
	select {
	case <-signal:
	case <-ctx.Done():
		t.Fatalf("wait for %s: %v", label, ctx.Err())
	}
}

func waitAuthorizationOutcome(
	t *testing.T,
	ctx context.Context,
	done <-chan authorizationWriteOutcome,
) authorizationWriteOutcome {
	t.Helper()
	select {
	case outcome := <-done:
		return outcome
	case <-ctx.Done():
		t.Fatalf("wait for authorization write: %v", ctx.Err())
		return authorizationWriteOutcome{}
	}
}

func waitError(t *testing.T, ctx context.Context, done <-chan error, label string) error {
	t.Helper()
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		t.Fatalf("wait for %s: %v", label, ctx.Err())
		return ctx.Err()
	}
}
