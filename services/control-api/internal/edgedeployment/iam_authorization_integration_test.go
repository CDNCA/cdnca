//go:build integration

package edgedeployment

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/apikeycredential"
	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/iamlock"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/sessioncredential"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type commandIAMFixture struct {
	pool       *pgxpool.Pool
	tokens     *identity.TokenManager
	authorizer *iamlock.Authorizer
	store      *Store
	publicKey  ed25519.PublicKey
	privateKey ed25519.PrivateKey
}

type commandState struct {
	requests, rollouts, deployments, outbox, audits int
	rolloutStatus                                   string
	rolloutRevision                                 int64
	cancelledDeployments, cancelledOutbox           int
}

type commandRollout struct {
	ID           uuid.UUID
	Revision     int64
	DeploymentID uuid.UUID
}

type blockingAuditAppender struct {
	delegate auditAppender
	entered  chan struct{}
	release  chan struct{}
}

func (appender *blockingAuditAppender) Append(ctx context.Context, tx pgx.Tx, event audit.Event) error {
	select {
	case appender.entered <- struct{}{}:
	case <-ctx.Done():
		return ctx.Err()
	}
	select {
	case <-appender.release:
	case <-ctx.Done():
		return ctx.Err()
	}
	return appender.delegate.Append(ctx, tx, event)
}

func TestIAMRolloutCommandsAuthorizeBeforeReplayAndBusinessWrites(t *testing.T) {
	fixture := newCommandIAMFixture(t, nil)
	platformScopeID := seedCommandScope(t, fixture.pool, ScopeKindPlatform)
	actor := fixture.seedActor(t, platformScopeID, ScopeKindPlatform, PermissionRead, PermissionManage)
	tenantScopeID, tenantUserID := seedEdgeScope(t, fixture.pool)
	tenantActor := fixture.seedActor(t, tenantScopeID, ScopeKindTenant, PermissionRead, PermissionManage)
	configID := fixture.persistConfig(t, tenantScopeID, "iam-command-primary")

	t.Run("active cancel and replay", func(t *testing.T) {
		rollout := fixture.createRollout(t, tenantScopeID, tenantUserID, configID, "iam-active-cancel")
		request := commandRequest(actor, tenantScopeID, rollout, "iam-active-cancel")
		cancelled, err := fixture.store.CancelRollout(t.Context(), request)
		if err != nil || cancelled.Replayed || cancelled.Rollout.State != RolloutStateCancelled {
			t.Fatalf("cancel result = %+v, %v", cancelled, err)
		}
		replayed, err := fixture.store.CancelRollout(t.Context(), request)
		if err != nil || !replayed.Replayed || replayed.Rollout.Revision != cancelled.Rollout.Revision {
			t.Fatalf("cancel replay = %+v, %v", replayed, err)
		}
	})

	t.Run("active tenant same target", func(t *testing.T) {
		rollout := fixture.createRollout(t, tenantScopeID, tenantUserID, configID, "iam-active-tenant")
		cancelled, err := fixture.store.CancelRollout(
			t.Context(), commandRequest(tenantActor, tenantScopeID, rollout, "iam-active-tenant"),
		)
		if err != nil || cancelled.Rollout.State != RolloutStateCancelled {
			t.Fatalf("tenant cancel result = %+v, %v", cancelled, err)
		}
	})

	t.Run("active retry", func(t *testing.T) {
		rollout := fixture.createRollout(t, tenantScopeID, tenantUserID, configID, "iam-active-retry")
		advanceDeploymentState(t, fixture.pool, rollout.DeploymentID, "delivered")
		advanceDeploymentState(t, fixture.pool, rollout.DeploymentID, "failed")
		snapshot, err := fixture.store.GetRollout(t.Context(), actor, tenantScopeID, rollout.ID)
		if err != nil {
			t.Fatal(err)
		}
		retried, err := fixture.store.RetryRollout(t.Context(), commandRequest(actor, tenantScopeID,
			commandRollout{ID: snapshot.ID, Revision: snapshot.Revision}, "iam-active-retry"))
		if err != nil || retried.Replayed || retried.Rollout.Progress.Pending != 1 || retried.Rollout.Revision != snapshot.Revision+1 {
			t.Fatalf("retry result = %+v, %v", retried, err)
		}
	})

	t.Run("revoked replay is denied before idempotency", func(t *testing.T) {
		rollout := fixture.createRollout(t, tenantScopeID, tenantUserID, configID, "iam-revoked-replay")
		request := commandRequest(actor, tenantScopeID, rollout, "iam-revoked-replay")
		if _, err := fixture.store.CancelRollout(t.Context(), request); err != nil {
			t.Fatal(err)
		}
		fixture.revokeSession(t, actor)
		before := loadCommandState(t, fixture.pool, rollout.ID)
		// A revoked session is an invalid credential: ErrUnauthenticated.
		if _, err := fixture.store.CancelRollout(t.Context(), request); !errors.Is(err, ErrUnauthenticated) {
			t.Fatalf("revoked replay error = %v", err)
		}
		assertCommandState(t, loadCommandState(t, fixture.pool, rollout.ID), before)
	})
}

func TestIAMRolloutCommandsRejectInvalidAuthorityWithZeroWrites(t *testing.T) {
	operations := []struct {
		name string
		run  func(context.Context, *Store, RolloutCommandRequest) (RolloutCommandResult, error)
	}{
		{name: "cancel", run: func(ctx context.Context, store *Store, request RolloutCommandRequest) (RolloutCommandResult, error) {
			return store.CancelRollout(ctx, request)
		}},
		{name: "retry", run: func(ctx context.Context, store *Store, request RolloutCommandRequest) (RolloutCommandResult, error) {
			return store.RetryRollout(ctx, request)
		}},
	}
	for _, operation := range operations {
		t.Run(operation.name, func(t *testing.T) {
			fixture := newCommandIAMFixture(t, nil)
			platformScopeID := seedCommandScope(t, fixture.pool, ScopeKindPlatform)
			active := fixture.seedActor(t, platformScopeID, ScopeKindPlatform, PermissionManage)
			missing := fixture.seedActor(t, platformScopeID, ScopeKindPlatform)
			firstScopeID, firstUserID := seedEdgeScope(t, fixture.pool)
			secondScopeID, secondUserID := seedEdgeScope(t, fixture.pool)
			firstConfigID := fixture.persistConfig(t, firstScopeID, "iam-denial-first")
			secondConfigID := fixture.persistConfig(t, secondScopeID, "iam-denial-second")

			unknown := fixture.mintActor(t, active.UserID, active.ScopeID, active.ScopeKind, uuid.New())
			revoked := fixture.seedActor(t, platformScopeID, ScopeKindPlatform, PermissionManage)
			identityService, err := identity.NewService(identity.NewStore(fixture.pool), fixture.tokens, time.Hour)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := identityService.AuthenticateSession(t.Context(), revoked.rawSession()); err != nil {
				t.Fatalf("upstream preauthentication: %v", err)
			}
			fixture.revokeSession(t, revoked)
			tenantActor := fixture.seedActor(t, firstScopeID, ScopeKindTenant, PermissionManage)
			wrongUser, wrongScope, wrongSession, wrongKind := active, active, active, active
			wrongUser.UserID = uuid.New()
			wrongScope.ScopeID = uuid.New()
			wrongSession.SessionID = uuid.New()
			wrongKind.ScopeKind = ScopeKindTenant

			tests := []struct {
				name        string
				actor       Actor
				targetScope uuid.UUID
				rollout     commandRollout
				store       *Store
				want        error
			}{
				{name: "unknown session", actor: unknown, targetScope: firstScopeID,
					rollout: fixture.createRollout(t, firstScopeID, firstUserID, firstConfigID, operation.name+"-unknown"), store: fixture.store, want: ErrUnauthenticated},
				{name: "revoked after preauthentication", actor: revoked, targetScope: firstScopeID,
					rollout: fixture.createRollout(t, firstScopeID, firstUserID, firstConfigID, operation.name+"-revoked"), store: fixture.store, want: ErrUnauthenticated},
				{name: "missing permission", actor: missing, targetScope: firstScopeID,
					rollout: fixture.createRollout(t, firstScopeID, firstUserID, firstConfigID, operation.name+"-missing"), store: fixture.store, want: ErrPermissionDenied},
				{name: "sealed user mismatch", actor: wrongUser, targetScope: firstScopeID,
					rollout: fixture.createRollout(t, firstScopeID, firstUserID, firstConfigID, operation.name+"-user-mismatch"), store: fixture.store, want: ErrPermissionDenied},
				{name: "sealed authentication scope mismatch", actor: wrongScope, targetScope: firstScopeID,
					rollout: fixture.createRollout(t, firstScopeID, firstUserID, firstConfigID, operation.name+"-scope-mismatch"), store: fixture.store, want: ErrPermissionDenied},
				{name: "sealed session mismatch", actor: wrongSession, targetScope: firstScopeID,
					rollout: fixture.createRollout(t, firstScopeID, firstUserID, firstConfigID, operation.name+"-session-mismatch"), store: fixture.store, want: ErrPermissionDenied},
				{name: "sealed scope kind mismatch", actor: wrongKind, targetScope: firstScopeID,
					rollout: fixture.createRollout(t, firstScopeID, firstUserID, firstConfigID, operation.name+"-kind-mismatch"), store: fixture.store, want: ErrPermissionDenied},
				{name: "tenant cross target", actor: tenantActor, targetScope: secondScopeID,
					rollout: fixture.createRollout(t, secondScopeID, secondUserID, secondConfigID, operation.name+"-tenant-cross"), store: fixture.store, want: ErrPermissionDenied},
				{name: "rollout target mismatch", actor: active, targetScope: secondScopeID,
					rollout: fixture.createRollout(t, firstScopeID, firstUserID, firstConfigID, operation.name+"-target-mismatch"), store: fixture.store, want: ErrNotFound},
			}
			legacy, err := NewStoreWithClock(fixture.pool, func() time.Time { return integrationClock })
			if err != nil {
				t.Fatal(err)
			}
			structural := Actor{UserID: active.UserID, ScopeID: active.ScopeID, ScopeKind: active.ScopeKind, SessionID: active.SessionID}
			tests = append(tests, struct {
				name        string
				actor       Actor
				targetScope uuid.UUID
				rollout     commandRollout
				store       *Store
				want        error
			}{name: "structural metadata through IAM store", actor: structural, targetScope: firstScopeID,
				rollout: fixture.createRollout(t, firstScopeID, firstUserID, firstConfigID, operation.name+"-iam-structural"), store: fixture.store, want: ErrPermissionDenied})
			tests = append(tests, struct {
				name        string
				actor       Actor
				targetScope uuid.UUID
				rollout     commandRollout
				store       *Store
				want        error
			}{name: "structural metadata through legacy store", actor: structural, targetScope: firstScopeID,
				rollout: fixture.createRollout(t, firstScopeID, firstUserID, firstConfigID, operation.name+"-legacy"), store: legacy, want: ErrPermissionDenied})

			for _, test := range tests {
				t.Run(test.name, func(t *testing.T) {
					before := loadCommandState(t, fixture.pool, test.rollout.ID)
					_, err := operation.run(t.Context(), test.store,
						commandRequest(test.actor, test.targetScope, test.rollout, operation.name+"-"+strings.ReplaceAll(test.name, " ", "-")))
					if !errors.Is(err, test.want) || containsSensitiveDatabaseError(err) {
						t.Fatalf("command error = %v, want %v", err, test.want)
					}
					assertCommandState(t, loadCommandState(t, fixture.pool, test.rollout.ID), before)
				})
			}
		})
	}
}

func TestIAMRolloutCommandsPreserveNotFoundWithZeroWrites(t *testing.T) {
	operations := []struct {
		name string
		run  func(context.Context, *Store, RolloutCommandRequest) (RolloutCommandResult, error)
	}{
		{name: "cancel", run: func(ctx context.Context, store *Store, request RolloutCommandRequest) (RolloutCommandResult, error) {
			return store.CancelRollout(ctx, request)
		}},
		{name: "retry", run: func(ctx context.Context, store *Store, request RolloutCommandRequest) (RolloutCommandResult, error) {
			return store.RetryRollout(ctx, request)
		}},
	}
	for _, operation := range operations {
		t.Run(operation.name, func(t *testing.T) {
			fixture := newCommandIAMFixture(t, nil)
			platformScopeID := seedCommandScope(t, fixture.pool, ScopeKindPlatform)
			actor := fixture.seedActor(t, platformScopeID, ScopeKindPlatform, PermissionManage)
			tenantScopeID, tenantUserID := seedEdgeScope(t, fixture.pool)
			configID := fixture.persistConfig(t, tenantScopeID, "iam-not-found-"+operation.name)
			witness := fixture.createRollout(t, tenantScopeID, tenantUserID, configID, "iam-not-found-witness-"+operation.name)
			before := loadCommandState(t, fixture.pool, witness.ID)
			_, err := operation.run(t.Context(), fixture.store, commandRequest(
				actor, tenantScopeID, commandRollout{ID: uuid.New(), Revision: 1}, "iam-not-found-"+operation.name,
			))
			if !errors.Is(err, ErrNotFound) || containsSensitiveDatabaseError(err) {
				t.Fatalf("missing rollout error = %v, want %v", err, ErrNotFound)
			}
			assertCommandState(t, loadCommandState(t, fixture.pool, witness.ID), before)
		})
	}
}

func TestIAMRolloutReadsRecheckPermissionAndSession(t *testing.T) {
	fixture := newCommandIAMFixture(t, nil)
	platformScopeID := seedCommandScope(t, fixture.pool, ScopeKindPlatform)
	reader := fixture.seedActor(t, platformScopeID, ScopeKindPlatform, PermissionRead)
	manager := fixture.seedActor(t, platformScopeID, ScopeKindPlatform, PermissionManage)
	tenantScopeID, tenantUserID := seedEdgeScope(t, fixture.pool)
	tenantReader := fixture.seedActor(t, tenantScopeID, ScopeKindTenant, PermissionRead)
	configID := fixture.persistConfig(t, tenantScopeID, "iam-read")
	rollout := fixture.createRollout(t, tenantScopeID, tenantUserID, configID, "iam-read")
	if _, err := fixture.store.GetRollout(t.Context(), reader, tenantScopeID, rollout.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.store.ListRollouts(t.Context(), reader, tenantScopeID, RolloutPageRequest{}); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.store.ListDeployments(t.Context(), reader, tenantScopeID, rollout.ID, DeploymentPageRequest{}); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.store.GetRollout(t.Context(), tenantReader, tenantScopeID, rollout.ID); err != nil {
		t.Fatalf("tenant read: %v", err)
	}
	if _, err := fixture.store.GetRollout(t.Context(), manager, tenantScopeID, rollout.ID); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("manager-only read error = %v", err)
	}
	legacy, err := NewStoreWithClock(fixture.pool, func() time.Time { return integrationClock })
	if err != nil {
		t.Fatal(err)
	}
	structural := Actor{UserID: reader.UserID, ScopeID: reader.ScopeID, ScopeKind: reader.ScopeKind, SessionID: reader.SessionID}
	stores := []struct {
		name  string
		store *Store
	}{
		{name: "IAM", store: fixture.store},
		{name: "legacy", store: legacy},
	}
	reads := []struct {
		name string
		run  func(*Store) error
	}{
		{name: "get rollout", run: func(store *Store) error {
			_, err := store.GetRollout(t.Context(), structural, tenantScopeID, rollout.ID)
			return err
		}},
		{name: "list rollouts", run: func(store *Store) error {
			_, err := store.ListRollouts(t.Context(), structural, tenantScopeID, RolloutPageRequest{})
			return err
		}},
		{name: "list deployments", run: func(store *Store) error {
			_, err := store.ListDeployments(t.Context(), structural, tenantScopeID, rollout.ID, DeploymentPageRequest{})
			return err
		}},
	}
	for _, store := range stores {
		for _, read := range reads {
			t.Run(store.name+"/structural "+read.name, func(t *testing.T) {
				if err := read.run(store.store); !errors.Is(err, ErrPermissionDenied) || containsSensitiveDatabaseError(err) {
					t.Fatalf("structural read error = %v, want %v", err, ErrPermissionDenied)
				}
			})
		}
	}
	fixture.revokeSession(t, reader)
	if _, err := fixture.store.GetRollout(t.Context(), reader, tenantScopeID, rollout.ID); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("revoked read error = %v", err)
	}
}

func TestIAMRolloutCommandRevocationOrdering(t *testing.T) {
	t.Run("command first", func(t *testing.T) {
		baseFixture := newCommandIAMFixture(t, nil)
		blocker := &blockingAuditAppender{
			delegate: audit.New(baseFixture.pool), entered: make(chan struct{}), release: make(chan struct{}),
		}
		store, err := NewIAMStoreWithClockAndAuditor(
			baseFixture.pool, func() time.Time { return integrationClock }, blocker, baseFixture.authorizer,
		)
		if err != nil {
			t.Fatal(err)
		}
		platformScopeID := seedCommandScope(t, baseFixture.pool, ScopeKindPlatform)
		actor := baseFixture.seedActor(t, platformScopeID, ScopeKindPlatform, PermissionManage)
		tenantScopeID, tenantUserID := seedEdgeScope(t, baseFixture.pool)
		configID := baseFixture.persistConfig(t, tenantScopeID, "iam-order-command")
		rollout := baseFixture.createRollout(t, tenantScopeID, tenantUserID, configID, "iam-order-command")
		commandDone := make(chan error, 1)
		go func() {
			_, err := store.CancelRollout(context.Background(), commandRequest(actor, tenantScopeID, rollout, "iam-order-command"))
			commandDone <- err
		}()
		select {
		case <-blocker.entered:
		case <-time.After(10 * time.Second):
			t.Fatal("command did not reach audited post-authorization point")
		}
		revokeDone := make(chan error, 1)
		go func() { revokeDone <- baseFixture.revokeSessionError(context.Background(), actor) }()
		waitForIAMGlobalWaiter(t, baseFixture.pool, "ExclusiveLock")
		close(blocker.release)
		if err := <-commandDone; err != nil {
			t.Fatalf("command-first command: %v", err)
		}
		if err := <-revokeDone; err != nil {
			t.Fatalf("command-first revocation: %v", err)
		}
	})

	t.Run("revocation first", func(t *testing.T) {
		fixture := newCommandIAMFixture(t, nil)
		platformScopeID := seedCommandScope(t, fixture.pool, ScopeKindPlatform)
		actor := fixture.seedActor(t, platformScopeID, ScopeKindPlatform, PermissionManage)
		tenantScopeID, tenantUserID := seedEdgeScope(t, fixture.pool)
		configID := fixture.persistConfig(t, tenantScopeID, "iam-order-revoke")
		rollout := fixture.createRollout(t, tenantScopeID, tenantUserID, configID, "iam-order-revoke")
		before := loadCommandState(t, fixture.pool, rollout.ID)
		revoker, err := fixture.pool.Begin(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = revoker.Rollback(context.Background()) }()
		if err := iamlock.AcquireExclusive(t.Context(), revoker); err != nil {
			t.Fatal(err)
		}
		if _, err := iamlock.AcquireScopes(t.Context(), revoker, []uuid.UUID{actor.ScopeID}); err != nil {
			t.Fatal(err)
		}
		if _, err := revoker.Exec(t.Context(), `UPDATE auth_sessions SET revoked_at=$2,revocation_reason='test_revoked' WHERE id=$1`,
			actor.SessionID, time.Now().UTC()); err != nil {
			t.Fatal(err)
		}
		commandDone := make(chan error, 1)
		go func() {
			_, err := fixture.store.CancelRollout(context.Background(), commandRequest(actor, tenantScopeID, rollout, "iam-order-revoke"))
			commandDone <- err
		}()
		waitForIAMGlobalWaiter(t, fixture.pool, "ShareLock")
		if err := revoker.Commit(t.Context()); err != nil {
			t.Fatal(err)
		}
		if err := <-commandDone; !errors.Is(err, ErrUnauthenticated) {
			t.Fatalf("revocation-first command error = %v", err)
		}
		assertCommandState(t, loadCommandState(t, fixture.pool, rollout.ID), before)
	})
}

func TestIAMRolloutCommandStorageFailureIsStable(t *testing.T) {
	fixture := newCommandIAMFixture(t, nil)
	platformScopeID := seedCommandScope(t, fixture.pool, ScopeKindPlatform)
	actor := fixture.seedActor(t, platformScopeID, ScopeKindPlatform, PermissionManage)
	fixture.pool.Close()
	_, err := fixture.store.CancelRollout(t.Context(), RolloutCommandRequest{
		Actor: actor, ConfigurationScopeID: uuid.New(), RolloutID: uuid.New(), ExpectedRevision: 1,
		IdempotencyKey: "closed-pool", RequestID: uuid.NewString(),
	})
	if !errors.Is(err, ErrUnavailable) || containsSensitiveDatabaseError(err) {
		t.Fatalf("closed pool error = %v", err)
	}
}

func TestIAMConcurrentRolloutCommandsHaveSingleCASWinner(t *testing.T) {
	operations := []struct {
		name    string
		prepare func(*testing.T, *commandIAMFixture, uuid.UUID, uuid.UUID, uuid.UUID) commandRollout
		run     func(context.Context, *Store, RolloutCommandRequest) (RolloutCommandResult, error)
	}{
		{
			name: "cancel",
			prepare: func(test *testing.T, fixture *commandIAMFixture, scopeID, userID, configID uuid.UUID) commandRollout {
				return fixture.createRollout(test, scopeID, userID, configID, "iam-concurrent-cancel")
			},
			run: func(ctx context.Context, store *Store, request RolloutCommandRequest) (RolloutCommandResult, error) {
				return store.CancelRollout(ctx, request)
			},
		},
		{
			name: "retry",
			prepare: func(test *testing.T, fixture *commandIAMFixture, scopeID, userID, configID uuid.UUID) commandRollout {
				rollout := fixture.createRollout(test, scopeID, userID, configID, "iam-concurrent-retry")
				advanceDeploymentState(test, fixture.pool, rollout.DeploymentID, "delivered")
				advanceDeploymentState(test, fixture.pool, rollout.DeploymentID, "failed")
				return rollout
			},
			run: func(ctx context.Context, store *Store, request RolloutCommandRequest) (RolloutCommandResult, error) {
				return store.RetryRollout(ctx, request)
			},
		},
	}
	for _, operation := range operations {
		t.Run(operation.name, func(t *testing.T) {
			fixture := newCommandIAMFixture(t, nil)
			platformScopeID := seedCommandScope(t, fixture.pool, ScopeKindPlatform)
			actor := fixture.seedActor(t, platformScopeID, ScopeKindPlatform, PermissionManage)
			tenantScopeID, tenantUserID := seedEdgeScope(t, fixture.pool)
			configID := fixture.persistConfig(t, tenantScopeID, "iam-concurrent-"+operation.name)
			rollout := operation.prepare(t, fixture, tenantScopeID, tenantUserID, configID)
			start := make(chan struct{})
			errs := make([]error, 2)
			var wait sync.WaitGroup
			for index := range errs {
				wait.Add(1)
				go func(index int) {
					defer wait.Done()
					<-start
					_, errs[index] = operation.run(context.Background(), fixture.store, commandRequest(
						actor, tenantScopeID, rollout, "iam-concurrent-"+operation.name+"-"+string(rune('a'+index)),
					))
				}(index)
			}
			close(start)
			wait.Wait()
			successes, conflicts := 0, 0
			for _, err := range errs {
				switch {
				case err == nil:
					successes++
				case errors.Is(err, ErrRevisionConflict):
					conflicts++
				default:
					t.Fatalf("concurrent %s error = %v", operation.name, err)
				}
			}
			if successes != 1 || conflicts != 1 {
				t.Fatalf("concurrent %s successes=%d conflicts=%d", operation.name, successes, conflicts)
			}
			var requests int
			if err := fixture.pool.QueryRow(t.Context(), `SELECT count(*) FROM edge_rollout_write_requests`).Scan(&requests); err != nil {
				t.Fatal(err)
			}
			if requests != 1 {
				t.Fatalf("concurrent %s persisted requests=%d", operation.name, requests)
			}
		})
	}
}

func newCommandIAMFixture(t *testing.T, appender auditAppender) *commandIAMFixture {
	t.Helper()
	pool := openEdgeTestDatabase(t, true)
	if appender == nil {
		appender = audit.New(pool)
	}
	tokens, err := identity.NewTokenManager("edgedeployment-iam-test-access-token-secret", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	sessions, err := sessioncredential.NewVerifier(tokens, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	apiKeys, err := apikeycredential.NewVerifier(bytes.Repeat([]byte{0x65}, 32), time.Now)
	if err != nil {
		t.Fatal(err)
	}
	authorizer, err := iamlock.NewAuthorizer(sessions, apiKeys)
	if err != nil {
		t.Fatal(err)
	}
	store, err := NewIAMStoreWithClockAndAuditor(pool, func() time.Time { return integrationClock }, appender, authorizer)
	if err != nil {
		t.Fatal(err)
	}
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &commandIAMFixture{
		pool: pool, tokens: tokens, authorizer: authorizer, store: store,
		publicKey: publicKey, privateKey: privateKey,
	}
}

func seedCommandScope(t *testing.T, pool *pgxpool.Pool, kind string) uuid.UUID {
	t.Helper()
	scopeID := uuid.New()
	if kind == ScopeKindPlatform {
		if _, err := pool.Exec(t.Context(), `INSERT INTO access_scopes(id,kind) VALUES($1,'platform')`, scopeID); err != nil {
			t.Fatal(err)
		}
		return scopeID
	}
	t.Fatal("tenant scopes must be seeded with seedEdgeScope")
	return uuid.Nil
}

func (fixture *commandIAMFixture) seedActor(t *testing.T, scopeID uuid.UUID, scopeKind string, permissions ...string) Actor {
	t.Helper()
	userID, roleID := uuid.New(), uuid.New()
	username := "deploy-iam-" + strings.ReplaceAll(userID.String(), "-", "")[:16]
	if _, err := fixture.pool.Exec(t.Context(), `
		WITH inserted_user AS (
			INSERT INTO users(id,username,display_name,password_hash)
			VALUES($1,$2,'Deployment IAM user','not-used')
		), inserted_membership AS (
			INSERT INTO memberships(scope_id,user_id) VALUES($3,$1)
		), inserted_role AS (
			-- Direct role inserts must be system roles; custom roles only come from
			-- custom RBAC facts (migration 042).
			INSERT INTO roles(id,scope_id,name,description,system_role)
			VALUES($4,$3,$5,'Deployment IAM role',true)
		), inserted_permissions AS (
			INSERT INTO role_permissions(role_id,permission_name)
			SELECT $4,name FROM permissions WHERE name=ANY($6::text[])
		)
		INSERT INTO role_assignments(scope_id,user_id,role_id) VALUES($3,$1,$4)`,
		userID, username, scopeID, roleID, "deployment_"+strings.ReplaceAll(roleID.String(), "-", "")[:16], permissions); err != nil {
		t.Fatal(err)
	}
	sessionID := uuid.New()
	now := time.Now().UTC().Truncate(time.Microsecond)
	refreshDigest := sha256.Sum256(sessionID[:])
	if _, err := fixture.pool.Exec(t.Context(), `INSERT INTO auth_sessions(
		id,family_id,user_id,scope_id,refresh_token_hash,created_at,expires_at
	) VALUES($1,$2,$3,$4,$5,$6,$7)`, sessionID, uuid.New(), userID, scopeID,
		refreshDigest[:], now.Add(-time.Minute), now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	return fixture.mintActor(t, userID, scopeID, scopeKind, sessionID)
}

func (fixture *commandIAMFixture) mintActor(t *testing.T, userID, scopeID uuid.UUID, scopeKind string, sessionID uuid.UUID) Actor {
	t.Helper()
	rawToken, _, err := fixture.tokens.Mint(userID, scopeID, sessionID)
	if err != nil {
		t.Fatal(err)
	}
	actor, err := NewSessionActor(userID, scopeID, scopeKind, sessionID, rawToken)
	if err != nil {
		t.Fatal(err)
	}
	return actor
}

func (fixture *commandIAMFixture) persistConfig(t *testing.T, scopeID uuid.UUID, key string) uuid.UUID {
	t.Helper()
	return persistTestConfig(t, fixture.store, testConfigRequest(
		t, scopeID, key, "iam-command-signing-key", fixture.publicKey, fixture.privateKey, []byte(key),
	)).ID
}

func (fixture *commandIAMFixture) createRollout(
	t *testing.T,
	scopeID, nodeOwnerID, configID uuid.UUID,
	key string,
) commandRollout {
	t.Helper()
	nodeID := uuid.New()
	seedEdgeNode(t, fixture.pool, scopeID, nodeOwnerID, nodeID)
	created, err := fixture.store.CreateRollout(t.Context(), testRolloutRequest(scopeID, configID, []uuid.UUID{nodeID}, key))
	if err != nil {
		t.Fatal(err)
	}
	return commandRollout{
		ID: created.Rollout.ID, Revision: created.Rollout.Revision,
		DeploymentID: created.Rollout.Deployments[0].ID,
	}
}

func commandRequest(actor Actor, scopeID uuid.UUID, rollout commandRollout, key string) RolloutCommandRequest {
	return RolloutCommandRequest{
		Actor: actor, ConfigurationScopeID: scopeID, RolloutID: rollout.ID,
		ExpectedRevision: rollout.Revision, IdempotencyKey: key, RequestID: uuid.NewString(),
	}
}

func (fixture *commandIAMFixture) revokeSession(t *testing.T, actor Actor) {
	t.Helper()
	if err := fixture.revokeSessionError(t.Context(), actor); err != nil {
		t.Fatal(err)
	}
}

func (fixture *commandIAMFixture) revokeSessionError(ctx context.Context, actor Actor) error {
	return pgx.BeginFunc(ctx, fixture.pool, func(tx pgx.Tx) error {
		if err := iamlock.AcquireExclusive(ctx, tx); err != nil {
			return err
		}
		if _, err := iamlock.AcquireScopes(ctx, tx, []uuid.UUID{actor.ScopeID}); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `UPDATE auth_sessions SET revoked_at=$2,revocation_reason='test_revoked' WHERE id=$1`,
			actor.SessionID, time.Now().UTC())
		return err
	})
}

func loadCommandState(t *testing.T, pool *pgxpool.Pool, rolloutID uuid.UUID) commandState {
	t.Helper()
	var state commandState
	if err := pool.QueryRow(t.Context(), `SELECT
		(SELECT count(*) FROM edge_rollout_write_requests),
		(SELECT count(*) FROM rollouts),
		(SELECT count(*) FROM node_deployments),
		(SELECT count(*) FROM edge_command_outbox),
		(SELECT count(*) FROM audit_events),
		(SELECT status FROM rollouts WHERE id=$1),
		(SELECT revision FROM rollouts WHERE id=$1),
		(SELECT count(*) FROM node_deployments WHERE rollout_id=$1 AND state='cancelled'),
		(SELECT count(*) FROM edge_command_outbox outbox JOIN node_deployments deployment
		 ON deployment.id=outbox.deployment_id AND deployment.attempt=outbox.deployment_attempt
		 WHERE deployment.rollout_id=$1 AND outbox.status='cancelled')`, rolloutID).Scan(
		&state.requests, &state.rollouts, &state.deployments, &state.outbox, &state.audits,
		&state.rolloutStatus, &state.rolloutRevision, &state.cancelledDeployments, &state.cancelledOutbox,
	); err != nil {
		t.Fatal(err)
	}
	return state
}

func assertCommandState(t *testing.T, actual, expected commandState) {
	t.Helper()
	if actual != expected {
		t.Fatalf("command state = %+v, want %+v", actual, expected)
	}
}

func waitForIAMGlobalWaiter(t *testing.T, pool *pgxpool.Pool, mode string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		var waiting bool
		if err := pool.QueryRow(t.Context(), `SELECT EXISTS(
			SELECT 1 FROM pg_catalog.pg_locks
			WHERE locktype='advisory' AND classid=1229016321::oid AND objid=1::oid
			  AND objsubid=2 AND mode=$1 AND NOT granted
		)`, mode).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for IAM global %s waiter", mode)
}

func containsSensitiveDatabaseError(err error) bool {
	if err == nil {
		return false
	}
	message := err.Error()
	for _, sensitive := range []string{"SQLSTATE", "40001", "40P01", "55P03", "pgx", "postgres"} {
		if strings.Contains(message, sensitive) {
			return true
		}
	}
	return false
}
