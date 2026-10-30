package iamlock_test

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"math/rand"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/apikeycredential"
	"github.com/cdnca/cdnca/services/control-api/internal/database"
	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
	"github.com/cdnca/cdnca/services/control-api/internal/iamlock"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/sessioncredential"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const testPermission069 = "iam069.test.write"

func TestAuthorizeSessionPreflightsLiveCredentialBeforeTargetLocks(t *testing.T) {
	source, err := os.ReadFile("authorizer.go")
	if err != nil {
		t.Fatal(err)
	}
	start := strings.Index(string(source), "func (authorizer *Authorizer) AuthorizeSession")
	end := strings.Index(string(source[start:]), "\nfunc (authorizer *Authorizer) AuthorizeAPIKey")
	if start < 0 || end < 0 {
		t.Fatal("AuthorizeSession source bounds not found")
	}
	body := string(source[start : start+end])
	preflight := strings.Index(body, "preflightSessionCredential")
	targetLocks := strings.Index(body,
		"AcquireScopes(ctx, tx, []uuid.UUID{authenticationScopeID, targetScopeID})")
	formalVerify := strings.Index(body,
		"authorizer.sessions.VerifyTx(ctx, tx, rawToken, lockedScopes)")
	if preflight < 0 || targetLocks < 0 || formalVerify < 0 ||
		preflight > targetLocks || targetLocks > formalVerify {
		t.Fatalf("AuthorizeSession order preflight=%d target_locks=%d formal_verify=%d",
			preflight, targetLocks, formalVerify)
	}
}

type fixture069 struct {
	pool       *pgxpool.Pool
	authorizer *iamlock.Authorizer
	now        time.Time
	tenantID   uuid.UUID
	scopeID    uuid.UUID
	userID     uuid.UUID
	roleID     uuid.UUID
	sessionID  uuid.UUID
	apiKeyID   uuid.UUID
	rawSession string
	rawAPIKey  string
}

type credentialKind069 string

const (
	sessionKind069 credentialKind069 = "session"
	apiKeyKind069  credentialKind069 = "api_key"
)

func TestIAM069RevocationCommitOrdersAndReplay(t *testing.T) {
	tests := []struct {
		name       string
		credential credentialKind069
		mutation   func(context.Context, pgx.Tx, *fixture069) error
	}{
		{name: "system role assignment", credential: sessionKind069, mutation: revokeAssignment069},
		{name: "role permission", credential: sessionKind069, mutation: revokePermission069},
		{name: "account", credential: sessionKind069, mutation: disableAccount069},
		{name: "session", credential: sessionKind069, mutation: revokeSession069},
		{name: "api key", credential: apiKeyKind069, mutation: revokeAPIKey069},
	}
	for index, test := range tests {
		t.Run(test.name+"/write-first", func(t *testing.T) {
			fixture, cleanup := newIAM069Fixture(t)
			defer cleanup()
			key := "write-first-" + strings.ReplaceAll(test.name, " ", "-")
			style := []string{"create", "update", "approve"}[index%3]

			writer, err := fixture.pool.Begin(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			defer writer.Rollback(context.Background())
			if err := fixture.authorize(t.Context(), writer, test.credential); err != nil {
				t.Fatalf("authorize writer: %v", err)
			}

			revokeDone := make(chan error, 1)
			go func() {
				revokeDone <- fixture.revoke(context.Background(), test.mutation)
			}()
			select {
			case err := <-revokeDone:
				t.Fatalf("revocation did not wait for shared global lock: %v", err)
			case <-time.After(75 * time.Millisecond):
			}

			if err := insertBusiness069(t.Context(), writer, key, style); err != nil {
				t.Fatal(err)
			}
			if err := writer.Commit(t.Context()); err != nil {
				t.Fatal(err)
			}
			if err := <-revokeDone; err != nil {
				t.Fatal(err)
			}
			assertBusinessCount069(t, fixture.pool, key, 1)

			err = fixture.write(t.Context(), test.credential, key, style, false)
			if !errors.Is(err, iamlock.ErrPermissionDenied) {
				t.Fatalf("post-revocation replay error = %v, want permission denied", err)
			}
			assertBusinessCount069(t, fixture.pool, key, 1)
		})

		t.Run(test.name+"/revoke-first", func(t *testing.T) {
			fixture, cleanup := newIAM069Fixture(t)
			defer cleanup()
			key := "revoke-first-" + strings.ReplaceAll(test.name, " ", "-")

			revoker, err := fixture.pool.Begin(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			defer revoker.Rollback(context.Background())
			if err := iamlock.AcquireExclusive(t.Context(), revoker); err != nil {
				t.Fatal(err)
			}
			if _, err := iamlock.AcquireScopes(t.Context(), revoker, []uuid.UUID{fixture.scopeID}); err != nil {
				t.Fatal(err)
			}
			if err := test.mutation(t.Context(), revoker, fixture); err != nil {
				t.Fatal(err)
			}

			writeDone := make(chan error, 1)
			go func() {
				writeDone <- fixture.write(context.Background(), test.credential, key, "approve", false)
			}()
			select {
			case err := <-writeDone:
				t.Fatalf("write did not wait for exclusive global lock: %v", err)
			case <-time.After(75 * time.Millisecond):
			}
			if err := revoker.Commit(t.Context()); err != nil {
				t.Fatal(err)
			}
			if err := <-writeDone; !errors.Is(err, iamlock.ErrPermissionDenied) {
				t.Fatalf("revoke-first write error = %v, want permission denied", err)
			}
			assertBusinessCount069(t, fixture.pool, key, 0)
			assertIdempotencyCount069(t, fixture.pool, key, 0)
		})
	}
}

func TestIAM069AuditAndIdempotencyRollback(t *testing.T) {
	fixture, cleanup := newIAM069Fixture(t)
	defer cleanup()
	key := "audit-rollback"
	if err := fixture.write(t.Context(), sessionKind069, key, "update", true); err == nil ||
		!strings.Contains(err.Error(), "simulated audit failure") {
		t.Fatalf("write error = %v", err)
	}
	assertBusinessCount069(t, fixture.pool, key, 0)
	assertIdempotencyCount069(t, fixture.pool, key, 0)
}

func TestIAM069StrongIsolationRevocationFailsClosedAsUnavailable(t *testing.T) {
	for _, isolation := range []struct {
		name  string
		level pgx.TxIsoLevel
	}{
		{name: "repeatable-read", level: pgx.RepeatableRead},
		{name: "serializable", level: pgx.Serializable},
	} {
		for _, revocation := range []struct {
			name       string
			credential credentialKind069
			mutation   func(context.Context, pgx.Tx, *fixture069) error
		}{
			{name: "session", credential: sessionKind069, mutation: revokeSession069},
			{name: "role-permission", credential: sessionKind069, mutation: revokePermission069},
			{name: "api-key", credential: apiKeyKind069, mutation: revokeAPIKey069},
		} {
			t.Run(isolation.name+"/"+revocation.name, func(t *testing.T) {
				fixture, cleanup := newIAM069Fixture(t)
				defer cleanup()
				key := "strong-isolation-" + isolation.name + "-" + revocation.name

				writer, err := fixture.pool.BeginTx(t.Context(), pgx.TxOptions{IsoLevel: isolation.level})
				if err != nil {
					t.Fatal(err)
				}
				defer writer.Rollback(context.Background())
				var snapshot string
				if err := writer.QueryRow(t.Context(), `SELECT pg_catalog.txid_current_snapshot()`).Scan(&snapshot); err != nil {
					t.Fatal(err)
				}
				if snapshot == "" {
					t.Fatal("strong-isolation transaction did not establish a snapshot")
				}
				if err := fixture.revoke(t.Context(), revocation.mutation); err != nil {
					t.Fatal(err)
				}

				err = fixture.writeTx(t.Context(), writer, revocation.credential, key, "approve", false)
				if !errors.Is(err, iamlock.ErrUnavailable) {
					t.Fatalf("write error = %v, want unavailable", err)
				}
				if strings.Contains(fmt.Sprint(err), "40001") || strings.Contains(fmt.Sprint(err), "SQLSTATE") {
					t.Fatalf("public error exposed PostgreSQL serialization detail: %v", err)
				}
				assertBusinessCount069(t, fixture.pool, key, 0)
				assertIdempotencyCount069(t, fixture.pool, key, 0)
				var audit int
				if err := fixture.pool.QueryRow(t.Context(),
					`SELECT count(*) FROM iam069_audit WHERE idempotency_key=$1`, key).Scan(&audit); err != nil {
					t.Fatal(err)
				}
				if audit != 0 {
					t.Fatalf("audit count = %d, want 0", audit)
				}
				if err := writer.Rollback(t.Context()); err != nil {
					t.Fatal(err)
				}

				err = fixture.write(t.Context(), revocation.credential, key, "approve", false)
				if !errors.Is(err, iamlock.ErrPermissionDenied) || errors.Is(err, iamlock.ErrUnavailable) {
					t.Fatalf("fresh retry error = %v, want permission denied", err)
				}
				assertBusinessCount069(t, fixture.pool, key, 0)
				assertIdempotencyCount069(t, fixture.pool, key, 0)
				if err := fixture.pool.QueryRow(t.Context(),
					`SELECT count(*) FROM iam069_audit WHERE idempotency_key=$1`, key).Scan(&audit); err != nil {
					t.Fatal(err)
				}
				if audit != 0 {
					t.Fatalf("audit count after fresh retry = %d, want 0", audit)
				}
			})
		}
	}
}

func TestIAM069UnconfiguredVerifierFailsClosedAsUnavailable(t *testing.T) {
	fixture, cleanup := newIAM069Fixture(t)
	defer cleanup()
	sessions, err := sessioncredential.NewVerifier(mustTokenManager069(t), time.Now)
	if err != nil {
		t.Fatal(err)
	}
	apiKeys, err := apikeycredential.NewVerifier(bytes.Repeat([]byte{3}, 32), time.Now)
	if err != nil {
		t.Fatal(err)
	}
	sessionsWithZeroTokens, err := sessioncredential.NewVerifier(new(identity.TokenManager), time.Now)
	if err != nil {
		t.Fatal(err)
	}

	for _, test := range []struct {
		name       string
		authorizer *iamlock.Authorizer
		call       func(context.Context, *iamlock.Authorizer, pgx.Tx) error
	}{
		{
			name:       "zero session verifier",
			authorizer: mustAuthorizer069(t, new(sessioncredential.Verifier), apiKeys),
			call: func(ctx context.Context, authorizer *iamlock.Authorizer, tx pgx.Tx) error {
				_, err := authorizer.AuthorizeSession(ctx, tx, "malformed-session", fixture.scopeID, testPermission069)
				return err
			},
		},
		{
			name:       "nested zero session verifier",
			authorizer: mustAuthorizer069(t, sessionsWithZeroTokens, apiKeys),
			call: func(ctx context.Context, authorizer *iamlock.Authorizer, tx pgx.Tx) error {
				_, err := authorizer.AuthorizeSession(ctx, tx, "malformed-session", fixture.scopeID, testPermission069)
				return err
			},
		},
		{
			name:       "zero API key verifier",
			authorizer: mustAuthorizer069(t, sessions, new(apikeycredential.Verifier)),
			call: func(ctx context.Context, authorizer *iamlock.Authorizer, tx pgx.Tx) error {
				_, err := authorizer.AuthorizeAPIKey(ctx, tx, "malformed-api-key", fixture.scopeID, testPermission069)
				return err
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			holder, err := fixture.pool.Begin(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			defer holder.Rollback(context.Background())
			if _, err := holder.Exec(t.Context(),
				`SELECT pg_catalog.pg_advisory_xact_lock(1229016321, 1)`); err != nil {
				t.Fatal(err)
			}
			holderPID := int32(holder.Conn().PgConn().PID())

			target, err := fixture.pool.Begin(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			defer target.Rollback(context.Background())
			targetPID := int32(target.Conn().PgConn().PID())

			callContext, cancelCall := context.WithCancel(t.Context())
			defer cancelCall()
			callDone := make(chan error, 1)
			go func() {
				callDone <- test.call(callContext, test.authorizer, target)
			}()

			poll := time.NewTicker(2 * time.Millisecond)
			defer poll.Stop()
			watchdog := time.NewTimer(2 * time.Second)
			defer watchdog.Stop()
			var authorizationErr error
		waitForResult:
			for {
				select {
				case authorizationErr = <-callDone:
					break waitForResult
				case <-poll.C:
					var blockedByHolder, waitingForGlobal bool
					err := fixture.pool.QueryRow(t.Context(), `SELECT
						$2::integer = ANY(pg_catalog.pg_blocking_pids($1::integer)),
						EXISTS (
							SELECT 1 FROM pg_catalog.pg_locks
							WHERE pid=$1::integer AND locktype='advisory'
							  AND classid=1229016321::oid AND objid=1::oid AND objsubid=2
							  AND mode='ShareLock' AND NOT granted
						)`, targetPID, holderPID).Scan(&blockedByHolder, &waitingForGlobal)
					if err != nil {
						cancelCall()
						_ = holder.Rollback(context.Background())
						<-callDone
						t.Fatal(err)
					}
					if blockedByHolder || waitingForGlobal {
						cancelCall()
						_ = holder.Rollback(context.Background())
						afterCancel := <-callDone
						t.Fatalf("unconfigured verifier attempted the global lock before failing closed: blocked=%t waiting=%t error_after_cancel=%v",
							blockedByHolder, waitingForGlobal, afterCancel)
					}
				case <-watchdog.C:
					cancelCall()
					_ = holder.Rollback(context.Background())
					afterCancel := <-callDone
					t.Fatalf("unconfigured verifier did not fail closed before the lock probe watchdog: %v", afterCancel)
				}
			}

			if callContext.Err() != nil {
				t.Fatalf("authorization returned only after context cancellation: %v", authorizationErr)
			}
			if !errors.Is(authorizationErr, iamlock.ErrUnavailable) ||
				errors.Is(authorizationErr, iamlock.ErrPermissionDenied) {
				t.Fatalf("authorization error = %v, want unavailable", authorizationErr)
			}

			var blockerCount, advisoryLocks, relationLocks int
			if err := fixture.pool.QueryRow(t.Context(), `SELECT
				pg_catalog.cardinality(pg_catalog.pg_blocking_pids($1::integer)),
				(SELECT count(*) FROM pg_catalog.pg_locks WHERE pid=$1::integer AND locktype='advisory'),
				(SELECT count(*) FROM pg_catalog.pg_locks WHERE pid=$1::integer AND locktype='relation')`,
				targetPID).Scan(&blockerCount, &advisoryLocks, &relationLocks); err != nil {
				t.Fatal(err)
			}
			if blockerCount != 0 || advisoryLocks != 0 || relationLocks != 0 {
				t.Fatalf("unconfigured verifier touched database locks: blockers=%d advisory=%d relation=%d",
					blockerCount, advisoryLocks, relationLocks)
			}
		})
	}
}

func TestIAM069ForgedCredentialsAndProtocolBypassAreDenied(t *testing.T) {
	fixture, cleanup := newIAM069Fixture(t)
	defer cleanup()
	tests := []struct {
		name string
		raw  string
		call func(context.Context, pgx.Tx, string) error
	}{
		{
			name: "session signature",
			raw:  fixture.rawSession + "x",
			call: func(ctx context.Context, tx pgx.Tx, raw string) error {
				_, err := fixture.authorizer.AuthorizeSession(ctx, tx, raw, fixture.scopeID, testPermission069)
				return err
			},
		},
		{
			name: "api key secret",
			raw:  fixture.rawAPIKey[:len(fixture.rawAPIKey)-1] + "A",
			call: func(ctx context.Context, tx pgx.Tx, raw string) error {
				_, err := fixture.authorizer.AuthorizeAPIKey(ctx, tx, raw, fixture.scopeID, testPermission069)
				return err
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := pgx.BeginFunc(t.Context(), fixture.pool, func(tx pgx.Tx) error {
				return test.call(t.Context(), tx, test.raw)
			})
			if !errors.Is(err, iamlock.ErrInvalidCredential) ||
				!errors.Is(err, iamlock.ErrPermissionDenied) {
				t.Fatalf("forged credential error = %v, want invalid credential and permission denied", err)
			}
			if strings.Contains(fmt.Sprint(err), test.raw) {
				t.Fatal("credential appeared in error")
			}
		})
	}

	err := pgx.BeginFunc(t.Context(), fixture.pool, func(tx pgx.Tx) error {
		_, err := fixture.authorizer.AuthorizeSession(
			t.Context(), tx, fixture.rawSession, uuid.New(), testPermission069)
		return err
	})
	if !errors.Is(err, iamlock.ErrPermissionDenied) {
		t.Fatalf("unknown target scope error = %v", err)
	}

	sessions, err := sessioncredential.NewVerifier(
		mustTokenManager069(t), func() time.Time { return fixture.now })
	if err != nil {
		t.Fatal(err)
	}
	tx, err := fixture.pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(context.Background())
	if _, err := sessions.VerifyTx(t.Context(), tx, fixture.rawSession, []uuid.UUID{fixture.scopeID}); !errors.Is(err, sessioncredential.ErrProtocolRequired) {
		t.Fatalf("direct verifier without protocol error = %v", err)
	}
}

func TestIAM069CredentialClassificationContract(t *testing.T) {
	for _, test := range []struct {
		name    string
		prepare func(context.Context, *fixture069) error
		invalid bool
	}{
		{
			name: "expired session",
			prepare: func(ctx context.Context, fixture *fixture069) error {
				return fixture.revoke(ctx, func(ctx context.Context, tx pgx.Tx, fixture *fixture069) error {
					_, err := tx.Exec(ctx, `UPDATE auth_sessions SET expires_at=$2 WHERE id=$1`,
						fixture.sessionID, fixture.now.Add(-time.Second))
					return err
				})
			},
			invalid: true,
		},
		{name: "revoked session", prepare: func(ctx context.Context, fixture *fixture069) error {
			return fixture.revoke(ctx, revokeSession069)
		}, invalid: true},
		{name: "permission revoked", prepare: func(ctx context.Context, fixture *fixture069) error {
			return fixture.revoke(ctx, revokePermission069)
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture, cleanup := newIAM069Fixture(t)
			defer cleanup()
			if err := test.prepare(t.Context(), fixture); err != nil {
				t.Fatal(err)
			}
			err := pgx.BeginFunc(t.Context(), fixture.pool, func(tx pgx.Tx) error {
				return fixture.authorize(t.Context(), tx, sessionKind069)
			})
			if !errors.Is(err, iamlock.ErrPermissionDenied) ||
				errors.Is(err, iamlock.ErrInvalidCredential) != test.invalid {
				t.Fatalf("authorization error=%v permission=%t invalid=%t want_invalid=%t", err,
					errors.Is(err, iamlock.ErrPermissionDenied),
					errors.Is(err, iamlock.ErrInvalidCredential), test.invalid)
			}
		})
	}
}

func TestIAM069InvalidSessionsFailBeforeUntrustedTargetScopeLocks(t *testing.T) {
	for _, test := range []struct {
		name    string
		prepare func(context.Context, *fixture069) (string, error)
	}{
		{
			name: "fake signed session",
			prepare: func(_ context.Context, fixture *fixture069) (string, error) {
				raw, _, err := mustTokenManager069(t).Mint(fixture.userID, fixture.scopeID, uuid.New())
				return raw, err
			},
		},
		{
			name: "revoked session",
			prepare: func(ctx context.Context, fixture *fixture069) (string, error) {
				return fixture.rawSession, fixture.revoke(ctx, revokeSession069)
			},
		},
		{
			name: "expired session",
			prepare: func(ctx context.Context, fixture *fixture069) (string, error) {
				err := fixture.revoke(ctx, func(ctx context.Context, tx pgx.Tx, fixture *fixture069) error {
					_, err := tx.Exec(ctx, `UPDATE auth_sessions SET expires_at=$2 WHERE id=$1`,
						fixture.sessionID, fixture.now.Add(-time.Second))
					return err
				})
				return fixture.rawSession, err
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture, cleanup := newIAM069Fixture(t)
			defer cleanup()
			rawSession, err := test.prepare(t.Context(), fixture)
			if err != nil {
				t.Fatal(err)
			}
			missingTargetScopeID := uuid.New()
			blocker, err := fixture.pool.Begin(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			defer blocker.Rollback(context.Background())
			if _, err := blocker.Exec(t.Context(), `SELECT pg_catalog.pg_advisory_xact_lock(
				1229016322, pg_catalog.hashtext('iam-scope:v1:' || $1::text) & 2147483647)`,
				missingTargetScopeID); err != nil {
				t.Fatal(err)
			}

			authorizationTx, err := fixture.pool.Begin(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			defer authorizationTx.Rollback(context.Background())
			done := make(chan error, 1)
			go func() {
				_, err := fixture.authorizer.AuthorizeSession(context.Background(), authorizationTx,
					rawSession, missingTargetScopeID, testPermission069)
				done <- err
			}()
			select {
			case err := <-done:
				if !errors.Is(err, iamlock.ErrInvalidCredential) {
					t.Fatalf("invalid session error = %v, want invalid credential", err)
				}
			case <-time.After(400 * time.Millisecond):
				_ = blocker.Rollback(context.Background())
				err := <-done
				t.Fatalf("invalid session reached untrusted target scope lock before rejection: %v", err)
			}
			assertBusinessCount069(t, fixture.pool, "invalid-session-target-lock", 0)
			assertIdempotencyCount069(t, fixture.pool, "invalid-session-target-lock", 0)
			var audits int
			if err := fixture.pool.QueryRow(t.Context(),
				`SELECT count(*) FROM iam069_audit WHERE idempotency_key='invalid-session-target-lock'`).
				Scan(&audits); err != nil {
				t.Fatal(err)
			}
			if audits != 0 {
				t.Fatalf("invalid session audit count = %d, want 0", audits)
			}
		})
	}
}

func TestIAM069ScopeOrderingConcurrencyAndUpgradeRejection(t *testing.T) {
	fixture, cleanup := newIAM069Fixture(t)
	defer cleanup()
	scopes := []uuid.UUID{fixture.scopeID, uuid.New(), uuid.New(), uuid.New()}
	for index := 0; index < 36; index++ {
		inputs := make([][]uuid.UUID, 2)
		for worker := range inputs {
			inputs[worker] = append([]uuid.UUID(nil), scopes...)
			rand.New(rand.NewSource(int64(index*17+worker))).Shuffle(len(inputs[worker]), func(i, j int) {
				inputs[worker][i], inputs[worker][j] = inputs[worker][j], inputs[worker][i]
			})
		}
		start := make(chan struct{})
		errorsByWorker := make(chan error, 2)
		var workers sync.WaitGroup
		for _, input := range inputs {
			workers.Add(1)
			go func(input []uuid.UUID) {
				defer workers.Done()
				<-start
				err := pgx.BeginFunc(context.Background(), fixture.pool, func(tx pgx.Tx) error {
					if err := iamlock.AcquireShared(context.Background(), tx); err != nil {
						return err
					}
					canonical, err := iamlock.AcquireScopes(context.Background(), tx, input)
					if err != nil {
						return err
					}
					if len(canonical) != len(scopes) {
						return fmt.Errorf("canonical scope count = %d", len(canonical))
					}
					_, err = tx.Exec(context.Background(), `SELECT pg_sleep(0.001)`)
					return err
				})
				errorsByWorker <- err
			}(input)
		}
		close(start)
		workers.Wait()
		close(errorsByWorker)
		for err := range errorsByWorker {
			if err != nil {
				t.Fatalf("round %d: %v", index, err)
			}
		}
	}

	tx, err := fixture.pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(context.Background())
	if err := iamlock.AcquireShared(t.Context(), tx); err != nil {
		t.Fatal(err)
	}
	if err := iamlock.AcquireExclusive(t.Context(), tx); !errors.Is(err, iamlock.ErrUpgradeForbidden) {
		t.Fatalf("shared to exclusive error = %v", err)
	}
}

func TestIAM069DifferentScopeSharedLocksProceedConcurrently(t *testing.T) {
	fixture, cleanup := newIAM069Fixture(t)
	defer cleanup()
	first, second := fixture.scopeID, uuid.New()
	tx1, err := fixture.pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer tx1.Rollback(context.Background())
	if err := iamlock.AcquireShared(t.Context(), tx1); err != nil {
		t.Fatal(err)
	}
	if _, err := iamlock.AcquireScopes(t.Context(), tx1, []uuid.UUID{first}); err != nil {
		t.Fatal(err)
	}

	done := make(chan error, 1)
	go func() {
		done <- pgx.BeginFunc(context.Background(), fixture.pool, func(tx pgx.Tx) error {
			if err := iamlock.AcquireShared(context.Background(), tx); err != nil {
				return err
			}
			_, err := iamlock.AcquireScopes(context.Background(), tx, []uuid.UUID{second})
			return err
		})
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("different-scope shared lock was serialized")
	}
}

func TestIAM069ThreeTransactionRevocationDeadlockStress(t *testing.T) {
	fixture, cleanup := newIAM069Fixture(t)
	defer cleanup()
	tests := []struct {
		name       string
		credential credentialKind069
		mutation   func(context.Context, pgx.Tx, *fixture069) error
		restore    func(context.Context, pgx.Tx, *fixture069) error
	}{
		{name: "assignment", credential: sessionKind069, mutation: revokeAssignment069, restore: restoreAssignment069},
		{name: "permission", credential: sessionKind069, mutation: revokePermission069, restore: restorePermission069},
		{name: "account", credential: sessionKind069, mutation: disableAccount069, restore: restoreAccount069},
		{name: "session", credential: sessionKind069, mutation: revokeSession069, restore: restoreSession069},
		{name: "api-key", credential: apiKeyKind069, mutation: revokeAPIKey069, restore: restoreAPIKey069},
	}

	for round := 0; round < 36; round++ {
		test := tests[round%len(tests)]
		key := fmt.Sprintf("three-tx-%02d-%s", round, test.name)
		style := []string{"create", "update", "approve"}[round%3]

		writer, err := fixture.pool.Begin(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		if err := fixture.authorize(t.Context(), writer, test.credential); err != nil {
			_ = writer.Rollback(context.Background())
			t.Fatalf("round %d authorize writer: %v", round, err)
		}

		revoker, err := fixture.pool.Begin(t.Context())
		if err != nil {
			_ = writer.Rollback(context.Background())
			t.Fatal(err)
		}
		var revokerPID uint32
		if err := revoker.QueryRow(t.Context(), `SELECT pg_backend_pid()`).Scan(&revokerPID); err != nil {
			_ = revoker.Rollback(context.Background())
			_ = writer.Rollback(context.Background())
			t.Fatal(err)
		}
		revokeDone := make(chan error, 1)
		go func() {
			err := iamlock.AcquireExclusive(context.Background(), revoker)
			if err == nil {
				_, err = iamlock.AcquireScopes(context.Background(), revoker, []uuid.UUID{fixture.scopeID})
			}
			if err == nil {
				err = test.mutation(context.Background(), revoker, fixture)
			}
			if err == nil {
				err = revoker.Commit(context.Background())
			} else {
				_ = revoker.Rollback(context.Background())
			}
			revokeDone <- err
		}()
		waitForGlobalWaiter069(t, fixture.pool, revokerPID, "ExclusiveLock")

		replay, err := fixture.pool.Begin(t.Context())
		if err != nil {
			_ = writer.Rollback(context.Background())
			t.Fatal(err)
		}
		var replayPID uint32
		if err := replay.QueryRow(t.Context(), `SELECT pg_backend_pid()`).Scan(&replayPID); err != nil {
			_ = replay.Rollback(context.Background())
			_ = writer.Rollback(context.Background())
			t.Fatal(err)
		}
		replayDone := make(chan error, 1)
		go func() {
			err := fixture.authorize(context.Background(), replay, test.credential)
			_ = replay.Rollback(context.Background())
			replayDone <- err
		}()
		waitForGlobalWaiter069(t, fixture.pool, replayPID, "ShareLock")

		if err := insertBusiness069(t.Context(), writer, key, style); err != nil {
			_ = writer.Rollback(context.Background())
			t.Fatal(err)
		}
		if _, err := writer.Exec(t.Context(),
			`INSERT INTO iam069_audit(id,idempotency_key) VALUES($1,$2)`, uuid.New(), key); err != nil {
			_ = writer.Rollback(context.Background())
			t.Fatal(err)
		}
		if err := writer.Commit(t.Context()); err != nil {
			t.Fatalf("round %d writer commit: %v", round, err)
		}
		if err := <-revokeDone; err != nil {
			t.Fatalf("round %d revocation: %v", round, err)
		}
		if err := <-replayDone; !errors.Is(err, iamlock.ErrPermissionDenied) {
			t.Fatalf("round %d replay error = %v, want permission denied", round, err)
		}
		assertBusinessCount069(t, fixture.pool, key, 1)
		assertIdempotencyCount069(t, fixture.pool, key, 1)

		err = pgx.BeginFunc(t.Context(), fixture.pool, func(tx pgx.Tx) error {
			if err := iamlock.AcquireExclusive(t.Context(), tx); err != nil {
				return err
			}
			if _, err := iamlock.AcquireScopes(t.Context(), tx, []uuid.UUID{fixture.scopeID}); err != nil {
				return err
			}
			return test.restore(t.Context(), tx, fixture)
		})
		if err != nil {
			t.Fatalf("round %d restore: %v", round, err)
		}
	}

	var idempotency, business, audit int
	if err := fixture.pool.QueryRow(t.Context(), `SELECT
		(SELECT count(*) FROM iam069_idempotency WHERE key LIKE 'three-tx-%'),
		(SELECT count(*) FROM iam069_business_facts WHERE idempotency_key LIKE 'three-tx-%'),
		(SELECT count(*) FROM iam069_audit WHERE idempotency_key LIKE 'three-tx-%')`).Scan(
		&idempotency, &business, &audit); err != nil {
		t.Fatal(err)
	}
	if idempotency != 36 || business != 36 || audit != 36 {
		t.Fatalf("three-transaction aggregate = idempotency:%d business:%d audit:%d, want 36/36/36",
			idempotency, business, audit)
	}
}

func (fixture *fixture069) authorize(ctx context.Context, tx pgx.Tx, kind credentialKind069) error {
	switch kind {
	case sessionKind069:
		_, err := fixture.authorizer.AuthorizeSession(ctx, tx, fixture.rawSession, fixture.scopeID, testPermission069)
		return err
	case apiKeyKind069:
		_, err := fixture.authorizer.AuthorizeAPIKey(ctx, tx, fixture.rawAPIKey, fixture.scopeID, testPermission069)
		return err
	default:
		return fmt.Errorf("unknown test credential %q", kind)
	}
}

func (fixture *fixture069) write(ctx context.Context, kind credentialKind069, key, style string, failAudit bool) error {
	return pgx.BeginFunc(ctx, fixture.pool, func(tx pgx.Tx) error {
		return fixture.writeTx(ctx, tx, kind, key, style, failAudit)
	})
}

func (fixture *fixture069) writeTx(
	ctx context.Context,
	tx pgx.Tx,
	kind credentialKind069,
	key, style string,
	failAudit bool,
) error {
	if err := fixture.authorize(ctx, tx, kind); err != nil {
		return err
	}
	var response string
	err := tx.QueryRow(ctx, `SELECT response FROM iam069_idempotency WHERE key=$1 FOR SHARE`, key).Scan(&response)
	if err == nil {
		return nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	if err := insertBusiness069(ctx, tx, key, style); err != nil {
		return err
	}
	if failAudit {
		return errors.New("simulated audit failure")
	}
	_, err = tx.Exec(ctx, `INSERT INTO iam069_audit(id,idempotency_key) VALUES($1,$2)`, uuid.New(), key)
	return err
}

func insertBusiness069(ctx context.Context, tx pgx.Tx, key, style string) error {
	if _, err := tx.Exec(ctx, `INSERT INTO iam069_idempotency(key,response) VALUES($1,'completed')`, key); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO iam069_business_facts(
		id,idempotency_key,style,state,revision
	) VALUES($1,$2,$3,'draft',1)`, uuid.New(), key, style); err != nil {
		return err
	}
	switch style {
	case "create":
		return nil
	case "update":
		_, err := tx.Exec(ctx, `UPDATE iam069_business_facts
			SET state='updated',revision=revision+1 WHERE idempotency_key=$1`, key)
		return err
	case "approve":
		_, err := tx.Exec(ctx, `UPDATE iam069_business_facts
			SET state='approved',revision=revision+1 WHERE idempotency_key=$1`, key)
		return err
	default:
		return errors.New("unknown business write style")
	}
}

func (fixture *fixture069) revoke(ctx context.Context,
	mutation func(context.Context, pgx.Tx, *fixture069) error,
) error {
	return pgx.BeginFunc(ctx, fixture.pool, func(tx pgx.Tx) error {
		if err := iamlock.AcquireExclusive(ctx, tx); err != nil {
			return err
		}
		if _, err := iamlock.AcquireScopes(ctx, tx, []uuid.UUID{fixture.scopeID}); err != nil {
			return err
		}
		return mutation(ctx, tx, fixture)
	})
}

func revokeAssignment069(ctx context.Context, tx pgx.Tx, fixture *fixture069) error {
	_, err := tx.Exec(ctx, `DELETE FROM role_assignments WHERE scope_id=$1 AND user_id=$2 AND role_id=$3`,
		fixture.scopeID, fixture.userID, fixture.roleID)
	return err
}

func revokePermission069(ctx context.Context, tx pgx.Tx, fixture *fixture069) error {
	_, err := tx.Exec(ctx, `DELETE FROM role_permissions WHERE role_id=$1 AND permission_name=$2`,
		fixture.roleID, testPermission069)
	return err
}

func disableAccount069(ctx context.Context, tx pgx.Tx, fixture *fixture069) error {
	_, err := tx.Exec(ctx, `UPDATE users SET status='disabled',revision=revision+1,updated_at=$2 WHERE id=$1`,
		fixture.userID, fixture.now)
	return err
}

func revokeSession069(ctx context.Context, tx pgx.Tx, fixture *fixture069) error {
	_, err := tx.Exec(ctx, `UPDATE auth_sessions SET revoked_at=$2,revocation_reason='iam069-test' WHERE id=$1`,
		fixture.sessionID, fixture.now)
	return err
}

func revokeAPIKey069(ctx context.Context, tx pgx.Tx, fixture *fixture069) error {
	_, err := tx.Exec(ctx, `UPDATE api_keys SET status='revoked',revoked_at=$2,revoked_by_user_id=$3,
		revision=revision+1,updated_at=$2 WHERE id=$1`, fixture.apiKeyID, fixture.now, fixture.userID)
	return err
}

func restoreAssignment069(ctx context.Context, tx pgx.Tx, fixture *fixture069) error {
	_, err := tx.Exec(ctx, `INSERT INTO role_assignments(scope_id,user_id,role_id,assigned_at)
		VALUES($1,$2,$3,$4)`, fixture.scopeID, fixture.userID, fixture.roleID, fixture.now)
	return err
}

func restorePermission069(ctx context.Context, tx pgx.Tx, fixture *fixture069) error {
	_, err := tx.Exec(ctx, `INSERT INTO role_permissions(role_id,permission_name) VALUES($1,$2)`,
		fixture.roleID, testPermission069)
	return err
}

func restoreAccount069(ctx context.Context, tx pgx.Tx, fixture *fixture069) error {
	_, err := tx.Exec(ctx, `UPDATE users SET status='active',revision=revision+1,updated_at=$2 WHERE id=$1`,
		fixture.userID, fixture.now)
	return err
}

func restoreSession069(ctx context.Context, tx pgx.Tx, fixture *fixture069) error {
	_, err := tx.Exec(ctx, `UPDATE auth_sessions SET revoked_at=NULL,revocation_reason=NULL WHERE id=$1`,
		fixture.sessionID)
	return err
}

func restoreAPIKey069(ctx context.Context, tx pgx.Tx, fixture *fixture069) error {
	keyIDUUID := uuid.New()
	keyID := "cfk_" + base64.RawURLEncoding.EncodeToString(keyIDUUID[:])
	secretBytes := sha256.Sum256([]byte(keyIDUUID.String()))
	secret := base64.RawURLEncoding.EncodeToString(secretBytes[:])
	digest := apiKeyDigest069(bytes.Repeat([]byte{3}, 32), keyID, secret)
	_, err := tx.Exec(ctx, `INSERT INTO api_keys(
		id,key_id,key_prefix,scope_id,tenant_id,user_id,name,scopes,secret_digest,pepper_version,status,
		expires_at,activated_at,created_by_user_id,revision,created_at,updated_at
	) VALUES($1,$2,$2||'.',$3,$4,$5,'IAM 069 replacement key',ARRAY[$6],$7,$10,'active',
		$8,$9,$5,1,$9,$9)`, keyIDUUID, keyID, fixture.scopeID, fixture.tenantID,
		fixture.userID, testPermission069, digest[:], fixture.now.Add(24*time.Hour), fixture.now,
		apikeycredential.LegacyPepperVersion)
	if err != nil {
		return err
	}
	fixture.apiKeyID = keyIDUUID
	fixture.rawAPIKey = keyID + "." + secret
	return nil
}

func waitForGlobalWaiter069(t *testing.T, pool *pgxpool.Pool, pid uint32, mode string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		var waiting bool
		if err := pool.QueryRow(t.Context(), `SELECT EXISTS(
			SELECT 1 FROM pg_catalog.pg_locks
			WHERE pid=$1 AND locktype='advisory' AND classid=1229016321::oid
			  AND objid=1::oid AND objsubid=2 AND mode=$2 AND NOT granted
		)`, pid, mode).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("backend %d did not wait for global %s", pid, mode)
}

func assertBusinessCount069(t *testing.T, pool *pgxpool.Pool, key string, want int) {
	t.Helper()
	var got int
	if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM iam069_business_facts WHERE idempotency_key=$1`, key).Scan(&got); err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("business fact count for %q = %d, want %d", key, got, want)
	}
}

func assertIdempotencyCount069(t *testing.T, pool *pgxpool.Pool, key string, want int) {
	t.Helper()
	var got int
	if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM iam069_idempotency WHERE key=$1`, key).Scan(&got); err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("idempotency count for %q = %d, want %d", key, got, want)
	}
}

func newIAM069Fixture(t *testing.T) (*fixture069, func()) {
	t.Helper()
	databaseURL := strings.TrimSpace(os.Getenv("TEST_DATABASE_URL"))
	if databaseURL == "" {
		t.Skip("TEST_DATABASE_URL is not set")
	}
	// A fresh 1..head migration per subtest takes minutes on a loaded server;
	// clone the release-head template when one is configured.
	if pool := databasetest.ClonedMigratedPool(t, func(config *pgxpool.Config) { config.MaxConns = 12 }); pool != nil {
		return seedIAM069Fixture(t, pool, pool.Close)
	}
	admin, err := pgxpool.New(t.Context(), databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	schema := "iamlock069_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if _, err := admin.Exec(t.Context(), "CREATE SCHEMA "+pgx.Identifier{schema}.Sanitize()); err != nil {
		admin.Close()
		t.Fatal(err)
	}
	config, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		admin.Close()
		t.Fatal(err)
	}
	config.ConnConfig.RuntimeParams["search_path"] = schema
	config.MaxConns = 12
	pool, err := pgxpool.NewWithConfig(t.Context(), config)
	if err != nil {
		admin.Close()
		t.Fatal(err)
	}
	cleanup := func() {
		pool.Close()
		_, _ = admin.Exec(context.Background(), "DROP SCHEMA "+pgx.Identifier{schema}.Sanitize()+" CASCADE")
		admin.Close()
	}
	if err := database.Migrate(t.Context(), pool, "up"); err != nil {
		cleanup()
		t.Fatal(err)
	}
	return seedIAM069Fixture(t, pool, cleanup)
}

func seedIAM069Fixture(t *testing.T, pool *pgxpool.Pool, cleanup func()) (*fixture069, func()) {
	t.Helper()
	now := time.Now().UTC().Add(time.Second)
	fixture := &fixture069{
		pool: pool, now: now, tenantID: uuid.New(), scopeID: uuid.New(), userID: uuid.New(),
		roleID: uuid.New(), sessionID: uuid.New(), apiKeyID: uuid.New(),
	}
	keyID := "cfk_" + base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{9}, 16))
	secret := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32))
	fixture.rawAPIKey = keyID + "." + secret
	pepper := bytes.Repeat([]byte{3}, 32)
	digest := apiKeyDigest069(pepper, keyID, secret)
	refreshHash := sha256.Sum256([]byte("iam069-refresh"))
	createdAt := now.Add(-time.Hour)
	if _, err := pool.Exec(t.Context(), `
		INSERT INTO permissions(name,description) VALUES($1,'IAM 069 integration permission');
		INSERT INTO tenants(id,display_name) VALUES($2,'IAM 069 tenant');
		INSERT INTO access_scopes(id,kind,tenant_id) VALUES($3,'tenant',$2);
		INSERT INTO users(id,username,display_name,password_hash,created_at,updated_at)
		VALUES($4,$5,'IAM 069 user','unused',$10,$10);
		INSERT INTO memberships(scope_id,user_id,created_at) VALUES($3,$4,$10);
		INSERT INTO roles(id,scope_id,name,description,system_role,created_at)
		VALUES($6,$3,'iam069_system_writer','IAM 069 system role',true,$10);
		INSERT INTO role_permissions(role_id,permission_name) VALUES($6,$1);
		INSERT INTO role_assignments(scope_id,user_id,role_id,assigned_at) VALUES($3,$4,$6,$10);
		INSERT INTO auth_sessions(
			id,family_id,user_id,scope_id,refresh_token_hash,created_at,expires_at
		) VALUES($7,$11,$4,$3,$12,$10,$13);
		INSERT INTO api_keys(
			id,key_id,key_prefix,scope_id,tenant_id,user_id,name,scopes,secret_digest,pepper_version,status,
			expires_at,activated_at,created_by_user_id,revision,created_at,updated_at
		) VALUES($8,$9,$9||'.',$3,$2,$4,'IAM 069 key',ARRAY[$1],$14,$15,'active',
			$13,$10,$4,1,$10,$10);
		CREATE TABLE iam069_idempotency(key text PRIMARY KEY,response text NOT NULL);
		CREATE TABLE iam069_business_facts(
			id uuid PRIMARY KEY,idempotency_key text NOT NULL UNIQUE,style text NOT NULL,
			state text NOT NULL,revision bigint NOT NULL
		);
		CREATE TABLE iam069_audit(id uuid PRIMARY KEY,idempotency_key text NOT NULL UNIQUE)`,
		pgx.QueryExecModeSimpleProtocol, testPermission069, fixture.tenantID, fixture.scopeID, fixture.userID,
		"iam069-"+strings.ReplaceAll(fixture.userID.String(), "-", ""), fixture.roleID,
		fixture.sessionID, fixture.apiKeyID, keyID, createdAt, uuid.New(),
		refreshHash[:], now.Add(24*time.Hour), digest[:], apikeycredential.LegacyPepperVersion); err != nil {
		cleanup()
		t.Fatal(err)
	}

	tokens, err := identity.NewTokenManager(strings.Repeat("s", 32), time.Hour)
	if err != nil {
		cleanup()
		t.Fatal(err)
	}
	fixture.rawSession, _, err = tokens.Mint(fixture.userID, fixture.scopeID, fixture.sessionID)
	if err != nil {
		cleanup()
		t.Fatal(err)
	}
	sessions, err := sessioncredential.NewVerifier(tokens, func() time.Time { return fixture.now })
	if err != nil {
		cleanup()
		t.Fatal(err)
	}
	apiKeys, err := apikeycredential.NewVerifier(pepper, func() time.Time { return fixture.now })
	if err != nil {
		cleanup()
		t.Fatal(err)
	}
	fixture.authorizer, err = iamlock.NewAuthorizer(sessions, apiKeys)
	if err != nil {
		cleanup()
		t.Fatal(err)
	}
	return fixture, cleanup
}

func mustTokenManager069(t *testing.T) *identity.TokenManager {
	t.Helper()
	tokens, err := identity.NewTokenManager(strings.Repeat("s", 32), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return tokens
}

func mustAuthorizer069(
	t *testing.T,
	sessions *sessioncredential.Verifier,
	apiKeys *apikeycredential.Verifier,
) *iamlock.Authorizer {
	t.Helper()
	authorizer, err := iamlock.NewAuthorizer(sessions, apiKeys)
	if err != nil {
		t.Fatal(err)
	}
	return authorizer
}

func apiKeyDigest069(pepper []byte, keyID, secret string) [32]byte {
	mac := hmac.New(sha256.New, pepper)
	_, _ = mac.Write([]byte("cdnca-control-api/api-key/digest/v1\x00"))
	_, _ = mac.Write([]byte(keyID))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write([]byte(secret))
	var digest [32]byte
	copy(digest[:], mac.Sum(nil))
	return digest
}
