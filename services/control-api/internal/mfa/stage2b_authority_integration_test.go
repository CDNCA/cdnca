package mfa

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/iamstage2b"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestStage2BCredentialMutationsWaitForRequiredLegacyScopes(t *testing.T) {
	t.Run("begin enrollment", func(t *testing.T) {
		fixture := newMFAFixture(t)
		holder := holdMFALegacyScopeExclusive(t, fixture.pool, fixture.actor.ScopeID)
		done := make(chan error, 1)
		go func() {
			_, err := fixture.service.BeginEnrollment(context.Background(), fixture.actor, EnrollmentRequest{
				AccountLabel: "stage2b@example.invalid", IdempotencyKey: "stage2b-begin",
				Context: requestContext("stage2b-begin"),
			})
			done <- err
		}()
		assertMFAAuthorityWaitThenRelease(t, holder, done)
	})

	t.Run("activate", func(t *testing.T) {
		fixture := newMFAFixture(t)
		enrollment := fixture.begin(t, "stage2b-activate")
		secret := decodeTOTPSecret(enrollment.Secret)
		holder := holdMFALegacyScopeExclusive(t, fixture.pool, fixture.actor.ScopeID)
		done := make(chan error, 1)
		go func() {
			_, err := fixture.service.Activate(context.Background(), fixture.actor, ActivationRequest{
				CredentialID: enrollment.CredentialID, Code: currentCode(secret, fixture.clock.Now()),
				IdempotencyKey: "stage2b-activate", Context: requestContext("stage2b-activate"),
			})
			done <- err
		}()
		assertMFAAuthorityWaitThenRelease(t, holder, done)
	})

	t.Run("issue step up", func(t *testing.T) {
		fixture := newMFAFixture(t)
		_, recoveryCodes := fixture.activate(t, "stage2b-issue")
		holder := holdMFALegacyScopeExclusive(t, fixture.pool, fixture.tenantA.scopeID)
		done := make(chan error, 1)
		go func() {
			_, err := fixture.service.CreateStepUp(context.Background(), fixture.actor, fixture.proofRequest(
				"stage2b-issue", Authentication{Method: MethodRecoveryCode, Code: recoveryCodes[0]}, 1))
			done <- err
		}()
		assertMFAAuthorityWaitThenRelease(t, holder, done)
	})

	t.Run("consume step up", func(t *testing.T) {
		fixture := newMFAFixture(t)
		_, recoveryCodes := fixture.activate(t, "stage2b-consume")
		proof, err := fixture.service.CreateStepUp(t.Context(), fixture.actor, fixture.proofRequest(
			"stage2b-consume", Authentication{Method: MethodRecoveryCode, Code: recoveryCodes[0]}, 1))
		if err != nil {
			t.Fatal(err)
		}
		holder := holdMFALegacyScopeExclusive(t, fixture.pool, fixture.tenantA.scopeID)
		done := make(chan error, 1)
		go func() {
			_, err := fixture.service.ConsumeStepUp(context.Background(), fixture.actor, ConsumeStepUpRequest{
				Token: proof.Token, TenantID: fixture.tenantA.id, Audience: "impersonation",
				Action: "grant.create", Context: requestContext("stage2b-consume-use"),
			})
			done <- err
		}()
		assertMFAAuthorityWaitThenRelease(t, holder, done)
	})

	for _, reset := range []bool{false, true} {
		t.Run(fmt.Sprintf("deactivate reset=%t", reset), func(t *testing.T) {
			fixture := newMFAFixture(t)
			_, recoveryCodes := fixture.activate(t, fmt.Sprintf("stage2b-deactivate-%t", reset))
			holder := holdMFALegacyScopeExclusive(t, fixture.pool, fixture.actor.ScopeID)
			done := make(chan error, 1)
			go func() {
				request := DeactivateRequest{
					Authentication: Authentication{Method: MethodRecoveryCode, Code: recoveryCodes[0]},
					Reason:         "stage2b review", IdempotencyKey: fmt.Sprintf("stage2b-deactivate-%t", reset),
					Context: requestContext(fmt.Sprintf("stage2b-deactivate-%t", reset)),
				}
				if reset {
					done <- fixture.service.Reset(context.Background(), fixture.actor, request)
					return
				}
				done <- fixture.service.Disable(context.Background(), fixture.actor, request)
			}()
			assertMFAAuthorityWaitThenRelease(t, holder, done)
		})
	}
}

func TestStage2BConsumeStepUpTxRequiresCallersCompleteExactScopes(t *testing.T) {
	fixture := newMFAFixture(t)
	_, recoveryCodes := fixture.activate(t, "stage2b-scoped-consume")
	proof, err := fixture.service.CreateStepUp(t.Context(), fixture.actor, fixture.proofRequest(
		"stage2b-scoped-consume", Authentication{Method: MethodRecoveryCode, Code: recoveryCodes[0]}, 1))
	if err != nil {
		t.Fatal(err)
	}
	request := ConsumeStepUpRequest{
		Token: proof.Token, TenantID: fixture.tenantA.id, Audience: "impersonation",
		Action: "grant.create", Context: requestContext("stage2b-scoped-consume-use"),
	}
	extraScope := uuid.New()
	completeScopes := []uuid.UUID{fixture.actor.ScopeID, fixture.tenantA.scopeID, extraScope}

	tx, err := fixture.pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	lockedScopes, err := iamstage2b.BeginAuthorityMutation(t.Context(), tx,
		iamstage2b.OperationMFAConsumeStepUp, completeScopes)
	if err != nil {
		_ = tx.Rollback(context.Background())
		t.Fatal(err)
	}
	_, err = fixture.service.ConsumeStepUpTxWithScopes(t.Context(), tx, fixture.actor,
		[]uuid.UUID{fixture.actor.ScopeID, fixture.tenantA.scopeID}, request)
	if !errors.Is(err, ErrUnavailable) {
		_ = tx.Rollback(context.Background())
		t.Fatalf("incomplete caller scope set error = %v, want unavailable", err)
	}
	if err := tx.Rollback(t.Context()); err != nil {
		t.Fatal(err)
	}
	assertCount(t, fixture.pool, "mfa_step_up_uses", 0)
	assertAuditCount(t, fixture.pool, request.Context.RequestID, "mfa.step_up.consume", 0)

	tx, err = fixture.pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	lockedScopes, err = iamstage2b.BeginAuthorityMutation(t.Context(), tx,
		iamstage2b.OperationMFAConsumeStepUp, completeScopes)
	if err != nil {
		_ = tx.Rollback(context.Background())
		t.Fatal(err)
	}
	evidence, err := fixture.service.ConsumeStepUpTxWithScopes(
		t.Context(), tx, fixture.actor, lockedScopes, request)
	if err != nil || evidence.ProofID != proof.ProofID {
		_ = tx.Rollback(context.Background())
		t.Fatalf("scoped consume = (%+v,%v)", evidence, err)
	}
	if err := tx.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
	assertCount(t, fixture.pool, "mfa_step_up_uses", 1)
	assertAuditCount(t, fixture.pool, request.Context.RequestID, "mfa.step_up.consume", 1)
}

func TestStage2BPostgresErrorsAreRedactedAndRollback(t *testing.T) {
	fixture := newMFAFixture(t)
	if _, err := fixture.pool.Exec(t.Context(), `CREATE FUNCTION reject_stage2b_mfa_write()
		RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN
			RAISE EXCEPTION USING ERRCODE='23505', MESSAGE='stage2b reviewer database detail';
		END
		$$;
		CREATE TRIGGER reject_stage2b_mfa_write
		BEFORE INSERT ON mfa_credentials
		FOR EACH ROW EXECUTE FUNCTION reject_stage2b_mfa_write()`); err != nil {
		t.Fatal(err)
	}
	request := EnrollmentRequest{
		AccountLabel: "stage2b-error@example.invalid", IdempotencyKey: "stage2b-pg-error",
		Context: requestContext("stage2b-pg-error"),
	}
	_, err := fixture.service.BeginEnrollment(t.Context(), fixture.actor, request)
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("PostgreSQL error = %v, want unavailable", err)
	}
	for _, leaked := range []string{"stage2b reviewer", "database detail", "23505", "SQLSTATE"} {
		if strings.Contains(err.Error(), leaked) {
			t.Fatalf("public error leaked %q: %v", leaked, err)
		}
	}
	assertCount(t, fixture.pool, "mfa_credentials", 0)
	assertCount(t, fixture.pool, "mfa_credential_events", 0)
	assertAuditCount(t, fixture.pool, request.Context.RequestID, "mfa.enrollment.begin", 0)
}

func holdMFALegacyScopeExclusive(t *testing.T, pool *pgxpool.Pool, scopeID uuid.UUID) pgx.Tx {
	t.Helper()
	tx, err := pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(t.Context(), `SELECT pg_catalog.pg_advisory_xact_lock(
		pg_catalog.hashtextextended($1,0))`, "iam-authz:v1:"+scopeID.String()); err != nil {
		_ = tx.Rollback(context.Background())
		t.Fatal(err)
	}
	return tx
}

func assertMFAAuthorityWaitThenRelease(t *testing.T, holder pgx.Tx, done <-chan error) {
	t.Helper()
	select {
	case err := <-done:
		_ = holder.Rollback(context.Background())
		t.Fatalf("MFA mutation did not wait for the legacy scope lock: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	if err := holder.Rollback(t.Context()); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("MFA mutation did not finish after releasing the legacy scope lock")
	}
}
