package accountrecovery

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func TestStage2BRequestFreshAndReplayWaitForScopeAuthority(t *testing.T) {
	for _, replay := range []bool{false, true} {
		t.Run(fmt.Sprintf("replay=%t", replay), func(t *testing.T) {
			fixture := newFixture(t, 20, 20)
			input := requestInput(fixture, fixture.username, "stage2b-request", "198.51.100.80")
			if replay {
				if _, err := fixture.service.Request(t.Context(), input); err != nil {
					t.Fatal(err)
				}
			}
			holder := holdLegacyScopeExclusive(t, fixture.pool, fixture.scopeID)
			done := make(chan error, 1)
			go func() {
				_, err := fixture.service.Request(context.Background(), input)
				done <- err
			}()
			assertAuthorityWaitThenRelease(t, holder, done)
		})
	}
}

func TestStage2BResetLocksCompleteUserScopeUnion(t *testing.T) {
	fixture := newFixture(t, 20, 20)
	if _, err := fixture.service.Request(t.Context(), requestInput(
		fixture, fixture.username, "stage2b-reset-request", "198.51.100.81")); err != nil {
		t.Fatal(err)
	}
	token := recoveryDeliveryForRequest(t, fixture, "stage2b-reset-request").Token
	_, otherScope := seedTenant(t, fixture.pool, "Stage2B other tenant")
	seedMembership(t, fixture.pool, otherScope, fixture.userID)
	seedSession(t, fixture.pool, fixture.userID, otherScope, fixture.clock.Now())

	holder := holdLegacyScopeExclusive(t, fixture.pool, otherScope)
	done := make(chan error, 1)
	go func() {
		_, err := fixture.service.Reset(context.Background(), resetInput(
			fixture, token, "stage2b-reset", "Changed-password-stage2b-1234"))
		done <- err
	}()
	assertAuthorityWaitThenRelease(t, holder, done)
}

func TestStage2BResetRejectsOversizedDatabaseScopeUnionWithoutSideEffects(t *testing.T) {
	fixture := newFixture(t, 20, 20)
	if _, err := fixture.service.Request(t.Context(), requestInput(
		fixture, fixture.username, "stage2b-large-request", "198.51.100.82")); err != nil {
		t.Fatal(err)
	}
	token := recoveryDeliveryForRequest(t, fixture, "stage2b-large-request").Token
	for index := range 64 {
		_, scopeID := seedTenant(t, fixture.pool, fmt.Sprintf("Stage2B large tenant %d", index))
		seedMembership(t, fixture.pool, scopeID, fixture.userID)
	}
	before := tableCounts(t, fixture.pool)
	var passwordHash string
	if err := fixture.pool.QueryRow(t.Context(), `SELECT password_hash FROM users WHERE id=$1`,
		fixture.userID).Scan(&passwordHash); err != nil {
		t.Fatal(err)
	}

	_, err := fixture.service.Reset(t.Context(), resetInput(
		fixture, token, "stage2b-large-reset", "Changed-password-stage2b-5678"))
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("oversized scope union error = %v, want unavailable", err)
	}
	if after := tableCounts(t, fixture.pool); fmt.Sprint(after) != fmt.Sprint(before) {
		t.Fatalf("oversized scope union changed facts before=%v after=%v", before, after)
	}
	var currentHash string
	if err := fixture.pool.QueryRow(t.Context(), `SELECT password_hash FROM users WHERE id=$1`,
		fixture.userID).Scan(&currentHash); err != nil {
		t.Fatal(err)
	}
	if currentHash != passwordHash {
		t.Fatal("oversized scope union changed the password hash")
	}
}

func TestStage2BPostgresErrorsAreStableAndDoNotLeakDetails(t *testing.T) {
	fixture := newFixture(t, 20, 20)
	before := tableCounts(t, fixture.pool)
	if _, err := fixture.pool.Exec(t.Context(), `CREATE FUNCTION reject_stage2b_recovery_write()
		RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN
			RAISE EXCEPTION USING ERRCODE='23505', MESSAGE='reviewer credential=secret SQLSTATE 23505';
		END
		$$;
		CREATE TRIGGER reject_stage2b_recovery_write
		BEFORE INSERT ON account_recovery_write_requests
		FOR EACH ROW EXECUTE FUNCTION reject_stage2b_recovery_write()`); err != nil {
		t.Fatal(err)
	}

	_, err := fixture.service.Request(t.Context(), requestInput(
		fixture, fixture.username, "stage2b-pg-error", "198.51.100.83"))
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("PostgreSQL failure error = %v, want unavailable", err)
	}
	for _, leaked := range []string{"reviewer", "credential", "secret", "SQLSTATE", "23505"} {
		if strings.Contains(err.Error(), leaked) {
			t.Fatalf("PostgreSQL failure leaked %q: %v", leaked, err)
		}
	}
	if after := tableCounts(t, fixture.pool); fmt.Sprint(after) != fmt.Sprint(before) {
		t.Fatalf("PostgreSQL failure changed facts before=%v after=%v", before, after)
	}
}

func holdLegacyScopeExclusive(t *testing.T, pool interface {
	Begin(context.Context) (pgx.Tx, error)
}, scopeID uuid.UUID) pgx.Tx {
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

func assertAuthorityWaitThenRelease(t *testing.T, holder pgx.Tx, done <-chan error) {
	t.Helper()
	select {
	case err := <-done:
		_ = holder.Rollback(context.Background())
		t.Fatalf("authority mutation did not wait for the legacy scope lock: %v", err)
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
		t.Fatal("authority mutation did not finish after releasing the legacy scope lock")
	}
}
