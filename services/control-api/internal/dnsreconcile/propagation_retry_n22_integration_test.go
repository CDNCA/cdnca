//go:build integration

package dnsreconcile

import (
	"context"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/dnscheck"
	"github.com/cdnca/cdnca/services/control-api/internal/dnspropagation"
	"github.com/cdnca/cdnca/services/control-api/internal/jobstate"
	"github.com/google/uuid"
)

// N22 (live-retest5, package 4f3a8123e): both A records were written within
// seconds, the first propagation check saw authority_conflict, and the task
// hung for its 16-minute lease. Decision: a record the provider
// accepted and its API lookup returns is done; propagation is the provider's
// business. With the propagation engine still answering authority_conflict
// the task now commits on the first claim, within seconds of the write, and
// no propagation attempt is recorded or waited for.
func TestPostgresProviderConfirmedWriteCommitsWithoutWaitingForPropagation(t *testing.T) {
	pool := openDNSReconcileStoreDatabase(t)
	clock := &dnsReconcileStoreClock{value: time.Now().UTC().Truncate(time.Microsecond)}
	store := newDNSReconcileStore(t, pool, clock)
	tenantID, siteID := seedDNSReconcileStoreSite(t, pool, "n22_propagation_retry")
	request, _ := dnsReconcileStoreRequest(t, pool, tenantID, siteID, "n22-propagation-key", "192.0.2.10")

	conflict := dnspropagation.Result{TenantID: tenantID, ZoneID: request.Check.Provider.ZoneID,
		Reason: dnspropagation.ReasonAuthorityConflict}
	engine := &propagationEngineRecorder{results: []dnspropagation.Result{conflict, conflict, conflict}}
	config := defaultN22RuntimeConfig(clock.Now)
	runtime, err := NewRuntime(config, RuntimeDependencies{
		Store: store, ProviderResolver: &testProviderResolver{provider: &testProvider{revision: request.Check.Provider.Revision}},
		Entitlement: testEntitlement{},
		Propagation: PropagationDependencies{
			Engine: engine, RetryStates: &propagationRetryStoreRecorder{},
			ContextResolver: &propagationContextResolverRecorder{context: PropagationContext{
				ScopeID: uuid.New(), ProviderID: uuid.New(), ZoneID: request.Check.Provider.ZoneID, Zone: "example.test",
			}},
			Policy: dnspropagation.ProviderRetryPolicy{
				BaseDelay: time.Second, MaxDelay: 30 * time.Second, BudgetWindow: time.Minute,
				CircuitOpen: time.Minute, AttemptsPerZone: 20, TransientFailuresToOpen: 3,
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	queued, err := runtime.Apply(t.Context(), request)
	if err != nil {
		t.Fatal(err)
	}

	start := clock.Now()
	var latest Task
	for round := 0; round < 10; round++ {
		tasks, err := runtime.RunOnce(t.Context(), tenantID, "n22-worker", 1)
		if err != nil {
			t.Fatalf("round %d RunOnce() error = %v (propagation retry must be persisted)", round, err)
		}
		latest, err = store.Get(t.Context(), tenantID, queued.ID)
		if err != nil {
			t.Fatal(err)
		}
		if latest.Job.State == jobstate.StateSucceeded {
			break
		}
		if len(tasks) == 0 {
			// Nothing claimable yet: move the clock to the yield's not_before.
			var notBefore time.Time
			if err := pool.QueryRow(t.Context(), `SELECT claimable_at FROM background_jobs WHERE id=$1`, queued.ID).
				Scan(&notBefore); err != nil {
				t.Fatal(err)
			}
			if wait := notBefore.Sub(clock.Now()); wait > 0 {
				clock.Advance(wait + time.Millisecond)
			}
			continue
		}
		if latest.Job.State != jobstate.StateQueued || latest.Result.Status != dnscheck.TaskPropagating {
			t.Fatalf("round %d: job=%s status=%s code=%q, want a queued propagating retry",
				round, latest.Job.State, latest.Result.Status, latest.Result.ErrorCode)
		}
	}
	if latest.Job.State != jobstate.StateSucceeded ||
		latest.Result.Status != dnscheck.TaskCommitted && latest.Result.Status != dnscheck.TaskReadyToCommit {
		t.Fatalf("job=%s status=%s code=%q, want succeeded and confirmed", latest.Job.State,
			latest.Result.Status, latest.Result.ErrorCode)
	}
	elapsed := clock.Now().Sub(start)
	t.Logf("done %s after the write", elapsed)
	if elapsed > 3*time.Second {
		t.Fatalf("done %s after the write, want at most 3 s", elapsed)
	}
	var rows int
	if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM dns_reconcile_propagation_attempts WHERE job_id=$1`,
		queued.ID).Scan(&rows); err != nil {
		t.Fatal(err)
	}
	if rows != 0 || len(engine.snapshot()) != 0 {
		t.Fatalf("propagation attempts=%d engine calls=%d, want 0/0 (not blocking)", rows, len(engine.snapshot()))
	}
}

func defaultN22RuntimeConfig(now func() time.Time) RuntimeConfig {
	return RuntimeConfig{
		ProviderAttempts: 3, ProviderTimeout: 5 * time.Second, PollAttempts: 20,
		RequiredConsecutive: 3, InitialBackoff: time.Second, MaximumBackoff: 30 * time.Second,
		OverallTimeout: 15 * time.Minute, ApplyLeaseDuration: 16 * time.Minute,
		CommitLeaseDuration: 16 * time.Minute, Now: now, PropagationEnabled: true,
		Sleep: func(context.Context, time.Duration) error { return nil },
	}
}
