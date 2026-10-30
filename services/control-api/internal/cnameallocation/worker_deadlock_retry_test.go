package cnameallocation

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/jobstate"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
)

// N20: deadlock, serialization failure and NOWAIT lock errors are retryable,
// not ErrConflict (which kept the intent leased for 16 minutes).
func TestMapErrorRetryableDatabaseConflicts(t *testing.T) {
	for _, code := range []string{"40P01", "40001", "55P03"} {
		err := mapError(fmt.Errorf("allocate: %w", &pgconn.PgError{Code: code}))
		if !errors.Is(err, ErrRetryable) || errors.Is(err, ErrConflict) || errors.Is(err, ErrUnavailable) {
			t.Fatalf("mapError(%s) = %v, want ErrRetryable only", code, err)
		}
		if again := mapError(err); !errors.Is(again, ErrRetryable) {
			t.Fatalf("mapError(mapError(%s)) = %v", code, again)
		}
	}
	if err := mapError(&pgconn.PgError{Code: "23505"}); !errors.Is(err, ErrConflict) {
		t.Fatalf("unique violation = %v, want ErrConflict", err)
	}
}

func captureWarnings(t *testing.T) *bytes.Buffer {
	t.Helper()
	var logs bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelWarn})))
	t.Cleanup(func() { slog.SetDefault(previous) })
	return &logs
}

// The live N20 case: PrepareIntent hits 40P01 against the site creation's
// automatic publication. The intent is claimable again within 2 s and a WARN
// names the job, instead of a silent wait for the 16-minute lease.
func TestWorkerRetriesDeadlockedIntentWithinSeconds(t *testing.T) {
	logs := captureWarnings(t)
	tenantID := uuid.New()
	claim := jobstate.Claim{Job: jobstate.StoredJob{ID: uuid.New(), TenantID: tenantID, Kind: "dns.cname.intent",
		Attempt: 1, MaxAttempts: maximumJobAttempts}, LeaseID: uuid.New(), WorkerID: "worker"}
	intents := &sequencedIntentStore{errors: []error{
		mapError(&pgconn.PgError{Code: "40P01", Message: "deadlock detected"}),
	}}
	targets := &fakeCNAMEStore{}
	worker, err := NewWorker(WorkerConfig{WorkerID: "worker", LeaseDuration: 16 * time.Minute}, WorkerDependencies{
		Intents: intents, Claims: &kindClaims{intent: claim}, Targets: targets, Reconcile: &fakeCNAMEReconcile{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := worker.runTenants(context.Background(), []uuid.UUID{tenantID}); err != nil {
		t.Fatal(err)
	}
	if targets.yieldCalls != 1 || targets.yieldClaim.Job.ID != claim.Job.ID || targets.yieldDelay <= 0 || targets.yieldDelay > 2*time.Second {
		t.Fatalf("yield calls=%d job=%s delay=%s, want one yield of the intent within 2s",
			targets.yieldCalls, targets.yieldClaim.Job.ID, targets.yieldDelay)
	}
	if !strings.Contains(logs.String(), "level=WARN") || !strings.Contains(logs.String(), claim.Job.ID.String()) {
		t.Fatalf("no WARN naming job %s: %q", claim.Job.ID, logs.String())
	}
}

// A serialization failure while settling an allocation job is retried the
// same way.
func TestWorkerRetriesSerializationFailureOfAllocation(t *testing.T) {
	captureWarnings(t)
	tenantID := uuid.New()
	target := committedTarget(tenantID)
	claims := newQueuedClaims(tenantID, 1)
	targets := &retryableCompleteStore{fakeCNAMEStore: fakeCNAMEStore{target: target}}
	worker := mustBacklogWorker(t, claims, &targets.fakeCNAMEStore)
	worker.dependencies.Targets = targets
	if _, err := worker.RunOnce(context.Background(), tenantID); !errors.Is(err, ErrRetryable) {
		t.Fatalf("RunOnce() = %v, want ErrRetryable", err)
	}
	if targets.yieldCalls != 1 || targets.yieldDelay > 2*time.Second {
		t.Fatalf("yield calls=%d delay=%s", targets.yieldCalls, targets.yieldDelay)
	}
}

type retryableCompleteStore struct{ fakeCNAMEStore }

func (store *retryableCompleteStore) Complete(context.Context, ResultRequest) (Allocation, error) {
	return Allocation{}, mapError(&pgconn.PgError{Code: "40001"})
}

// fix-cnamewait: a conflicted intent (its shared allocation still pending for
// another site) gives its lease back on the child poll back-off instead of
// waiting for the 16-minute lease; near max_attempts it keeps the lease.
func TestWorkerConflictYieldsOnChildPollBackoff(t *testing.T) {
	for _, test := range []struct {
		attempt uint32
		delay   time.Duration
	}{{1, 2 * time.Second}, {childPollFastAttempts, 2 * time.Second}, {childPollFastAttempts + 1, 4 * time.Second},
		{maximumJobAttempts - yieldReservedAttempts, childPollMaximum}, {maximumJobAttempts - 1, 0}} {
		logs := captureWarnings(t)
		tenantID := uuid.New()
		claim := jobstate.Claim{Job: jobstate.StoredJob{ID: uuid.New(), TenantID: tenantID, Kind: "dns.cname.intent",
			Attempt: test.attempt}, LeaseID: uuid.New(), WorkerID: "worker"}
		targets := &fakeCNAMEStore{}
		worker, err := NewWorker(WorkerConfig{WorkerID: "worker", LeaseDuration: 16 * time.Minute}, WorkerDependencies{
			Intents: &sequencedIntentStore{errors: []error{ErrConflict}}, Claims: &kindClaims{intent: claim},
			Targets: targets, Reconcile: &fakeCNAMEReconcile{},
		})
		if err != nil {
			t.Fatal(err)
		}
		if err := worker.runTenants(context.Background(), []uuid.UUID{tenantID}); err != nil {
			t.Fatal(err)
		}
		wantYields := 1
		if test.delay == 0 {
			wantYields = 0
		}
		if targets.yieldCalls != wantYields || targets.yieldDelay != test.delay {
			t.Fatalf("attempt %d: yields=%d delay=%s, want %d yield(s) of %s", test.attempt, targets.yieldCalls,
				targets.yieldDelay, wantYields, test.delay)
		}
		if !strings.Contains(logs.String(), "CNAME job round stopped") || !strings.Contains(logs.String(), claim.Job.ID.String()) {
			t.Fatalf("attempt %d: conflict not logged: %q", test.attempt, logs.String())
		}
	}
}

// N20 upper bound from the intent: one deadlock retry (retryDelay), then the
// allocation's DNS write and the child commit polls must still list the
// CNAME within 10 s. Same model as TestCNAMEListedWithinTenSecondsOfTheWrite.
func TestCNAMEListedWithinTenSecondsOfTheIntentAfterDeadlock(t *testing.T) {
	const childCommittedAfter = 1*time.Second + 3*time.Second // write + 3 consecutive checks
	elapsed := retryDelay
	for attempt := uint32(1); elapsed < retryDelay+childCommittedAfter; attempt++ {
		targets := &fakeCNAMEStore{}
		worker := &Worker{dependencies: WorkerDependencies{Targets: targets}}
		if err := worker.yield(context.Background(), jobstate.Claim{Job: jobstate.StoredJob{Attempt: attempt,
			MaxAttempts: maximumJobAttempts}}); err != nil {
			t.Fatal(err)
		}
		elapsed += targets.yieldDelay
	}
	if elapsed > 10*time.Second {
		t.Fatalf("CNAME listed %s after the intent, want at most 10s", elapsed)
	}
}
