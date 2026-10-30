package dnsreconcile

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/dnscheck"
	"github.com/google/uuid"
)

type voluntaryYieldStore struct {
	*memoryStore
	checkpointCalls int
	yieldCalls      int
	delay           time.Duration
	result          dnscheck.ReconcileResult
}

func (store *voluntaryYieldStore) CheckpointApply(
	_ context.Context,
	lease ApplyLease,
	result dnscheck.ReconcileResult,
) (Task, error) {
	store.checkpointCalls++
	lease.Task.Result = result
	return lease.Task, nil
}

func (store *voluntaryYieldStore) checkpointApplyAfter(
	_ context.Context,
	lease ApplyLease,
	result dnscheck.ReconcileResult,
	delay time.Duration,
) (Task, error) {
	store.yieldCalls++
	store.delay = delay
	store.result, _ = consumeRetryAfterHints(result)
	lease.Task.Result = store.result
	return lease.Task, nil
}

type noVoluntaryYieldStore struct {
	*memoryStore
	checkpointCalls int
}

func (store *noVoluntaryYieldStore) CheckpointApply(
	_ context.Context,
	lease ApplyLease,
	result dnscheck.ReconcileResult,
) (Task, error) {
	store.checkpointCalls++
	lease.Task.Result = result
	return lease.Task, nil
}

func TestRetryAfterSchedulerDeterministicBoundedJitter(t *testing.T) {
	now := time.Date(2026, 8, 7, 12, 0, 0, 0, time.UTC)
	lease := ApplyLease{
		Task: Task{ID: uuid.MustParse("11111111-1111-1111-1111-111111111111"),
			TenantID: uuid.MustParse("22222222-2222-2222-2222-222222222222")},
		Attempt: 3, LeaseID: uuid.MustParse("33333333-3333-3333-3333-333333333333"),
		WorkerID: "dns-worker-1", LeaseExpiresAt: now.Add(16 * time.Minute),
	}
	hint := 37 * time.Second
	first := retryAfterDelay(lease, hint)
	second := retryAfterDelay(lease, hint)
	if first != second || first < hint || first > hint+hint/10 {
		t.Fatalf("retryAfterDelay() = (%s,%s), want stable bounded delay in [%s,%s]",
			first, second, hint, hint+hint/10)
	}
	if first >= lease.LeaseExpiresAt.Sub(now) {
		t.Fatalf("37s provider hint was swallowed by %s apply lease", lease.LeaseExpiresAt.Sub(now))
	}
	if got := retryAfterDelay(lease, 2*time.Hour); got != maximumRetryAfterDeferral {
		t.Fatalf("retryAfterDelay(oversize)=%s, want %s", got, maximumRetryAfterDeferral)
	}
	if got := retryAfterDelay(lease, 0); got != 0 {
		t.Fatalf("retryAfterDelay(0)=%s, want zero", got)
	}
}

func TestRetryAfterSchedulerVoluntarilyYieldsActiveApply(t *testing.T) {
	store := &voluntaryYieldStore{memoryStore: newMemoryStore()}
	runtime := &Runtime{store: store}
	lease := ApplyLease{
		Task: Task{ID: uuid.New(), TenantID: uuid.New()}, Attempt: 2,
		LeaseID: uuid.New(), WorkerID: "worker-a", LeaseExpiresAt: time.Now().Add(16 * time.Minute),
	}
	result := retryAfterResult(37 * time.Second)
	result.Operations[0].ReportSequence = 9

	if _, err := runtime.checkpointApply(t.Context(), lease, result); err != nil {
		t.Fatal(err)
	}
	if store.yieldCalls != 1 || store.checkpointCalls != 0 || store.delay < 37*time.Second ||
		store.delay > 37*time.Second+3700*time.Millisecond || store.result.Operations[0].RetryAfter != 0 ||
		store.result.Operations[0].ReportSequence != 9 {
		t.Fatalf("yield calls=%d regular=%d delay=%s result=%#v",
			store.yieldCalls, store.checkpointCalls, store.delay, store.result)
	}
}

func TestRetryAfterSchedulerFailsClosedWithoutYieldCapability(t *testing.T) {
	store := &noVoluntaryYieldStore{memoryStore: newMemoryStore()}
	runtime := &Runtime{store: store}
	lease := ApplyLease{Task: Task{ID: uuid.New(), TenantID: uuid.New()}, Attempt: 1, LeaseID: uuid.New(), WorkerID: "worker-b"}
	if _, err := runtime.checkpointApply(t.Context(), lease, retryAfterResult(time.Minute)); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("checkpointApply() error=%v, want ErrUnavailable", err)
	}
	if store.checkpointCalls != 0 {
		t.Fatalf("regular checkpoint calls=%d, want zero", store.checkpointCalls)
	}
}

func TestRetryAfterSchedulerKeepsExistingCheckpointPaths(t *testing.T) {
	for _, test := range []struct {
		name   string
		result dnscheck.ReconcileResult
	}{
		{name: "no hint", result: retryAfterResult(0)},
		{name: "success", result: dnscheck.ReconcileResult{Status: dnscheck.TaskReadyToCommit,
			Operations: []dnscheck.OperationResult{{Status: dnscheck.OperationSucceeded}}}},
		{name: "dependency unavailable", result: func() dnscheck.ReconcileResult {
			result := retryAfterResult(time.Minute)
			result.ErrorCode = "dependency_unavailable"
			return result
		}()},
	} {
		t.Run(test.name, func(t *testing.T) {
			store := &voluntaryYieldStore{memoryStore: newMemoryStore()}
			runtime := &Runtime{store: store}
			lease := ApplyLease{Task: Task{ID: uuid.New(), TenantID: uuid.New()}, Attempt: 1, LeaseID: uuid.New(), WorkerID: "worker-c"}
			if _, err := runtime.checkpointApply(t.Context(), lease, test.result); err != nil {
				t.Fatal(err)
			}
			if store.checkpointCalls != 1 || store.yieldCalls != 0 {
				t.Fatalf("checkpoint calls=(regular=%d yield=%d), want regular path", store.checkpointCalls, store.yieldCalls)
			}
		})
	}
}

func TestRetryAfterSchedulerProductionTransactionContract(t *testing.T) {
	runtimeSource, err := os.ReadFile("runtime.go")
	if err != nil {
		t.Fatal(err)
	}
	postgresSource, err := os.ReadFile("postgres_store.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{
		"if activeRetryAfter(lease.Task.Result) > 0",
		"latest, err = runtime.checkpointApply(checkpointContext, lease, result)",
	} {
		if !strings.Contains(string(runtimeSource), required) {
			t.Fatalf("runtime retry scheduler missing %q", required)
		}
	}
	text := string(postgresSource)
	for _, required := range []string{
		"func (store *PostgresStore) checkpointApplyAfter(",
		"jobstate.VoluntaryYieldTx(ctx, tx, jobstate.VoluntaryYieldInput{",
		"NotBefore: now.Add(retryDelay)",
	} {
		if !strings.Contains(text, required) {
			t.Fatalf("Postgres retry scheduler missing %q", required)
		}
	}
	if strings.Count(text, "pgx.BeginFunc(ctx, store.pool, func(tx pgx.Tx) error {") < 1 {
		t.Fatal("checkpoint and voluntary yield must share the appendResult pgx transaction")
	}
}

func retryAfterResult(delay time.Duration) dnscheck.ReconcileResult {
	return dnscheck.ReconcileResult{
		Status: dnscheck.TaskPropagating,
		Operations: []dnscheck.OperationResult{{
			Status: dnscheck.OperationRunning, ErrorClass: dnscheck.ProviderErrorTransient,
			ErrorCode: "provider_recovery_pending", RetryAfter: delay,
		}},
	}
}
