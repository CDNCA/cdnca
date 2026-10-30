//go:build integration

package dnsreconcile

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/dnscheck"
	"github.com/cdnca/cdnca/services/control-api/internal/dnspropagation"
	"github.com/google/uuid"
)

// replayingProvider honours the ProviderAdapter contract: a repeated
// ClientRequestID replays the first result instead of mutating again.
// crashAfter, when set, applies that delete and then reports the caller's
// context as cancelled, like a control-api killed right after the provider
// accepted the write.
type replayingProvider struct {
	mu         sync.Mutex
	revision   int64
	results    map[string]dnscheck.ProviderMutationResult
	calls      []dnscheck.ProviderMutation
	effects    []dnscheck.ProviderMutation
	crashAfter func(dnscheck.ProviderMutation) bool
	crash      context.CancelFunc
}

func (provider *replayingProvider) CurrentRevision(context.Context, dnscheck.ProviderRevisionRequest) (int64, error) {
	provider.mu.Lock()
	defer provider.mu.Unlock()
	return provider.revision, nil
}

func (provider *replayingProvider) Mutate(_ context.Context, mutation dnscheck.ProviderMutation) (dnscheck.ProviderMutationResult, error) {
	provider.mu.Lock()
	defer provider.mu.Unlock()
	provider.calls = append(provider.calls, mutation)
	if result, ok := provider.results[mutation.ClientRequestID]; ok {
		return result, nil
	}
	if mutation.ExpectedRevision != provider.revision {
		return dnscheck.ProviderMutationResult{}, dnscheck.ErrProviderRevisionConflict
	}
	provider.revision++
	provider.effects = append(provider.effects, mutation)
	recordID := mutation.Operation.RecordID
	if mutation.Operation.Action == dnscheck.ProviderCreate {
		recordID = fmt.Sprintf("created-%d", len(provider.effects))
	}
	result := dnscheck.ProviderMutationResult{
		ProviderRequestID: fmt.Sprintf("provider-%d", len(provider.effects)), RecordID: recordID, Revision: provider.revision,
	}
	provider.results[mutation.ClientRequestID] = result
	if provider.crashAfter != nil && provider.crashAfter(mutation) {
		provider.crashAfter = nil
		provider.crash()
		return dnscheck.ProviderMutationResult{}, context.Canceled
	}
	return result, nil
}

func (provider *replayingProvider) snapshot() (calls, effects []dnscheck.ProviderMutation) {
	provider.mu.Lock()
	defer provider.mu.Unlock()
	return append([]dnscheck.ProviderMutation(nil), provider.calls...), append([]dnscheck.ProviderMutation(nil), provider.effects...)
}

func deletesOf(mutations []dnscheck.ProviderMutation) []dnscheck.ProviderMutation {
	var deletes []dnscheck.ProviderMutation
	for _, mutation := range mutations {
		if mutation.Operation.Action == dnscheck.ProviderDelete {
			deletes = append(deletes, mutation)
		}
	}
	return deletes
}

type n25Scenario struct {
	name     string
	current  []dnscheck.ProviderRecord
	expected []dnscheck.ExpectedRecord
	// deletes is how many old records the commit must remove (0: no commit).
	deletes int
}

func n25Scenarios() []n25Scenario {
	a := func(id, value string) dnscheck.ProviderRecord {
		return dnscheck.ProviderRecord{RecordID: id, Name: "label.cdn.example.test", Type: dnscheck.RecordA, Value: value, TTL: 300}
	}
	cname := func(id, value string) dnscheck.ProviderRecord {
		return dnscheck.ProviderRecord{RecordID: id, Name: "label.cdn.example.test", Type: dnscheck.RecordCNAME, Value: value, TTL: 300}
	}
	return []n25Scenario{
		{name: "initial", expected: []dnscheck.ExpectedRecord{{Type: dnscheck.RecordA, Values: []string{"192.0.2.78", "192.0.2.85"}}}},
		{name: "escalate_bc_drop_85", current: []dnscheck.ProviderRecord{a("r78", "192.0.2.78"), a("r85", "192.0.2.85")},
			expected: []dnscheck.ExpectedRecord{{Type: dnscheck.RecordA, Values: []string{"192.0.2.78"}}}, deletes: 1},
		{name: "escalate_d_blackhole", current: []dnscheck.ProviderRecord{a("r78", "192.0.2.78"), a("r85", "192.0.2.85")},
			expected: []dnscheck.ExpectedRecord{{Type: dnscheck.RecordA, Values: []string{"0.0.0.0"}}}, deletes: 2},
		{name: "restore_a_from_blackhole", current: []dnscheck.ProviderRecord{a("rbh", "0.0.0.0")},
			expected: []dnscheck.ExpectedRecord{{Type: dnscheck.RecordA, Values: []string{"192.0.2.78", "192.0.2.85"}}}, deletes: 1},
		{name: "package_line_group_change", current: []dnscheck.ProviderRecord{cname("rc", "old-group.cdn.example.test")},
			expected: []dnscheck.ExpectedRecord{{Type: dnscheck.RecordCNAME, Values: []string{"new-group.cdn.example.test"}}}, deletes: 1},
	}
}

func n25Runtime(t *testing.T, store *PostgresStore, provider dnscheck.ProviderAdapter, zoneID uuid.UUID, now func() time.Time) *Runtime {
	t.Helper()
	runtime, err := NewRuntime(defaultN22RuntimeConfig(now), RuntimeDependencies{
		Store: store, ProviderResolver: &testProviderResolver{provider: provider}, Entitlement: testEntitlement{},
		Propagation: PropagationDependencies{
			Engine: &propagationEngineRecorder{}, RetryStates: &propagationRetryStoreRecorder{},
			ContextResolver: &propagationContextResolverRecorder{context: PropagationContext{
				ScopeID: uuid.New(), ProviderID: uuid.New(), ZoneID: zoneID, Zone: "example.test",
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
	return runtime
}

// n25Apply queues the retarget-shaped apply (apply key cnrt-<digest>) and runs
// the worker until the new records are written.
func n25Apply(t *testing.T, runtime *Runtime, store *PostgresStore, tenantID, siteID, zoneID, actorID uuid.UUID,
	scenario n25Scenario, digest string) Task {
	t.Helper()
	check := dnscheck.CheckRequest{
		TenantID: tenantID, SiteID: siteID, Name: "label.cdn.example.test", Expected: scenario.expected,
		TTL: 300, PropagationWindow: 5 * time.Minute,
		Provider: dnscheck.ProviderSnapshot{TenantID: tenantID, SiteID: siteID, ZoneID: zoneID, Revision: 7,
			Records: scenario.current},
	}
	queued, err := runtime.Apply(t.Context(), ApplyRequest{
		TenantID: tenantID, SiteID: siteID, ActorUserID: actorID, IdempotencyKey: "cnrt-" + digest,
		RequestID: "cname-retarget/" + scenario.name, Traceparent: "00-" + digest[:32] + "-" + digest[32:48] + "-01",
		ExpectedRevision: 7, RequiredConsecutive: 3, Check: check,
	})
	if err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	if _, err := runtime.RunOnce(t.Context(), tenantID, "n25-worker", 1); err != nil {
		t.Fatalf("RunOnce() error = %v", err)
	}
	task, err := store.Get(t.Context(), tenantID, queued.ID)
	if err != nil {
		t.Fatal(err)
	}
	return task
}

func n25CommitRequest(task Task, actorID uuid.UUID, digest string) CommitRequest {
	return CommitRequest{
		TenantID: task.TenantID, SiteID: task.SiteID, TaskID: task.ID, ActorUserID: actorID,
		// The retarget worker's commit key (cnameallocation/retarget.go).
		IdempotencyKey: "cnrt-commit-" + digest[:48], RequestID: "cname-retarget/commit",
		Traceparent: "00-" + digest[:32] + "-" + digest[32:48] + "-01", ExpectedRevision: task.Revision,
	}
}

// N25 (live-retest6 S7): a retarget writes the new records at apply and
// defers deleting the old ones to commit. The commit's first checkpoint (the
// delete marked running) was refused because the store recomputed the delete
// request ID from the commit command's key while every other part of the
// chain (dnscheck, the 076 operation rows, the 089 claim trigger) uses the
// task's apply key: 0 provider calls, the lease held for 16 minutes, and the
// same refusal on every retry. Every DNS change that removes a record (attack
// escalation B/C/D, back to A, package line group change) was stuck.
func TestPostgresRetargetCommitDeletesDeferredRecords(t *testing.T) {
	pool := openDNSReconcileStoreDatabase(t)
	for _, scenario := range n25Scenarios() {
		t.Run(scenario.name, func(t *testing.T) {
			clock := &dnsReconcileStoreClock{value: time.Now().UTC().Truncate(time.Microsecond)}
			store := newDNSReconcileStore(t, pool, clock)
			tenantID, siteID := seedDNSReconcileStoreSite(t, pool, "n25_"+scenario.name)
			actorID := n25Actor(t, store, siteID)
			provider := &replayingProvider{revision: 7, results: map[string]dnscheck.ProviderMutationResult{}}
			zoneID := uuid.New()
			runtime := n25Runtime(t, store, provider, zoneID, clock.Now)
			digest := strings.Repeat(fmt.Sprintf("%02x", len(scenario.name)), 32)
			task := n25Apply(t, runtime, store, tenantID, siteID, zoneID, actorID, scenario, digest)
			if scenario.deletes == 0 {
				if task.Result.Status != dnscheck.TaskCommitted {
					t.Fatalf("initial publish status=%s code=%q, want committed without a commit", task.Result.Status, task.Result.ErrorCode)
				}
				return
			}
			if task.Result.Status != dnscheck.TaskReadyToCommit || len(task.Result.DeferredDeletes) != scenario.deletes {
				t.Fatalf("after apply status=%s code=%q deferred=%d, want ready_to_commit with %d deferred deletes",
					task.Result.Status, task.Result.ErrorCode, len(task.Result.DeferredDeletes), scenario.deletes)
			}
			command := n25CommitRequest(task, actorID, digest)
			committed, err := runtime.Commit(t.Context(), command)
			if err != nil || committed.Result.Status != dnscheck.TaskCommitted {
				t.Fatalf("Commit() = (%s/%q, %v), want committed", committed.Result.Status, committed.Result.ErrorCode, err)
			}
			_, effects := provider.snapshot()
			if deletes := deletesOf(effects); len(deletes) != scenario.deletes {
				t.Fatalf("provider deletes=%d, want %d", len(deletes), scenario.deletes)
			}
			// Retrying the same commit replays it: no new provider write.
			replay := command
			replay.RequestID = "cname-retarget/commit-retry"
			replayed, err := runtime.Commit(t.Context(), replay)
			if err != nil || !replayed.Replayed || replayed.Result.Status != dnscheck.TaskCommitted {
				t.Fatalf("replayed Commit() = (%#v, %v)", replayed.Result.Status, err)
			}
			if _, again := provider.snapshot(); len(again) != len(effects) {
				t.Fatalf("replayed commit wrote to the provider again: %d -> %d", len(effects), len(again))
			}
			var deleteFacts, commitFacts int
			if err := pool.QueryRow(t.Context(), `SELECT count(*) FILTER (WHERE event_type='delete_succeeded'),
				count(*) FILTER (WHERE event_type='committed') FROM dns_reconcile_commit_facts WHERE tenant_id=$1 AND job_id=$2`,
				tenantID, task.ID).Scan(&deleteFacts, &commitFacts); err != nil {
				t.Fatal(err)
			}
			if deleteFacts != scenario.deletes || commitFacts != 1 {
				t.Fatalf("commit facts deletes=%d committed=%d, want %d/1", deleteFacts, commitFacts, scenario.deletes)
			}
		})
	}
}

// A control-api killed after the provider accepted the delete but before the
// result was saved: once the lease expires the same commit is claimed again,
// sends the same request ID (the provider replays it, no second delete) and
// commits.
func TestPostgresRetargetCommitRecoversAfterCrashMidDelete(t *testing.T) {
	pool := openDNSReconcileStoreDatabase(t)
	clock := &dnsReconcileStoreClock{value: time.Now().UTC().Truncate(time.Microsecond)}
	store := newDNSReconcileStore(t, pool, clock)
	tenantID, siteID := seedDNSReconcileStoreSite(t, pool, "n25_crash")
	actorID := n25Actor(t, store, siteID)
	provider := &replayingProvider{revision: 7, results: map[string]dnscheck.ProviderMutationResult{}}
	zoneID := uuid.New()
	runtime := n25Runtime(t, store, provider, zoneID, clock.Now)
	scenario := n25Scenarios()[2] // D blackhole: two deferred deletes
	digest := strings.Repeat("cd", 32)
	task := n25Apply(t, runtime, store, tenantID, siteID, zoneID, actorID, scenario, digest)
	if task.Result.Status != dnscheck.TaskReadyToCommit {
		t.Fatalf("after apply status=%s code=%q", task.Result.Status, task.Result.ErrorCode)
	}
	command := n25CommitRequest(task, actorID, digest)

	crashContext, crash := context.WithCancel(t.Context())
	provider.crash = crash
	provider.crashAfter = func(mutation dnscheck.ProviderMutation) bool {
		return mutation.Operation.Action == dnscheck.ProviderDelete
	}
	if _, err := runtime.Commit(crashContext, command); err == nil {
		t.Fatal("crashed Commit() error = nil")
	}
	_, effects := provider.snapshot()
	firstDeletes := deletesOf(effects)
	if len(firstDeletes) != 1 {
		t.Fatalf("deletes before the crash=%d, want 1 (the crash happens after the provider accepted it)", len(firstDeletes))
	}
	stored, err := store.Get(t.Context(), tenantID, task.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.Result.DeferredDeletes[0].ClientRequestID != firstDeletes[0].ClientRequestID {
		t.Fatalf("persisted delete intent %q, provider saw %q", stored.Result.DeferredDeletes[0].ClientRequestID,
			firstDeletes[0].ClientRequestID)
	}

	clock.Advance(17 * time.Minute) // the 16-minute commit lease expires
	command.RequestID = "cname-retarget/commit-after-crash"
	committed, err := runtime.Commit(t.Context(), command)
	if err != nil || committed.Result.Status != dnscheck.TaskCommitted {
		t.Fatalf("recovered Commit() = (%s/%q, %v)", committed.Result.Status, committed.Result.ErrorCode, err)
	}
	calls, effects := provider.snapshot()
	if deletes := deletesOf(effects); len(deletes) != 2 {
		t.Fatalf("provider deletes=%d, want 2 (the replayed delete must not run twice)", len(deletes))
	}
	retried := 0
	for _, call := range deletesOf(calls) {
		if call.ClientRequestID == firstDeletes[0].ClientRequestID {
			retried++
		}
	}
	if retried != 2 {
		t.Fatalf("delete %q sent %d times, want 2 (once before the crash, replayed once after)",
			firstDeletes[0].ClientRequestID, retried)
	}
}

func n25Actor(t *testing.T, store *PostgresStore, siteID uuid.UUID) uuid.UUID {
	t.Helper()
	var actorID uuid.UUID
	if err := store.pool.QueryRow(t.Context(), `SELECT owner_user_id FROM sites WHERE id=$1`, siteID).Scan(&actorID); err != nil {
		t.Fatal(err)
	}
	return actorID
}
