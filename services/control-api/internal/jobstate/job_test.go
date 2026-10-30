package jobstate

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
)

var fixedNow = time.Date(2026, 7, 22, 10, 0, 0, 0, time.FixedZone("CST", 8*60*60))

func TestJobSucceedsWithStableProgress(t *testing.T) {
	job := submitTestJob(t, Request{
		IdempotencyKey: "refresh-1",
		Payload:        []byte(`{"site":"site-1"}`),
		ItemIDs:        []string{"node-b", "node-a"},
		MaxRetries:     2,
	})
	started, err := job.Start()
	if err != nil {
		t.Fatal(err)
	}
	if started.State != StateRunning || started.Attempt != 1 || started.Progress.Pending != 2 {
		t.Fatalf("unexpected started snapshot: %+v", started)
	}

	if applied, err := job.Apply(success("node-a", 1, 1)); err != nil || !applied {
		t.Fatalf("apply first result: applied=%v err=%v", applied, err)
	}
	middle := job.Snapshot()
	if middle.State != StateRunning || middle.Progress != (Progress{Total: 2, Completed: 1, Succeeded: 1, Pending: 1}) {
		t.Fatalf("unexpected middle snapshot: %+v", middle)
	}
	if middle.Items[0].ItemID != "node-b" || middle.Items[1].ItemID != "node-a" {
		t.Fatalf("item order changed: %+v", middle.Items)
	}

	if applied, err := job.Apply(success("node-b", 1, 1)); err != nil || !applied {
		t.Fatalf("apply final result: applied=%v err=%v", applied, err)
	}
	finished := job.Snapshot()
	if finished.State != StateSucceeded || finished.Progress != (Progress{Total: 2, Completed: 2, Succeeded: 2}) {
		t.Fatalf("unexpected finished snapshot: %+v", finished)
	}
	if !finished.CompletedAt.Equal(fixedNow.UTC()) || job.CanCancel() {
		t.Fatalf("unexpected completion metadata: %+v", finished)
	}
}

func TestSucceededReportWithCodeIsRejectedWithoutMutation(t *testing.T) {
	job := submitTestJob(t, Request{IdempotencyKey: "success-code", ItemIDs: []string{"node-a"}})
	if _, err := job.Start(); err != nil {
		t.Fatal(err)
	}
	before := job.Snapshot()
	applied, err := job.Apply(Report{
		ItemID: "node-a", State: ItemSucceeded, Code: "unexpected_error", Attempt: 1, Sequence: 1,
	})
	if applied || !errors.Is(err, ErrInvalidReport) {
		t.Fatalf("success with code: applied=%v err=%v", applied, err)
	}
	if after := job.Snapshot(); !reflect.DeepEqual(after, before) {
		t.Fatalf("invalid report mutated job: before=%+v after=%+v", before, after)
	}
}

func TestInvalidTransitions(t *testing.T) {
	job := submitTestJob(t, Request{IdempotencyKey: "transition-1", ItemIDs: []string{"node-a"}})
	if _, err := job.Retry(); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("retry queued job: %v", err)
	}
	if _, err := job.Start(); err != nil {
		t.Fatal(err)
	}
	if _, err := job.Start(); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("start running job: %v", err)
	}
	if _, err := job.Retry(); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("retry running job: %v", err)
	}
	if _, err := job.Apply(success("node-a", 1, 1)); err != nil {
		t.Fatal(err)
	}
	if _, err := job.Cancel(); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("cancel succeeded job: %v", err)
	}
	if CanTransition(StateSucceeded, StateRunning) || !CanTransition(StatePartialFailed, StateQueued) {
		t.Fatal("transition table does not enforce terminal and retry rules")
	}
}

func TestDuplicateAndOutOfOrderReportsDoNotRegressTerminalItem(t *testing.T) {
	job := submitTestJob(t, Request{IdempotencyKey: "reports-1", ItemIDs: []string{"node-a", "node-b"}})
	if _, err := job.Start(); err != nil {
		t.Fatal(err)
	}
	if applied, err := job.Apply(success("node-a", 1, 2)); err != nil || !applied {
		t.Fatalf("apply sequence 2: applied=%v err=%v", applied, err)
	}
	if applied, err := job.Apply(success("node-a", 1, 2)); err != nil || applied {
		t.Fatalf("duplicate report: applied=%v err=%v", applied, err)
	}
	if applied, err := job.Apply(failure("node-a", 1, 1, "timeout")); err != nil || applied {
		t.Fatalf("out-of-order report: applied=%v err=%v", applied, err)
	}
	if applied, err := job.Apply(failure("node-a", 1, 3, "timeout")); err != nil || applied {
		t.Fatalf("later terminal report: applied=%v err=%v", applied, err)
	}
	if _, err := job.Apply(failure("node-a", 1, 2, "timeout")); !errors.Is(err, ErrReportConflict) {
		t.Fatalf("same-sequence conflict: %v", err)
	}
	if item := job.Snapshot().Items[0]; item.State != ItemSucceeded || item.Sequence != 2 {
		t.Fatalf("terminal item regressed: %+v", item)
	}
}

func TestPartialFailureRetriesOnlyFailedItem(t *testing.T) {
	job := submitTestJob(t, Request{
		IdempotencyKey: "partial-1", ItemIDs: []string{"node-a", "node-b"}, MaxRetries: 1,
	})
	if _, err := job.Start(); err != nil {
		t.Fatal(err)
	}
	_, _ = job.Apply(success("node-a", 1, 1))
	_, _ = job.Apply(failure("node-b", 1, 1, "offline"))
	partial := job.Snapshot()
	if partial.State != StatePartialFailed || partial.Progress.Succeeded != 1 || partial.Progress.Failed != 1 {
		t.Fatalf("unexpected partial failure: %+v", partial)
	}

	queued, err := job.Retry()
	if err != nil {
		t.Fatal(err)
	}
	if queued.State != StateQueued || queued.Progress != (Progress{Total: 2, Completed: 1, Succeeded: 1, Pending: 1}) {
		t.Fatalf("unexpected retry queue: %+v", queued)
	}
	if _, err := job.Start(); err != nil {
		t.Fatal(err)
	}
	if applied, err := job.Apply(success("node-a", 1, 2)); err != nil || applied {
		t.Fatalf("old successful item was reopened: applied=%v err=%v", applied, err)
	}
	if applied, err := job.Apply(success("node-b", 2, 1)); err != nil || !applied {
		t.Fatalf("retry failed item: applied=%v err=%v", applied, err)
	}
	if snapshot := job.Snapshot(); snapshot.State != StateSucceeded || snapshot.Attempt != 2 {
		t.Fatalf("unexpected retry result: %+v", snapshot)
	}
}

func TestCancellationGatesWorkAndLateReports(t *testing.T) {
	job := submitTestJob(t, Request{IdempotencyKey: "cancel-1", ItemIDs: []string{"node-a", "node-b"}, MaxRetries: 2})
	if _, err := job.Start(); err != nil {
		t.Fatal(err)
	}
	_, _ = job.Apply(success("node-a", 1, 1))
	cancelled, err := job.Cancel()
	if err != nil {
		t.Fatal(err)
	}
	if cancelled.State != StateCancelled || cancelled.Progress != (Progress{Total: 2, Completed: 2, Succeeded: 1, Cancelled: 1}) {
		t.Fatalf("unexpected cancellation: %+v", cancelled)
	}
	if applied, err := job.Apply(success("node-b", 1, 1)); err != nil || applied {
		t.Fatalf("late report passed cancellation gate: applied=%v err=%v", applied, err)
	}
	if _, err := job.Start(); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("start cancelled job: %v", err)
	}
	if _, err := job.Retry(); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("retry cancelled job: %v", err)
	}
	replayed, err := job.Cancel()
	if err != nil || replayed.State != StateCancelled {
		t.Fatalf("repeat cancellation: snapshot=%+v err=%v", replayed, err)
	}
}

func TestRetriesExhaustedAndStaleAttemptIgnored(t *testing.T) {
	job := submitTestJob(t, Request{IdempotencyKey: "retry-1", ItemIDs: []string{"node-a"}, MaxRetries: 1})
	if _, err := job.Start(); err != nil {
		t.Fatal(err)
	}
	_, _ = job.Apply(failure("node-a", 1, 1, "offline"))
	if _, err := job.Retry(); err != nil {
		t.Fatal(err)
	}
	if applied, err := job.Apply(success("node-a", 1, 2)); err != nil || applied {
		t.Fatalf("late report while retry is queued: applied=%v err=%v", applied, err)
	}
	if _, err := job.Start(); err != nil {
		t.Fatal(err)
	}
	if applied, err := job.Apply(success("node-a", 1, 99)); err != nil || applied {
		t.Fatalf("stale attempt report: applied=%v err=%v", applied, err)
	}
	if _, err := job.Apply(success("node-a", 3, 1)); !errors.Is(err, ErrInvalidReport) {
		t.Fatalf("future attempt report: %v", err)
	}
	_, _ = job.Apply(failure("node-a", 2, 1, "offline"))
	if _, err := job.Retry(); !errors.Is(err, ErrRetriesExhausted) {
		t.Fatalf("retry after exhaustion: %v", err)
	}
}

func TestRegistryIdempotencyDigestAndConflict(t *testing.T) {
	registry := NewRegistry(func() time.Time { return fixedNow })
	request := Request{IdempotencyKey: "same-key", Payload: []byte("payload-a"), ItemIDs: []string{"node-a"}, MaxRetries: 1}
	first, replayed, err := registry.Submit(request)
	if err != nil || replayed {
		t.Fatalf("submit first: replayed=%v err=%v", replayed, err)
	}
	second, replayed, err := registry.Submit(request)
	if err != nil || !replayed || first != second {
		t.Fatalf("replay request: replayed=%v same=%v err=%v", replayed, first == second, err)
	}
	request.Payload = []byte("payload-b")
	if _, _, err := registry.Submit(request); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("same key with different payload: %v", err)
	}
	if first.Snapshot().Digest.String() == "" {
		t.Fatal("request digest is empty")
	}
}

func TestIdentifierBoundariesAndAuditInjectionGuards(t *testing.T) {
	validKey := strings.Repeat("a", 128)
	if _, _, err := NewRegistry(func() time.Time { return fixedNow }).Submit(Request{
		IdempotencyKey: validKey,
		ItemIDs:        []string{"节点-上海"},
	}); err != nil {
		t.Fatalf("128-byte key and normal Unicode item were rejected: %v", err)
	}

	invalidKeys := []string{
		strings.Repeat("a", 129),
		"bad\nkey",
		"bad\x00key",
		"非-ascii",
	}
	for _, key := range invalidKeys {
		if _, _, err := NewRegistry(nil).Submit(Request{IdempotencyKey: key, ItemIDs: []string{"node-a"}}); !errors.Is(err, ErrInvalidRequest) {
			t.Fatalf("invalid idempotency key %q: %v", key, err)
		}
	}

	invalidItems := []string{"bad\nitem", "bad\x00item", "bad\u2028item", "bad\u2029item"}
	for _, itemID := range invalidItems {
		if _, _, err := NewRegistry(nil).Submit(Request{IdempotencyKey: "safe-key", ItemIDs: []string{itemID}}); !errors.Is(err, ErrInvalidRequest) {
			t.Fatalf("unsafe item ID %q: %v", itemID, err)
		}
	}
}

func TestStoreInputIdentifiers(t *testing.T) {
	tenantID := uuid.MustParse("00000000-0000-4000-8000-000000000001")
	valid := CreateInput{
		TenantID: tenantID, Kind: "cache.refresh", Subject: "站点/示例",
		IdempotencyKey: strings.Repeat("k", 128), Items: []CreateItem{{ItemID: "节点-一"}},
		MaxAttempts: 2, RequestID: "request-1", TraceID: "00-abcdef",
	}
	if err := validateCreate(valid); err != nil {
		t.Fatalf("valid create input: %v", err)
	}
	for _, mutate := range []func(*CreateInput){
		func(input *CreateInput) { input.Kind = "Cache.Refresh" },
		func(input *CreateInput) { input.Kind = "cache\nrefresh" },
		func(input *CreateInput) { input.Subject = "site\nsubject" },
		func(input *CreateInput) { input.Subject = "site\x00subject" },
		func(input *CreateInput) { input.Subject = "site\u2028subject" },
	} {
		input := valid
		mutate(&input)
		if err := validateCreate(input); !errors.Is(err, ErrInvalidRequest) {
			t.Fatalf("unsafe create input accepted: %+v err=%v", input, err)
		}
	}
	for _, test := range []struct {
		name    string
		report  Report
		wantErr bool
	}{
		{name: "success", report: success("节点-一", 1, 1)},
		{name: "failure", report: failure("节点-一", 1, 1, "node_offline")},
		{name: "success with code", report: Report{ItemID: "节点-一", State: ItemSucceeded, Code: "unexpected_error", Attempt: 1, Sequence: 1}, wantErr: true},
		{name: "failure without code", report: Report{ItemID: "节点-一", State: ItemFailed, Attempt: 1, Sequence: 1}, wantErr: true},
		{name: "provider accepted is not settlement", report: Report{ItemID: "节点-一", State: ItemState("accepted"), Attempt: 1, Sequence: 1}, wantErr: true},
		{name: "provider queued is not settlement", report: Report{ItemID: "节点-一", State: ItemState("queued"), Attempt: 1, Sequence: 1}, wantErr: true},
		{name: "unsafe error code", report: failure("节点-一", 1, 1, "bad\ncode"), wantErr: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := validateStoreReport(ReportInput{
				TenantID: tenantID, JobID: uuid.New(), WorkerID: "worker-1", LeaseID: uuid.New(), Report: test.report,
			})
			if test.wantErr && !errors.Is(err, ErrInvalidReport) {
				t.Fatalf("validate report: %v", err)
			}
			if !test.wantErr && err != nil {
				t.Fatalf("validate report: %v", err)
			}
		})
	}
	for _, workerID := range []string{"worker\u2028id", "worker\u2029id"} {
		if err := validateClaim(ClaimInput{
			TenantID: tenantID, Kind: "cache.refresh", WorkerID: workerID,
			Limit: 1, LeaseDuration: time.Second,
		}); !errors.Is(err, ErrInvalidRequest) {
			t.Fatalf("unsafe worker ID %q: %v", workerID, err)
		}
	}
}

func TestRetryDelayIsBoundedExponential(t *testing.T) {
	tests := []struct {
		attempt uint32
		want    time.Duration
	}{
		{attempt: 1, want: 5 * time.Second},
		{attempt: 2, want: 10 * time.Second},
		{attempt: 6, want: 160 * time.Second},
		{attempt: 7, want: 5 * time.Minute},
		{attempt: 1000, want: 5 * time.Minute},
	}
	for _, test := range tests {
		if got := retryDelay(test.attempt); got != test.want {
			t.Fatalf("retryDelay(%d)=%s, want %s", test.attempt, got, test.want)
		}
	}
}

func TestConcurrentAggregation(t *testing.T) {
	const itemCount = 256
	itemIDs := make([]string, itemCount)
	for index := range itemIDs {
		itemIDs[index] = fmt.Sprintf("node-%03d", index)
	}
	job := submitTestJob(t, Request{IdempotencyKey: "concurrent-1", ItemIDs: itemIDs})
	if _, err := job.Start(); err != nil {
		t.Fatal(err)
	}

	stopSnapshots := make(chan struct{})
	var readers sync.WaitGroup
	for range 4 {
		readers.Add(1)
		go func() {
			defer readers.Done()
			for {
				select {
				case <-stopSnapshots:
					return
				default:
					snapshot := job.Snapshot()
					progress := snapshot.Progress
					if progress.Completed != progress.Succeeded+progress.Failed+progress.Cancelled ||
						progress.Completed+progress.Pending != progress.Total {
						t.Errorf("unstable progress: %+v", snapshot.Progress)
						return
					}
				}
			}
		}()
	}

	var writers sync.WaitGroup
	for _, itemID := range itemIDs {
		itemID := itemID
		writers.Add(1)
		go func() {
			defer writers.Done()
			if applied, err := job.Apply(success(itemID, 1, 1)); err != nil || !applied {
				t.Errorf("apply %s: applied=%v err=%v", itemID, applied, err)
			}
			if applied, err := job.Apply(success(itemID, 1, 1)); err != nil || applied {
				t.Errorf("duplicate %s: applied=%v err=%v", itemID, applied, err)
			}
		}()
	}
	writers.Wait()
	close(stopSnapshots)
	readers.Wait()

	snapshot := job.Snapshot()
	if snapshot.State != StateSucceeded || snapshot.Progress != (Progress{Total: itemCount, Completed: itemCount, Succeeded: itemCount}) {
		t.Fatalf("unexpected concurrent result: %+v", snapshot)
	}
}

func submitTestJob(t *testing.T, request Request) *Job {
	t.Helper()
	job, replayed, err := NewRegistry(func() time.Time { return fixedNow }).Submit(request)
	if err != nil {
		t.Fatal(err)
	}
	if replayed {
		t.Fatal("new registry unexpectedly replayed request")
	}
	return job
}

func success(itemID string, attempt uint32, sequence uint64) Report {
	return Report{ItemID: itemID, State: ItemSucceeded, Attempt: attempt, Sequence: sequence}
}

func failure(itemID string, attempt uint32, sequence uint64, code string) Report {
	return Report{ItemID: itemID, State: ItemFailed, Code: code, Attempt: attempt, Sequence: sequence}
}

func cancelledReport(itemID string, attempt uint32, sequence uint64) Report {
	return Report{ItemID: itemID, State: ItemCancelled, Code: CodeCancelled, Attempt: attempt, Sequence: sequence}
}

// fix-cacheflow2 §1: a producer reports an item it stopped as cancelled, and
// the job settles the way the cache operation does (cancelled is neither
// success nor failure).
func TestProducerReportedCancellationSettlesLikeCacheOperation(t *testing.T) {
	for _, test := range []struct {
		name    string
		reports []Report
		state   State
		want    Progress
	}{
		{name: "success and cancelled", reports: []Report{success("a", 1, 1), cancelledReport("b", 1, 1)},
			state: StatePartialFailed, want: Progress{Total: 2, Completed: 2, Succeeded: 1, Cancelled: 1}},
		{name: "failed and cancelled", reports: []Report{failure("a", 1, 1, "node_offline"), cancelledReport("b", 1, 1)},
			state: StatePartialFailed, want: Progress{Total: 2, Completed: 2, Failed: 1, Cancelled: 1}},
		{name: "all cancelled", reports: []Report{cancelledReport("a", 1, 1), cancelledReport("b", 1, 1)},
			state: StateCancelled, want: Progress{Total: 2, Completed: 2, Cancelled: 2}},
	} {
		t.Run(test.name, func(t *testing.T) {
			job := submitTestJob(t, Request{IdempotencyKey: "producer-cancel", ItemIDs: []string{"a", "b"}, MaxRetries: 1})
			if _, err := job.Start(); err != nil {
				t.Fatal(err)
			}
			for _, report := range test.reports {
				if applied, err := job.Apply(report); err != nil || !applied {
					t.Fatalf("apply %+v: applied=%v err=%v", report, applied, err)
				}
			}
			if snapshot := job.Snapshot(); snapshot.State != test.state || snapshot.Progress != test.want {
				t.Fatalf("snapshot=%+v, want state=%s progress=%+v", snapshot, test.state, test.want)
			}
		})
	}
}

func TestReportValidationAcceptsOnlyCanonicalCancellation(t *testing.T) {
	if err := validateReport(cancelledReport("a", 1, 1)); err != nil {
		t.Fatalf("canonical cancellation refused: %v", err)
	}
	for _, code := range []string{"", "worker_stopped"} {
		report := cancelledReport("a", 1, 1)
		report.Code = code
		if err := validateReport(report); !errors.Is(err, ErrInvalidReport) {
			t.Fatalf("cancelled code=%q err=%v, want ErrInvalidReport", code, err)
		}
	}
}

func TestAggregateStateCountsCancellation(t *testing.T) {
	for _, test := range []struct {
		succeeded, failed, cancelled int
		state                        State
		code                         string
	}{
		{succeeded: 2, state: StateSucceeded},
		{failed: 2, state: StateFailed, code: CodeAllItemsFailed},
		{cancelled: 2, state: StateCancelled, code: CodeCancelled},
		{succeeded: 1, failed: 1, state: StatePartialFailed, code: CodeItemFailed},
		{succeeded: 1, cancelled: 1, state: StatePartialFailed, code: CodeCancelled},
		{failed: 1, cancelled: 1, state: StatePartialFailed, code: CodeItemFailed},
	} {
		state, code := aggregateState(test.succeeded+test.failed+test.cancelled, test.succeeded, test.failed, test.cancelled)
		if state != test.state || code != test.code {
			t.Errorf("%+v: state=%s code=%q", test, state, code)
		}
	}
}
