package dnscheck

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type fakeProviderAdapter struct {
	mu            sync.Mutex
	revision      int64
	revisionCalls int
	mutations     []ProviderMutation
	mutate        func(*fakeProviderAdapter, int, ProviderMutation) (ProviderMutationResult, error)
}

func (p *fakeProviderAdapter) CurrentRevision(ctx context.Context, _ ProviderRevisionRequest) (int64, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.revisionCalls++
	return p.revision, nil
}

func (p *fakeProviderAdapter) Mutate(ctx context.Context, mutation ProviderMutation) (ProviderMutationResult, error) {
	if err := ctx.Err(); err != nil {
		return ProviderMutationResult{}, err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.mutations = append(p.mutations, mutation)
	call := len(p.mutations)
	if p.mutate != nil {
		return p.mutate(p, call, mutation)
	}
	return p.succeed(call, mutation)
}

func (p *fakeProviderAdapter) succeed(call int, mutation ProviderMutation) (ProviderMutationResult, error) {
	if mutation.ExpectedRevision != p.revision {
		return ProviderMutationResult{}, ErrProviderRevisionConflict
	}
	p.revision++
	recordID := mutation.Operation.RecordID
	if mutation.Operation.Action == ProviderCreate {
		recordID = fmt.Sprintf("created-%d", call)
	}
	return ProviderMutationResult{
		ProviderRequestID: fmt.Sprintf("provider-request-%d", call), RecordID: recordID, Revision: p.revision,
	}, nil
}

func (p *fakeProviderAdapter) snapshot() (int64, int, []ProviderMutation) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.revision, p.revisionCalls, append([]ProviderMutation(nil), p.mutations...)
}

func newHealthyReconcileFixture(t *testing.T, now time.Time) (*Checker, CheckRequest) {
	t.Helper()
	authorityOne := testEndpoint(t, "192.0.2.81", 53)
	authorityTwo := testEndpoint(t, "192.0.2.82", 53)
	publicOne := testEndpoint(t, "198.51.100.81", 53)
	publicTwo := testEndpoint(t, "198.51.100.82", 53)
	query := DNSQuery{Name: "www.example.test.", Type: RecordA}
	resolver := newFakeResolver()
	for _, endpoint := range []ResolverEndpoint{authorityOne, authorityTwo} {
		resolver.set(endpoint, query, responseHandler(answerResponse(true, query.Name, RecordA, "192.0.2.10")))
	}
	for _, endpoint := range []ResolverEndpoint{publicOne, publicTwo} {
		resolver.set(endpoint, query, responseHandler(answerResponse(false, query.Name, RecordA, "192.0.2.10")))
	}
	checker := testChecker(t, resolver,
		[]NamedResolver{{Name: "ns1.example.test", Endpoint: authorityOne}, {Name: "ns2.example.test", Endpoint: authorityTwo}},
		[]NamedResolver{{Name: "public-a", Endpoint: publicOne}, {Name: "public-b", Endpoint: publicTwo}}, now, 1, 4)
	request := baseRequest(now, RecordA, "192.0.2.10")
	request.Provider.Records[0].Value = "192.0.2.20"
	return checker, request
}

func newTestReconciler(t *testing.T, checker *Checker, provider ProviderAdapter, now time.Time, customize func(*ReconcilerConfig)) *Reconciler {
	t.Helper()
	config := ReconcilerConfig{
		Checker: checker, Provider: provider, ProviderAttempts: 3, ProviderTimeout: 50 * time.Millisecond,
		PollAttempts: 4, RequiredConsecutive: 2, InitialBackoff: time.Millisecond, MaximumBackoff: 8 * time.Millisecond,
		OverallTimeout: time.Second, JitterFraction: 0.25, Now: func() time.Time { return now },
		Sleep: func(ctx context.Context, _ time.Duration) error {
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
				return nil
			}
		},
		Random: func() float64 { return 0.5 },
	}
	if customize != nil {
		customize(&config)
	}
	reconciler, err := NewReconciler(config)
	if err != nil {
		t.Fatalf("NewReconciler() error = %v", err)
	}
	return reconciler
}

func TestReconcilerDryRunApplyCommitAndReplay(t *testing.T) {
	now := time.Date(2026, 7, 22, 15, 0, 0, 0, time.UTC)
	checker, checkRequest := newHealthyReconcileFixture(t, now)
	provider := &fakeProviderAdapter{revision: checkRequest.Provider.Revision}
	reconciler := newTestReconciler(t, checker, provider, now, nil)
	request := ReconcileRequest{IdempotencyKey: "dns-reconcile-1", Check: checkRequest}

	dryRun, err := reconciler.DryRun(request)
	if err != nil {
		t.Fatalf("DryRun() error = %v", err)
	}
	_, revisionCalls, mutations := provider.snapshot()
	if dryRun.Status != TaskDryRun || revisionCalls != 0 || len(mutations) != 0 || len(dryRun.Operations) != 1 || len(dryRun.DeferredDeletes) != 1 {
		t.Fatalf("DryRun() = %#v; revisionCalls=%d mutations=%#v", dryRun, revisionCalls, mutations)
	}
	if dryRun.Operations[0].Operation.Action != ProviderCreate || dryRun.Operations[0].ClientRequestID == "" ||
		dryRun.DeferredDeletes[0].Operation.Action != ProviderDelete || dryRun.DeferredDeletes[0].ClientRequestID != "" {
		t.Fatalf("unsafe dry-run stages: operations=%#v deferred=%#v", dryRun.Operations, dryRun.DeferredDeletes)
	}

	applied, err := reconciler.Apply(context.Background(), request)
	if err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	_, revisionCalls, mutations = provider.snapshot()
	if applied.Status != TaskReadyToCommit || len(applied.Propagation) != 2 || applied.Operations[0].Status != OperationSucceeded ||
		applied.Operations[0].ProviderRequestID == "" || applied.DeferredDeletes[0].Status != OperationDeferred ||
		revisionCalls != 1 || len(mutations) != 1 || mutations[0].Operation.Action != ProviderCreate {
		t.Fatalf("Apply() = %#v; revisionCalls=%d mutations=%#v", applied, revisionCalls, mutations)
	}

	reported, err := reconciler.RecordProviderReport(ProviderReportRequest{
		TenantID: applied.TenantID, SiteID: applied.SiteID, IdempotencyKey: request.IdempotencyKey, PayloadDigest: applied.PayloadDigest,
		Report: ProviderReport{ClientRequestID: applied.Operations[0].ClientRequestID, Status: OperationRunning, Sequence: applied.Operations[0].ReportSequence + 100},
	})
	if err != nil || reported.Operations[0].Status != OperationSucceeded {
		t.Fatalf("late RecordProviderReport() = (%#v, %v)", reported, err)
	}

	committed, err := reconciler.Commit(context.Background(), CommitRequest{
		TenantID: applied.TenantID, SiteID: applied.SiteID, IdempotencyKey: request.IdempotencyKey, PayloadDigest: applied.PayloadDigest,
	})
	if err != nil {
		t.Fatalf("Commit() error = %v", err)
	}
	_, revisionCalls, mutations = provider.snapshot()
	if committed.Status != TaskCommitted || committed.DeferredDeletes[0].Status != OperationSucceeded ||
		committed.DeferredDeletes[0].ClientRequestID == "" || committed.DeferredDeletes[0].ProviderRequestID == "" ||
		revisionCalls != 1 || len(mutations) != 2 || mutations[1].Operation.Action != ProviderDelete {
		t.Fatalf("Commit() = %#v; revisionCalls=%d mutations=%#v", committed, revisionCalls, mutations)
	}

	replayed, err := reconciler.Apply(context.Background(), request)
	if err != nil || !replayed.Replayed || replayed.Status != TaskCommitted {
		t.Fatalf("replayed Apply() = (%#v, %v)", replayed, err)
	}
	replayedCommit, err := reconciler.Commit(context.Background(), CommitRequest{
		TenantID: applied.TenantID, SiteID: applied.SiteID, IdempotencyKey: request.IdempotencyKey, PayloadDigest: applied.PayloadDigest,
	})
	if err != nil || !replayedCommit.Replayed || replayedCommit.Status != TaskCommitted {
		t.Fatalf("replayed Commit() = (%#v, %v)", replayedCommit, err)
	}
	_, _, mutations = provider.snapshot()
	if len(mutations) != 2 {
		t.Fatalf("replay made %d provider mutations", len(mutations))
	}

	conflicting := request
	conflicting.Check.TTL = 120
	if _, err := reconciler.Apply(context.Background(), conflicting); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("conflicting Apply() error = %v", err)
	}
}

func TestReconcilerRevisionConflictDoesNotMutate(t *testing.T) {
	now := time.Date(2026, 7, 22, 15, 0, 0, 0, time.UTC)
	checker, request := newHealthyReconcileFixture(t, now)
	provider := &fakeProviderAdapter{revision: request.Provider.Revision + 1}
	reconciler := newTestReconciler(t, checker, provider, now, nil)
	result, err := reconciler.Apply(context.Background(), ReconcileRequest{IdempotencyKey: "revision-conflict", Check: request})
	if err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	_, _, mutations := provider.snapshot()
	if result.Status != TaskFailed || result.ErrorClass != ProviderErrorRevisionConflict || len(mutations) != 0 {
		t.Fatalf("Apply() = %#v; mutations=%#v", result, mutations)
	}
}

func TestReconcilerPartialFailureProducesDeterministicCompensation(t *testing.T) {
	now := time.Date(2026, 7, 22, 15, 0, 0, 0, time.UTC)
	checker, request := newHealthyReconcileFixture(t, now)
	request.Expected = []ExpectedRecord{
		{Type: RecordA, Values: []string{"192.0.2.10"}},
		{Type: RecordAAAA, Values: []string{"2001:db8::10"}},
	}
	request.Provider.Records = nil
	provider := &fakeProviderAdapter{revision: request.Provider.Revision}
	provider.mutate = func(provider *fakeProviderAdapter, call int, mutation ProviderMutation) (ProviderMutationResult, error) {
		if call == 1 {
			return provider.succeed(call, mutation)
		}
		return ProviderMutationResult{}, &ProviderError{
			Class: ProviderErrorPermanent, Code: "record_rejected", ProviderRequestID: "provider-failure-2",
		}
	}
	reconciler := newTestReconciler(t, checker, provider, now, nil)
	result, err := reconciler.Apply(context.Background(), ReconcileRequest{IdempotencyKey: "partial-failure", Check: request})
	if err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	_, _, mutations := provider.snapshot()
	if result.Status != TaskFailed || len(result.Operations) != 2 || result.Operations[0].Status != OperationSucceeded ||
		result.Operations[1].Status != OperationPermanentFailed || result.Operations[1].ProviderRequestID != "provider-failure-2" ||
		len(result.CompensationPlan) != 1 || result.CompensationPlan[0].Action != ProviderDelete ||
		result.CompensationPlan[0].RecordID != result.Operations[0].ProviderRecordID || len(mutations) != 2 {
		t.Fatalf("Apply() = %#v; mutations=%#v", result, mutations)
	}
	for _, mutation := range mutations {
		if mutation.Operation.Action == ProviderDelete {
			t.Fatal("partial failure executed compensation automatically")
		}
	}
}

func TestMergeProviderReportRejectsOutOfOrderAndTerminalRegression(t *testing.T) {
	current := OperationResult{ClientRequestID: "dns-request", Status: OperationRunning, ReportSequence: 4}
	succeeded, changed := MergeProviderReport(current, ProviderReport{
		ClientRequestID: "dns-request", ProviderRequestID: "provider-request", ProviderRecordID: "record-new",
		ProviderRevision: 8, Status: OperationSucceeded, Sequence: 6,
	})
	if !changed || succeeded.Status != OperationSucceeded || succeeded.ReportSequence != 6 {
		t.Fatalf("MergeProviderReport(success) = (%#v, %t)", succeeded, changed)
	}
	for _, report := range []ProviderReport{
		{ClientRequestID: "dns-request", Status: OperationRunning, Sequence: 5},
		{ClientRequestID: "dns-request", Status: OperationRunning, Sequence: 7},
		{ClientRequestID: "other-request", Status: OperationPermanentFailed, Sequence: 8},
	} {
		got, changed := MergeProviderReport(succeeded, report)
		if changed || got.Status != OperationSucceeded || got.ReportSequence != 6 {
			t.Fatalf("terminal regressed with %#v: (%#v, %t)", report, got, changed)
		}
	}
	newerRunning := OperationResult{
		ClientRequestID: "dns-request", ProviderRequestID: "provider-request",
		ProviderRecordID: "record-new", ProviderRevision: 100,
		Status: OperationRunning, ReportSequence: 10,
	}
	regressed, changed := MergeProviderReport(newerRunning, ProviderReport{
		ClientRequestID: "dns-request", ProviderRequestID: "provider-request",
		ProviderRecordID: "record-new", ProviderRevision: 8,
		Status: OperationSucceeded, Sequence: 11,
	})
	if changed || regressed.ProviderRevision != 100 || regressed.ReportSequence != 10 {
		t.Fatalf("provider revision regressed: (%#v, %t)", regressed, changed)
	}
}

func TestMergeProviderReportPreservesEstablishedIdentities(t *testing.T) {
	current := OperationResult{
		SourceSequence: 3,
		Operation: ProviderOperation{
			Sequence: 3, Action: ProviderCreate, Name: "www.example.test.", Type: RecordA,
			Value: "192.0.2.10", TTL: 300,
		},
		ClientRequestID: "dns-request", ProviderRequestID: "provider-request", ProviderRecordID: "record-1",
		ProviderRevision: 7, Status: OperationRunning, Attempts: 2,
		ErrorClass: ProviderErrorTransient, ErrorCode: "provider_pending", ReportSequence: 4,
	}
	report := ProviderReport{
		ClientRequestID: "dns-request", ProviderRequestID: "provider-request", ProviderRecordID: "record-1",
		ProviderRevision: 8, Status: OperationSucceeded, ErrorCode: "completed", Sequence: 5,
	}
	for _, test := range []struct {
		name              string
		providerRequestID string
		providerRecordID  string
	}{
		{name: "request ID drift", providerRequestID: "other-provider-request", providerRecordID: "record-1"},
		{name: "record ID drift", providerRequestID: "provider-request", providerRecordID: "other-record"},
		{name: "both identities drift", providerRequestID: "other-provider-request", providerRecordID: "other-record"},
	} {
		t.Run(test.name, func(t *testing.T) {
			drifted := report
			drifted.ProviderRequestID = test.providerRequestID
			drifted.ProviderRecordID = test.providerRecordID
			got, changed := MergeProviderReport(current, drifted)
			if changed || got != current {
				t.Fatalf("MergeProviderReport() = (%#v, %t), want unchanged %#v", got, changed, current)
			}
		})
	}

	t.Run("same identities accepted", func(t *testing.T) {
		got, changed := MergeProviderReport(current, report)
		if !changed || got.ProviderRequestID != current.ProviderRequestID ||
			got.ProviderRecordID != current.ProviderRecordID || got.ProviderRevision != 8 ||
			got.Status != OperationSucceeded || got.ReportSequence != 5 {
			t.Fatalf("MergeProviderReport() = (%#v, %t)", got, changed)
		}
	})

	t.Run("empty current establishes identities", func(t *testing.T) {
		empty := current
		empty.ProviderRequestID = ""
		empty.ProviderRecordID = ""
		got, changed := MergeProviderReport(empty, report)
		if !changed || got.ProviderRequestID != report.ProviderRequestID ||
			got.ProviderRecordID != report.ProviderRecordID || got.ProviderRevision != 8 ||
			got.Status != OperationSucceeded || got.ReportSequence != 5 {
			t.Fatalf("MergeProviderReport() = (%#v, %t)", got, changed)
		}
	})

	t.Run("omitted identities preserve current", func(t *testing.T) {
		omitted := report
		omitted.ProviderRequestID = ""
		omitted.ProviderRecordID = ""
		got, changed := MergeProviderReport(current, omitted)
		if !changed || got.ProviderRequestID != current.ProviderRequestID ||
			got.ProviderRecordID != current.ProviderRecordID || got.ProviderRevision != 8 ||
			got.Status != OperationSucceeded || got.ReportSequence != 5 {
			t.Fatalf("MergeProviderReport() = (%#v, %t)", got, changed)
		}
	})
}

func TestProviderOperationUsesCanonicalRecordIDForUpdateAndDelete(t *testing.T) {
	now := time.Date(2026, 7, 28, 15, 0, 0, 0, time.UTC)
	checker, request := newHealthyReconcileFixture(t, now)
	for _, action := range []ProviderAction{ProviderUpdate, ProviderDelete} {
		t.Run(string(action), func(t *testing.T) {
			provider := &fakeProviderAdapter{revision: request.Provider.Revision}
			provider.mutate = func(_ *fakeProviderAdapter, _ int, _ ProviderMutation) (ProviderMutationResult, error) {
				return ProviderMutationResult{
					ProviderRequestID: "provider-request", RecordID: "record?invalid",
					Revision: request.Provider.Revision + 1,
				}, nil
			}
			reconciler := newTestReconciler(t, checker, provider, now, nil)
			result := reconciler.executeProviderOperation(t.Context(), OperationResult{
				ClientRequestID: "dns-request", Status: OperationRunning, ReportSequence: 1,
				Operation: ProviderOperation{Action: action, RecordID: "record-valid"},
			}, request, request.Provider.Revision)
			if result.Status != OperationSucceeded || result.ProviderRecordID != "record-valid" {
				t.Fatalf("executeProviderOperation(%s) = %#v", action, result)
			}
		})
	}
}

func TestProviderIdentifierMatchesPersistentContract(t *testing.T) {
	for _, value := range []string{"provider-1", "provider.example/record:1", "A_b.C-1"} {
		if !validProviderIdentifier(value) {
			t.Errorf("validProviderIdentifier(%q) = false", value)
		}
	}
	for _, value := range []string{"", "-leading", "provider?request", "provider request", strings.Repeat("a", 257)} {
		if validProviderIdentifier(value) {
			t.Errorf("validProviderIdentifier(%q) = true", value)
		}
	}
}

type httpTestProvider struct {
	mu       sync.Mutex
	revision int64
	client   *http.Client
	url      string
}

func (p *httpTestProvider) CurrentRevision(context.Context, ProviderRevisionRequest) (int64, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.revision, nil
}

func (p *httpTestProvider) Mutate(ctx context.Context, mutation ProviderMutation) (ProviderMutationResult, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.url, nil)
	if err != nil {
		return ProviderMutationResult{}, &ProviderError{Class: ProviderErrorPermanent, Code: "request_invalid"}
	}
	req.Header.Set("X-Client-Request-ID", mutation.ClientRequestID)
	response, err := p.client.Do(req)
	if err != nil {
		return ProviderMutationResult{}, err
	}
	defer response.Body.Close()
	providerRequestID := response.Header.Get("X-Provider-Request-ID")
	switch {
	case response.StatusCode == http.StatusTooManyRequests:
		return ProviderMutationResult{}, &ProviderError{
			Class: ProviderErrorTransient, Code: "provider_rate_limited", RetryAfter: 2 * time.Millisecond, ProviderRequestID: providerRequestID,
		}
	case response.StatusCode >= 500:
		return ProviderMutationResult{}, &ProviderError{
			Class: ProviderErrorTransient, Code: "provider_unavailable", ProviderRequestID: providerRequestID,
		}
	case response.StatusCode >= 400:
		return ProviderMutationResult{}, &ProviderError{
			Class: ProviderErrorPermanent, Code: "provider_rejected", ProviderRequestID: providerRequestID,
		}
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if mutation.ExpectedRevision != p.revision {
		return ProviderMutationResult{}, ErrProviderRevisionConflict
	}
	p.revision++
	return ProviderMutationResult{ProviderRequestID: providerRequestID, RecordID: "http-created-record", Revision: p.revision}, nil
}

func TestReconcilerRetriesHTTProvider429And5xxWithSameRequestID(t *testing.T) {
	var calls atomic.Int32
	var mu sync.Mutex
	clientRequestIDs := make([]string, 0, 3)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		call := calls.Add(1)
		mu.Lock()
		clientRequestIDs = append(clientRequestIDs, request.Header.Get("X-Client-Request-ID"))
		mu.Unlock()
		w.Header().Set("X-Provider-Request-ID", fmt.Sprintf("http-provider-%d", call))
		switch call {
		case 1:
			w.WriteHeader(http.StatusTooManyRequests)
		case 2:
			w.WriteHeader(http.StatusServiceUnavailable)
		default:
			w.WriteHeader(http.StatusNoContent)
		}
	}))
	t.Cleanup(server.Close)
	now := time.Date(2026, 7, 22, 15, 0, 0, 0, time.UTC)
	checker, request := newHealthyReconcileFixture(t, now)
	provider := &httpTestProvider{revision: request.Provider.Revision, client: server.Client(), url: server.URL}
	delays := make([]time.Duration, 0)
	reconciler := newTestReconciler(t, checker, provider, now, func(config *ReconcilerConfig) {
		config.Sleep = func(ctx context.Context, delay time.Duration) error {
			delays = append(delays, delay)
			return ctx.Err()
		}
	})
	result, err := reconciler.Apply(context.Background(), ReconcileRequest{IdempotencyKey: "http-retries", Check: request})
	if err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	mu.Lock()
	requestIDs := append([]string(nil), clientRequestIDs...)
	mu.Unlock()
	if result.Status != TaskReadyToCommit || result.Operations[0].Attempts != 3 ||
		result.Operations[0].ProviderRequestID != "http-provider-3" || len(requestIDs) != 3 ||
		requestIDs[0] == "" || requestIDs[0] != requestIDs[1] || requestIDs[1] != requestIDs[2] || len(delays) < 3 || delays[0] < 2*time.Millisecond {
		t.Fatalf("Apply() = %#v; requestIDs=%#v delays=%#v", result, requestIDs, delays)
	}
}

type convergingResolver struct {
	mu           sync.Mutex
	authorityOne ResolverEndpoint
	authorityTwo ResolverEndpoint
	publicOne    ResolverEndpoint
	publicTwo    ResolverEndpoint
	poll         int
}

func (r *convergingResolver) Resolve(ctx context.Context, endpoint ResolverEndpoint, query DNSQuery) (DNSResponse, error) {
	if err := ctx.Err(); err != nil {
		return DNSResponse{}, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if endpoint == r.authorityOne {
		r.poll++
	}
	value := "192.0.2.10"
	if endpoint == r.authorityTwo && r.poll == 1 {
		value = "192.0.2.20"
	}
	authoritative := endpoint == r.authorityOne || endpoint == r.authorityTwo
	return answerResponse(authoritative, query.Name, query.Type, value), nil
}

func TestReconcilerSplitAuthorityEventuallyConverges(t *testing.T) {
	now := time.Date(2026, 7, 22, 15, 0, 0, 0, time.UTC)
	authorityOne := testEndpoint(t, "192.0.2.91", 53)
	authorityTwo := testEndpoint(t, "192.0.2.92", 53)
	publicOne := testEndpoint(t, "198.51.100.91", 53)
	publicTwo := testEndpoint(t, "198.51.100.92", 53)
	resolver := &convergingResolver{
		authorityOne: authorityOne, authorityTwo: authorityTwo, publicOne: publicOne, publicTwo: publicTwo,
	}
	checker := testChecker(t, resolver,
		[]NamedResolver{{Name: "ns1.example.test", Endpoint: authorityOne}, {Name: "ns2.example.test", Endpoint: authorityTwo}},
		[]NamedResolver{{Name: "public-a", Endpoint: publicOne}, {Name: "public-b", Endpoint: publicTwo}}, now, 1, 4)
	request := baseRequest(now, RecordA, "192.0.2.10")
	request.Provider.Records[0].Value = "192.0.2.20"
	provider := &fakeProviderAdapter{revision: request.Provider.Revision}
	reconciler := newTestReconciler(t, checker, provider, now, nil)
	result, err := reconciler.Apply(context.Background(), ReconcileRequest{IdempotencyKey: "eventual-convergence", Check: request})
	if err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	want := []Classification{ClassificationAuthorityInconsistent, ClassificationHealthy, ClassificationHealthy}
	if result.Status != TaskReadyToCommit || len(result.Propagation) != len(want) {
		t.Fatalf("Apply() = %#v", result)
	}
	for index := range want {
		if result.Propagation[index].Status != want[index] {
			t.Fatalf("propagation[%d] = %#v, want %q", index, result.Propagation[index], want[index])
		}
	}
}

func TestReconcilerNXDOMAINNeverDeletesOldRecord(t *testing.T) {
	now := time.Date(2026, 7, 22, 15, 0, 0, 0, time.UTC)
	authority := testEndpoint(t, "192.0.2.93", 53)
	public := testEndpoint(t, "198.51.100.93", 53)
	query := DNSQuery{Name: "www.example.test.", Type: RecordA}
	nxdomainSOA := []DNSRecord{{Name: "example.test.", Type: RecordSOA, TTL: 90}}
	resolver := newFakeResolver()
	resolver.set(authority, query, responseHandler(DNSResponse{Authoritative: true, RCode: 3, Authority: nxdomainSOA}))
	resolver.set(public, query, responseHandler(DNSResponse{RCode: 3, Authority: nxdomainSOA}))
	checker := testChecker(t, resolver,
		[]NamedResolver{{Name: "ns1.example.test", Endpoint: authority}},
		[]NamedResolver{{Name: "public", Endpoint: public}}, now, 1, 4)
	request := baseRequest(now, RecordA, "192.0.2.10")
	request.Provider.Records[0].Value = "192.0.2.20"
	provider := &fakeProviderAdapter{revision: request.Provider.Revision}
	reconciler := newTestReconciler(t, checker, provider, now, func(config *ReconcilerConfig) {
		config.PollAttempts = 2
		config.RequiredConsecutive = 1
	})
	result, err := reconciler.Apply(context.Background(), ReconcileRequest{IdempotencyKey: "nxdomain", Check: request})
	if err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	_, _, mutations := provider.snapshot()
	if result.Status != TaskFailed || result.ErrorCode != "propagation_not_converged" || len(result.Propagation) != 2 ||
		result.Propagation[0].Status != ClassificationNXDOMAIN || len(result.CompensationPlan) != 1 ||
		len(mutations) != 1 || mutations[0].Operation.Action != ProviderCreate {
		t.Fatalf("Apply() = %#v; mutations=%#v", result, mutations)
	}
	if _, err := reconciler.Commit(context.Background(), CommitRequest{
		TenantID: result.TenantID, SiteID: result.SiteID, IdempotencyKey: "nxdomain", PayloadDigest: result.PayloadDigest,
	}); !errors.Is(err, ErrCommitNotReady) {
		t.Fatalf("Commit() error = %v", err)
	}
}

func TestReconcilerCancellationStopsPropagationAndOnlyPlansCompensation(t *testing.T) {
	now := time.Date(2026, 7, 22, 15, 0, 0, 0, time.UTC)
	authority := testEndpoint(t, "192.0.2.94", 53)
	public := testEndpoint(t, "198.51.100.94", 53)
	query := DNSQuery{Name: "www.example.test.", Type: RecordA}
	resolver := newFakeResolver()
	blocking := func(ctx context.Context, _ ResolverEndpoint, _ DNSQuery) (DNSResponse, error) {
		<-ctx.Done()
		return DNSResponse{}, ctx.Err()
	}
	resolver.set(authority, query, blocking)
	resolver.set(public, query, blocking)
	checker := testChecker(t, resolver,
		[]NamedResolver{{Name: "ns1.example.test", Endpoint: authority}},
		[]NamedResolver{{Name: "public", Endpoint: public}}, now, 1, 4)
	request := baseRequest(now, RecordA, "192.0.2.10")
	request.Provider.Records[0].Value = "192.0.2.20"
	created := make(chan struct{})
	var once sync.Once
	provider := &fakeProviderAdapter{revision: request.Provider.Revision}
	provider.mutate = func(provider *fakeProviderAdapter, call int, mutation ProviderMutation) (ProviderMutationResult, error) {
		result, err := provider.succeed(call, mutation)
		once.Do(func() { close(created) })
		return result, err
	}
	reconciler := newTestReconciler(t, checker, provider, now, nil)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan ReconcileResult, 1)
	go func() {
		result, _ := reconciler.Apply(ctx, ReconcileRequest{IdempotencyKey: "cancelled", Check: request})
		done <- result
	}()
	<-created
	cancel()
	select {
	case result := <-done:
		_, _, mutations := provider.snapshot()
		if result.Status != TaskCancelled || result.ErrorClass != ProviderErrorCancelled || len(result.CompensationPlan) != 1 ||
			len(mutations) != 1 || mutations[0].Operation.Action != ProviderCreate {
			t.Fatalf("Apply() = %#v; mutations=%#v", result, mutations)
		}
	case <-time.After(time.Second):
		t.Fatal("cancelled reconcile did not stop")
	}
}

func TestReconcilerProviderTimeoutIsBounded(t *testing.T) {
	now := time.Date(2026, 7, 22, 15, 0, 0, 0, time.UTC)
	checker, request := newHealthyReconcileFixture(t, now)
	provider := &timeoutProviderAdapter{revision: request.Provider.Revision}
	reconciler := newTestReconciler(t, checker, provider, now, func(config *ReconcilerConfig) {
		config.ProviderAttempts = 1
		config.ProviderTimeout = 10 * time.Millisecond
	})
	started := time.Now()
	result, err := reconciler.Apply(context.Background(), ReconcileRequest{IdempotencyKey: "provider-timeout", Check: request})
	if err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	if result.Status != TaskTimedOut || result.Operations[0].Status != OperationTransientFailed ||
		result.Operations[0].ErrorClass != ProviderErrorTimeout || time.Since(started) > 500*time.Millisecond {
		t.Fatalf("Apply() = %#v; elapsed=%s", result, time.Since(started))
	}
}

func TestReconcilerRecoveryPendingDoesNotBurnImmediateProviderAttempts(t *testing.T) {
	now := time.Date(2026, 8, 3, 9, 0, 0, 0, time.UTC)
	checker, request := newHealthyReconcileFixture(t, now)
	provider := &fakeProviderAdapter{revision: request.Provider.Revision}
	provider.mutate = func(_ *fakeProviderAdapter, _ int, mutation ProviderMutation) (ProviderMutationResult, error) {
		return ProviderMutationResult{}, &ProviderError{
			Class: ProviderErrorTransient, Code: "provider_recovery_pending", RetryAfter: 2 * time.Minute,
			ProviderRequestID: "dns-reconcile-recovery-request",
		}
	}
	reconciler := newTestReconciler(t, checker, provider, now, nil)
	result, err := reconciler.Apply(t.Context(), ReconcileRequest{
		IdempotencyKey: "durable-provider-recovery", Check: request,
	})
	if err != nil {
		t.Fatal(err)
	}
	_, _, mutations := provider.snapshot()
	if result.Status != TaskPropagating || result.ErrorClass != ProviderErrorTransient ||
		result.ErrorCode != "provider_recovery_pending" || len(result.CompensationPlan) != 0 || len(mutations) != 1 ||
		mutations[0].ClientRequestID != result.Operations[0].ClientRequestID {
		t.Fatalf("result=%#v mutations=%#v", result, mutations)
	}
}

type timeoutProviderAdapter struct{ revision int64 }

func (p *timeoutProviderAdapter) CurrentRevision(context.Context, ProviderRevisionRequest) (int64, error) {
	return p.revision, nil
}

func (*timeoutProviderAdapter) Mutate(ctx context.Context, _ ProviderMutation) (ProviderMutationResult, error) {
	<-ctx.Done()
	return ProviderMutationResult{}, ctx.Err()
}

func TestReconcilerConcurrentDuplicateRunsProviderOnce(t *testing.T) {
	now := time.Date(2026, 7, 22, 15, 0, 0, 0, time.UTC)
	checker, request := newHealthyReconcileFixture(t, now)
	started := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	provider := &fakeProviderAdapter{revision: request.Provider.Revision}
	provider.mutate = func(provider *fakeProviderAdapter, call int, mutation ProviderMutation) (ProviderMutationResult, error) {
		once.Do(func() { close(started) })
		<-release
		return provider.succeed(call, mutation)
	}
	reconciler := newTestReconciler(t, checker, provider, now, nil)
	reconcileRequest := ReconcileRequest{IdempotencyKey: "concurrent-replay", Check: request}
	results := make(chan ReconcileResult, 2)
	go func() {
		result, _ := reconciler.Apply(context.Background(), reconcileRequest)
		results <- result
	}()
	<-started
	go func() {
		result, _ := reconciler.Apply(context.Background(), reconcileRequest)
		results <- result
	}()
	close(release)
	first := <-results
	second := <-results
	_, _, mutations := provider.snapshot()
	if first.Status != TaskReadyToCommit || second.Status != TaskReadyToCommit || first.Replayed == second.Replayed || len(mutations) != 1 {
		t.Fatalf("results=(%#v, %#v), mutations=%#v", first, second, mutations)
	}
}
