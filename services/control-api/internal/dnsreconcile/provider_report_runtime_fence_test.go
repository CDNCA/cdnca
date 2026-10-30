package dnsreconcile

import (
	"context"
	"reflect"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/dnscheck"
	"github.com/google/uuid"
)

type providerReportRuntimeStore struct {
	Store
	calls   int
	request ProviderReportRequest
	result  ReportResult
}

func (store *providerReportRuntimeStore) RecordProviderReport(
	_ context.Context,
	request ProviderReportRequest,
) (ReportResult, error) {
	store.calls++
	store.request = request
	return store.result, nil
}

func TestRuntimeProviderReportRequiresDurableFenceBeforeStore(t *testing.T) {
	valid := ProviderReportRequest{
		TenantID: uuid.New(), SiteID: uuid.New(), TaskID: uuid.New(),
		WorkloadID: "provider-worker-a", JobAttempt: 3, LeaseID: uuid.New(),
		IdempotencyKey: "provider-report-fence", RequestID: "provider-report-request",
		Traceparent:      "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
		ExpectedRevision: 7,
		Report:           dnscheck.ProviderReport{ClientRequestID: "provider-operation-1", Sequence: 1},
	}

	t.Run("nil context", func(t *testing.T) {
		store, runtime := newProviderReportRuntime(t, valid)
		if _, err := runtime.RecordProviderReport(nil, valid); err != ErrInvalidInput {
			t.Fatalf("RecordProviderReport(nil) error=%v, want ErrInvalidInput", err)
		}
		if store.calls != 0 {
			t.Fatalf("store calls=%d, want 0", store.calls)
		}
	})

	t.Run("cancelled context", func(t *testing.T) {
		store, runtime := newProviderReportRuntime(t, valid)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if _, err := runtime.RecordProviderReport(ctx, valid); err != ErrInvalidInput {
			t.Fatalf("RecordProviderReport(cancelled) error=%v, want ErrInvalidInput", err)
		}
		if store.calls != 0 {
			t.Fatalf("store calls=%d, want 0", store.calls)
		}
	})

	for _, test := range []struct {
		name   string
		mutate func(*ProviderReportRequest)
	}{
		{name: "tenant", mutate: func(request *ProviderReportRequest) { request.TenantID = uuid.Nil }},
		{name: "site", mutate: func(request *ProviderReportRequest) { request.SiteID = uuid.Nil }},
		{name: "task", mutate: func(request *ProviderReportRequest) { request.TaskID = uuid.Nil }},
		{name: "empty workload", mutate: func(request *ProviderReportRequest) { request.WorkloadID = "" }},
		{name: "malformed workload", mutate: func(request *ProviderReportRequest) { request.WorkloadID = " provider-worker-a" }},
		{name: "oversize workload", mutate: func(request *ProviderReportRequest) { request.WorkloadID = strings.Repeat("w", 129) }},
		{name: "attempt", mutate: func(request *ProviderReportRequest) { request.JobAttempt = 0 }},
		{name: "lease", mutate: func(request *ProviderReportRequest) { request.LeaseID = uuid.Nil }},
		{name: "idempotency key", mutate: func(request *ProviderReportRequest) { request.IdempotencyKey = "" }},
		{name: "request id", mutate: func(request *ProviderReportRequest) { request.RequestID = "" }},
		{name: "traceparent", mutate: func(request *ProviderReportRequest) { request.Traceparent = "" }},
		{name: "revision", mutate: func(request *ProviderReportRequest) { request.ExpectedRevision = 0 }},
		{name: "client request id", mutate: func(request *ProviderReportRequest) { request.Report.ClientRequestID = "" }},
		{name: "sequence", mutate: func(request *ProviderReportRequest) { request.Report.Sequence = 0 }},
	} {
		t.Run("missing or invalid "+test.name, func(t *testing.T) {
			store, runtime := newProviderReportRuntime(t, valid)
			request := valid
			test.mutate(&request)
			if _, err := runtime.RecordProviderReport(t.Context(), request); err != ErrInvalidInput {
				t.Fatalf("RecordProviderReport() error=%v, want ErrInvalidInput", err)
			}
			if store.calls != 0 {
				t.Fatalf("store calls=%d, want 0", store.calls)
			}
		})
	}

	t.Run("valid durable tuple", func(t *testing.T) {
		store, runtime := newProviderReportRuntime(t, valid)
		got, err := runtime.RecordProviderReport(t.Context(), valid)
		if err != nil || !reflect.DeepEqual(got, store.result) {
			t.Fatalf("RecordProviderReport()=(%#v,%v), want %#v", got, err, store.result)
		}
		if store.calls != 1 || !reflect.DeepEqual(store.request, valid) {
			t.Fatalf("store calls=%d request=%#v, want one unchanged request", store.calls, store.request)
		}
	})
}

func newProviderReportRuntime(
	t *testing.T,
	request ProviderReportRequest,
) (*providerReportRuntimeStore, *Runtime) {
	t.Helper()
	store := &providerReportRuntimeStore{result: ReportResult{
		Task:     Task{ID: request.TaskID, TenantID: request.TenantID, SiteID: request.SiteID},
		Accepted: true,
	}}
	runtime, err := NewRuntime(testRuntimeConfig(), RuntimeDependencies{
		Store: store, CheckerResolver: &testCheckerResolver{},
		ProviderResolver: &testProviderResolver{}, Entitlement: testEntitlement{},
	})
	if err != nil {
		t.Fatal(err)
	}
	return store, runtime
}
