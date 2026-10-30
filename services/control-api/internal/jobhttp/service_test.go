package jobhttp

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestNewServiceRequiresValidCursorKeyring(t *testing.T) {
	reader := &fixtureReader{}
	tests := []struct {
		name   string
		config ServiceConfig
	}{
		{name: "missing config", config: ServiceConfig{}},
		{
			name: "short key",
			config: ServiceConfig{
				ActiveCursorKeyID: "active",
				CursorKeys:        map[string][]byte{"active": []byte("too-short")},
			},
		},
		{
			name: "unknown active key id",
			config: ServiceConfig{
				ActiveCursorKeyID: "missing",
				CursorKeys:        map[string][]byte{"known": slices.Clone(fixtureCursorKey)},
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := NewService(reader, test.config); !errors.Is(err, ErrInvalidRequest) {
				t.Fatalf("NewService() error = %v, want %v", err, ErrInvalidRequest)
			}
		})
	}
	if _, err := NewService(nil, fixtureServiceConfig()); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("NewService(nil) error = %v, want %v", err, ErrInvalidRequest)
	}
}

func TestServiceListRBACIsolationAndStablePagination(t *testing.T) {
	platformScope := uuid.MustParse("10000000-0000-4000-8000-000000000001")
	tenantScope := uuid.MustParse("20000000-0000-4000-8000-000000000001")
	tenantA := uuid.MustParse("30000000-0000-4000-8000-000000000001")
	tenantB := uuid.MustParse("30000000-0000-4000-8000-000000000002")
	ids := []uuid.UUID{
		uuid.MustParse("40000000-0000-4000-8000-000000000004"),
		uuid.MustParse("40000000-0000-4000-8000-000000000003"),
		uuid.MustParse("40000000-0000-4000-8000-000000000002"),
		uuid.MustParse("40000000-0000-4000-8000-000000000001"),
	}
	reader := &fixtureReader{
		jobs: []Job{
			fixtureJob(ids[3], tenantA, StateQueued, fixtureNow.Add(-3*time.Minute)),
			fixtureJob(ids[1], tenantB, StateRunning, fixtureNow),
			fixtureJob(ids[0], tenantA, StateSucceeded, fixtureNow),
			fixtureJob(ids[2], tenantA, StateFailed, fixtureNow.Add(-time.Minute)),
		},
		scopeTenants: map[uuid.UUID]uuid.UUID{tenantScope: tenantA},
	}
	for _, job := range reader.jobs {
		if err := validateJob(job); err != nil {
			t.Fatalf("invalid fixture job %+v: %v", job, err)
		}
	}
	service := fixtureService(reader)
	request := fixtureListRequest(AudiencePlatform)
	var got []uuid.UUID
	for {
		page, err := service.List(t.Context(), platformPrincipal(platformScope), request)
		if err != nil {
			t.Fatal(err)
		}
		for _, job := range page.Data {
			got = append(got, job.TaskID)
		}
		if page.Page.NextCursor == "" {
			break
		}
		request.Cursor = page.Page.NextCursor
	}
	if want := ids; !slices.Equal(got, want) {
		t.Fatalf("paged task ids = %v, want %v", got, want)
	}

	tenantPage, err := service.List(t.Context(), tenantPrincipal(tenantScope), fixtureListRequest(AudienceTenant))
	if err != nil {
		t.Fatal(err)
	}
	for _, job := range tenantPage.Data {
		if job.TenantID != tenantA {
			t.Fatalf("tenant saw foreign job: %+v", job)
		}
	}
	override := fixtureListRequest(AudienceTenant)
	override.TenantID = &tenantA
	if _, err := service.List(t.Context(), tenantPrincipal(tenantScope), override); !errors.Is(err, ErrScopeForbidden) {
		t.Fatalf("tenant override error = %v", err)
	}
	if _, err := service.Get(t.Context(), tenantPrincipal(tenantScope), AudienceTenant, ids[1]); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-tenant detail error = %v", err)
	}
	foreignChild := ChildPageRequest{Audience: AudienceTenant, TaskID: ids[1], Limit: 20}
	if _, err := service.Attempts(t.Context(), tenantPrincipal(tenantScope), foreignChild); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-tenant attempts error = %v", err)
	}
	if _, err := service.Results(t.Context(), tenantPrincipal(tenantScope), foreignChild); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-tenant results error = %v", err)
	}
	denied := tenantPrincipal(tenantScope)
	denied.Permissions = nil
	if _, err := service.List(t.Context(), denied, fixtureListRequest(AudienceTenant)); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("permission error = %v", err)
	}
	wrongAudience := platformPrincipal(platformScope)
	if _, err := service.List(t.Context(), wrongAudience, fixtureListRequest(AudienceTenant)); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("audience error = %v", err)
	}
}

func TestServiceRejectsInvalidFiltersAndBoundCursorReuse(t *testing.T) {
	platformScope := uuid.MustParse("10000000-0000-4000-8000-000000000002")
	tenantID := uuid.MustParse("30000000-0000-4000-8000-000000000003")
	reader := &fixtureReader{jobs: []Job{
		fixtureJob(uuid.MustParse("40000000-0000-4000-8000-000000000005"), tenantID, StateQueued, fixtureNow),
		fixtureJob(uuid.MustParse("40000000-0000-4000-8000-000000000004"), tenantID, StateRunning, fixtureNow.Add(-time.Minute)),
	}}
	service := fixtureService(reader)
	principal := platformPrincipal(platformScope)
	base := fixtureListRequest(AudiencePlatform)
	base.Limit = 1
	page, err := service.List(t.Context(), principal, base)
	if err != nil || page.Page.NextCursor == "" {
		t.Fatalf("first page = %+v, err=%v", page, err)
	}
	changed := base
	changed.Cursor = page.Page.NextCursor
	changed.States = []State{StateQueued}
	if _, err := service.List(t.Context(), principal, changed); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("changed cursor binding error = %v", err)
	}

	tests := []ListRequest{
		{Audience: AudiencePlatform, From: fixtureNow, To: fixtureNow.Add(31*24*time.Hour + time.Nanosecond)},
		{Audience: AudiencePlatform, From: fixtureNow, To: fixtureNow.Add(time.Hour), States: []State{"unknown"}},
		{Audience: AudiencePlatform, From: fixtureNow, To: fixtureNow.Add(time.Hour), States: []State{StateQueued, StateQueued}},
		{Audience: AudiencePlatform, From: fixtureNow, To: fixtureNow.Add(time.Hour), Kind: "BadKind"},
		{Audience: AudiencePlatform, From: fixtureNow, To: fixtureNow.Add(time.Hour), Resource: " bad"},
		{Audience: AudiencePlatform, From: fixtureNow, To: fixtureNow.Add(time.Hour), Cursor: "not-base64"},
	}
	for index, request := range tests {
		if _, err := service.List(t.Context(), principal, request); !errors.Is(err, ErrInvalidRequest) {
			t.Errorf("invalid request %d error = %v", index, err)
		}
	}
}

func TestServicePreservesEveryCanonicalState(t *testing.T) {
	platformScope := uuid.MustParse("10000000-0000-4000-8000-000000000003")
	tenantID := uuid.MustParse("30000000-0000-4000-8000-000000000004")
	states := []State{StateQueued, StateRunning, StateSucceeded, StatePartialFailed, StateFailed, StateCancelled}
	reader := &fixtureReader{}
	for index, state := range states {
		id := uuid.MustParse("50000000-0000-4000-8000-" + []string{
			"000000000001", "000000000002", "000000000003", "000000000004", "000000000005", "000000000006",
		}[index])
		reader.jobs = append(reader.jobs, fixtureJob(id, tenantID, state, fixtureNow.Add(-time.Duration(index)*time.Minute)))
	}
	reader.jobs[0].RequestID = "upstream:request/1"
	request := fixtureListRequest(AudiencePlatform)
	request.Limit = 10
	page, err := fixtureService(reader).List(t.Context(), platformPrincipal(platformScope), request)
	if err != nil {
		t.Fatal(err)
	}
	got := make([]State, len(page.Data))
	for index, job := range page.Data {
		got[index] = job.Status
	}
	if !slices.Equal(got, states) {
		t.Fatalf("states = %v, want %v", got, states)
	}
	reader.jobs[0].Status = "regressed_unknown"
	if _, err := fixtureService(reader).List(t.Context(), platformPrincipal(platformScope), request); !errors.Is(err, ErrInvalidStoreResponse) {
		t.Fatalf("unknown stored state error = %v", err)
	}
}

func TestServiceRejectsTerminalJobWithPendingItems(t *testing.T) {
	platformScope := uuid.MustParse("10000000-0000-4000-8000-000000000020")
	tenantID := uuid.MustParse("30000000-0000-4000-8000-000000000020")
	taskID := uuid.MustParse("50000000-0000-4000-8000-000000000020")
	job := fixtureJob(taskID, tenantID, StateCancelled, fixtureNow)
	job.Progress = Progress{Total: 2, Completed: 1, Cancelled: 1, Pending: 1}

	_, err := fixtureService(&fixtureReader{jobs: []Job{job}}).Get(
		t.Context(), platformPrincipal(platformScope), AudiencePlatform, taskID,
	)
	if !errors.Is(err, ErrInvalidStoreResponse) {
		t.Fatalf("Get() error = %v, want %v", err, ErrInvalidStoreResponse)
	}
}

func TestServiceValidatesAttemptAndMaxAttemptBoundaries(t *testing.T) {
	platformScope := uuid.MustParse("10000000-0000-4000-8000-000000000021")
	tenantID := uuid.MustParse("30000000-0000-4000-8000-000000000021")
	taskID := uuid.MustParse("50000000-0000-4000-8000-000000000021")
	tests := []struct {
		name        string
		attempt     uint32
		maxAttempts uint32
		wantError   bool
	}{
		{name: "maximum accepted", attempt: maximumJobAttempts, maxAttempts: maximumJobAttempts},
		{name: "maximum exceeded", attempt: 1, maxAttempts: maximumJobAttempts + 1, wantError: true},
		{name: "attempt exceeds maximum", attempt: maximumJobAttempts + 1, maxAttempts: maximumJobAttempts, wantError: true},
		{name: "zero maximum", attempt: 0, maxAttempts: 0, wantError: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			job := fixtureJob(taskID, tenantID, StateSucceeded, fixtureNow)
			job.Attempt = test.attempt
			job.MaxAttempts = test.maxAttempts
			reader := &fixtureReader{jobs: []Job{job}}
			_, err := fixtureService(reader).Get(t.Context(), platformPrincipal(platformScope), AudiencePlatform, taskID)
			if test.wantError && !errors.Is(err, ErrInvalidStoreResponse) {
				t.Fatalf("Get() error = %v, want %v", err, ErrInvalidStoreResponse)
			}
			if !test.wantError && err != nil {
				t.Fatalf("Get() error = %v", err)
			}
		})
	}
}

func TestServiceRejectsInvalidTerminalResultCompletedAt(t *testing.T) {
	platformScope := uuid.MustParse("10000000-0000-4000-8000-000000000022")
	tenantID := uuid.MustParse("30000000-0000-4000-8000-000000000022")
	taskID := uuid.MustParse("50000000-0000-4000-8000-000000000022")
	nonUTC := fixtureNow.In(time.FixedZone("CST", 8*60*60))
	outOfRange := time.Date(10000, time.January, 1, 0, 0, 0, 0, time.UTC)
	zero := time.Time{}
	tests := []struct {
		name      string
		status    ResultState
		failure   string
		completed *time.Time
		wantError bool
	}{
		{name: "valid UTC", status: ResultSucceeded, completed: timePointer(fixtureNow)},
		{name: "succeeded zero", status: ResultSucceeded, completed: &zero, wantError: true},
		{name: "failed zero", status: ResultFailed, failure: "item_failed", completed: &zero, wantError: true},
		{name: "cancelled zero", status: ResultCancelled, failure: "cancelled", completed: &zero, wantError: true},
		{name: "non UTC", status: ResultSucceeded, completed: &nonUTC, wantError: true},
		{name: "not RFC3339 encodable", status: ResultSucceeded, completed: &outOfRange, wantError: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			reader := &fixtureReader{
				jobs: []Job{fixtureJob(taskID, tenantID, StateSucceeded, fixtureNow)},
				results: map[uuid.UUID][]ItemResult{taskID: {{
					Ordinal: 1, ItemID: "item-1", Status: test.status, Attempt: 1, Sequence: 1,
					FailureCode: test.failure, CompletedAt: test.completed,
				}}},
			}
			_, err := fixtureService(reader).Results(t.Context(), platformPrincipal(platformScope), ChildPageRequest{
				Audience: AudiencePlatform, TaskID: taskID, Limit: 20,
			})
			if test.wantError && !errors.Is(err, ErrInvalidStoreResponse) {
				t.Fatalf("Results() error = %v, want %v", err, ErrInvalidStoreResponse)
			}
			if !test.wantError && err != nil {
				t.Fatalf("Results() error = %v", err)
			}
		})
	}
}

func TestServicePagesAttemptsAndItemNodeResults(t *testing.T) {
	platformScope := uuid.MustParse("10000000-0000-4000-8000-000000000004")
	tenantID := uuid.MustParse("30000000-0000-4000-8000-000000000005")
	taskID := uuid.MustParse("50000000-0000-4000-8000-000000000010")
	nodeID := uuid.MustParse("60000000-0000-4000-8000-000000000001")
	completed := fixtureNow.Add(-time.Minute)
	reader := &fixtureReader{
		jobs: []Job{fixtureJob(taskID, tenantID, StateSucceeded, fixtureNow.Add(-2*time.Minute))},
		attempts: map[uuid.UUID][]Attempt{taskID: {
			{Number: 2, Status: AttemptSucceeded, StartedAt: completed.Add(-3 * time.Second), LastHeartbeatAt: completed.Add(-2 * time.Second), LeaseExpiresAt: completed.Add(time.Second), CompletedAt: &completed},
			{Number: 1, Status: AttemptLeaseExpired, StartedAt: completed.Add(-10 * time.Second), LastHeartbeatAt: completed.Add(-9 * time.Second), LeaseExpiresAt: completed.Add(-5 * time.Second), CompletedAt: timePointer(completed.Add(-4 * time.Second)), FailureCode: "lease_expired"},
		}},
		results: map[uuid.UUID][]ItemResult{taskID: {
			{Ordinal: 1, ItemID: "node-item", NodeID: &nodeID, Status: ResultSucceeded, Attempt: 2, Sequence: 1, CompletedAt: &completed},
			{Ordinal: 2, ItemID: "plain-item", Status: ResultSucceeded, Attempt: 1, Sequence: 1, CompletedAt: &completed},
		}},
	}
	service := fixtureService(reader)
	principal := platformPrincipal(platformScope)
	attemptRequest := ChildPageRequest{Audience: AudiencePlatform, TaskID: taskID, Limit: 1}
	firstAttempts, err := service.Attempts(t.Context(), principal, attemptRequest)
	if err != nil || firstAttempts.Data[0].Number != 2 || firstAttempts.Page.NextCursor == "" {
		t.Fatalf("attempt page = %+v, err=%v", firstAttempts, err)
	}
	attemptRequest.Cursor = firstAttempts.Page.NextCursor
	secondAttempts, err := service.Attempts(t.Context(), principal, attemptRequest)
	if err != nil || len(secondAttempts.Data) != 1 || secondAttempts.Data[0].Number != 1 {
		t.Fatalf("attempt page two = %+v, err=%v", secondAttempts, err)
	}
	resultRequest := ChildPageRequest{Audience: AudiencePlatform, TaskID: taskID, Limit: 1}
	firstResults, err := service.Results(t.Context(), principal, resultRequest)
	if err != nil || firstResults.Data[0].NodeID == nil || firstResults.Page.NextCursor == "" {
		t.Fatalf("result page = %+v, err=%v", firstResults, err)
	}
	resultRequest.Cursor = firstResults.Page.NextCursor
	secondResults, err := service.Results(t.Context(), principal, resultRequest)
	if err != nil || len(secondResults.Data) != 1 || secondResults.Data[0].Ordinal != 2 || secondResults.Data[0].NodeID != nil {
		t.Fatalf("result page two = %+v, err=%v", secondResults, err)
	}
}

func TestServiceEmptyUnavailableAndCancelledContext(t *testing.T) {
	platformScope := uuid.MustParse("10000000-0000-4000-8000-000000000005")
	principal := platformPrincipal(platformScope)
	empty, err := fixtureService(&fixtureReader{}).List(t.Context(), principal, fixtureListRequest(AudiencePlatform))
	if err != nil || empty.Data == nil || len(empty.Data) != 0 {
		t.Fatalf("empty page = %+v, err=%v", empty, err)
	}
	reader := &fixtureReader{listErr: errors.New("database password=secret")}
	if _, err := fixtureService(reader).List(t.Context(), principal, fixtureListRequest(AudiencePlatform)); !errors.Is(err, ErrStoreUnavailable) ||
		err.Error() != ErrStoreUnavailable.Error() {
		t.Fatalf("unavailable error = %q", err)
	}

	cancelReader := &fixtureReader{waitForCancel: true, contextDone: make(chan struct{})}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := fixtureService(cancelReader).List(ctx, principal, fixtureListRequest(AudiencePlatform)); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled context error = %v", err)
	}
	select {
	case <-cancelReader.contextDone:
	case <-time.After(time.Second):
		t.Fatal("reader did not observe cancelled request context")
	}
}
