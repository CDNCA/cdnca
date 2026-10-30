package jobhttp

import (
	"context"
	"slices"
	"sort"
	"sync"
	"time"

	"github.com/google/uuid"
)

var fixtureNow = time.Date(2026, 7, 23, 4, 0, 0, 0, time.UTC)

const fixtureCursorKeyID = "fixture-v1"

var fixtureCursorKey = []byte("0123456789abcdef0123456789abcdef")

type fixtureReader struct {
	mu            sync.Mutex
	calls         int
	jobs          []Job
	attempts      map[uuid.UUID][]Attempt
	results       map[uuid.UUID][]ItemResult
	receipts      map[uuid.UUID][]SettlementReceipt
	deadLetters   map[uuid.UUID][]DeadLetter
	scopeTenants  map[uuid.UUID]uuid.UUID
	listErr       error
	getErr        error
	attemptsErr   error
	resultsErr    error
	waitForCancel bool
	contextDone   chan struct{}
	commandErr    error
	commandCalls  int
	commandAudits []fixtureCommandAudit
	commandKeys   map[string]fixtureCommandReceipt
	failAudit     bool
	failQueue     bool
}

func (reader *fixtureReader) List(ctx context.Context, scope ReadScope, query ListQuery) ([]Job, error) {
	reader.recordCall()
	if reader.waitForCancel {
		<-ctx.Done()
		if reader.contextDone != nil {
			close(reader.contextDone)
		}
		return nil, ctx.Err()
	}
	reader.mu.Lock()
	defer reader.mu.Unlock()
	if reader.listErr != nil {
		return nil, reader.listErr
	}
	jobs := make([]Job, 0, len(reader.jobs))
	for _, job := range reader.jobs {
		if scope.Kind == ScopeTenant && reader.scopeTenants[scope.ID] != job.TenantID ||
			query.TenantID != nil && *query.TenantID != job.TenantID ||
			query.TaskID != nil && *query.TaskID != job.TaskID ||
			len(query.States) > 0 && !slices.Contains(query.States, job.Status) ||
			query.Kind != "" && query.Kind != job.Kind ||
			query.Resource != "" && query.Resource != job.RelatedResource.Reference ||
			job.CreatedAt.Before(query.From) || !job.CreatedAt.Before(query.To) {
			continue
		}
		if query.AfterCreated != nil && !jobBefore(job, *query.AfterCreated, *query.AfterTaskID) {
			continue
		}
		jobs = append(jobs, job)
	}
	sort.Slice(jobs, func(left, right int) bool {
		return jobs[left].CreatedAt.After(jobs[right].CreatedAt) ||
			jobs[left].CreatedAt.Equal(jobs[right].CreatedAt) && jobs[left].TaskID.String() > jobs[right].TaskID.String()
	})
	if len(jobs) > query.Limit {
		jobs = jobs[:query.Limit]
	}
	return slices.Clone(jobs), nil
}

func (reader *fixtureReader) Get(ctx context.Context, scope ReadScope, taskID uuid.UUID) (Job, error) {
	reader.recordCall()
	if err := ctx.Err(); err != nil {
		return Job{}, err
	}
	reader.mu.Lock()
	defer reader.mu.Unlock()
	if reader.getErr != nil {
		return Job{}, reader.getErr
	}
	for _, job := range reader.jobs {
		if job.TaskID == taskID && (scope.Kind == ScopePlatform || reader.scopeTenants[scope.ID] == job.TenantID) {
			return job, nil
		}
	}
	return Job{}, ErrNotFound
}

func (reader *fixtureReader) Attempts(
	ctx context.Context,
	_ ReadScope,
	taskID uuid.UUID,
	query AttemptQuery,
) ([]Attempt, error) {
	reader.recordCall()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	reader.mu.Lock()
	defer reader.mu.Unlock()
	if reader.attemptsErr != nil {
		return nil, reader.attemptsErr
	}
	items := make([]Attempt, 0, len(reader.attempts[taskID]))
	for _, item := range reader.attempts[taskID] {
		if query.AfterAttempt == nil || item.Number < *query.AfterAttempt {
			items = append(items, item)
		}
	}
	sort.Slice(items, func(left, right int) bool { return items[left].Number > items[right].Number })
	if len(items) > query.Limit {
		items = items[:query.Limit]
	}
	return slices.Clone(items), nil
}

func (reader *fixtureReader) Results(
	ctx context.Context,
	_ ReadScope,
	taskID uuid.UUID,
	query ResultQuery,
) ([]ItemResult, error) {
	reader.recordCall()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	reader.mu.Lock()
	defer reader.mu.Unlock()
	if reader.resultsErr != nil {
		return nil, reader.resultsErr
	}
	items := make([]ItemResult, 0, len(reader.results[taskID]))
	for _, item := range reader.results[taskID] {
		if query.AfterOrdinal == nil || item.Ordinal > *query.AfterOrdinal {
			items = append(items, item)
		}
	}
	sort.Slice(items, func(left, right int) bool { return items[left].Ordinal < items[right].Ordinal })
	if len(items) > query.Limit {
		items = items[:query.Limit]
	}
	return slices.Clone(items), nil
}

func (reader *fixtureReader) Receipts(
	ctx context.Context,
	_ ReadScope,
	taskID uuid.UUID,
	query ReceiptQuery,
) ([]SettlementReceipt, error) {
	reader.recordCall()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	reader.mu.Lock()
	defer reader.mu.Unlock()
	items := slices.Clone(reader.receipts[taskID])
	sort.Slice(items, func(left, right int) bool {
		return items[left].Attempt > items[right].Attempt ||
			items[left].Attempt == items[right].Attempt && items[left].Ordinal < items[right].Ordinal
	})
	if len(items) > query.Limit {
		items = items[:query.Limit]
	}
	return items, nil
}

func (reader *fixtureReader) DeadLetters(
	ctx context.Context,
	_ ReadScope,
	taskID uuid.UUID,
	query DeadLetterQuery,
) ([]DeadLetter, error) {
	reader.recordCall()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	reader.mu.Lock()
	defer reader.mu.Unlock()
	items := slices.Clone(reader.deadLetters[taskID])
	sort.Slice(items, func(left, right int) bool { return items[left].Attempt > items[right].Attempt })
	if len(items) > query.Limit {
		items = items[:query.Limit]
	}
	return items, nil
}

func (reader *fixtureReader) recordCall() {
	reader.mu.Lock()
	reader.calls++
	reader.mu.Unlock()
}

func (reader *fixtureReader) callCount() int {
	reader.mu.Lock()
	defer reader.mu.Unlock()
	return reader.calls
}

func fixtureJob(id, tenantID uuid.UUID, state State, createdAt time.Time) Job {
	updatedAt := createdAt
	job := Job{
		TaskID: id, TenantID: tenantID, Kind: "cache.purge",
		RelatedResource: RelatedResource{Reference: "site/site-1"},
		RequestID:       "request-1", TraceID: "trace-1", Status: state,
		MaxAttempts: 3, Progress: Progress{Total: 2, Pending: 2},
		CreatedAt: createdAt, UpdatedAt: updatedAt,
	}
	switch state {
	case StateRunning:
		job.Attempt = 1
		job.StartedAt = timePointer(createdAt)
	case StateSucceeded:
		job.Attempt = 1
		job.Progress = Progress{Total: 2, Completed: 2, Succeeded: 2}
		job.StartedAt = timePointer(createdAt)
		job.CompletedAt = timePointer(updatedAt)
	case StatePartialFailed:
		job.Attempt = 1
		job.Progress = Progress{Total: 2, Completed: 2, Succeeded: 1, Failed: 1}
		job.FailureCode = "item_failed"
		job.StartedAt = timePointer(createdAt)
		job.CompletedAt = timePointer(updatedAt)
	case StateFailed:
		job.Attempt = 1
		job.Progress = Progress{Total: 2, Completed: 2, Failed: 2}
		job.FailureCode = "all_items_failed"
		job.StartedAt = timePointer(createdAt)
		job.CompletedAt = timePointer(updatedAt)
	case StateCancelled:
		job.Progress = Progress{Total: 2, Completed: 2, Cancelled: 2}
		job.FailureCode = "cancelled"
		job.CompletedAt = timePointer(updatedAt)
	}
	job.Revision = "1"
	return job
}

func fixtureService(reader *fixtureReader) *Service {
	service, err := NewService(reader, fixtureServiceConfig())
	if err != nil {
		panic(err)
	}
	return service
}

func fixtureServiceConfig() ServiceConfig {
	return ServiceConfig{
		ActiveCursorKeyID: fixtureCursorKeyID,
		CursorKeys:        map[string][]byte{fixtureCursorKeyID: slices.Clone(fixtureCursorKey)},
	}
}

func fixtureCursorCodec() cursorCodec {
	codec, err := newCursorCodec(fixtureServiceConfig())
	if err != nil {
		panic(err)
	}
	return codec
}

func platformPrincipal(scopeID uuid.UUID) Principal {
	return Principal{
		UserID:  uuid.MustParse("00000000-0000-4000-8000-000000000001"),
		ScopeID: scopeID, ScopeKind: ScopePlatform,
		Permissions: map[string]struct{}{PermissionReadAll: {}},
	}
}

func tenantPrincipal(scopeID uuid.UUID) Principal {
	return Principal{
		UserID:  uuid.MustParse("00000000-0000-4000-8000-000000000002"),
		ScopeID: scopeID, ScopeKind: ScopeTenant,
		Permissions: map[string]struct{}{PermissionRead: {}},
	}
}

func fixtureListRequest(audience Audience) ListRequest {
	return ListRequest{
		Audience: audience, From: fixtureNow.Add(-time.Hour), To: fixtureNow.Add(time.Hour), Limit: 2,
	}
}

func timePointer(value time.Time) *time.Time {
	copy := value
	return &copy
}

var _ Reader = (*fixtureReader)(nil)
var _ SettlementReader = (*fixtureReader)(nil)
