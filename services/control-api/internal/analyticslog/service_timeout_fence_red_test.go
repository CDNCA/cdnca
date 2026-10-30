package analyticslog

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const timeoutFenceTenant = "10000000-0000-4000-8000-000000000091"

type manualDeadlineContext struct {
	done    chan struct{}
	once    sync.Once
	expired atomic.Bool
}

func newManualDeadlineContext() *manualDeadlineContext {
	return &manualDeadlineContext{done: make(chan struct{})}
}

func (*manualDeadlineContext) Deadline() (time.Time, bool) { return time.Time{}, false }
func (ctx *manualDeadlineContext) Done() <-chan struct{}   { return ctx.done }
func (ctx *manualDeadlineContext) Err() error {
	if ctx.expired.Load() {
		return context.DeadlineExceeded
	}
	return nil
}
func (*manualDeadlineContext) Value(any) any { return nil }

func (ctx *manualDeadlineContext) expire() {
	ctx.expired.Store(true)
	ctx.once.Do(func() { close(ctx.done) })
}

type lateDeadlineStore struct {
	accessPage  AccessPage
	blockPage   BlockEventPage
	accessErr   error
	blockErr    error
	accessCalls atomic.Int32
	blockCalls  atomic.Int32
}

func (store *lateDeadlineStore) ListAccess(
	ctx context.Context,
	_ scope,
	_ Filter,
	_ uint16,
	_ string,
) (AccessPage, error) {
	store.accessCalls.Add(1)
	waitForDeadline(ctx)
	return store.accessPage, store.accessErr
}

func (store *lateDeadlineStore) ListBlockEvents(
	ctx context.Context,
	_ scope,
	_ Filter,
	_ uint16,
	_ string,
) (BlockEventPage, error) {
	store.blockCalls.Add(1)
	waitForDeadline(ctx)
	return store.blockPage, store.blockErr
}

func waitForDeadline(ctx context.Context) {
	if manual, ok := ctx.(*manualDeadlineContext); ok {
		manual.expire()
	}
	<-ctx.Done()
}

func TestServiceDeadlineFenceRejectsLateSuccessAndPrivateError(t *testing.T) {
	latePrivateError := errors.New("late ClickHouse private transport detail")
	store := &lateDeadlineStore{
		accessPage: AccessPage{
			Items: []AccessLog{{EventID: "late-access"}}, NextCursor: "late-access-cursor",
			SnapshotAt: time.Date(2026, 8, 5, 1, 0, 0, 0, time.UTC),
		},
		blockPage: BlockEventPage{
			Items: []BlockEvent{{EventID: "late-block"}}, NextCursor: "late-block-cursor",
			SnapshotAt: time.Date(2026, 8, 5, 1, 0, 0, 0, time.UTC),
		},
		blockErr: latePrivateError,
	}
	service := newTimeoutFenceService(t, store)
	actor, request := timeoutFenceQuery()

	access, err := service.ListAccess(newManualDeadlineContext(), actor, request)
	if !errors.Is(err, context.DeadlineExceeded) || !zeroAccessPage(access) {
		t.Fatalf("late access page/error = (%#v,%v), want zero/deadline", access, err)
	}
	block, err := service.ListBlockEvents(newManualDeadlineContext(), actor, request)
	if !errors.Is(err, context.DeadlineExceeded) || errors.Is(err, latePrivateError) || !zeroBlockEventPage(block) {
		t.Fatalf("late block page/error = (%#v,%v), want zero/deadline precedence", block, err)
	}
	if store.accessCalls.Load() != 1 || store.blockCalls.Load() != 1 {
		t.Fatalf("late store calls access/block = %d/%d, want 1/1",
			store.accessCalls.Load(), store.blockCalls.Load())
	}
}

func TestServiceDeadlineFenceRejectsExpiredContextBeforeStore(t *testing.T) {
	store := &lateDeadlineStore{}
	service := newTimeoutFenceService(t, store)
	actor, request := timeoutFenceQuery()
	ctx := newManualDeadlineContext()
	ctx.expire()

	page, err := service.ListAccess(ctx, actor, request)
	if !errors.Is(err, context.DeadlineExceeded) || !zeroAccessPage(page) {
		t.Fatalf("expired access page/error = (%#v,%v), want zero/deadline", page, err)
	}
	if store.accessCalls.Load() != 0 {
		t.Fatalf("expired context reached Store %d times", store.accessCalls.Load())
	}
}

func TestHandlerDeadlineFenceMapsLateSuccessToTimeout(t *testing.T) {
	store := &lateDeadlineStore{accessPage: AccessPage{
		Items: []AccessLog{{EventID: "late-handler-access"}}, NextCursor: "late-handler-cursor",
		SnapshotAt: time.Date(2026, 8, 5, 1, 0, 0, 0, time.UTC),
	}}
	service := newTimeoutFenceService(t, store)
	actor, request := timeoutFenceQuery()
	handler, err := NewHandler(service, func(*http.Request) (Actor, error) {
		return actor, nil
	}, HandlerConfig{
		QueryTimeout: time.Millisecond,
		Logger:       slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	values := url.Values{
		"from": {request.Filter.From.Format(time.RFC3339Nano)},
		"to":   {request.Filter.To.Format(time.RFC3339Nano)},
	}
	httpRequest := httptest.NewRequest(http.MethodGet,
		"/v1/analytics/logs/access?"+values.Encode(), nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httpRequest)

	if response.Code != http.StatusGatewayTimeout ||
		!strings.Contains(response.Body.String(), `"code":"analytics_logs_query_timeout"`) {
		t.Fatalf("late handler status/body = %d/%s, want 504 timeout", response.Code, response.Body.String())
	}
	if store.accessCalls.Load() != 1 {
		t.Fatalf("handler Store calls = %d, want 1", store.accessCalls.Load())
	}
}

func timeoutFenceQuery() (Actor, QueryRequest) {
	from := time.Date(2026, 8, 5, 0, 0, 0, 0, time.UTC)
	return Actor{
			ScopeKind: "tenant", TenantID: timeoutFenceTenant, Permissions: []string{ReadPermission},
		}, QueryRequest{
			Audience: AudienceTenant, Limit: 1, Filter: Filter{From: from, To: from.Add(time.Hour)},
		}
}

func newTimeoutFenceService(t *testing.T, store Store) *Service {
	t.Helper()
	service, err := NewService(store)
	if err != nil {
		t.Fatal(err)
	}
	return service
}

func zeroAccessPage(page AccessPage) bool {
	return page.Items == nil && page.NextCursor == "" && page.SnapshotAt.IsZero()
}

func zeroBlockEventPage(page BlockEventPage) bool {
	return page.Items == nil && page.NextCursor == "" && page.SnapshotAt.IsZero()
}
