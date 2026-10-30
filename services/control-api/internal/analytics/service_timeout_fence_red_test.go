package analytics

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

type manualDeadlineContext struct {
	parent  context.Context
	done    chan struct{}
	expired atomic.Bool
}

func newManualDeadlineContext() *manualDeadlineContext {
	return &manualDeadlineContext{parent: context.Background(), done: make(chan struct{})}
}

func (ctx *manualDeadlineContext) Deadline() (time.Time, bool) {
	return time.Time{}, false
}

func (ctx *manualDeadlineContext) Done() <-chan struct{} {
	return ctx.done
}

func (ctx *manualDeadlineContext) Err() error {
	if ctx.expired.Load() {
		return context.DeadlineExceeded
	}
	return nil
}

func (ctx *manualDeadlineContext) Value(key any) any {
	return ctx.parent.Value(key)
}

func (ctx *manualDeadlineContext) expire() {
	if ctx.expired.CompareAndSwap(false, true) {
		close(ctx.done)
	}
}

type deadlineFenceStore struct {
	calls   int
	expire  func()
	err     error
	summary Summary
	trend   []TrendPoint
	rank    RankPage
}

func (store *deadlineFenceStore) Summary(context.Context, Scope, Filter) (Summary, error) {
	store.calls++
	store.expire()
	return store.summary, store.err
}

func (store *deadlineFenceStore) Trend(context.Context, Scope, Filter) ([]TrendPoint, error) {
	store.calls++
	store.expire()
	return store.trend, store.err
}

func (store *deadlineFenceStore) Rank(context.Context, Scope, Filter, RankDimension, uint16, string) (RankPage, error) {
	store.calls++
	store.expire()
	return store.rank, store.err
}

func TestServiceDeadlineWinsLateStoreResults(t *testing.T) {
	t.Parallel()
	lateErr := errors.New("private late store error")
	actor := Actor{ScopeKind: "tenant", TenantID: testTenantID, Permissions: []string{ReadPermission}}
	request := serviceQueryRequest(AudienceTenant)

	t.Run("summary", func(t *testing.T) {
		ctx := newManualDeadlineContext()
		store := &deadlineFenceStore{
			expire:  ctx.expire,
			err:     lateErr,
			summary: Summary{MetricVersion: MetricVersion, RequestCount: 99},
		}
		service, err := NewService(store)
		if err != nil {
			t.Fatal(err)
		}
		got, err := service.Summary(ctx, actor, request)
		if !errors.Is(err, context.DeadlineExceeded) || errors.Is(err, lateErr) {
			t.Fatalf("error = %v, want deadline exceeded without late store error", err)
		}
		if got != (Summary{}) || store.calls != 1 {
			t.Fatalf("summary=%#v calls=%d, want zero result and one store call", got, store.calls)
		}
	})

	t.Run("trend", func(t *testing.T) {
		ctx := newManualDeadlineContext()
		store := &deadlineFenceStore{
			expire: ctx.expire,
			err:    lateErr,
			trend:  []TrendPoint{{MetricVersion: MetricVersion, RequestCount: 99}},
		}
		service, err := NewService(store)
		if err != nil {
			t.Fatal(err)
		}
		got, err := service.Trend(ctx, actor, request)
		if !errors.Is(err, context.DeadlineExceeded) || errors.Is(err, lateErr) {
			t.Fatalf("error = %v, want deadline exceeded without late store error", err)
		}
		if got != nil || store.calls != 1 {
			t.Fatalf("trend=%#v calls=%d, want nil result and one store call", got, store.calls)
		}
	})

	t.Run("rank", func(t *testing.T) {
		ctx := newManualDeadlineContext()
		store := &deadlineFenceStore{
			expire: ctx.expire,
			err:    lateErr,
			rank: RankPage{
				Items: []RankItem{{Key: "/late", RequestCount: 99}}, NextCursor: "late",
			},
		}
		service, err := NewService(store)
		if err != nil {
			t.Fatal(err)
		}
		got, err := service.Rank(ctx, actor, request, RankByURL, 10, "")
		if !errors.Is(err, context.DeadlineExceeded) || errors.Is(err, lateErr) {
			t.Fatalf("error = %v, want deadline exceeded without late store error", err)
		}
		if len(got.Items) != 0 || got.NextCursor != "" || !got.SnapshotAt.IsZero() || store.calls != 1 {
			t.Fatalf("rank=%#v calls=%d, want zero result and one store call", got, store.calls)
		}
	})
}

func TestServiceRejectsAlreadyExpiredContextBeforeStore(t *testing.T) {
	t.Parallel()
	actor := Actor{ScopeKind: "tenant", TenantID: testTenantID, Permissions: []string{ReadPermission}}
	request := serviceQueryRequest(AudienceTenant)

	t.Run("summary", func(t *testing.T) {
		ctx := newManualDeadlineContext()
		ctx.expire()
		store := &deadlineFenceStore{expire: ctx.expire}
		service, err := NewService(store)
		if err != nil {
			t.Fatal(err)
		}
		got, err := service.Summary(ctx, actor, request)
		if !errors.Is(err, context.DeadlineExceeded) || got != (Summary{}) || store.calls != 0 {
			t.Fatalf("summary=%#v err=%v calls=%d, want zero/deadline/zero calls", got, err, store.calls)
		}
	})

	t.Run("trend", func(t *testing.T) {
		ctx := newManualDeadlineContext()
		ctx.expire()
		store := &deadlineFenceStore{expire: ctx.expire}
		service, err := NewService(store)
		if err != nil {
			t.Fatal(err)
		}
		got, err := service.Trend(ctx, actor, request)
		if !errors.Is(err, context.DeadlineExceeded) || got != nil || store.calls != 0 {
			t.Fatalf("trend=%#v err=%v calls=%d, want nil/deadline/zero calls", got, err, store.calls)
		}
	})

	t.Run("rank", func(t *testing.T) {
		ctx := newManualDeadlineContext()
		ctx.expire()
		store := &deadlineFenceStore{expire: ctx.expire}
		service, err := NewService(store)
		if err != nil {
			t.Fatal(err)
		}
		got, err := service.Rank(ctx, actor, request, RankByURL, 10, "")
		if !errors.Is(err, context.DeadlineExceeded) || len(got.Items) != 0 || got.NextCursor != "" || !got.SnapshotAt.IsZero() || store.calls != 0 {
			t.Fatalf("rank=%#v err=%v calls=%d, want zero/deadline/zero calls", got, err, store.calls)
		}
	})
}
