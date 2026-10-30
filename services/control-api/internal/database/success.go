package database

import (
	"context"
	"sync/atomic"

	"github.com/jackc/pgx/v5"
)

// B05 (X11): runWithDBBackoff must reset its continuous failure window only
// after the worker really reached the database, not after an attempt that
// merely ran for a while (a connect or lock wait can last longer than the
// backoff cap). The background loop attaches a success recorder to the ctx of
// each attempt; the pool tracer marks it when any query of that ctx completes
// without error. Queries use the ctx passed down from Run, so no call site of
// the eight wrapped workers changes.

type querySuccessKey struct{}

// WithQuerySuccess returns a ctx whose successful queries set the returned
// flag.
func WithQuerySuccess(ctx context.Context) (context.Context, *atomic.Bool) {
	flag := new(atomic.Bool)
	return context.WithValue(ctx, querySuccessKey{}, flag), flag
}

// MarkQuerySucceeded records a successful database round trip on ctx; it is a
// no-op when ctx carries no recorder.
func MarkQuerySucceeded(ctx context.Context) {
	if flag, ok := ctx.Value(querySuccessKey{}).(*atomic.Bool); ok {
		flag.Store(true)
	}
}

// querySuccessTracer is installed on every pool opened by Open.
type querySuccessTracer struct{}

func (querySuccessTracer) TraceQueryStart(ctx context.Context, _ *pgx.Conn, _ pgx.TraceQueryStartData) context.Context {
	return ctx
}

func (querySuccessTracer) TraceQueryEnd(ctx context.Context, _ *pgx.Conn, data pgx.TraceQueryEndData) {
	if data.Err == nil {
		MarkQuerySucceeded(ctx)
	}
}
