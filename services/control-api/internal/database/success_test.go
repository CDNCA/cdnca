package database

import (
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5"
)

// B05: only a query that completed without error marks the attempt.
func TestQuerySuccessTracerMarksOnlySuccessfulQueries(t *testing.T) {
	tracer := querySuccessTracer{}
	ctx, flag := WithQuerySuccess(context.Background())
	tracer.TraceQueryEnd(tracer.TraceQueryStart(ctx, nil, pgx.TraceQueryStartData{}), nil,
		pgx.TraceQueryEndData{Err: errors.New("terminating connection")})
	if flag.Load() {
		t.Fatal("failed query marked the attempt as succeeded")
	}
	tracer.TraceQueryEnd(ctx, nil, pgx.TraceQueryEndData{})
	if !flag.Load() {
		t.Fatal("successful query did not mark the attempt")
	}
	// A ctx without a recorder is ignored.
	tracer.TraceQueryEnd(context.Background(), nil, pgx.TraceQueryEndData{})
}
