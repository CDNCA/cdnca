//go:build integration

package site

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type countingTracer struct{ queries atomic.Int64 }

func (tracer *countingTracer) TraceQueryStart(ctx context.Context, _ *pgx.Conn, _ pgx.TraceQueryStartData) context.Context {
	tracer.queries.Add(1)
	return ctx
}

func (*countingTracer) TraceQueryEnd(context.Context, *pgx.Conn, pgx.TraceQueryEndData) {}

// PJ-C04: the site list projects status for the whole page with a fixed number
// of queries (no per-row re-read), and the projection equals Get's for every row.
func TestListStatusProjectionIsPageWide(t *testing.T) {
	f := newTrustFixture(t)
	ctx := context.Background()
	actor := f.a.siteActor()
	for i := range 12 {
		key := f.key(fmt.Sprintf("list-batch-%d", i))
		if _, err := f.sites.Create(ctx, actor, CreateRequest{IdempotencyKey: key, RequestID: key,
			Fields: SiteFields{Domains: []string{fmt.Sprintf("batch-%d.example.test", i)}, Origins: []string{"192.0.2.1"},
				Enabled: true, Status: StatusActive}}); err != nil {
			t.Fatalf("create %d: %v", i, err)
		}
	}
	// Give one site a traffic suspension so the batched suspension read is exercised.
	var suspended string
	if err := f.pool.QueryRow(ctx, `SELECT id::text FROM sites WHERE domain='batch-3.example.test'`).Scan(&suspended); err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Exec(ctx, `UPDATE sites SET status='traffic_exceeded' WHERE id=$1`, suspended); err != nil {
		t.Fatal(err)
	}

	store := f.sites.store
	count := func(limit int) (ListResult, int64) {
		config := store.pool.Config().Copy()
		tracer := &countingTracer{}
		config.ConnConfig.Tracer = tracer
		pool, err := pgxpool.NewWithConfig(ctx, config)
		if err != nil {
			t.Fatal(err)
		}
		defer pool.Close()
		traced := *store
		traced.pool = pool
		result, err := traced.List(ctx, actor, ListFilter{Page: 1, Limit: limit})
		if err != nil {
			t.Fatalf("list limit=%d: %v", limit, err)
		}
		return result, tracer.queries.Load()
	}
	small, smallQueries := count(2)
	large, largeQueries := count(12)
	if len(small.Items) != 2 || len(large.Items) != 12 {
		t.Fatalf("items small=%d large=%d", len(small.Items), len(large.Items))
	}
	if largeQueries != smallQueries {
		t.Fatalf("list queries grow with the page: limit 2 -> %d, limit 12 -> %d", smallQueries, largeQueries)
	}
	// fix-pre1035: the domain search also takes the numeric site display ID
	// (exact match, alongside the domain substring match).
	var displayID string
	if err := f.pool.QueryRow(ctx, `SELECT display_id::text FROM sites WHERE id=$1`, suspended).Scan(&displayID); err != nil {
		t.Fatal(err)
	}
	byID, err := store.List(ctx, actor, ListFilter{Page: 1, Limit: 20, Domain: displayID})
	found := false
	for _, item := range byID.Items {
		found = found || item.ID.String() == suspended
		if item.ID.String() != suspended && !strings.Contains(item.Domain, displayID) {
			t.Fatalf("display id %s matched unrelated site %s (%s)", displayID, item.ID, item.Domain)
		}
	}
	if err != nil || !found {
		t.Fatalf("list by display id %s = %+v err=%v", displayID, byID.Items, err)
	}
	if none, err := store.List(ctx, actor, ListFilter{Page: 1, Limit: 20, Domain: "999999"}); err != nil || len(none.Items) != 0 {
		t.Fatalf("unknown display id = %+v err=%v", none.Items, err)
	}
	for _, item := range large.Items {
		// WEB-C01/C05: no certificate was bound to any of these sites.
		if item.HTTPSCertificateBound {
			t.Fatalf("site %s reports a bound certificate without a binding fact", item.ID)
		}
		single, err := store.Get(ctx, actor, item.ID)
		if err != nil {
			t.Fatal(err)
		}
		if item.OperationalStatus != single.OperationalStatus || !reflect.DeepEqual(item.StatusRecovery, single.StatusRecovery) ||
			!reflect.DeepEqual(item.TrafficEnforcement, single.TrafficEnforcement) {
			t.Fatalf("site %s list projection %v/%+v/%+v != get %v/%+v/%+v", item.ID, item.OperationalStatus, item.StatusRecovery,
				item.TrafficEnforcement, single.OperationalStatus, single.StatusRecovery, single.TrafficEnforcement)
		}
	}
}
