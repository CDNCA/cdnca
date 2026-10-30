package nodescheduler

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

type loadRow struct {
	nodeID     uuid.UUID
	inflight   int64
	observedAt time.Time
}

type fakeLoadRows struct {
	items []loadRow
	index int
	err   error
}

func (rows *fakeLoadRows) Next() bool {
	return rows.index < len(rows.items)
}

func (rows *fakeLoadRows) Scan(destinations ...any) error {
	item := rows.items[rows.index]
	rows.index++
	*destinations[0].(*uuid.UUID) = item.nodeID
	*destinations[1].(*int64) = item.inflight
	*destinations[2].(*time.Time) = item.observedAt
	return nil
}

func (rows *fakeLoadRows) Err() error { return rows.err }
func (rows *fakeLoadRows) Close()     {}

type fakeLoadQuerier struct {
	rows  loadRows
	err   error
	query string
	args  []any
}

func (querier *fakeLoadQuerier) Query(_ context.Context, query string, args ...any) (loadRows, error) {
	querier.query, querier.args = query, args
	return querier.rows, querier.err
}

func TestPostgresLoadProviderBindsScopeAndMapsNodeMetricsToEndpoints(t *testing.T) {
	scopeID := uuid.MustParse("10000000-0000-4000-8000-000000000001")
	nodeA := uuid.MustParse("20000000-0000-4000-8000-000000000001")
	nodeB := uuid.MustParse("20000000-0000-4000-8000-000000000002")
	endpointA := uuid.MustParse("30000000-0000-4000-8000-000000000001")
	endpointAlias := uuid.MustParse("30000000-0000-4000-8000-000000000002")
	endpointMissing := uuid.MustParse("30000000-0000-4000-8000-000000000003")
	endpointUnbound := uuid.MustParse("30000000-0000-4000-8000-000000000004")
	observedAt := time.Date(2026, 8, 8, 10, 0, 0, 0, time.UTC)
	queries := &fakeLoadQuerier{rows: &fakeLoadRows{items: []loadRow{{
		nodeID: nodeA, inflight: 17, observedAt: observedAt,
	}}}}
	provider := newPostgresLoadProvider(queries)

	loads, err := provider.Loads(t.Context(), scopeID, []Endpoint{
		{ID: endpointA, NodeID: nodeA},
		{ID: endpointAlias, NodeID: nodeA},
		{ID: endpointMissing, NodeID: nodeB},
		{ID: endpointUnbound},
	})
	if err != nil {
		t.Fatal(err)
	}
	want := map[uuid.UUID]LoadSample{
		endpointA:     {Inflight: 17, ObservedAt: observedAt},
		endpointAlias: {Inflight: 17, ObservedAt: observedAt},
	}
	if !reflect.DeepEqual(loads, want) {
		t.Fatalf("loads=%#v want=%#v", loads, want)
	}
	if len(queries.args) != 2 || queries.args[0] != scopeID ||
		!reflect.DeepEqual(queries.args[1], []uuid.UUID{nodeA, nodeB}) {
		t.Fatalf("query args=%#v", queries.args)
	}
	for _, required := range []string{
		"node.scope_id=$1", "node.id = ANY($2::uuid[])",
		"metric.metrics_known", "metric.active_connections IS NOT NULL",
	} {
		if !strings.Contains(queries.query, required) {
			t.Fatalf("query does not bind %q: %s", required, queries.query)
		}
	}
}

func TestPostgresLoadProviderFailsClosedOnInvalidInputAndQueryFailure(t *testing.T) {
	provider := newPostgresLoadProvider(&fakeLoadQuerier{err: errors.New("metrics unavailable")})
	endpoint := Endpoint{ID: uuid.New(), NodeID: uuid.New()}
	if _, err := provider.Loads(t.Context(), uuid.New(), []Endpoint{endpoint}); err == nil ||
		!strings.Contains(err.Error(), "metrics unavailable") {
		t.Fatalf("query error=%v", err)
	}
	if _, err := provider.Loads(nil, uuid.New(), []Endpoint{endpoint}); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("nil context error=%v", err)
	}
	if _, err := provider.Loads(t.Context(), uuid.Nil, []Endpoint{endpoint}); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("nil scope error=%v", err)
	}
	overCapacity := make([]Endpoint, maxEndpoints+1)
	if _, err := provider.Loads(t.Context(), uuid.New(), overCapacity); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("capacity error=%v", err)
	}
}
