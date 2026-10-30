package dnspropagation

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func TestPostgresRetryStoreAtomicCASUsesTenantZoneProviderAuthority(t *testing.T) {
	key := retryStoreTestKey()
	expected := uint64(7)
	next := retryStoreTestState(expected + 1)
	updatedAt := time.Date(2026, 8, 8, 17, 2, 3, 456789123,
		time.FixedZone("test-offset", 8*60*60))
	normalizedUpdatedAt := updatedAt.UTC().Truncate(time.Microsecond)
	encoded, err := json.Marshal(next)
	if err != nil {
		t.Fatal(err)
	}
	query := &retryStoreQuery{row: retryStoreRow{
		revision: next.Revision, state: encoded, updatedAt: normalizedUpdatedAt,
	}}
	store, err := NewPostgresRetryStore(query)
	if err != nil {
		t.Fatal(err)
	}

	result, err := store.CompareAndSwap(context.Background(), key, expected, next, updatedAt)
	if err != nil {
		t.Fatal(err)
	}
	if result.State != next || !result.UpdatedAt.Equal(normalizedUpdatedAt) || result.Replayed {
		t.Fatalf("result = %#v, want applied snapshot", result)
	}
	if query.calls != 1 {
		t.Fatalf("QueryRow calls = %d, want one atomic statement", query.calls)
	}
	assertRetryStoreCASStatement(t, query.statement)
	if len(query.args) != 7 {
		t.Fatalf("QueryRow args = %#v, want seven ordered values", query.args)
	}
	if query.args[0] != key.TenantID || query.args[1] != key.ZoneID || query.args[2] != key.ProviderID ||
		query.args[3] != int64(expected) || query.args[4] != int64(next.Revision) ||
		!reflect.DeepEqual(query.args[5], encoded) || query.args[6] != normalizedUpdatedAt {
		t.Fatalf("QueryRow args = %#v, want key/expected/next/json/updated_at", query.args)
	}
}

func TestPostgresRetryStoreAllowsInsertAndCurrentRevisionUpdate(t *testing.T) {
	key := retryStoreTestKey()
	updatedAt := retryStoreTestTime()
	for _, test := range []struct {
		name     string
		expected uint64
	}{
		{name: "insert absent head", expected: 0},
		{name: "update matching head", expected: 12},
	} {
		t.Run(test.name, func(t *testing.T) {
			next := retryStoreTestState(test.expected + 1)
			encoded, err := json.Marshal(next)
			if err != nil {
				t.Fatal(err)
			}
			query := &retryStoreQuery{row: retryStoreRow{
				revision: next.Revision, state: encoded, updatedAt: updatedAt,
			}}
			store, err := NewPostgresRetryStore(query)
			if err != nil {
				t.Fatal(err)
			}
			result, err := store.CompareAndSwap(context.Background(), key, test.expected, next, updatedAt)
			if err != nil || result.State != next || result.Replayed {
				t.Fatalf("CompareAndSwap() = (%#v,%v), want applied revision %d", result, err, next.Revision)
			}
			if query.calls != 1 || query.args[3] != int64(test.expected) || query.args[4] != int64(next.Revision) {
				t.Fatalf("query = calls:%d args:%#v", query.calls, query.args)
			}
		})
	}
}

func TestPostgresRetryStoreAbsentHeadRequiresExpectedRevisionZero(t *testing.T) {
	key := retryStoreTestKey()
	expected := uint64(5)
	next := retryStoreTestState(expected + 1)
	query := &retryStoreQuery{row: retryStoreRow{err: pgx.ErrNoRows}}
	store, err := NewPostgresRetryStore(query)
	if err != nil {
		t.Fatal(err)
	}

	// The row is absent, but expected>0 claims a prior head. The INSERT SELECT
	// guard must suppress creation so the empty CTE result becomes a conflict.
	_, err = store.CompareAndSwap(context.Background(), key, expected, next, retryStoreTestTime())
	if !errors.Is(err, ErrProviderRetryStateConflict) || query.calls != 1 {
		t.Fatalf("absent nonzero expected = (err=%v,calls=%d), want one stable conflict", err, query.calls)
	}
	assertRetryStoreCASStatement(t, query.statement)
}

func TestPostgresRetryStoreAcceptsOnlyExactSnapshotReplay(t *testing.T) {
	key := retryStoreTestKey()
	expected := uint64(20)
	next := retryStoreTestState(expected + 1)
	updatedAt := retryStoreTestTime()
	encoded, err := json.Marshal(next)
	if err != nil {
		t.Fatal(err)
	}

	query := &retryStoreQuery{row: retryStoreRow{
		revision: next.Revision, state: encoded, updatedAt: updatedAt, replayed: true,
	}}
	store, err := NewPostgresRetryStore(query)
	if err != nil {
		t.Fatal(err)
	}
	result, err := store.CompareAndSwap(context.Background(), key, expected, next, updatedAt)
	if err != nil || !result.Replayed || result.State != next || !result.UpdatedAt.Equal(updatedAt) {
		t.Fatalf("exact replay = (%#v,%v)", result, err)
	}

	for _, test := range []struct {
		name      string
		wantError error
	}{
		{name: "different revision", wantError: ErrProviderRetryStateConflict},
		{name: "different state json", wantError: ErrProviderRetryStateConflict},
		{name: "different updated at", wantError: ErrProviderRetryStateConflict},
	} {
		t.Run(test.name, func(t *testing.T) {
			// A non-exact prior row makes the atomic CTE return no row.
			conflictQuery := &retryStoreQuery{row: retryStoreRow{err: pgx.ErrNoRows}}
			conflictStore, err := NewPostgresRetryStore(conflictQuery)
			if err != nil {
				t.Fatal(err)
			}
			_, err = conflictStore.CompareAndSwap(context.Background(), key, expected, next, updatedAt)
			if !errors.Is(err, test.wantError) || conflictQuery.calls != 1 {
				t.Fatalf("conflict error = %v calls=%d", err, conflictQuery.calls)
			}
		})
	}
}

func TestPostgresRetryStoreRejectsInvalidCASBeforeQuery(t *testing.T) {
	validKey := retryStoreTestKey()
	validState := retryStoreTestState(2)
	for _, test := range []struct {
		name      string
		ctx       context.Context
		key       ProviderRetryKey
		expected  uint64
		next      ProviderRetryState
		updatedAt time.Time
	}{
		{name: "nil context", key: validKey, expected: 1, next: validState, updatedAt: retryStoreTestTime()},
		{name: "missing tenant", ctx: context.Background(), key: ProviderRetryKey{ZoneID: validKey.ZoneID, ProviderID: validKey.ProviderID}, expected: 1, next: validState, updatedAt: retryStoreTestTime()},
		{name: "missing zone", ctx: context.Background(), key: ProviderRetryKey{TenantID: validKey.TenantID, ProviderID: validKey.ProviderID}, expected: 1, next: validState, updatedAt: retryStoreTestTime()},
		{name: "missing provider", ctx: context.Background(), key: ProviderRetryKey{TenantID: validKey.TenantID, ZoneID: validKey.ZoneID}, expected: 1, next: validState, updatedAt: retryStoreTestTime()},
		{name: "next skips revision", ctx: context.Background(), key: validKey, expected: 1, next: retryStoreTestState(3), updatedAt: retryStoreTestTime()},
		{name: "invalid circuit phase", ctx: context.Background(), key: validKey, expected: 1, next: func() ProviderRetryState {
			state := validState
			state.Phase = CircuitPhase("future_phase")
			return state
		}(), updatedAt: retryStoreTestTime()},
		{name: "zero updated at", ctx: context.Background(), key: validKey, expected: 1, next: validState},
	} {
		t.Run(test.name, func(t *testing.T) {
			query := &retryStoreQuery{row: retryStoreRow{err: errors.New("must not query")}}
			store, err := NewPostgresRetryStore(query)
			if err != nil {
				t.Fatal(err)
			}
			_, err = store.CompareAndSwap(test.ctx, test.key, test.expected, test.next, test.updatedAt)
			if !errors.Is(err, ErrInvalidInput) || query.calls != 0 {
				t.Fatalf("invalid CAS = (err=%v,calls=%d)", err, query.calls)
			}
		})
	}
}

func TestPostgresRetryStoreMapsQueryAndSnapshotFailures(t *testing.T) {
	key := retryStoreTestKey()
	next := retryStoreTestState(2)
	updatedAt := retryStoreTestTime()
	for _, test := range []struct {
		name string
		row  retryStoreRow
	}{
		{name: "database error", row: retryStoreRow{err: errors.New("database unavailable")}},
		{name: "malformed state", row: retryStoreRow{revision: next.Revision, state: []byte(`{"Revision":`), updatedAt: updatedAt}},
		{name: "row revision disagrees with state", row: retryStoreRow{revision: next.Revision + 1, state: retryStoreTestJSON(t, next), updatedAt: updatedAt}},
	} {
		t.Run(test.name, func(t *testing.T) {
			query := &retryStoreQuery{row: test.row}
			store, err := NewPostgresRetryStore(query)
			if err != nil {
				t.Fatal(err)
			}
			_, err = store.CompareAndSwap(context.Background(), key, 1, next, updatedAt)
			if !errors.Is(err, ErrProviderRetryStateUnavailable) || query.calls != 1 {
				t.Fatalf("failure = (err=%v,calls=%d)", err, query.calls)
			}
		})
	}
}

func TestPostgresRetryStoreLoadFencesTenantZoneProviderAndValidatesSnapshot(t *testing.T) {
	key := retryStoreTestKey()
	state := retryStoreTestState(17)
	updatedAt := retryStoreTestTime()
	query := &retryStoreQuery{row: retryStoreRow{
		revision: state.Revision, state: retryStoreTestJSON(t, state), updatedAt: updatedAt,
	}}
	store, err := NewPostgresRetryStore(query)
	if err != nil {
		t.Fatal(err)
	}

	result, found, err := store.Load(t.Context(), key)
	if err != nil || !found || result.State != state || !result.UpdatedAt.Equal(updatedAt) || result.Replayed {
		t.Fatalf("Load() = (%#v,%t,%v), want exact persisted snapshot", result, found, err)
	}
	if query.calls != 1 || len(query.args) != 3 || query.args[0] != key.TenantID ||
		query.args[1] != key.ZoneID || query.args[2] != key.ProviderID {
		t.Fatalf("Load query = calls:%d args:%#v", query.calls, query.args)
	}
	normalized := strings.Join(strings.Fields(query.statement), " ")
	for _, required := range []string{
		"SELECT revision,state,updated_at", "FROM dns_provider_retry_states",
		"WHERE tenant_id=$1 AND zone_id=$2 AND provider_id=$3",
	} {
		if !strings.Contains(normalized, required) {
			t.Fatalf("Load SQL missing %q: %s", required, normalized)
		}
	}
}

func TestPostgresRetryStoreLoadDistinguishesAbsentFromUnavailable(t *testing.T) {
	key := retryStoreTestKey()
	for _, test := range []struct {
		name      string
		row       retryStoreRow
		wantFound bool
		wantError error
	}{
		{name: "absent", row: retryStoreRow{err: pgx.ErrNoRows}},
		{name: "query unavailable", row: retryStoreRow{err: errors.New("database unavailable")}, wantError: ErrProviderRetryStateUnavailable},
		{name: "malformed json", row: retryStoreRow{revision: 2, state: []byte(`{"Revision":`), updatedAt: retryStoreTestTime()}, wantError: ErrProviderRetryStateUnavailable},
		{name: "revision mismatch", row: retryStoreRow{revision: 3, state: retryStoreTestJSON(t, retryStoreTestState(2)), updatedAt: retryStoreTestTime()}, wantError: ErrProviderRetryStateUnavailable},
		{name: "invalid phase", row: retryStoreRow{revision: 2, state: retryStoreTestJSON(t, func() ProviderRetryState {
			state := retryStoreTestState(2)
			state.Phase = CircuitPhase("tampered")
			return state
		}()), updatedAt: retryStoreTestTime()}, wantError: ErrProviderRetryStateUnavailable},
		{name: "timestamp precision tamper", row: retryStoreRow{revision: 2, state: retryStoreTestJSON(t, retryStoreTestState(2)), updatedAt: retryStoreTestTime().Add(time.Nanosecond)}, wantError: ErrProviderRetryStateUnavailable},
	} {
		t.Run(test.name, func(t *testing.T) {
			query := &retryStoreQuery{row: test.row}
			store, err := NewPostgresRetryStore(query)
			if err != nil {
				t.Fatal(err)
			}
			_, found, err := store.Load(t.Context(), key)
			if found != test.wantFound || !errors.Is(err, test.wantError) || query.calls != 1 {
				t.Fatalf("Load() = (found=%t,error=%v,calls=%d), want (%t,%v,1)",
					found, err, query.calls, test.wantFound, test.wantError)
			}
		})
	}
}

func TestPostgresRetryStoreLoadRejectsInvalidKeyBeforeQuery(t *testing.T) {
	query := &retryStoreQuery{row: retryStoreRow{err: errors.New("must not query")}}
	store, err := NewPostgresRetryStore(query)
	if err != nil {
		t.Fatal(err)
	}
	_, found, err := store.Load(t.Context(), ProviderRetryKey{})
	if found || !errors.Is(err, ErrInvalidInput) || query.calls != 0 {
		t.Fatalf("Load() = (found=%t,error=%v,calls=%d), want invalid input before query", found, err, query.calls)
	}
}

func assertRetryStoreCASStatement(t *testing.T, statement string) {
	t.Helper()
	normalized := strings.Join(strings.Fields(statement), " ")
	for _, required := range []string{
		"WITH prior AS", "SELECT revision,state,updated_at", "FROM dns_provider_retry_states",
		"WHERE tenant_id=$1 AND zone_id=$2 AND provider_id=$3", "FOR UPDATE",
		"INSERT INTO dns_provider_retry_states", "WHERE $4=0",
		"ON CONFLICT (tenant_id,zone_id,provider_id) DO UPDATE SET",
		"dns_provider_retry_states.revision=$4", "dns_provider_retry_states.revision=$5",
		"dns_provider_retry_states.state=$6::jsonb", "dns_provider_retry_states.updated_at=$7",
		"SELECT write.revision,write.state,write.updated_at",
	} {
		if !strings.Contains(normalized, required) {
			t.Fatalf("atomic CAS SQL missing %q:\n%s", required, normalized)
		}
	}
}

type retryStoreQuery struct {
	row       pgx.Row
	calls     int
	statement string
	args      []any
}

func (query *retryStoreQuery) QueryRow(_ context.Context, statement string, args ...any) pgx.Row {
	query.calls++
	query.statement = statement
	query.args = append([]any(nil), args...)
	return query.row
}

type retryStoreRow struct {
	revision  uint64
	state     []byte
	updatedAt time.Time
	replayed  bool
	err       error
}

func (row retryStoreRow) Scan(destinations ...any) error {
	if row.err != nil {
		return row.err
	}
	if len(destinations) != 3 && len(destinations) != 4 {
		return errors.New("retry store fake row destination count mismatch")
	}
	switch target := destinations[0].(type) {
	case *uint64:
		*target = row.revision
	case *int64:
		*target = int64(row.revision)
	default:
		return errors.New("retry store fake row revision destination mismatch")
	}
	state, ok := destinations[1].(*[]byte)
	if !ok {
		return errors.New("retry store fake row state destination mismatch")
	}
	updatedAt, ok := destinations[2].(*time.Time)
	if !ok {
		return errors.New("retry store fake row updated_at destination mismatch")
	}
	if len(destinations) == 4 {
		replayed, ok := destinations[3].(*bool)
		if !ok {
			return errors.New("retry store fake row replay destination mismatch")
		}
		*replayed = row.replayed
	}
	*state = append([]byte(nil), row.state...)
	*updatedAt = row.updatedAt
	return nil
}

func retryStoreTestKey() ProviderRetryKey {
	return ProviderRetryKey{
		TenantID:   uuid.MustParse("11111111-1111-4111-8111-111111111111"),
		ZoneID:     uuid.MustParse("22222222-2222-4222-8222-222222222222"),
		ProviderID: uuid.MustParse("33333333-3333-4333-8333-333333333333"),
	}
}

func retryStoreTestState(revision uint64) ProviderRetryState {
	return ProviderRetryState{
		Revision: revision, WindowStartedAt: retryStoreTestTime().Add(-time.Minute), AttemptsInWindow: 1,
		ConsecutiveTransient: 1, Phase: CircuitOpen, OpenUntil: retryStoreTestTime().Add(time.Minute),
		LastOperationID: "operation-retry-store", LastProviderRequestID: "provider-request-retry-store",
	}
}

func retryStoreTestTime() time.Time {
	return time.Date(2026, 8, 8, 9, 2, 3, 456789000, time.UTC)
}

func retryStoreTestJSON(t *testing.T, state ProviderRetryState) []byte {
	t.Helper()
	encoded, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

var _ pgx.Row = retryStoreRow{}
