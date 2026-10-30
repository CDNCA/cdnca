package observabilitylog

import (
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
)

// A18：默认时间范围必须在首次查询时固定，并由签名游标带到后续页；
// 时钟前进不能让同会话同条件的下一页失效，会话/条件变化仍须拒绝。
func TestA18DefaultRangeFrozenIntoCursorAcrossClockAdvance(t *testing.T) {
	for _, tc := range []struct {
		name          string
		explicitRange bool
		rotate        bool
		changeTo      bool
		wantErr       error
	}{
		{name: "implicit_range_advancing_clock"},
		{name: "explicit_range_advancing_clock", explicitRange: true},
		{name: "rotated_session_rejected", rotate: true, wantErr: ErrInvalidCursor},
		{name: "changed_explicit_bound_rejected", changeTo: true, wantErr: ErrInvalidCursor},
	} {
		t.Run(tc.name, func(t *testing.T) {
			now := time.Date(2026, 10, 24, 2, 0, 0, 0, time.UTC)
			t0 := now
			actor := Actor{UserID: uuid.New(), ScopeID: uuid.New(), ScopeKind: ScopeTenant,
				SessionID: uuid.New(), Permissions: []string{"identity.self.read"}}
			fact := func(id string, at time.Time) Fact {
				return Fact{ID: id, ScopeID: actor.ScopeID, Kind: KindLogin, ActorUserID: &actor.UserID,
					Action: "auth.login", ReasonCode: "credentials_accepted", ResultCode: "success",
					SourceIP: "unknown", GeoCode: "unknown", OccurredAt: at}
			}
			repository := &fakeRepository09{rows: []Fact{fact("event-2", t0.Add(-time.Minute)), fact("event-1", t0.Add(-2*time.Minute))}}
			service, err := NewService(repository, []byte("0123456789abcdef0123456789abcdef"), func() time.Time { return now })
			if err != nil {
				t.Fatal(err)
			}
			query := Query{Kinds: []Kind{KindLogin}, Limit: 1}
			if tc.explicitRange {
				query.From, query.To = t0.Add(-time.Hour), t0
			}
			first, err := service.List(t.Context(), actor, query)
			if err != nil || len(first.Items) != 1 || first.NextCursor == "" {
				t.Fatalf("first page invalid: %v", err)
			}
			query.Cursor = first.NextCursor
			now = now.Add(time.Second)
			if tc.rotate {
				actor.SessionID = uuid.New()
			}
			if tc.changeTo {
				query.From, query.To = t0.Add(-2*time.Hour), t0
			}
			repository.rows = []Fact{fact("event-1", t0.Add(-2*time.Minute))}
			second, err := service.List(t.Context(), actor, query)
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("want %v, got %v", tc.wantErr, err)
				}
				return
			}
			if err != nil || len(second.Items) != 1 {
				t.Fatalf("same-session unchanged filters must paginate after clock advances: %v", err)
			}
			firstQuery, secondQuery := repository.queries[0], repository.queries[1]
			if !firstQuery.From.Equal(secondQuery.From) || !firstQuery.To.Equal(secondQuery.To) {
				t.Fatalf("range drifted: first=%s..%s second=%s..%s", firstQuery.From, firstQuery.To, secondQuery.From, secondQuery.To)
			}
		})
	}
}
