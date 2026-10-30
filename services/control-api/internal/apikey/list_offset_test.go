package apikey

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/google/uuid"
)

// tp-b7b: offset pages and the first page carry the filtered total; cursor
// continuation pages do not; offset and cursor cannot be combined.
func TestAPIKeyListOffsetPagesCarryTotal(t *testing.T) {
	snapshot := time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC)
	scopeID := uuid.MustParse("00000000-0000-4000-8000-000000000201")
	userID := uuid.MustParse("00000000-0000-4000-8000-000000000202")
	rows := []Key{
		pageKey(5, scopeID, userID, "cfk_AAAAAAAAAAAAAAAAAAAAAA", "Alpha", StatusActive, snapshot.Add(-time.Minute)),
		pageKey(4, scopeID, userID, "cfk_BBBBBBBBBBBBBBBBBBBBBB", "Beta", StatusRevoked, snapshot.Add(-2*time.Minute)),
		pageKey(3, scopeID, userID, "cfk_CCCCCCCCCCCCCCCCCCCCCC", "Gamma", StatusActive, snapshot.Add(-3*time.Minute)),
		pageKey(2, scopeID, userID, "cfk_DDDDDDDDDDDDDDDDDDDDDD", "Delta", StatusActive, snapshot.Add(-4*time.Minute)),
		pageKey(1, scopeID, userID, "cfk_EEEEEEEEEEEEEEEEEEEEEE", "Epsilon", StatusActive, snapshot.Add(-5*time.Minute)),
	}
	reader := &pageReaderFixture{rows: &rows}
	service := pageTestService(snapshot, scopeID, userID, reader.read)
	var counted []apiKeyPageStoreRequest
	service.pageCount = func(ctx context.Context, request apiKeyPageStoreRequest) (int, error) {
		counted = append(counted, request)
		all := request
		all.Limit, all.Offset = len(rows)+1, 0
		items, err := reader.read(ctx, all)
		return len(items), err
	}
	principal := tenantPagePrincipal(scopeID, userID)

	first, err := service.ListSelfPage(t.Context(), principal, APIKeyListInput{Limit: 2})
	if err != nil || first.Total == nil || *first.Total != 5 || first.NextCursor == "" {
		t.Fatalf("first page = %#v, %v", first, err)
	}
	third, err := service.ListSelfPage(t.Context(), principal, APIKeyListInput{Limit: 2, Offset: 4})
	if err != nil || third.Total == nil || *third.Total != 5 || !reflect.DeepEqual(pageIDs(third.Items), []int{1}) || third.NextCursor != "" {
		t.Fatalf("offset page = ids=%v total=%v cursor=%q err=%v", pageIDs(third.Items), third.Total, third.NextCursor, err)
	}
	filtered, err := service.ListSelfPage(t.Context(), principal, APIKeyListInput{Limit: 2, Offset: 2, Status: StatusActive})
	if err != nil || filtered.Total == nil || *filtered.Total != 4 || !reflect.DeepEqual(pageIDs(filtered.Items), []int{2, 1}) {
		t.Fatalf("filtered offset page = ids=%v total=%v err=%v", pageIDs(filtered.Items), filtered.Total, err)
	}
	beyond, err := service.ListSelfPage(t.Context(), principal, APIKeyListInput{Limit: 2, Offset: 40})
	if err != nil || beyond.Total == nil || *beyond.Total != 5 || len(beyond.Items) != 0 {
		t.Fatalf("beyond page = %#v, %v", beyond, err)
	}
	before := len(counted)
	next, err := service.ListSelfPage(t.Context(), principal, APIKeyListInput{Limit: 2, Cursor: first.NextCursor})
	if err != nil || next.Total != nil || len(counted) != before {
		t.Fatalf("cursor page total=%v counts=%d err=%v", next.Total, len(counted)-before, err)
	}
	for _, input := range []APIKeyListInput{
		{Limit: 2, Offset: -1},
		{Limit: 2, Offset: MaxListOffset + 1},
		{Limit: 2, Offset: 2, Cursor: first.NextCursor},
	} {
		if _, err := service.ListSelfPage(t.Context(), principal, input); !errors.Is(err, ErrInvalidInput) {
			t.Fatalf("ListSelfPage(%+v) err = %v", input, err)
		}
	}
}
