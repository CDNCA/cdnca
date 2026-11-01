package apikey

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/google/uuid"
)

// AA-UI02：已到期的 active 生命周期密钥不能算"可用"。usable=true 只返回服务端快照时刻仍可调用的
// active 密钥（expires_at 为空或晚于快照），游标续页保留该筛选；与 status 只能是空或 active 组合。
func TestAPIKeyListUsableExcludesExpiredActiveKeys(t *testing.T) {
	snapshot := time.Date(2026, 10, 28, 11, 52, 1, 0, time.UTC)
	scopeID := uuid.MustParse("00000000-0000-4000-8000-000000000301")
	userID := uuid.MustParse("00000000-0000-4000-8000-000000000302")
	at := func(value time.Time) *time.Time { return &value }
	expiredEarlier := pageKey(5, scopeID, userID, "cfk_AAAAAAAAAAAAAAAAAAAAAA", "Alpha", StatusActive, snapshot.Add(-time.Minute))
	expiredEarlier.ExpiresAt = at(snapshot.Add(-time.Hour))
	expiredNow := pageKey(4, scopeID, userID, "cfk_BBBBBBBBBBBBBBBBBBBBBB", "Beta", StatusActive, snapshot.Add(-2*time.Minute))
	expiredNow.ExpiresAt = at(snapshot)
	future := pageKey(3, scopeID, userID, "cfk_CCCCCCCCCCCCCCCCCCCCCC", "Gamma", StatusActive, snapshot.Add(-3*time.Minute))
	future.ExpiresAt = at(snapshot.Add(time.Second))
	revoked := pageKey(2, scopeID, userID, "cfk_DDDDDDDDDDDDDDDDDDDDDD", "Delta", StatusRevoked, snapshot.Add(-4*time.Minute))
	never := pageKey(1, scopeID, userID, "cfk_EEEEEEEEEEEEEEEEEEEEEE", "Epsilon", StatusActive, snapshot.Add(-5*time.Minute))
	rows := []Key{expiredEarlier, expiredNow, future, revoked, never}
	reader := &pageReaderFixture{rows: &rows}
	service := pageTestService(snapshot, scopeID, userID, reader.read)
	service.pageCount = func(ctx context.Context, request apiKeyPageStoreRequest) (int, error) {
		all := request
		all.Limit, all.Offset = len(rows)+1, 0
		items, err := reader.read(ctx, all)
		return len(items), err
	}
	principal := tenantPagePrincipal(scopeID, userID)

	// The two newest keys are expired: a plain "first two active" read would wrongly say there is no usable key.
	first, err := service.ListSelfPage(t.Context(), principal, APIKeyListInput{Limit: 1, Usable: true})
	if err != nil || !reflect.DeepEqual(pageIDs(first.Items), []int{3}) || first.Total == nil || *first.Total != 2 || first.NextCursor == "" {
		t.Fatalf("usable first page ids=%v total=%v cursor=%q err=%v", pageIDs(first.Items), first.Total, first.NextCursor, err)
	}
	if !first.SnapshotAt.Equal(snapshot) {
		t.Fatalf("snapshot_at=%s, want server snapshot %s", first.SnapshotAt, snapshot)
	}
	next, err := service.ListSelfPage(t.Context(), principal, APIKeyListInput{Limit: 1, Usable: true, Cursor: first.NextCursor})
	if err != nil || !reflect.DeepEqual(pageIDs(next.Items), []int{1}) || next.NextCursor != "" {
		t.Fatalf("usable next page ids=%v cursor=%q err=%v", pageIDs(next.Items), next.NextCursor, err)
	}
	// A cursor issued without the usable filter cannot continue a usable traversal and vice versa.
	plain, err := service.ListSelfPage(t.Context(), principal, APIKeyListInput{Limit: 1})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.ListSelfPage(t.Context(), principal, APIKeyListInput{Limit: 1, Usable: true, Cursor: plain.NextCursor}); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("mixed cursor err=%v", err)
	}
	// The lifecycle list keeps expired active keys as history.
	lifecycle, err := service.ListSelfPage(t.Context(), principal, APIKeyListInput{Limit: 10, Status: StatusActive})
	if err != nil || !reflect.DeepEqual(pageIDs(lifecycle.Items), []int{5, 4, 3, 1}) {
		t.Fatalf("lifecycle ids=%v err=%v", pageIDs(lifecycle.Items), err)
	}
	if _, err := service.ListSelfPage(t.Context(), principal, APIKeyListInput{Limit: 1, Usable: true, Status: StatusRevoked}); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("usable+revoked err=%v", err)
	}
	withActive, err := service.ListSelfPage(t.Context(), principal, APIKeyListInput{Limit: 10, Usable: true, Status: StatusActive})
	if err != nil || !reflect.DeepEqual(pageIDs(withActive.Items), []int{3, 1}) {
		t.Fatalf("usable+active ids=%v err=%v", pageIDs(withActive.Items), err)
	}
}
