package observabilitylog

import (
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
)

// approval-center3：backup 不再是日志类型（数据只来自已删的旧高危操作中心）。
// 按 backup 过滤是非法输入，不查库；不指定类型时默认四类，不含 backup。
func TestListRejectsRemovedBackupKind(t *testing.T) {
	now := time.Date(2026, 10, 25, 3, 0, 0, 0, time.UTC)
	repository := &fakeRepository09{}
	service, err := NewService(repository, []byte("0123456789abcdef0123456789abcdef"), func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	scopeID := uuid.New()
	actor := Actor{UserID: uuid.New(), ScopeID: scopeID, SessionID: uuid.New(), ScopeKind: ScopeTenant, Permissions: []string{"identity.self.read"}}
	for _, kinds := range [][]Kind{{"backup"}, {KindOperation, "backup"}} {
		if _, err := service.List(t.Context(), actor, Query{Kinds: kinds}); !errors.Is(err, ErrInvalidInput) {
			t.Fatalf("kinds %v err=%v, want invalid input", kinds, err)
		}
	}
	if repository.listCalls != 0 {
		t.Fatalf("backup filter reached the store %d times", repository.listCalls)
	}
	if _, err := service.List(t.Context(), actor, Query{}); err != nil {
		t.Fatal(err)
	}
	want := []Kind{"frontend", "login", "notification", "operation"} // sorted by the service
	got := repository.query.Kinds
	if len(got) != len(want) {
		t.Fatalf("default kinds = %v, want %v", got, want)
	}
	for index := range want {
		if got[index] != want[index] {
			t.Fatalf("default kinds = %v, want %v", got, want)
		}
	}
}
