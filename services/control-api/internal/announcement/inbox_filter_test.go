package announcement

import (
	"context"
	"errors"
	"testing"
)

// 收件箱接受 popup 筛选（未读且需弹窗）；其他未知筛选仍拒绝。
// 校验在访问数据库之前，零值 Store 即可。
func TestListInboxAcceptsPopupFilter(t *testing.T) {
	store := &Store{}
	if _, err := store.ListInbox(context.Background(), Actor{}, ListRequest{Limit: 1, ReadFilter: "bogus"}); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("bogus filter: %v", err)
	}
	func() {
		defer func() { _ = recover() }() // past validation the zero Store has no pool
		if _, err := store.ListInbox(context.Background(), Actor{}, ListRequest{Limit: 1, ReadFilter: "popup"}); errors.Is(err, ErrInvalidInput) {
			t.Fatal("popup filter rejected as invalid input")
		}
	}()
}
