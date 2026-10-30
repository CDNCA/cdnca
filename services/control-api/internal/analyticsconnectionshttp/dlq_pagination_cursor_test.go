package analyticsconnectionshttp

import (
	"context"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/analyticsconnections"
)

type dlqPagedStoreStub struct {
	*dlqStoreStub30
	pageQueries []analyticsconnections.DeadLetterQuery
	next        uint64
}

func (store *dlqPagedStoreStub) ListDeadLettersPage(_ context.Context, query analyticsconnections.DeadLetterQuery) ([]analyticsconnections.DeadLetterReceiptView, uint64, error) {
	store.pageQueries = append(store.pageQueries, query)
	return append([]analyticsconnections.DeadLetterReceiptView(nil), store.rows...), store.next, store.err
}

func TestDLQServiceReturnsScanCursorForEmptyTenantPage(t *testing.T) {
	legacyStore := &dlqStoreStub30{}
	store := &dlqPagedStoreStub{dlqStoreStub30: legacyStore, next: analyticsconnections.MaximumDeadLetterScan}
	service, err := NewDLQService(store)
	if err != nil {
		t.Fatalf("service: %v", err)
	}

	page, err := service.List(context.Background(), DeadLetterListRequest{TenantID: dlqTenantID, Limit: 1})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(page.Items) != 0 || page.NextAfterSequence != analyticsconnections.MaximumDeadLetterScan {
		t.Fatalf("page = %#v, want empty items and next %d", page, analyticsconnections.MaximumDeadLetterScan)
	}
	if len(store.pageQueries) != 1 || store.pageQueries[0].Limit != 1 || len(legacyStore.listQuery) != 0 {
		t.Fatalf("paged queries = %#v, legacy queries = %#v", store.pageQueries, legacyStore.listQuery)
	}
}
