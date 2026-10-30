package analyticslog

import (
	"context"
	"errors"
	"testing"
	"time"
)

const (
	boundaryTenant = "10000000-0000-4000-8000-00000000000a"
	boundarySite   = "20000000-0000-4000-8000-00000000000a"
	boundaryNode   = "30000000-0000-4000-8000-00000000000a"
)

type serviceBoundaryStore struct {
	accessPage AccessPage
	blockPage  BlockEventPage
}

func (store *serviceBoundaryStore) ListAccess(context.Context, scope, Filter, uint16, string) (AccessPage, error) {
	return store.accessPage, nil
}

func (store *serviceBoundaryStore) ListBlockEvents(context.Context, scope, Filter, uint16, string) (BlockEventPage, error) {
	return store.blockPage, nil
}

func TestServiceRejectsMalformedStoragePages(t *testing.T) {
	actor := Actor{ScopeKind: "tenant", TenantID: boundaryTenant, Permissions: []string{ReadPermission}}
	from := time.Date(2026, 8, 7, 10, 0, 0, 0, time.UTC)
	request := QueryRequest{Audience: AudienceTenant, Limit: 2, Filter: Filter{From: from, To: from.Add(time.Hour)}}
	now := request.Filter.To.Add(-time.Millisecond)
	validAccess := AccessLog{EventID: "event-b", OccurredAt: now, SiteID: boundarySite, NodeID: boundaryNode}
	olderAccess := validAccess
	olderAccess.EventID = "event-a"
	olderAccess.OccurredAt = now.Add(-time.Second)
	validBlock := BlockEvent{EventID: "event-b", OccurredAt: now, SiteID: boundarySite, NodeID: boundaryNode}
	olderBlock := validBlock
	olderBlock.EventID = "event-a"
	olderBlock.OccurredAt = now.Add(-time.Second)

	tests := []struct {
		name       string
		accessPage AccessPage
		blockPage  BlockEventPage
		listBlock  bool
	}{
		{name: "access zero occurred at", accessPage: AccessPage{Items: []AccessLog{{EventID: "event-a", SiteID: boundarySite, NodeID: boundaryNode}}}},
		{name: "access duplicate event", accessPage: AccessPage{Items: []AccessLog{validAccess, validAccess}}},
		{name: "access non descending", accessPage: AccessPage{Items: []AccessLog{olderAccess, validAccess}}},
		{name: "access over limit", accessPage: AccessPage{Items: []AccessLog{validAccess, olderAccess, {EventID: "event-c", OccurredAt: now.Add(-2 * time.Second), SiteID: boundarySite, NodeID: boundaryNode}}}},
		{name: "access cursor without snapshot", accessPage: AccessPage{Items: []AccessLog{validAccess}, NextCursor: "next"}},
		{name: "block zero occurred at", listBlock: true, blockPage: BlockEventPage{Items: []BlockEvent{{EventID: "event-a", SiteID: boundarySite, NodeID: boundaryNode}}}},
		{name: "block duplicate event", listBlock: true, blockPage: BlockEventPage{Items: []BlockEvent{validBlock, validBlock}}},
		{name: "block non descending", listBlock: true, blockPage: BlockEventPage{Items: []BlockEvent{olderBlock, validBlock}}},
		{name: "block cursor on empty page", listBlock: true, blockPage: BlockEventPage{NextCursor: "next", SnapshotAt: now}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			service, err := NewService(&serviceBoundaryStore{accessPage: test.accessPage, blockPage: test.blockPage})
			if err != nil {
				t.Fatal(err)
			}
			if test.listBlock {
				page, err := service.ListBlockEvents(context.Background(), actor, request)
				if !errors.Is(err, ErrInvalidResponse) || len(page.Items) != 0 || page.NextCursor != "" || !page.SnapshotAt.IsZero() {
					t.Fatalf("page/error = (%#v, %v), want zero/ErrInvalidResponse", page, err)
				}
				return
			}
			page, err := service.ListAccess(context.Background(), actor, request)
			if !errors.Is(err, ErrInvalidResponse) || len(page.Items) != 0 || page.NextCursor != "" || !page.SnapshotAt.IsZero() {
				t.Fatalf("page/error = (%#v, %v), want zero/ErrInvalidResponse", page, err)
			}
		})
	}
}
