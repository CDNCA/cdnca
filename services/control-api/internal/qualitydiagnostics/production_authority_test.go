package qualitydiagnostics

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/analyticslog"
	"github.com/cdnca/cdnca/services/control-api/internal/analyticsrealtime"
	"github.com/google/uuid"
)

type productionAccessSourceStub struct {
	request analyticslog.FinalizedAccessRequest
	page    analyticslog.FinalizedAccessPage
	err     error
}

func (stub *productionAccessSourceStub) ReadFinalizedAccess(
	_ context.Context,
	request analyticslog.FinalizedAccessRequest,
) (analyticslog.FinalizedAccessPage, error) {
	stub.request = request
	return stub.page, stub.err
}

func TestProductionAccessAuthorityPreservesExactScopeFilterAndSnapshot(t *testing.T) {
	now := time.Date(2026, 8, 8, 12, 0, 0, 0, time.UTC)
	snapshot := analyticsrealtime.Snapshot{
		At: now.Add(-time.Second), SourceWatermark: 44,
		FinalizedThrough: now.Add(-time.Minute), ExpiresAt: now.Add(time.Minute),
	}
	tenantID := uuid.MustParse("018f0000-0000-7000-8000-000000000001")
	siteID := uuid.MustParse("018f0000-0000-7000-8000-000000000002")
	nodeID := uuid.MustParse("018f0000-0000-7000-8000-000000000003")
	log := analyticslog.AccessLog{EventID: "event-a", SiteID: siteID.String(), NodeID: nodeID.String()}
	source := &productionAccessSourceStub{page: analyticslog.FinalizedAccessPage{
		Facts:      []analyticslog.FinalizedAccessFact{{TenantID: tenantID.String(), Log: log}},
		NextCursor: "source.next", Snapshot: snapshot,
	}}
	authority, err := NewProductionAccessAuthority(source)
	if err != nil {
		t.Fatal(err)
	}
	request := ReadRequest{
		Scope: Scope{TenantID: tenantID}, Filter: Filter{
			From: now.Add(-time.Hour), To: now.Add(-time.Minute), SiteID: siteID, NodeID: nodeID,
			Category: CategoryEdge530,
		}, Limit: 17, SourceCursor: "source.current", Snapshot: &snapshot,
	}
	page, err := authority.ReadFinalizedAccess(t.Context(), request)
	if err != nil {
		t.Fatal(err)
	}
	if source.request.TenantID != tenantID.String() || source.request.SiteID != siteID.String() ||
		source.request.NodeID != nodeID.String() || source.request.From != request.Filter.From ||
		source.request.To != request.Filter.To || source.request.Category != string(request.Filter.Category) ||
		source.request.Limit != request.Limit || source.request.Cursor != request.SourceCursor ||
		source.request.Snapshot == nil || *source.request.Snapshot != snapshot {
		t.Fatalf("source request = %#v", source.request)
	}
	if len(page.Facts) != 1 || page.Facts[0].TenantID != tenantID || page.Facts[0].Log.EventID != log.EventID ||
		page.NextSourceCursor != source.page.NextCursor || page.Snapshot != snapshot {
		t.Fatalf("authority page = %#v", page)
	}
}

func TestProductionAccessAuthorityFailsClosedAndMapsStableErrors(t *testing.T) {
	var typedNil *productionAccessSourceStub
	if authority, err := NewProductionAccessAuthority(typedNil); authority != nil || !errors.Is(err, ErrInvalidConfiguration) {
		t.Fatalf("typed nil source = %#v, %v", authority, err)
	}
	for _, test := range []struct {
		name string
		err  error
		want error
	}{
		{name: "input", err: analyticslog.ErrInvalidInput, want: ErrInvalidRequest},
		{name: "response", err: analyticslog.ErrInvalidResponse, want: ErrInvalidResponse},
		{name: "storage", err: analyticslog.ErrStorageUnavailable, want: ErrUnavailable},
		{name: "deadline", err: context.DeadlineExceeded, want: context.DeadlineExceeded},
	} {
		t.Run(test.name, func(t *testing.T) {
			authority, err := NewProductionAccessAuthority(&productionAccessSourceStub{err: test.err})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := authority.ReadFinalizedAccess(t.Context(), ReadRequest{}); !errors.Is(err, test.want) {
				t.Fatalf("mapped error = %v, want %v", err, test.want)
			}
		})
	}
}
