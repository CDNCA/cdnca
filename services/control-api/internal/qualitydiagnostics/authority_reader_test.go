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

type finalizedAuthorityStub struct {
	request ReadRequest
	page    ReadPage
	err     error
	cancel  context.CancelFunc
}

func (stub *finalizedAuthorityStub) ReadFinalizedAccess(
	ctx context.Context,
	request ReadRequest,
) (ReadPage, error) {
	stub.request = request
	if stub.cancel != nil {
		stub.cancel()
	}
	return stub.page, stub.err
}

func TestAuthorityReaderAdapterPreservesExactFinalizedRequestAndSnapshot(t *testing.T) {
	now := time.Date(2026, 8, 8, 8, 0, 0, 0, time.UTC)
	snapshot := analyticsrealtime.Snapshot{
		At: now.Add(-time.Second), SourceWatermark: 44,
		FinalizedThrough: now.Add(-time.Minute), ExpiresAt: now.Add(time.Minute),
	}
	scope := Scope{TenantID: uuid.MustParse("018f0000-0000-7000-8000-000000000001")}
	filter := Filter{
		From: now.Add(-time.Hour), To: now.Add(-time.Minute),
		SiteID:   uuid.MustParse("018f0000-0000-7000-8000-000000000002"),
		NodeID:   uuid.MustParse("018f0000-0000-7000-8000-000000000003"),
		Category: CategoryEdge530,
	}
	fact := ScopedAccessFact{TenantID: scope.TenantID, Log: analyticslog.AccessLog{
		EventID: "event-44", OccurredAt: now.Add(-2 * time.Minute),
		SiteID: filter.SiteID.String(), NodeID: filter.NodeID.String(), StatusCode: 530,
	}}
	authority := &finalizedAuthorityStub{page: ReadPage{
		Facts: []ScopedAccessFact{fact}, NextSourceCursor: "authority.next", Snapshot: snapshot,
	}}
	reader, err := NewAuthorityReaderAdapter(authority)
	if err != nil {
		t.Fatal(err)
	}
	request := ReadRequest{
		Scope: scope, Filter: filter, Limit: 17,
		SourceCursor: "authority.current", Snapshot: &snapshot,
	}
	page, err := reader.ReadFinalizedLatest(t.Context(), request)
	if err != nil {
		t.Fatal(err)
	}
	if authority.request.Scope != scope || authority.request.Filter != filter || authority.request.Limit != request.Limit ||
		authority.request.SourceCursor != request.SourceCursor || authority.request.Snapshot == nil ||
		!sameSnapshot(*authority.request.Snapshot, snapshot) {
		t.Fatalf("authority request = %#v; want exact %#v", authority.request, request)
	}
	if len(page.Facts) != 1 || page.Facts[0].Log.EventID != fact.Log.EventID ||
		page.NextSourceCursor != "authority.next" || !sameSnapshot(page.Snapshot, snapshot) {
		t.Fatalf("adapter page = %#v", page)
	}
}

func TestAuthorityReaderAdapterFailsClosedForTypedNilAndSnapshotDrift(t *testing.T) {
	var typedNil *finalizedAuthorityStub
	if _, err := NewAuthorityReaderAdapter(typedNil); !errors.Is(err, ErrInvalidConfiguration) {
		t.Fatalf("NewAuthorityReaderAdapter(typed nil) error = %v", err)
	}

	now := time.Date(2026, 8, 8, 8, 0, 0, 0, time.UTC)
	want := analyticsrealtime.Snapshot{
		At: now.Add(-time.Second), SourceWatermark: 44,
		FinalizedThrough: now.Add(-time.Minute), ExpiresAt: now.Add(time.Minute),
	}
	drifted := want
	drifted.SourceWatermark++
	reader, err := NewAuthorityReaderAdapter(&finalizedAuthorityStub{page: ReadPage{Snapshot: drifted}})
	if err != nil {
		t.Fatal(err)
	}
	_, err = reader.ReadFinalizedLatest(t.Context(), ReadRequest{
		Scope:  Scope{TenantID: uuid.MustParse("018f0000-0000-7000-8000-000000000001")},
		Filter: Filter{From: now.Add(-time.Hour), To: now.Add(-time.Minute)},
		Limit:  10, SourceCursor: "authority.current", Snapshot: &want,
	})
	if !errors.Is(err, ErrInvalidSnapshot) {
		t.Fatalf("snapshot drift error = %v", err)
	}
}

func TestAuthorityReaderAdapterMapsOnlyStableErrorsAndPreservesContext(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want error
	}{
		{name: "invalid response", err: analyticslog.ErrInvalidResponse, want: ErrInvalidResponse},
		{name: "invalid snapshot", err: analyticsrealtime.ErrInvalidSnapshot, want: ErrInvalidSnapshot},
		{name: "storage", err: analyticslog.ErrStorageUnavailable, want: ErrUnavailable},
		{name: "dependency", err: analyticsrealtime.ErrDependencyUnavailable, want: ErrUnavailable},
		{name: "unknown", err: errors.New("private storage detail"), want: ErrUnavailable},
		{name: "deadline", err: context.DeadlineExceeded, want: context.DeadlineExceeded},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			reader, err := NewAuthorityReaderAdapter(&finalizedAuthorityStub{err: test.err})
			if err != nil {
				t.Fatal(err)
			}
			_, err = reader.ReadFinalizedLatest(t.Context(), ReadRequest{})
			if !errors.Is(err, test.want) {
				t.Fatalf("ReadFinalizedLatest() error = %v, want %v", err, test.want)
			}
		})
	}

	ctx, cancel := context.WithCancel(context.Background())
	reader, err := NewAuthorityReaderAdapter(&finalizedAuthorityStub{
		err: errors.New("must not escape"), cancel: cancel,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reader.ReadFinalizedLatest(ctx, ReadRequest{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled authority error = %v", err)
	}
}
