package l4analytics

import (
	"context"
	"errors"
	"testing"
	"time"
)

const (
	testTenant = "018f47a2-5b9c-7d31-8a60-104c9c0b7102"
	testSite   = "018f47a2-5b9c-7d31-8a60-104c9c0b7103"
	testStream = "018f47a2-5b9c-7d31-8a60-104c9c0b7104"
	testNode   = "018f47a2-5b9c-7d31-8a60-104c9c0b7105"
)

type sourceStub struct {
	scope  Scope
	filter Filter
	page   Page
	err    error
}

func (stub *sourceStub) Read(_ context.Context, scope Scope, filter Filter) (Page, error) {
	stub.scope, stub.filter = scope, filter
	return stub.page, stub.err
}

func TestServiceEnforcesTenantSnapshotAndStableCursor(t *testing.T) {
	now := time.Date(2026, 8, 8, 12, 0, 0, 0, time.UTC)
	source := &sourceStub{page: Page{
		Snapshot: Snapshot{At: now, SourceWatermark: 41, FinalizedThrough: now.Add(-time.Second)},
		Rows: []Row{{Bucket: now.Add(-time.Minute), NodeID: testNode, SiteID: testSite, StreamID: testStream,
			ListenerID: testStream, Protocol: "tcp", ListenPort: 18080, Sessions: 3, BytesUp: 300, BytesDown: 1200, Errors: 1}},
		HasMore: true,
	}}
	service, err := NewService(source, Config{Now: func() time.Time { return now }, CursorKey: []byte("01234567890123456789012345678901")})
	if err != nil {
		t.Fatal(err)
	}
	query := Query{Audience: AudienceTenant, TenantID: testTenant, Range: "1h", Timezone: "UTC", SiteID: testSite, StreamID: testStream, ListenPort: 18080, Limit: 1}
	response, err := service.Read(t.Context(), Actor{ScopeKind: "tenant", TenantID: testTenant, Permissions: []string{ReadPermission}}, query)
	if err != nil || source.scope.TenantID != testTenant || source.filter.ListenPort != 18080 || source.filter.Snapshot.SourceWatermark != 0 || response.Meta.Snapshot.SourceWatermark != 41 ||
		response.Totals.Sessions != 3 || response.Totals.BytesUp != 300 || response.Totals.BytesDown != 1200 || response.Totals.Errors != 1 || response.NextCursor == "" {
		t.Fatalf("L4 response=%#v scope=%#v filter=%#v error=%v", response, source.scope, source.filter, err)
	}
	query.Cursor = response.NextCursor
	query.NodeID = testNode
	if _, err := service.Read(t.Context(), Actor{ScopeKind: "tenant", TenantID: testTenant, Permissions: []string{ReadPermission}}, query); !errors.Is(err, ErrInvalidCursor) {
		t.Fatalf("changed-filter cursor error = %v", err)
	}
	for _, actor := range []Actor{
		{ScopeKind: "tenant", TenantID: "018f47a2-5b9c-7d31-8a60-104c9c0b7199", Permissions: []string{ReadPermission}},
		{ScopeKind: "tenant", TenantID: testTenant},
	} {
		if _, err := service.Read(t.Context(), actor, Query{Audience: AudienceTenant, TenantID: testTenant, Range: "1h", Timezone: "UTC", Limit: 10}); !errors.Is(err, ErrPermissionDenied) {
			t.Fatalf("actor %#v error = %v", actor, err)
		}
	}
}

func TestServiceAllowsPlatformWideAndEmptyRealtimeReads(t *testing.T) {
	now := time.Date(2026, 9, 15, 3, 0, 0, 0, time.UTC)
	source := &sourceStub{page: Page{
		Snapshot: Snapshot{At: now, FinalizedThrough: now},
		Rows:     []Row{},
	}}
	service, err := NewService(source, Config{Now: func() time.Time { return now }, CursorKey: []byte("01234567890123456789012345678901")})
	if err != nil {
		t.Fatal(err)
	}
	response, err := service.Read(t.Context(), Actor{ScopeKind: "platform", Permissions: []string{"platform.admin"}}, Query{
		Audience: AudiencePlatform, Range: "1h", Timezone: "UTC", Limit: 100,
	})
	if err != nil || source.scope.TenantID != "" || len(response.Rows) != 0 || response.Totals != (Totals{}) {
		t.Fatalf("platform response=%#v scope=%#v error=%v", response, source.scope, err)
	}
}
