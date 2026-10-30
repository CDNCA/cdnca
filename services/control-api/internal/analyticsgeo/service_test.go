package analyticsgeo

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/analyticslog"
)

const (
	tenantID = "018f0000-0000-7000-8000-000000000001"
	siteID   = "018f0000-0000-7000-8000-000000000002"
	nodeID   = "018f0000-0000-7000-8000-000000000003"
)

type sourceStub struct {
	actor   Actor
	request QueryRequest
	page    SourcePage
	err     error
	cancel  context.CancelFunc
}

func (source *sourceStub) ReadEvents(ctx context.Context, actor Actor, request QueryRequest) (SourcePage, error) {
	source.actor, source.request = actor, request
	if source.cancel != nil {
		source.cancel()
	}
	return source.page, source.err
}

func testCatalog(t *testing.T) *Catalog {
	t.Helper()
	data := []byte(`{"version":"geo-2026.08","provider":"example-geo","published_at":"2026-08-01T00:00:00Z","effective_at":"2026-08-02T00:00:00Z","entries":[{"prefix":"203.0.113.0/24","country_code":"CN","region":"CN-SH","city":"Shanghai","carrier":"CMCC","asn":9808},{"prefix":"2001:db8::/32","country_code":"US","region":"US-CA","city":"Los Angeles","carrier":"IPv6-NET","asn":64512}]}`)
	catalog, err := NewCatalog([]CatalogInput{catalogInput(data)}, "geo-2026.08")
	if err != nil {
		t.Fatal(err)
	}
	return catalog
}

func TestServiceBindsTenantLogFactAndProjectsProvenance(t *testing.T) {
	occurredAt := time.Date(2026, 8, 8, 3, 0, 0, 0, time.UTC)
	source := &sourceStub{page: SourcePage{Items: []SourceEvent{{
		EventID: "access-event-1", OccurredAt: occurredAt, SiteID: siteID, NodeID: nodeID,
		ClientIP: "203.0.113.7", CountryCode: "CN", Carrier: "CMCC",
	}}}}
	service, err := NewService(source, testCatalog(t))
	if err != nil {
		t.Fatal(err)
	}
	request := QueryRequest{Audience: AudienceTenant, Kind: KindAccess, EventID: "access-event-1",
		From: occurredAt, To: occurredAt.Add(time.Millisecond), SiteID: siteID, NodeID: nodeID, ClientIP: "203.0.113.7"}
	item, err := service.Lookup(t.Context(), Actor{ScopeKind: "tenant", TenantID: tenantID,
		Permissions: []string{analyticslog.ReadPermission}}, request)
	if err != nil {
		t.Fatal(err)
	}
	if source.request.ClientIP != "203.0.113.7" || source.actor.TenantID != tenantID || item.EventID != request.EventID ||
		item.CountryCode != "CN" || item.Region != "CN-SH" || item.City != "Shanghai" || item.Carrier != "CMCC" || item.ASN != 9808 ||
		item.AddressFamily != "ipv4" || item.LookupReason != LookupReasonPrefixMatch ||
		item.Resolution != ResolutionMatched || item.Reconciliation != ReconciliationMatch ||
		item.Provenance.Version != "geo-2026.08" || item.Provenance.Provider != "example-geo" ||
		!item.Provenance.EffectiveAt.Equal(time.Date(2026, 8, 2, 0, 0, 0, 0, time.UTC)) || len(item.Provenance.SHA256) != 64 {
		t.Fatalf("source/item = %#v %#v", source, item)
	}
	if item.ClientIP != "" {
		t.Fatalf("response leaked raw client IP: %#v", item)
	}
}

func TestServiceMakesUnknownMismatchCapacityAndCancellationExplicit(t *testing.T) {
	occurredAt := time.Date(2026, 8, 8, 3, 0, 0, 0, time.UTC)
	request := QueryRequest{Audience: AudienceTenant, Kind: KindBlock, EventID: "block-event-1",
		From: occurredAt, To: occurredAt.Add(time.Millisecond), SiteID: siteID, NodeID: nodeID, ClientIP: "198.51.100.7"}
	actor := Actor{ScopeKind: "tenant", TenantID: tenantID, Permissions: []string{analyticslog.ReadPermission}}

	unknown := &sourceStub{page: SourcePage{Items: []SourceEvent{{EventID: request.EventID, OccurredAt: occurredAt,
		SiteID: siteID, NodeID: nodeID, ClientIP: request.ClientIP, CountryCode: "ZZ", Carrier: "legacy"}}}}
	service, _ := NewService(unknown, testCatalog(t))
	item, err := service.Lookup(t.Context(), actor, request)
	if err != nil || item.Resolution != ResolutionUnknown || item.Reconciliation != ReconciliationUnverified ||
		item.AddressFamily != "ipv4" || item.LookupReason != LookupReasonNoPrefixMatch || item.City != "__unknown__" {
		t.Fatalf("unknown lookup = %#v, %v", item, err)
	}

	capacity := &sourceStub{page: SourcePage{NextCursor: "more-results"}}
	service, _ = NewService(capacity, testCatalog(t))
	if _, err := service.Lookup(t.Context(), actor, request); !errors.Is(err, ErrCapacityExceeded) {
		t.Fatalf("capacity error = %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancelled := &sourceStub{cancel: cancel, page: SourcePage{Items: []SourceEvent{{EventID: request.EventID,
		OccurredAt: occurredAt, SiteID: siteID, NodeID: nodeID, ClientIP: request.ClientIP}}}}
	service, _ = NewService(cancelled, testCatalog(t))
	if _, err := service.Lookup(ctx, actor, request); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation error = %v", err)
	}
}
