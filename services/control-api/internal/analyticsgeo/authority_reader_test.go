package analyticsgeo

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/analyticslog"
)

func TestAuthorityReaderAdapterBindsExactTenantEventAndProjectsAuthority(t *testing.T) {
	occurredAt := time.Date(2026, 8, 8, 3, 0, 0, 0, time.UTC)
	source := &sourceStub{page: SourcePage{Items: []SourceEvent{{
		EventID: "access-event-authority-1", OccurredAt: occurredAt, SiteID: siteID, NodeID: nodeID,
		ClientIP: "203.0.113.129", CountryCode: "JP", Carrier: "specific",
	}}}}
	authority, privateKey, clock := newAuthorityFixture(t, 1<<20)
	oldInput, currentInput := authorityCatalogInputs()
	expiresAt := clock.Now().Add(time.Hour)
	snapshot := signedAuthoritySnapshot(t, privateKey, 7, "geo-2026.08", expiresAt, []CatalogInput{oldInput, currentInput})
	if err := authority.Reload(t.Context(), snapshot); err != nil {
		t.Fatal(err)
	}
	if _, err := NewAuthorityReaderAdapter(nil, authority); !errors.Is(err, ErrInvalidConfiguration) {
		t.Fatalf("NewAuthorityReaderAdapter(nil, authority) error = %v", err)
	}
	adapter, err := NewAuthorityReaderAdapter(source, authority)
	if err != nil {
		t.Fatal(err)
	}
	actor := Actor{ScopeKind: "tenant", TenantID: tenantID, Permissions: []string{analyticslog.ReadPermission}}
	request := QueryRequest{Audience: AudienceTenant, Kind: KindAccess, EventID: "access-event-authority-1",
		From: occurredAt, To: occurredAt.Add(time.Millisecond), SiteID: siteID, NodeID: nodeID,
		ClientIP: "203.0.113.129"}

	result, err := adapter.LookupWithAuthority(t.Context(), actor, request)
	if err != nil {
		t.Fatal(err)
	}
	if source.actor.TenantID != tenantID || source.request != request {
		t.Fatalf("source binding = actor %#v request %#v", source.actor, source.request)
	}
	if result.Item.EventID != request.EventID || result.Item.CountryCode != "JP" || result.Item.Region != "JP-13" ||
		result.Item.Carrier != "specific" || result.Item.ASN != 64512 || result.Item.Resolution != ResolutionMatched ||
		result.Item.Reconciliation != ReconciliationMatch || result.Item.Provenance.Version != "geo-2026.08" ||
		len(result.Item.Provenance.SHA256) != 64 || result.Item.ClientIP != "" || result.Revision != snapshot.Revision ||
		!result.ExpiresAt.Equal(expiresAt) || result.State != AuthorityStateActive || result.Reason != AuthorityReasonNone {
		t.Fatalf("LookupWithAuthority() = %#v", result)
	}
	item, err := adapter.Lookup(t.Context(), actor, request)
	if err != nil {
		t.Fatal(err)
	}
	if item.EventID != result.Item.EventID || item.Provenance != result.Item.Provenance || item.ClientIP != "" {
		t.Fatalf("Lookup() = %#v, authority item = %#v", item, result.Item)
	}
}

func TestAuthorityReaderAdapterMakesUnknownAndInvalidEvidenceExplicit(t *testing.T) {
	occurredAt := time.Date(2026, 8, 8, 3, 0, 0, 0, time.UTC)
	actor := Actor{ScopeKind: "tenant", TenantID: tenantID, Permissions: []string{analyticslog.ReadPermission}}
	request := QueryRequest{Audience: AudienceTenant, Kind: KindBlock, EventID: "block-event-authority-1",
		From: occurredAt, To: occurredAt.Add(time.Millisecond), SiteID: siteID, NodeID: nodeID,
		ClientIP: "198.51.100.7"}
	authority, privateKey, clock := newAuthorityFixture(t, 1<<20)
	_, currentInput := authorityCatalogInputs()
	snapshot := signedAuthoritySnapshot(t, privateKey, 11, "geo-2026.08", clock.Now().Add(time.Hour), []CatalogInput{currentInput})
	if err := authority.Reload(t.Context(), snapshot); err != nil {
		t.Fatal(err)
	}

	unknown := &sourceStub{page: SourcePage{Items: []SourceEvent{{
		EventID: request.EventID, OccurredAt: occurredAt, SiteID: siteID, NodeID: nodeID, ClientIP: request.ClientIP,
	}}}}
	adapter, err := NewAuthorityReaderAdapter(unknown, authority)
	if err != nil {
		t.Fatal(err)
	}
	result, err := adapter.LookupWithAuthority(t.Context(), actor, request)
	if err != nil || result.Item.Resolution != ResolutionUnknown || result.Item.Reconciliation != ReconciliationUnverified ||
		result.Item.CountryCode != "__unknown__" || result.Item.Region != "__unknown__" ||
		result.Item.Carrier != "__unknown__" || result.Item.ClientIP != "" || result.Revision != snapshot.Revision {
		t.Fatalf("unknown authority lookup = %#v, %v", result, err)
	}

	for _, test := range []struct {
		name string
		page SourcePage
		err  error
	}{
		{name: "next cursor is ambiguous", page: SourcePage{NextCursor: "more"}, err: ErrCapacityExceeded},
		{name: "multiple rows are ambiguous", page: SourcePage{Items: []SourceEvent{{}, {}}}, err: ErrCapacityExceeded},
		{name: "mismatched event is invalid", page: SourcePage{Items: []SourceEvent{{
			EventID: "different-event", OccurredAt: occurredAt, SiteID: siteID, NodeID: nodeID, ClientIP: request.ClientIP,
		}}}, err: ErrInvalidResponse},
	} {
		t.Run(test.name, func(t *testing.T) {
			adapter, err := NewAuthorityReaderAdapter(&sourceStub{page: test.page}, authority)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := adapter.LookupWithAuthority(t.Context(), actor, request); !errors.Is(err, test.err) {
				t.Fatalf("LookupWithAuthority() error = %v, want %v", err, test.err)
			}
		})
	}
}

func TestAuthorityReaderAdapterPreservesCancellationAndDependencyErrors(t *testing.T) {
	occurredAt := time.Date(2026, 8, 8, 3, 0, 0, 0, time.UTC)
	actor := Actor{ScopeKind: "tenant", TenantID: tenantID, Permissions: []string{analyticslog.ReadPermission}}
	request := QueryRequest{Audience: AudienceTenant, Kind: KindAccess, EventID: "access-event-authority-2",
		From: occurredAt, To: occurredAt.Add(time.Millisecond), SiteID: siteID, NodeID: nodeID,
		ClientIP: "203.0.113.129"}
	authority, privateKey, clock := newAuthorityFixture(t, 1<<20)
	_, currentInput := authorityCatalogInputs()
	if err := authority.Reload(t.Context(), signedAuthoritySnapshot(t, privateKey, 1, "geo-2026.08",
		clock.Now().Add(time.Hour), []CatalogInput{currentInput})); err != nil {
		t.Fatal(err)
	}
	row := SourceEvent{EventID: request.EventID, OccurredAt: occurredAt, SiteID: siteID, NodeID: nodeID,
		ClientIP: request.ClientIP, CountryCode: "JP", Carrier: "specific"}

	ctx, cancel := context.WithCancel(context.Background())
	cancellingSource := &sourceStub{cancel: cancel, page: SourcePage{Items: []SourceEvent{row}}}
	adapter, err := NewAuthorityReaderAdapter(cancellingSource, authority)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := adapter.LookupWithAuthority(ctx, actor, request); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled LookupWithAuthority() error = %v", err)
	}

	adapter, err = NewAuthorityReaderAdapter(&sourceStub{page: SourcePage{Items: []SourceEvent{row}}}, authority)
	if err != nil {
		t.Fatal(err)
	}
	request.DatabaseVersion = "geo-missing"
	if _, err := adapter.LookupWithAuthority(t.Context(), actor, request); !errors.Is(err, ErrVersionNotFound) {
		t.Fatalf("missing authority version error = %v", err)
	}
}
