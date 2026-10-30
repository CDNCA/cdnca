package analytics

import (
	"testing"
	"time"
)

func TestNewIngestReceiptBuildsRealtimeExpectedCounts(t *testing.T) {
	decoded := authorityDecodedIngestV1(t)
	first := decoded.AccessEvents[0]
	first.Host = "CDN.Example.Test"
	first.ListenPort = 443
	first.OccurredAt = time.Date(2026, 8, 7, 1, 15, 0, 0, time.UTC)
	second := first
	second.EventID = "expected-second"
	second.OccurredAt = first.OccurredAt.Add(20 * time.Minute)
	third := first
	third.EventID = "expected-third"
	third.ListenPort = 8443
	decoded.AccessEvents = []AccessEvent{first, second, third}

	receipt, err := NewIngestReceiptV1(authorityGenerationV1(), 42, decoded)
	if err != nil {
		t.Fatal(err)
	}
	if len(receipt.RealtimeExpectedCounts) != 2 {
		t.Fatalf("expected dimensions = %#v", receipt.RealtimeExpectedCounts)
	}
	wantHour := first.OccurredAt.Truncate(time.Hour)
	if got := receipt.RealtimeExpectedCounts[0]; !got.Hour.Equal(wantHour) || got.TenantID != first.TenantID ||
		got.SiteID != first.SiteID || got.Host != "cdn.example.test" || got.ListenPort != 443 || got.EventCount != 2 {
		t.Fatalf("first expected count = %#v", got)
	}
	if got := receipt.RealtimeExpectedCounts[1]; got.ListenPort != 8443 || got.EventCount != 1 {
		t.Fatalf("second expected count = %#v", got)
	}

	production := decoded
	production.AccessEvents = []AccessEvent{first}
	productionReceipt, err := NewIngestReceiptV1(authorityGenerationV1(), 42, production)
	if err != nil {
		t.Fatal(err)
	}
	legacy := production
	legacy.AccessEvents = append([]AccessEvent(nil), production.AccessEvents...)
	legacy.AccessEvents[0].ListenPort = 0
	legacyReceipt, err := NewIngestReceiptV1(authorityGenerationV1(), 42, legacy)
	if err != nil {
		t.Fatal(err)
	}
	if legacyReceipt.CanonicalEventSHA256 == productionReceipt.CanonicalEventSHA256 {
		t.Fatal("production listen port did not bind canonical event identity")
	}
}
