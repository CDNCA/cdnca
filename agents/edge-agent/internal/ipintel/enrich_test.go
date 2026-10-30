package ipintel

import (
	"context"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/eventspool"
	format "github.com/cdnca/cdnca/libs/entitlement/ipintel"
)

type recordingSink struct{ batches [][]eventspool.Envelope }

func (sink *recordingSink) AppendBatch(_ context.Context, envelopes []eventspool.Envelope) ([]eventspool.AppendResult, error) {
	sink.batches = append(sink.batches, append([]eventspool.Envelope(nil), envelopes...))
	return nil, nil
}

func TestEnricherFillsCountryAndCarrierFromTheInstalledLibrary(t *testing.T) {
	artifact, err := format.Build(format.BuildInput{Revision: 1, BuildID: buildID(1),
		GeneratedAt: testNow.Add(-time.Hour), DataUpdatedAt: testNow.Add(-2 * time.Hour), StaleAfter: testNow.Add(30 * 24 * time.Hour),
		SourceRelease: "ipx-test", Notice: "test",
		Sources: []format.Source{{ID: "geo", Name: "test", URL: "https://example.invalid", License: "CC0-1.0", Ref: "1", Role: "asn"}},
		Facts: []format.Fact{{Prefix: netip.MustParsePrefix("1.0.1.0/24"), ASN: 4134, Country: "CN", Tags: format.TagCNTelecom | format.TagIDCCN},
			{Prefix: netip.MustParsePrefix("8.8.8.0/24"), ASN: 15169, Country: "US"}}})
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	sink := &recordingSink{}
	clock := testNow
	enricher := NewEnricher(sink, root, func() time.Time { return clock })
	events := func() []eventspool.Envelope {
		return []eventspool.Envelope{
			{Type: eventspool.EventSecurity, ClientIP: "1.0.1.9"},
			{Type: eventspool.EventAccess, ClientIP: "8.8.8.8"},
			{Type: eventspool.EventSecurity, ClientIP: "1.0.1.9", CountryCode: "HK"},
			{Type: eventspool.EventSecurity, ClientIP: "192.0.2.1"},
			{Type: eventspool.EventL4Session, ClientIP: "1.0.1.9"},
		}
	}
	// No library: unchanged.
	if _, err := enricher.AppendBatch(t.Context(), events()); err != nil || sink.batches[0][0].CountryCode != "" {
		t.Fatalf("enriched without a library: %+v %v", sink.batches[0][0], err)
	}
	if err := os.WriteFile(filepath.Join(root, CurrentFile), artifact.Bytes, 0o600); err != nil {
		t.Fatal(err)
	}
	clock = clock.Add(enrichRefresh)
	if _, err := enricher.AppendBatch(t.Context(), events()); err != nil {
		t.Fatal(err)
	}
	got := sink.batches[1]
	if got[0].CountryCode != "CN" || got[0].Carrier != "carrier:cn-telecom" {
		t.Fatalf("security event = %+v", got[0])
	}
	if got[1].CountryCode != "US" || got[1].Carrier != "" {
		t.Fatalf("access event = %+v", got[1])
	}
	if got[2].CountryCode != "HK" || got[2].Carrier != "carrier:cn-telecom" {
		t.Fatalf("a value the node set was replaced: %+v", got[2])
	}
	if got[3].CountryCode != "" || got[4].CountryCode != "" {
		t.Fatalf("unknown address or other event type enriched: %+v %+v", got[3], got[4])
	}
}
