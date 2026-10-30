package main

import (
	"context"
	"errors"
	"testing"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/eventspool"
)

type retryFirewallHitSource struct {
	batches [][]eventspool.Envelope
	reads   int
}

func (source *retryFirewallHitSource) ReadBatch(context.Context, int) ([]eventspool.Envelope, error) {
	if source.reads >= len(source.batches) {
		source.reads++
		return nil, nil
	}
	batch := append([]eventspool.Envelope(nil), source.batches[source.reads]...)
	source.reads++
	return batch, nil
}

func (*retryFirewallHitSource) Close() error { return nil }

type retryFirewallSink struct {
	attempts [][]eventspool.Envelope
	fail     error
}

func (sink *retryFirewallSink) AppendBatch(_ context.Context, events []eventspool.Envelope) ([]eventspool.AppendResult, error) {
	sink.attempts = append(sink.attempts, append([]eventspool.Envelope(nil), events...))
	if len(sink.attempts) == 1 {
		return nil, sink.fail
	}
	return make([]eventspool.AppendResult, len(events)), nil
}

func TestFirewallHitsRetrySameBatchBeforeReadingKernelAgain(t *testing.T) {
	backpressure := errors.New("telemetry spool backpressure")
	source := &retryFirewallHitSource{batches: [][]eventspool.Envelope{{
		{EventID: "firewall-hit-1", SiteID: telemetryTestSiteID},
		{EventID: "firewall-hit-2", SiteID: telemetryTestSiteID},
	}}}
	sink := &retryFirewallSink{fail: backpressure}
	runner := &telemetrySourceRunner{
		config: telemetrySourceConfig{FirewallRoot: "/unused", MaxBatchEvents: 2},
		sink:   sink, firewallHits: source,
		// The hits' site has an active telemetry identity (bindFirewallHits).
		sources: map[string]telemetrySourceRegistration{"/unused/security.jsonl": {Identity: eventspool.TrustedIdentity{
			TenantID: telemetryTestTenantID, SiteID: telemetryTestSiteID, ConfigVersionID: "cfg-v1"}}},
	}

	if err := runner.syncFirewallHits(context.Background()); !errors.Is(err, backpressure) {
		t.Fatalf("first append error = %v, want backpressure", err)
	}
	if source.reads != 1 || len(runner.firewallPending) != 2 {
		t.Fatalf("failed batch was not retained: reads=%d pending=%d", source.reads, len(runner.firewallPending))
	}
	if err := runner.syncFirewallHits(context.Background()); err != nil {
		t.Fatalf("retry append error = %v", err)
	}
	if source.reads != 1 || len(runner.firewallPending) != 0 || len(sink.attempts) != 2 {
		t.Fatalf("retry read ahead or retained state: reads=%d pending=%d attempts=%d",
			source.reads, len(runner.firewallPending), len(sink.attempts))
	}
	for index, event := range sink.attempts[0] {
		if sink.attempts[1][index].EventID != event.EventID {
			t.Fatalf("retry event %d changed identity: first=%q second=%q",
				index, event.EventID, sink.attempts[1][index].EventID)
		}
	}
	if err := runner.syncFirewallHits(context.Background()); err != nil || source.reads != 2 {
		t.Fatalf("source did not resume after durable append: reads=%d err=%v", source.reads, err)
	}
}
