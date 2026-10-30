package gateway

import "testing"

// sec-log-agg: a security event's count (an aggregated CC challenge / 429
// line) decodes strictly and is bounded like the event spool's.
func TestTelemetrySecurityEventCount(t *testing.T) {
	var event telemetrySecurityEventV2
	if err := decodeStrictTelemetryJSON([]byte(`{"installation_id":"","count":10}`), &event); err != nil || event.Count != 10 {
		t.Fatalf("count decode: %v %d", err, event.Count)
	}
	if !validTelemetrySecurityEvidence(telemetrySecurityEvent{Count: 1_000_000_000}) ||
		validTelemetrySecurityEvidence(telemetrySecurityEvent{Count: 1_000_000_001}) {
		t.Fatal("count bound")
	}
	if err := decodeStrictTelemetryJSON([]byte(`{"installation_id":"","counts":10}`), &event); err == nil {
		t.Fatal("unknown field accepted")
	}
}
