package main

import (
	"fmt"
	"testing"
)

func TestTelemetrySourceRunnerReportsExpiredEvents(t *testing.T) {
	runner := &telemetrySourceRunner{}
	runner.setError(fmt.Errorf("round: %w", errTelemetryEventsExpired))
	if code := runner.ErrorCode(); code != "TELEMETRY_SOURCE_EVENTS_EXPIRED" {
		t.Fatalf("error code = %q", code)
	}
	runner.setError(nil)
	if code := runner.ErrorCode(); code != "" {
		t.Fatalf("cleared error code = %q", code)
	}
}
