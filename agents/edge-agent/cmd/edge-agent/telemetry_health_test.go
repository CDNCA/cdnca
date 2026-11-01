package main

import (
	"testing"
	"time"
)

// the heartbeat carries the telemetry pipeline's error code
// (EdgeRuntimeStatus.telemetry = 8) with first/last seen time and count.
func TestTelemetryHealthTrackerReportsCodeWithFirstLastAndCount(t *testing.T) {
	now := time.Date(2026, 10, 28, 1, 0, 0, 0, time.UTC)
	code := ""
	tracker := newTelemetryHealthTracker(func() time.Time { return now })
	if tracker.Report() != nil {
		t.Fatal("unbound tracker must report nothing")
	}
	tracker.Bind(func() telemetryDaemonSnapshot {
		return telemetryDaemonSnapshot{Enabled: true, Degraded: code != "", LastErrorCode: code}
	})
	if tracker.Report() != nil {
		t.Fatal("healthy pipeline must report nothing")
	}

	code = "L4_USAGE_LEDGER_FULL"
	first := now
	report := tracker.Report()
	if report.GetErrorCode() != code || report.GetCount() != 1 || !report.GetFirstSeenTime().AsTime().Equal(first) ||
		!report.GetLastSeenTime().AsTime().Equal(first) {
		t.Fatalf("first report = %v", report)
	}
	now = now.Add(30 * time.Second)
	report = tracker.Report()
	if report.GetCount() != 2 || !report.GetFirstSeenTime().AsTime().Equal(first) || !report.GetLastSeenTime().AsTime().Equal(now) {
		t.Fatalf("repeat report = %v", report)
	}

	// A different code starts over.
	code = "L4_USAGE_ATTRIBUTION_PENDING"
	now = now.Add(30 * time.Second)
	report = tracker.Report()
	if report.GetErrorCode() != code || report.GetCount() != 1 || !report.GetFirstSeenTime().AsTime().Equal(now) {
		t.Fatalf("changed code report = %v", report)
	}

	// Recovery clears it; the same code later is a new episode.
	code = ""
	if tracker.Report() != nil {
		t.Fatal("recovered pipeline must report nothing")
	}
	code = "L4_USAGE_ATTRIBUTION_PENDING"
	now = now.Add(time.Minute)
	if report = tracker.Report(); report.GetCount() != 1 || !report.GetFirstSeenTime().AsTime().Equal(now) {
		t.Fatalf("new episode report = %v", report)
	}
}

func TestTelemetryHealthTrackerDropsMalformedCodeAndClockSkew(t *testing.T) {
	now := time.Date(2026, 10, 28, 1, 0, 0, 0, time.UTC)
	code := "not a code"
	tracker := newTelemetryHealthTracker(func() time.Time { return now })
	tracker.Bind(func() telemetryDaemonSnapshot {
		return telemetryDaemonSnapshot{Enabled: true, Degraded: true, LastErrorCode: code}
	})
	if tracker.Report() != nil {
		t.Fatal("malformed code must not be reported")
	}
	// Degraded without a code is reported as the generic telemetry code.
	code = ""
	if got := tracker.Report().GetErrorCode(); got != "TELEMETRY_UNAVAILABLE" {
		t.Fatalf("degraded without code = %q", got)
	}
	code = "L4_USAGE_LEDGER_FULL"
	first := now
	tracker.Report()
	// The clock stepping back never makes last < first.
	now = now.Add(-time.Hour)
	report := tracker.Report()
	if report.GetLastSeenTime().AsTime().Before(report.GetFirstSeenTime().AsTime()) || !report.GetFirstSeenTime().AsTime().Equal(first) {
		t.Fatalf("clock skew report = %v", report)
	}
}
