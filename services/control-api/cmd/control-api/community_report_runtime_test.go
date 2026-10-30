package main

import (
	"path/filepath"
	"testing"
	"time"
)

func TestCommunityReporterConfiguration(t *testing.T) {
	t.Setenv(communityReportURLEnv, "off")
	if reporter, err := newCommunityReporter(nil, "1.0.0"); reporter != nil || err != nil {
		t.Fatalf("off: %v %v", reporter, err)
	}
	t.Setenv(communityReportURLEnv, "http://insecure.example.test/report")
	if _, err := newCommunityReporter(nil, "1.0.0"); err != nil {
		t.Fatalf("no pool must disable the reporter before URL validation: %v", err)
	}
}

func TestCommunityReportCadence(t *testing.T) {
	now := time.Date(2026, 10, 29, 12, 0, 0, 0, time.UTC)
	reporter := &communityReporter{state: filepath.Join(t.TempDir(), "community", "last-report"), now: func() time.Time { return now }}
	if got := reporter.nextDelay(); got != communityReportFirstDelay {
		t.Fatalf("first start delay %s", got)
	}
	reporter.recordReported()
	if got := reporter.nextDelay(); got != communityReportInterval {
		t.Fatalf("after a report the next is due in 7 days, got %s", got)
	}
	now = now.Add(6 * 24 * time.Hour)
	if got := reporter.nextDelay(); got != 24*time.Hour {
		t.Fatalf("restart on day 6 waits 1 day, got %s", got)
	}
	now = now.Add(30 * 24 * time.Hour)
	if got := reporter.nextDelay(); got != communityReportFirstDelay {
		t.Fatalf("overdue report goes soon, got %s", got)
	}
}
