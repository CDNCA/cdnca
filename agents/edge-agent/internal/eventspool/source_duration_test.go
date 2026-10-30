package eventspool

import (
	"bytes"
	"testing"
)

// The rendered access log's duration_us reaches the analytics event: bandwidth
// spreads a response over its transfer time on the control plane.
func TestSourceAccessKeepsTransferDuration(t *testing.T) {
	line := sourceLine(t, sourceAccess(tenantOne))
	line = append([]byte(`{"duration_us":100250000,`), line[1:]...)
	parsed, err := ParseSourceLineBound(line, CapturePolicy{}, TrustedIdentity{
		EnrollmentNodeID: nodeOne, TenantID: tenantOne, SiteID: siteOne, ConfigVersionID: "cfg-1",
	})
	if err != nil {
		t.Fatalf("access log with duration rejected: %v", err)
	}
	if parsed.DurationUS != 100250000 {
		t.Fatalf("duration_us = %d", parsed.DurationUS)
	}
	event := analyticsAccessFrom(parsed)
	if event.DurationUS != 100250000 {
		t.Fatalf("published duration_us = %d", event.DurationUS)
	}
	if bytes.Contains(line, []byte(`"duration_us":-`)) {
		t.Fatal("fixture")
	}
}
