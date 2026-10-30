package eventspool

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestSourceAcceptsRenderedConnectionFieldsWithoutPublishingGauge(t *testing.T) {
	line := sourceLine(t, sourceAccess(tenantOne))
	line = append([]byte(`{"connection":"123","connection_requests":2,`), line[1:]...)
	parsed, err := ParseSourceLineBound(line, CapturePolicy{}, TrustedIdentity{
		EnrollmentNodeID: nodeOne, TenantID: tenantOne, SiteID: siteOne, ConfigVersionID: "cfg-1",
	})
	if err != nil {
		t.Fatalf("rendered access log rejected: %v", err)
	}
	encoded, err := json.Marshal(parsed)
	if err != nil || bytes.Contains(encoded, []byte(`"connection"`)) || bytes.Contains(encoded, []byte(`"connection_requests"`)) {
		t.Fatal("request-local connection identifiers must not become a connection gauge or wire fields")
	}
	if parsed.TenantID != tenantOne || parsed.NodeID != nodeOne || parsed.RequestHeaders != nil || parsed.RequestBody != nil {
		t.Fatal("source authority or capture policy changed")
	}
}

func TestSourceConnectionMetadataKeepsStrictValidation(t *testing.T) {
	base := sourceLine(t, sourceAccess(tenantOne))
	for _, fields := range []string{
		`"connection":"123",`,
		`"connection_requests":2,`,
		`"connection":"0","connection_requests":1,`,
		`"connection":"bad","connection_requests":1,`,
		`"connection":"123","connection_requests":0,`,
		`"connection":"123","connection_requests":-1,`,
		`"connection":"123","connection_requests":1.5,`,
		`"connection":"123","connection_requests":"2",`,
		`"connection":"123","connection_requests":2,"unknown_source_field":1,`,
	} {
		line := append([]byte("{"+fields), base[1:]...)
		if _, err := ParseSourceLine(line, CapturePolicy{}); err != ErrInvalidEvent {
			t.Fatalf("invalid connection metadata accepted: %s", fields)
		}
	}
}
