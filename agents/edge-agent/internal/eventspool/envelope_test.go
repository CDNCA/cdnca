package eventspool

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

const (
	tenantOne = "11111111-1111-4111-8111-111111111111"
	tenantTwo = "22222222-2222-4222-8222-222222222222"
	siteOne   = "33333333-3333-4333-8333-333333333333"
	nodeOne   = "44444444-4444-4444-8444-444444444444"
)

func sourceAccess(tenant string) Envelope {
	return Envelope{
		SchemaVersion: SchemaVersion, Type: EventAccess, OccurredAt: time.Unix(1_700_000_000, 0).UTC(),
		TenantID: tenant, SiteID: siteOne, NodeID: nodeOne, ConfigVersionID: "cfg-1",
		RequestID: "request-1", TraceID: "trace-1", Host: "example.test",
		Path: "/login?token=secret&safe=yes", ClientIP: "2001:db8::1", Method: "GET",
		Protocol: "HTTP/2", CacheStatus: "MISS", StatusCode: 200, ResponseBytes: 12,
	}
}

func pendingAccess(id, tenant string) Envelope {
	event := sourceAccess(tenant)
	event.EventID = id
	return event
}

func sourceLine(t *testing.T, event Envelope) []byte {
	t.Helper()
	payload, err := json.Marshal(event)
	if err != nil {
		t.Fatal(err)
	}
	return payload
}

func TestParseSourceLineDefaultsAndRedaction(t *testing.T) {
	event := sourceAccess(tenantOne)
	event.RequestHeaders = map[string]string{
		"Authorization": "Bearer secret", "X-Allowed": "line\nvalue", "X-Dropped": "secret",
	}
	event.ResponseHeaders = map[string]string{"Set-Cookie": "session=secret"}
	event.RequestBody = map[string]any{
		"profile": map[string]any{"name": "alice", "password": "secret"},
		"token":   "secret", "ignored": "secret",
	}

	withoutCapture, err := ParseSourceLine(sourceLine(t, event), CapturePolicy{})
	if err != nil {
		t.Fatal(err)
	}
	if withoutCapture.RequestHeaders != nil || withoutCapture.ResponseHeaders != nil || withoutCapture.RequestBody != nil {
		t.Fatal("headers and bodies must be omitted by default")
	}
	if !strings.Contains(withoutCapture.Path, "%5BREDACTED%5D") || strings.Contains(withoutCapture.Path, "secret") {
		t.Fatalf("sensitive query was not redacted: %q", withoutCapture.Path)
	}

	captured, err := ParseSourceLine(sourceLine(t, event), CapturePolicy{
		RequestHeaders: []string{"authorization", "x-allowed"}, ResponseHeaders: []string{"set-cookie"},
		RequestBodyFields: []string{"profile", "token"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if captured.RequestHeaders["Authorization"] != redactedValue || captured.ResponseHeaders["Set-Cookie"] != redactedValue ||
		captured.RequestHeaders["X-Allowed"] != "line\nvalue" {
		t.Fatalf("unexpected captured headers: %#v %#v", captured.RequestHeaders, captured.ResponseHeaders)
	}
	profile := captured.RequestBody["profile"].(map[string]any)
	if captured.RequestBody["token"] != redactedValue || profile["password"] != redactedValue || profile["name"] != "alice" {
		t.Fatalf("unexpected captured body: %#v", captured.RequestBody)
	}
	captured.EventID = "evt_test"
	captured.Sequence = 1
	encoded, err := encodeEnvelope(captured)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encoded[:len(encoded)-1], []byte("\n")) || bytes.Contains(encoded, []byte("Bearer secret")) || bytes.Contains(encoded, []byte("session=secret")) {
		t.Fatalf("encoded event contains raw newline or secret: %q", encoded)
	}
}

func TestParseSourceLineAcceptsAccessListenPort(t *testing.T) {
	event := sourceAccess(tenantOne)
	event.ListenPort = 443
	parsed, err := ParseSourceLine(sourceLine(t, event), CapturePolicy{})
	if err != nil {
		t.Fatal(err)
	}
	if parsed.ListenPort != 443 {
		t.Fatalf("listen port = %d, want 443", parsed.ListenPort)
	}

	legacy := sourceAccess(tenantOne)
	if _, err := ParseSourceLine(sourceLine(t, legacy), CapturePolicy{}); err != nil {
		t.Fatalf("legacy zero listen port: %v", err)
	}
}

func TestParseSourceLineRejectsDuplicateKeysAndInvalidShape(t *testing.T) {
	valid := sourceLine(t, sourceAccess(tenantOne))
	duplicate := append([]byte(`{"schema_version":1,`), valid[1:]...)
	if _, err := ParseSourceLine(duplicate, CapturePolicy{}); err != ErrInvalidEvent {
		t.Fatalf("duplicate key error = %v", err)
	}
	event := sourceAccess(tenantOne)
	event.StatusCode = 99
	if _, err := ParseSourceLine(sourceLine(t, event), CapturePolicy{}); err != ErrInvalidEvent {
		t.Fatalf("invalid access event error = %v", err)
	}
	security := sourceAccess(tenantOne)
	security.Type = EventSecurity
	security.ListenPort, security.Protocol, security.RequestClass = 443, "https", "standard"
	security.CacheStatus = ""
	security.StatusCode = 0
	security.SecurityType, security.Action, security.Severity = "waf", "block", "high"
	if _, err := ParseSourceLine(sourceLine(t, security), CapturePolicy{}); err != nil {
		t.Fatalf("valid security event: %v", err)
	}
	for _, class := range []string{"websocket", "sse", "task_stream", "import", "acme", "health"} {
		candidate := security
		candidate.RequestClass = class
		if _, err := ParseSourceLine(sourceLine(t, candidate), CapturePolicy{}); err != nil {
			t.Fatalf("valid security request class %q: %v", class, err)
		}
	}
	security.RequestClass = "unknown"
	if _, err := ParseSourceLine(sourceLine(t, security), CapturePolicy{}); err != ErrInvalidEvent {
		t.Fatalf("unknown security request class error = %v", err)
	}
}
