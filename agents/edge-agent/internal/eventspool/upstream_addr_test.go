package eventspool

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

// fix-upstreamaddr：节点日志行的 upstream_addr（回源地址）经 spool 原样送到主控；
// 只允许在访问事件上，≤64 字节、无首尾空白；空值不出现在发布载荷里。
func TestUpstreamAddrSurvivesSpoolAndPublication(t *testing.T) {
	line := strings.Replace(string(sourceLine(t, sourceAccess(tenantOne))), `"status_code":200`,
		`"status_code":200,"upstream_addr":"10.0.0.1:80, 10.0.0.2:80"`, 1)
	parsed, err := ParseSourceLine([]byte(line), CapturePolicy{})
	if err != nil || parsed.UpstreamAddr != "10.0.0.1:80, 10.0.0.2:80" {
		t.Fatalf("parsed upstream_addr=%q err=%v", parsed.UpstreamAddr, err)
	}
	if legacy, err := ParseSourceLine(sourceLine(t, sourceAccess(tenantOne)), CapturePolicy{}); err != nil || legacy.UpstreamAddr != "" {
		t.Fatalf("line without upstream_addr=%q err=%v", legacy.UpstreamAddr, err)
	}
	for _, bad := range []string{strings.Repeat("a", 65), " 10.0.0.1:80", "10.0.0.1:80 "} {
		event := sourceAccess(tenantOne)
		event.UpstreamAddr = bad
		if validateEnvelope(event, identitySource) == nil {
			t.Fatalf("upstream_addr %q accepted", bad)
		}
	}
	security := sourceAccess(tenantOne)
	security.Type, security.SecurityType, security.Action, security.Severity = EventSecurity, "waf", "block", "high"
	security.UpstreamAddr = "10.0.0.1:80"
	if validateEnvelope(security, identitySource) == nil {
		t.Fatal("upstream_addr accepted on a security event")
	}

	spool := newTestSpool(t, testConfig(t.TempDir()))
	origin, local := pendingAccess("evt-origin", tenantOne), pendingAccess("evt-local", tenantOne)
	origin.UpstreamAddr = "127.0.0.1:8080"
	if _, err := spool.AppendBatch(context.Background(), []Envelope{origin, local}); err != nil {
		t.Fatal(err)
	}
	records, err := spool.nextBatch(context.Background(), 10)
	if err != nil {
		t.Fatal(err)
	}
	publications, err := buildPublications(records)
	if err != nil || len(publications) != 1 {
		t.Fatalf("publications=%d err=%v", len(publications), err)
	}
	if !ValidPublicationMessageID(publications[0]) {
		t.Fatal("publication with upstream_addr does not re-validate")
	}
	var payload struct {
		Events []map[string]json.RawMessage `json:"events"`
	}
	if err := json.Unmarshal(publications[0].Payload, &payload); err != nil || len(payload.Events) != 2 {
		t.Fatalf("payload=%s err=%v", publications[0].Payload, err)
	}
	for _, event := range payload.Events {
		value, present := event["upstream_addr"]
		if want := string(event["event_id"]) == `"evt-origin"`; present != want || present && string(value) != `"127.0.0.1:8080"` {
			t.Fatalf("event %s upstream_addr=%s", event["event_id"], value)
		}
	}
}
