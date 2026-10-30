package eventspool

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

// FX60：节点日志的 blocked 标记经 spool 原样送到主控；只允许出现在访问事件上。
func TestBlockedAccessFlagSurvivesSpoolAndPublication(t *testing.T) {
	line := strings.Replace(string(sourceLine(t, sourceAccess(tenantOne))), `"status_code":200`, `"status_code":403,"blocked":true`, 1)
	parsed, err := ParseSourceLine([]byte(line), CapturePolicy{})
	if err != nil || !parsed.Blocked {
		t.Fatalf("parsed blocked=%v err=%v", parsed.Blocked, err)
	}
	legacy, err := ParseSourceLine(sourceLine(t, sourceAccess(tenantOne)), CapturePolicy{})
	if err != nil || legacy.Blocked {
		t.Fatalf("untagged line blocked=%v err=%v", legacy.Blocked, err)
	}
	security := sourceAccess(tenantOne)
	security.Type, security.SecurityType, security.Action, security.Severity = EventSecurity, "waf", "block", "high"
	security.Blocked = true
	if validateEnvelope(security, identitySource) == nil {
		t.Fatal("blocked accepted on a security event")
	}

	spool := newTestSpool(t, testConfig(t.TempDir()))
	blocked, plain := pendingAccess("evt-blocked", tenantOne), pendingAccess("evt-plain", tenantOne)
	blocked.Blocked = true
	if _, err := spool.AppendBatch(context.Background(), []Envelope{blocked, plain}); err != nil {
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
	var payload struct {
		Events []map[string]json.RawMessage `json:"events"`
	}
	if err := json.Unmarshal(publications[0].Payload, &payload); err != nil || len(payload.Events) != 2 {
		t.Fatalf("payload=%s err=%v", publications[0].Payload, err)
	}
	for _, event := range payload.Events {
		_, tagged := event["blocked"]
		if want := string(event["event_id"]) == `"evt-blocked"`; tagged != want || tagged && string(event["blocked"]) != "true" {
			t.Fatalf("event %s blocked field=%s", event["event_id"], event["blocked"])
		}
	}
}
