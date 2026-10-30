package analyticslog

import (
	"context"
	"net/http"
	"testing"
	"time"
)

// ge-waf S4: the block log carries the attack evidence (policy, detector,
// matched fragment, User-Agent, body excerpt) from security_event_evidence_
// state_v1; events without evidence read empty strings, and the latest
// ingested version wins.
func TestClickHouseBlockEventsCarryAttackEvidence(t *testing.T) {
	database := newIntegrationDatabase(t)
	database.create(t)
	now := time.Now().UTC()
	from := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC).AddDate(0, 1, 0)
	to := from.Add(24 * time.Hour)
	ingested := now.Add(-10 * time.Second).Truncate(time.Millisecond)
	tenant := "10000000-0000-4000-8000-0000000000e5"
	withEvidence := integrationSecurity("evidence-a", from.Add(time.Hour), ingested, tenant, "block", "/login")
	withEvidence.PolicyID = "22222222-2222-4222-8222-2222222222e5"
	withEvidence.Detector, withEvidence.Matched = "sqli", "id=1' or '1'='1"
	withEvidence.UserAgent, withEvidence.RequestBodyExcerpt = "sqlmap/1.7", "user=admin&pw=x"
	replaced := withEvidence
	replaced.IngestedAt = ingested.Add(time.Second)
	replaced.Matched = "id=2 union select"
	plain := integrationSecurity("evidence-b", from.Add(2*time.Hour), ingested, tenant, "block", "/plain")
	insertIntegrationRows(t, database, "security_events", []integrationSecurityRow{withEvidence, plain})
	insertIntegrationRows(t, database, "security_events", []integrationSecurityRow{replaced})

	client, err := NewClient(ClientConfig{Endpoint: database.endpoint, Database: database.name, Username: database.username,
		Password: database.password, CursorKeyring: testLogCursorKeyring()}, &http.Client{Timeout: 15 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	page, err := client.ListBlockEvents(context.Background(), scope{tenantID: tenant}, Filter{From: from, To: to}, 10, "")
	if err != nil {
		t.Fatalf("ListBlockEvents: %v", err)
	}
	if len(page.Items) != 2 {
		t.Fatalf("items = %+v", page.Items)
	}
	byID := map[string]BlockEvent{}
	for _, item := range page.Items {
		byID[item.EventID] = item
	}
	got := byID["evidence-a"]
	if got.PolicyID != withEvidence.PolicyID || got.Detector != "sqli" || got.Matched != "id=2 union select" ||
		got.UserAgent != "sqlmap/1.7" || got.RequestBodyExcerpt != "user=admin&pw=x" {
		t.Fatalf("evidence = %+v", got)
	}
	if empty := byID["evidence-b"]; empty.PolicyID != "" || empty.Detector != "" || empty.Matched != "" || empty.UserAgent != "" {
		t.Fatalf("plain event evidence = %+v", empty)
	}
}
