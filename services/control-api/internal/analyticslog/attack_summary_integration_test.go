package analyticslog

import (
	"context"
	"fmt"
	"net/http"
	"testing"
	"time"
)

// ge-waf S7: the attack alert aggregation counts enforced WAF / CC decisions
// per site (block, challenge, temporary ban; not log, not the global
// firewall), keeps tenants apart, applies the threshold and the window.
func TestClickHouseAttackSummariesAggregatePerSite(t *testing.T) {
	database := newIntegrationDatabase(t)
	database.create(t)
	now := time.Now().UTC()
	from := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC).AddDate(0, 1, 0)
	to := from.Add(5 * time.Minute)
	ingested := now.Add(-10 * time.Second).Truncate(time.Millisecond)
	tenantA, tenantB := "10000000-0000-4000-8000-0000000000a7", "10000000-0000-4000-8000-0000000000b7"
	var rows []integrationSecurityRow
	add := func(prefix string, count int, tenant, site, eventType, action, detector, ip string, at time.Time) {
		for index := range count {
			row := integrationSecurity(fmt.Sprintf("%s-%d", prefix, index), at.Add(time.Duration(index)*time.Millisecond),
				ingested, tenant, action, "/attack")
			row.SiteID, row.EventType, row.Detector, row.ClientIP = site, eventType, detector, ip
			rows = append(rows, row)
		}
	}
	siteA2 := "30000000-0000-4000-8000-0000000000a2"
	add("a-block", 6, tenantA, siteA, "waf", "block", "sqli", "2001:db8::1", from.Add(time.Minute))
	add("a-xss", 2, tenantA, siteA, "waf", "block", "xss", "2001:db8::2", from.Add(time.Minute))
	add("a-challenge", 3, tenantA, siteA, "cc", "challenge", "", "::ffff:203.0.113.9", from.Add(2*time.Minute))
	// sec-log-agg: one aggregated CC 429 line standing for 40 requests
	add("a-cc429", 1, tenantA, siteA, "cc", "block", "", "::ffff:203.0.113.9", from.Add(2*time.Minute))
	rows[len(rows)-1].EventCount = 40
	add("a-ban", 1, tenantA, siteA, "waf", "temporary_ban", "", "2001:db8::1", from.Add(3*time.Minute))
	add("a-log", 50, tenantA, siteA, "waf", "log", "sqli", "2001:db8::3", from.Add(time.Minute))
	add("a-firewall", 50, tenantA, siteA, "global_firewall", "block", "", "2001:db8::4", from.Add(time.Minute))
	add("a-outside", 50, tenantA, siteA, "waf", "block", "sqli", "2001:db8::5", to.Add(time.Second))
	add("a2-few", 2, tenantA, siteA2, "waf", "block", "", "2001:db8::6", from.Add(time.Minute))
	add("b-block", 5, tenantB, siteA, "waf", "block", "cmdi", "2001:db8::7", from.Add(time.Minute))
	insertIntegrationRows(t, database, "security_events", rows)

	client, err := NewClient(ClientConfig{Endpoint: database.endpoint, Database: database.name, Username: database.username,
		Password: database.password, CursorKeyring: testLogCursorKeyring()}, &http.Client{Timeout: 15 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	got, err := client.ListAttackSummaries(context.Background(), from, to, 5, 10)
	if err != nil {
		t.Fatalf("ListAttackSummaries: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("summaries = %+v", got)
	}
	a, b := got[0], got[1]
	if a.TenantID != tenantA || a.SiteID != siteA || a.Events != 52 || a.Blocked != 48 || a.Challenged != 3 || a.Banned != 1 ||
		a.Clients != 3 || a.TopDetector != "sqli" || a.TopClientIP != "2001:db8::1" ||
		!a.FirstEventAt.Equal(from.Add(time.Minute)) || !a.LastEventAt.Before(to) {
		t.Fatalf("tenant A site = %+v", a)
	}
	if b.TenantID != tenantB || b.Events != 5 || b.TopDetector != "cmdi" {
		t.Fatalf("tenant B site = %+v", b)
	}
	if few, err := client.ListAttackSummaries(context.Background(), from, to, 53, 10); err != nil || len(few) != 0 {
		t.Fatalf("over threshold = %+v, %v", few, err)
	}
	if _, err := client.ListAttackSummaries(context.Background(), to, from, 1, 10); err != ErrInvalidInput {
		t.Fatalf("reversed window = %v", err)
	}
}
