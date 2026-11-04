package analyticslog

import (
	"context"
	"fmt"
	"net/http"
	"testing"
	"time"
)

// observe-only WAF / CC decisions per site (action log), in
// requests, inside the window; enforced decisions and the global firewall
// are not counted, and ListAttackSummaries still leaves log out.
func TestClickHouseLoggedSummariesPerSite(t *testing.T) {
	database := newIntegrationDatabase(t)
	database.create(t)
	now := time.Now().UTC()
	from := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC).AddDate(0, 1, 0)
	to := from.Add(5 * time.Minute)
	ingested := now.Add(-10 * time.Second).Truncate(time.Millisecond)
	tenantA, tenantB := "10000000-0000-4000-8000-0000000000a8", "10000000-0000-4000-8000-0000000000b8"
	siteLogOnly := "30000000-0000-4000-8000-0000000000c8"
	var rows []integrationSecurityRow
	add := func(prefix string, count int, tenant, site, eventType, action string, at time.Time) {
		for index := range count {
			row := integrationSecurity(fmt.Sprintf("%s-%d", prefix, index), at.Add(time.Duration(index)*time.Millisecond),
				ingested, tenant, action, "/attack")
			row.SiteID, row.EventType, row.ClientIP = site, eventType, "2001:db8::9"
			rows = append(rows, row)
		}
	}
	add("a-log", 4, tenantA, siteA, "waf", "log", from.Add(time.Minute))
	add("a-cclog", 1, tenantA, siteA, "cc", "log", from.Add(time.Minute))
	rows[len(rows)-1].EventCount = 20 // one aggregated CC line for 20 requests
	add("a-block", 3, tenantA, siteA, "waf", "block", from.Add(time.Minute))
	add("a-firewall", 9, tenantA, siteA, "global_firewall", "log", from.Add(time.Minute))
	add("a-outside", 9, tenantA, siteA, "waf", "log", to.Add(time.Second))
	add("c-log", 2, tenantA, siteLogOnly, "waf", "log", from.Add(2*time.Minute))
	add("b-block", 5, tenantB, siteA, "waf", "block", from.Add(time.Minute))
	insertIntegrationRows(t, database, "security_events", rows)

	client, err := NewClient(ClientConfig{Endpoint: database.endpoint, Database: database.name, Username: database.username,
		Password: database.password, CursorKeyring: testLogCursorKeyring()}, &http.Client{Timeout: 15 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	got, err := client.ListLoggedSummaries(context.Background(), from, to, 10)
	if err != nil {
		t.Fatalf("ListLoggedSummaries: %v", err)
	}
	want := []LoggedSiteSummary{{TenantID: tenantA, SiteID: siteA, Logged: 24}, {TenantID: tenantA, SiteID: siteLogOnly, Logged: 2}}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("logged summaries = %+v", got)
	}
	enforced, err := client.ListAttackSummaries(context.Background(), from, to, 1, 10)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range enforced {
		if s.SiteID == siteLogOnly || (s.TenantID == tenantA && s.Events != 3) {
			t.Fatalf("attack summaries changed by log rows: %+v", enforced)
		}
	}
	if _, err := client.ListLoggedSummaries(context.Background(), to, from, 10); err != ErrInvalidInput {
		t.Fatalf("reversed window = %v", err)
	}
}
