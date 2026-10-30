package analytics

import (
	"net/http"
	"testing"
	"time"
)

// sec-log-agg: the ingest writer stores an aggregated line's count in
// event_count (migration 025) and an ordinary event as 1; the security log's
// count state (security_event_count_state_v1) follows.
func TestWriteSecurityEventsStoresEventCount(t *testing.T) {
	database := newRankTestDatabase(t)
	database.reset(t)
	applyAllClickHouseMigrations(t, database)
	client, err := NewClient(Config{Endpoint: database.endpoint, Database: database.name, Username: database.username,
		Password: database.password, QueryTimeout: 5 * time.Second}, &http.Client{Timeout: 10 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	aggregated := validSecurityEvent("security-aggregated")
	aggregated.EventType, aggregated.Action, aggregated.Severity, aggregated.StatusCode, aggregated.Count = "cc", "challenge", "medium", 503, 10
	if err := client.WriteSecurityEvents(t.Context(), "count-batch", []SecurityEvent{aggregated, validSecurityEvent("security-single")}); err != nil {
		t.Fatal(err)
	}
	for _, query := range []string{
		"SELECT throwIf(groupArray((event_id, event_count)) != [('security-aggregated', 10), ('security-single', 1)]) " +
			"FROM (SELECT event_id, event_count FROM security_events ORDER BY event_id)",
		"SELECT throwIf(groupArray((event_id, count)) != [('security-aggregated', 10), ('security-single', 1)]) FROM " +
			"(SELECT event_id, argMaxMerge(latest_count_state) AS count FROM security_event_count_state_v1 GROUP BY event_id ORDER BY event_id)",
	} {
		if err := database.execute(t.Context(), query, true, nil); err != nil {
			t.Fatalf("%v\n%s", err, query)
		}
	}
	// The dashboard counts requests (10 + 1) and keeps the line count (2).
	window := Filter{From: aggregated.OccurredAt.Truncate(time.Hour), To: aggregated.OccurredAt.Truncate(time.Hour).Add(time.Hour)}
	summary, err := client.Summary(t.Context(), AdminScope(), window)
	if err != nil || summary.SecurityEvents != 11 || summary.SecurityEventRows != 2 {
		t.Fatalf("summary security events %d rows %d: %v", summary.SecurityEvents, summary.SecurityEventRows, err)
	}
	trend, err := client.Trend(t.Context(), AdminScope(), window)
	if err != nil || len(trend) != 1 || trend[0].SecurityEvents != 11 || trend[0].SecurityEventRows != 2 {
		t.Fatalf("trend %+v: %v", trend, err)
	}
}
