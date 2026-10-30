package analytics

import (
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestClickHouseRealtimeQueriesIdleAndActiveSources(t *testing.T) {
	database := newRankTestDatabase(t)
	database.reset(t)
	applyRealtimeFinalizerClickHouseMigrations(t, database)
	capture := &realtimeClickHouseErrorCapture{}
	client, err := NewClient(Config{Endpoint: database.endpoint, Database: database.name, Username: database.username, Password: database.password}, &http.Client{Transport: capture, Timeout: 10 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	from := time.Now().UTC().Truncate(time.Hour).Add(-time.Hour)
	filter := RealtimeFilter{From: from, To: from.Add(time.Hour)}
	result, err := client.Realtime(t.Context(), AdminScope(), filter)
	if err != nil || result.Summary != (RealtimeMetrics{}) || len(result.Series) != 0 {
		t.Fatalf("empty: %+v %v diagnostic=%s", result.Summary, err, capture.body)
	}
	candidate, _, _, _ := realtimeCoverageFixture(t)
	candidate.WindowStart, candidate.WindowEnd = filter.From, filter.To
	candidate.TenantID, candidate.SiteID, candidate.Host, candidate.ListenPort = rankTenantA, rankSiteA1, "cdn.example.test", 443
	rows := []realtimeConnectionReceiptIntegrationRow{
		realtimeConnectionReceiptRow(candidate, rankNodeA1, "018f0000-0000-7000-8000-000000000007", "query-node-a", 1, strings.Repeat("a", 64), 1, "broker_ack_observed", 3),
		realtimeConnectionReceiptRow(candidate, rankNodeA2, "018f0000-0000-7000-8000-000000000007", "query-node-b", 1, strings.Repeat("b", 64), 2, "broker_ack_observed", 3),
	}
	for i := range rows {
		rows[i].OccurredAt = from.Add(time.Minute)
	}
	insertRankRows(t, database, "INSERT INTO connections_ingest_receipts_v1 FORMAT JSONEachRow", rows)
	result, err = client.Realtime(t.Context(), AdminScope(), filter)
	if err != nil || result.Summary.Requests != 0 || result.Summary.Connections != 3 || result.Summary.AverageDurationUS != 0 {
		t.Fatalf("idle observed listeners: %+v %v diagnostic=%s", result.Summary, err, capture.body)
	}
	event := rankAccessEvent("query-request", from.Add(time.Minute+time.Second), rankTenantA, rankSiteA1, rankNodeA1, candidate.Host, "/", "192.0.2.1", "CN", "test", 200, 10, 20)
	event.ListenPort = 443
	event.UpstreamResult = ""
	insertRankRows(t, database, insertRankAccessSQL, []rankAccessRow{{AccessEvent: event, IngestedAt: filter.To}})
	result, err = client.Realtime(t.Context(), AdminScope(), filter)
	if err != nil || result.Summary.Requests != 1 || result.Summary.TrafficBytes != 30 || result.Summary.Connections != 3 || len(result.Series) != 1 || result.Series[0].Connections != 3 || !result.Series[0].Bucket.Equal(from.Add(time.Minute)) {
		t.Fatalf("active: %+v series=%+v %v diagnostic=%s", result.Summary, result.Series, err, capture.body)
	}
	service, _ := NewServiceWithRealtimeExpectedCounts(client, &realtimeExpectedCountFixture{evidence: completeRealtimeExpectedEvidence("", filter, 1)})
	if _, err := service.Realtime(t.Context(), Actor{ScopeKind: "platform", Permissions: []string{"platform.admin"}}, RealtimeRequest{Audience: AudiencePlatform, From: filter.From, To: filter.To}); err != nil {
		t.Fatalf("active service validation: %v result=%+v", err, result)
	}
	filter.Host = "unrelated.example.test"
	result, err = client.Realtime(t.Context(), AdminScope(), filter)
	if err != nil || result.Summary != (RealtimeMetrics{}) || len(result.Series) != 0 {
		t.Fatalf("host isolation: %+v %v", result.Summary, err)
	}
	scope, _ := TenantScope(rankTenantB)
	filter.Host = ""
	result, err = client.Realtime(t.Context(), scope, filter)
	if err != nil || result.Summary != (RealtimeMetrics{}) || len(result.Series) != 0 {
		t.Fatalf("tenant isolation: %+v %v", result.Summary, err)
	}
}
