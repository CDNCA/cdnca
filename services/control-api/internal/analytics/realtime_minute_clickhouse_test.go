package analytics

import (
	"fmt"
	"math"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestClickHouseRealtimeMinuteFull31Days(t *testing.T) {
	database := newRankTestDatabase(t)
	database.reset(t)
	applyRealtimeFinalizerClickHouseMigrations(t, database)
	// Fixture retention is independent of the wall clock; only this task database is changed.
	if err := database.execute(t.Context(), "ALTER TABLE access_events REMOVE TTL", true, nil); err != nil {
		t.Fatal(err)
	}
	from := time.Date(2026, 8, 24, 10, 17, 0, 0, time.UTC)
	filter := RealtimeFilter{From: from, To: from.Add(31 * 24 * time.Hour)}
	rows := make([]rankAccessRow, maximumRealtimePoints)
	for index := range rows {
		at := from.Add(time.Duration(index)*time.Hour + time.Second)
		event := rankAccessEvent(fmt.Sprintf("full-range-%d", index), at, rankTenantA, rankSiteA1, rankNodeA1,
			fmt.Sprintf("host-%02d.example.test", index%13), "/", "192.0.2.1", "CN", "test", 200, 10, 20)
		event.ListenPort, event.UpstreamResult = 443, ""
		rows[index] = rankAccessRow{AccessEvent: event, IngestedAt: filter.To}
	}
	insertRankRows(t, database, insertRankAccessSQL, rows)
	capture := &realtimeClickHouseErrorCapture{}
	client, err := NewClient(Config{Endpoint: database.endpoint, Database: database.name, Username: database.username, Password: database.password}, &http.Client{Transport: capture, Timeout: 10 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	result, err := client.Realtime(t.Context(), AdminScope(), filter)
	if err != nil || len(result.Series) != maximumRealtimePoints || len(result.Top) != maximumRealtimeTopItems ||
		result.Summary.Requests != maximumRealtimePoints || result.SeriesBucketSeconds != 3600 ||
		result.Evidence.ObservedEvents != maximumRealtimePoints || result.Evidence.CoverageTo.Sub(result.Evidence.CoverageFrom) != 745*time.Hour {
		t.Fatalf("full 31-day projection: points=%d top=%d summary=%+v evidence=%+v err=%v diagnostic=%s",
			len(result.Series), len(result.Top), result.Summary, result.Evidence, err, capture.body)
	}
	for index, point := range result.Series {
		if !point.Bucket.Equal(from.Add(time.Duration(index)*time.Hour)) || point.Requests != 1 {
			t.Fatalf("bucket %d: %+v", index, point)
		}
	}
}

func TestClickHouseRealtimeMinuteProjection(t *testing.T) {
	database := newRankTestDatabase(t)
	database.reset(t)
	applyRealtimeFinalizerClickHouseMigrations(t, database)
	// The fixed fixture date ages past the 30-day access_events TTL (the rows
	// were dropped on insert after 2026-10-24); only this task database is changed.
	if err := database.execute(t.Context(), "ALTER TABLE access_events REMOVE TTL", true, nil); err != nil {
		t.Fatal(err)
	}
	capture := &realtimeClickHouseErrorCapture{}
	client, err := NewClient(Config{Endpoint: database.endpoint, Database: database.name, Username: database.username, Password: database.password}, &http.Client{Transport: capture, Timeout: 10 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	from := time.Date(2026, 9, 24, 10, 17, 0, 0, time.UTC)
	filter := RealtimeFilter{From: from, To: from.Add(745 * time.Minute), Host: "cdn.example.test", ListenPort: 443}
	coverage := realtimeCoverageFilter(filter)
	var rows []rankAccessRow
	for index, at := range []time.Time{coverage.From, from, from.Add(time.Minute), filter.To.Add(-time.Second), filter.To} {
		event := rankAccessEvent("minute-"+at.Format("150405"), at, rankTenantA, rankSiteA1, rankNodeA1, "cdn.example.test", "/", "192.0.2.1", "CN", "test", 200, 10, 20)
		event.ListenPort, event.UpstreamResult = 443, ""
		if index == 2 {
			event.StatusCode, event.CacheStatus = 404, "MISS"
			duration := uint64(2500)
			event.OriginTotalUS = &duration
		}
		rows = append(rows, rankAccessRow{AccessEvent: event, IngestedAt: coverage.To})
	}
	// Both exclusion dimensions and the ingestion cutoff are exercised with real facts.
	foreign := rows[1]
	foreign.EventID, foreign.TenantID = "foreign-tenant", rankTenantB
	rows = append(rows, foreign)
	future := rows[1]
	future.EventID, future.IngestedAt = "future-ingestion", time.Now().UTC().Add(24*time.Hour)
	rows = append(rows, future)
	insertRankRows(t, database, strings.Replace(insertRankAccessSQL, "duration_us)", "duration_us, origin_total_us)", 1), rows)
	scope, _ := TenantScope(rankTenantA)
	candidate, _, _, _ := realtimeCoverageFixture(t)
	candidate.WindowStart, candidate.WindowEnd = coverage.From, coverage.To
	candidate.TenantID, candidate.SiteID, candidate.Host, candidate.ListenPort = rankTenantA, rankSiteA1, filter.Host, 443
	var receipts []realtimeConnectionReceiptIntegrationRow
	for index, at := range []time.Time{from.Add(-time.Minute), from.Add(time.Minute), filter.To.Add(time.Minute)} {
		row := realtimeConnectionReceiptRow(candidate, rankNodeA1, "018f0000-0000-7000-8000-000000000007",
			fmt.Sprintf("minute-connection-%d", index), uint64(index+1), strings.Repeat("a", 64), uint64(index+1), "broker_ack_observed", 3)
		row.OccurredAt = at
		row.Connections = uint64(100 * (index + 1))
		if index == 1 {
			row.Connections = 2
		}
		receipts = append(receipts, row)
	}
	insertRankRows(t, database, "INSERT INTO connections_ingest_receipts_v1 FORMAT JSONEachRow", receipts)
	result, err := client.Realtime(t.Context(), scope, filter)
	if err != nil {
		t.Fatalf("minute projection: %v diagnostic=%s", err, capture.body)
	}
	if result.SeriesBucketSeconds != 120 || result.Summary.Requests != 3 || result.Summary.TrafficBytes != 90 ||
		result.Evidence.ObservedEvents != 5 || result.Evidence.AccessSourceCount != 3 || result.Evidence.ExpectedEvents != 0 || len(result.Series) != 2 ||
		result.Summary.Connections != 2 || result.Evidence.ConnectionSourceCount != 1 {
		t.Fatalf("exact projection/bounding count: %+v", result)
	}
	first, last := result.Series[0], result.Series[1]
	if !first.Bucket.Equal(from) || first.Requests != 2 || first.CacheHits != 1 || first.CacheMisses != 1 || first.CacheHitBytes != 30 ||
		first.Status4xx != 1 || first.Connections != 2 || first.OriginTotalUS == nil || *first.OriginTotalUS != 2500 ||
		first.OriginTrafficBytes != nil || first.OriginBandwidthBPS != nil {
		t.Fatalf("quality/origin samples: %+v", first)
	}
	if !last.Bucket.Equal(from.Add(744*time.Minute)) || last.OriginTotalUS != nil || math.Abs(last.BandwidthBPS-4) > 1e-9 {
		t.Fatalf("last one-minute bucket must not divide by full two minutes: %+v", last)
	}
	service, _ := NewServiceWithRealtimeExpectedCounts(client, &realtimeExpectedCountFixture{evidence: completeRealtimeExpectedEvidence(rankTenantA, coverage, 5)})
	_, err = service.Realtime(t.Context(), Actor{ScopeKind: "tenant", TenantID: rankTenantA, Permissions: []string{ReadPermission}},
		RealtimeRequest{Audience: AudienceTenant, From: filter.From, To: filter.To, Host: filter.Host, ListenPort: filter.ListenPort})
	if err != nil {
		t.Fatalf("service independent reconciliation: %v", err)
	}
	filter.Host = "missing.example.test"
	result, err = client.Realtime(t.Context(), scope, filter)
	if err != nil || result.Summary.Requests != 0 || result.Evidence.ObservedEvents != 0 || len(result.Series) != 0 {
		t.Fatalf("empty filtered scope: %+v %v diagnostic=%s", result, err, capture.body)
	}
}
