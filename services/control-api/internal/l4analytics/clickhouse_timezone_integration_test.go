//go:build integration

package l4analytics

import (
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

// Range and cursor parameters are UTC strings. A bare {from:DateTime64(3)} is
// read in the server's time zone, so an Asia/Shanghai server looks 8 hours
// earlier and misses the rows. The session time zone is pinned to
// Asia/Shanghai so a UTC test machine catches the regression too
// (CDNCA_TEST_CLICKHOUSE_URL with the ClickHouse migrations applied).
func TestClickHouseReadsUTCWindowOnShanghaiServer(t *testing.T) {
	endpoint := strings.TrimSpace(os.Getenv("CDNCA_TEST_CLICKHOUSE_URL"))
	if endpoint == "" {
		t.Skip("CDNCA_TEST_CLICKHOUSE_URL is not set")
	}
	parsed, err := url.Parse(endpoint)
	if err != nil {
		t.Fatal(err)
	}
	query := parsed.Query()
	query.Set("session_timezone", "Asia/Shanghai")
	parsed.RawQuery = query.Encode()
	source, err := NewClickHouseSource(ClickHouseConfig{Endpoint: parsed.String(), Database: "default", QueryTimeout: 10 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	tenant, eventID := uuid.NewString(), "tz-"+uuid.NewString()
	finalized := time.Date(2026, 11, 6, 2, 30, 0, 0, time.UTC)
	stamp := finalized.Format("2006-01-02 15:04:05.000")
	ids := `"tenant_id":"` + tenant + `","node_id":"` + testNode + `","site_id":"` + testSite + `","stream_id":"` + testStream +
		`","listener_id":"` + testStream + `","session_id":"s1","started_at":"` + stamp + `","finalized_at":"` + stamp + `"`
	if err := source.insertRows(t.Context(), "l4_session_facts_v1", []byte(`{`+ids+`,"bytes_up":10,"bytes_down":20,"status_code":200,`+
		`"error_code":"","config_version_id":"`+testStream+`","config_revision":1,"protocol":"tcp","listen_port":18080,"event_id":"`+eventID+
		`","traceparent":"","task_id":"","source_watermark":5,"evidence_sha256":"`+strings.Repeat("a", 64)+
		`","canonical_event_sha256":"`+strings.Repeat("b", 64)+`"}`+"\n")); err != nil {
		t.Fatal(err)
	}
	if err := source.insertRows(t.Context(), sessionLogTable, []byte(`{`+ids+`,"protocol":"tcp","listen_port":18080,"client_ip":"203.0.113.10",`+
		`"client_port":40000,"peer_ip":"","upstream_addr":"","upstream_connect_ms":null,"bytes_up":10,"bytes_down":20,"status_code":200,`+
		`"end_reason":"closed","event_id":"`+eventID+`","source_watermark":5}`+"\n")); err != nil {
		t.Fatal(err)
	}
	scope := Scope{TenantID: tenant}
	filter := Filter{From: finalized.Add(-time.Hour), To: finalized.Add(time.Hour), Limit: 10}

	page, err := source.Read(t.Context(), scope, filter)
	if err != nil {
		t.Fatal(err)
	}
	if page.Snapshot.SourceWatermark != 5 || len(page.Rows) != 1 || page.Rows[0].Sessions != 1 ||
		!page.Rows[0].Bucket.Equal(finalized) {
		t.Fatalf("aggregates in [%s, %s) = %+v; want the 02:30 UTC session", filter.From, filter.To, page)
	}
	// The cursor at the row's own bucket excludes it.
	filter.Snapshot = page.Snapshot
	filter.After = &After{Bucket: finalized, NodeID: testNode, SiteID: testSite, StreamID: testStream, ListenerID: testStream}
	if rows, err := source.readAggregates(t.Context(), scope, filter); err != nil || len(rows) != 0 {
		t.Fatalf("aggregates after the row's bucket = %+v, %v; want none", rows, err)
	}

	logs, err := source.readSessionLogs(t.Context(), scope, sessionLogFilter{Filter: Filter{From: filter.From, To: filter.To, Limit: 10}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(logs) != 1 || logs[0].EventID != eventID || !logs[0].FinalizedAt.Equal(finalized) {
		t.Fatalf("session logs = %+v; want the 02:30 UTC session", logs)
	}
	// The cursor just after the row (the next page of a DESC listing) still includes it.
	after := &sessionLogAfter{FinalizedAt: finalized.Add(time.Millisecond), EventID: ""}
	if logs, err := source.readSessionLogs(t.Context(), scope, sessionLogFilter{Filter: Filter{From: filter.From, To: filter.To, Limit: 10}}, after); err != nil ||
		len(logs) != 1 {
		t.Fatalf("session logs before %s = %+v, %v; want the row", after.FinalizedAt, logs, err)
	}
}
