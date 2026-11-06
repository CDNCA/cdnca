package l4analytics

import (
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"
)

// Every DateTime64 query parameter is typed with the UTC zone and sent as a
// UTC "YYYY-MM-DD hh:mm:ss.sss" string; a bare DateTime64(3) parameter is read
// in the ClickHouse server's time zone (8 hours off on an Asia/Shanghai
// server). TestClickHouseReadsUTCWindowOnShanghaiServer checks it on a real
// ClickHouse.
func TestClickHouseDateTimeParametersAreUTC(t *testing.T) {
	var mu sync.Mutex
	var queries []string
	var params []map[string]string
	now := time.Date(2026, 11, 6, 2, 30, 0, 0, time.FixedZone("CST", 8*3600))
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		body, _ := io.ReadAll(request.Body)
		mu.Lock()
		queries = append(queries, string(body))
		values := map[string]string{}
		for key, list := range request.URL.Query() {
			if strings.HasPrefix(key, "param_") {
				values[strings.TrimPrefix(key, "param_")] = list[0]
			}
		}
		params = append(params, values)
		mu.Unlock()
		if strings.Contains(string(body), "max(source_watermark)") {
			writeClickHouseJSONLine(t, writer, snapshotRow{AtMilliseconds: now.UnixMilli(), SourceWatermark: 7,
				FinalizedThroughMilliseconds: now.UnixMilli()})
		}
	}))
	defer server.Close()
	source, err := NewClickHouseSource(ClickHouseConfig{Endpoint: server.URL, Database: "default", QueryTimeout: time.Second,
		HTTPClient: server.Client()})
	if err != nil {
		t.Fatal(err)
	}
	filter := Filter{From: now.Add(-time.Hour), To: now, Limit: 10,
		After: &After{Bucket: now.Add(-time.Minute), NodeID: testNode, SiteID: testSite, StreamID: testStream, ListenerID: testStream}}
	if _, err := source.Read(t.Context(), Scope{TenantID: testTenant}, filter); err != nil {
		t.Fatal(err)
	}
	if _, err := source.readSessionLogs(t.Context(), Scope{TenantID: testTenant}, sessionLogFilter{Filter: filter},
		&sessionLogAfter{FinalizedAt: now, EventID: "e"}); err != nil {
		t.Fatal(err)
	}
	typed := regexp.MustCompile(`\{([a-z_]+):DateTime64\(3, 'UTC'\)\}`)
	bare := regexp.MustCompile(`\{[a-z_]+:DateTime(64)?(\(3\))?\}`)
	utc := map[string]string{"from": "2026-11-05 17:30:00.000", "to": "2026-11-05 18:30:00.000",
		"after_bucket": "2026-11-05 18:29:00.000", "after_finalized": "2026-11-05 18:30:00.000"}
	seen := map[string]bool{}
	for index, query := range queries {
		if bare.MatchString(query) {
			t.Errorf("query %d has a time parameter without a time zone:\n%s", index, query)
		}
		for _, match := range typed.FindAllStringSubmatch(query, -1) {
			name := match[1]
			seen[name] = true
			if params[index][name] != utc[name] {
				t.Errorf("query %d param %s = %q, want UTC %q", index, name, params[index][name], utc[name])
			}
		}
	}
	for name := range utc {
		if !seen[name] {
			t.Errorf("no query used the %s parameter", name)
		}
	}
}
