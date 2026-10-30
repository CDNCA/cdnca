package retentioncleanup

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"
)

func TestCurrentTTLDays(t *testing.T) {
	for _, test := range []struct {
		engine, column string
		days           int
		fails          bool
	}{
		{`ReplacingMergeTree(ingested_at) ORDER BY x TTL toDateTime(occurred_at, \'UTC\') + toIntervalDay(30) SETTINGS index_granularity = 8192`,
			"toDateTime(occurred_at, 'UTC')", 30, false},
		{`ReplacingMergeTree(ingested_at) ORDER BY x TTL hour + toIntervalDay(400) SETTINGS index_granularity = 8192`, "hour", 400, false},
		{`ReplacingMergeTree(ingested_at) ORDER BY x TTL hour + toIntervalDay(7)`, "hour", 7, false},
		{`ReplacingMergeTree(ingested_at) ORDER BY x SETTINGS index_granularity = 8192`, "hour", -1, false},
		// Another column, or a TTL with extra clauses, is not ours to rewrite.
		{`MergeTree ORDER BY x TTL ingested_at + toIntervalDay(30) SETTINGS index_granularity = 8192`, "hour", 0, true},
		{`MergeTree ORDER BY x TTL hour + toIntervalDay(30) TO VOLUME 'cold' SETTINGS index_granularity = 8192`, "hour", 0, true},
	} {
		days, err := currentTTLDays(test.engine, test.column)
		if (err != nil) != test.fails || (!test.fails && days != test.days) {
			t.Errorf("currentTTLDays(%q) = %d, %v", test.engine, days, err)
		}
	}
}

func TestTTLStatement(t *testing.T) {
	item := ttlTarget{"access_events", "access_logs_days", "toDateTime(occurred_at, 'UTC')"}
	if got := ttlStatement(item, 7); got != "ALTER TABLE access_events MODIFY TTL toDateTime(occurred_at, 'UTC') + INTERVAL 7 DAY DELETE" {
		t.Fatalf("statement = %q", got)
	}
	if got := ttlStatement(item, 0); got != "ALTER TABLE access_events REMOVE TTL" {
		t.Fatalf("keep-forever statement = %q", got)
	}
}

// The ingest identity is granted ALTER MODIFY TTL on exactly the tables the
// sync manages; the two lists must not drift.
func TestTTLTargetsMatchClickHouseGrants(t *testing.T) {
	_, file, _, _ := runtime.Caller(0)
	script, err := os.ReadFile(filepath.Join(filepath.Dir(file), "../../../../scripts/native-runtime/configure-clickhouse.py"))
	if err != nil {
		t.Fatal(err)
	}
	block := regexp.MustCompile(`(?s)RETENTION_TTL_TABLES = \[(.*?)\]`).FindSubmatch(script)
	if block == nil {
		t.Fatal("RETENTION_TTL_TABLES not found")
	}
	var granted []string
	for _, match := range regexp.MustCompile(`"([a-z0-9_]+)"`).FindAllSubmatch(block[1], -1) {
		granted = append(granted, string(match[1]))
	}
	var managed []string
	for _, item := range ttlTargets {
		managed = append(managed, item.table)
		if !strings.Contains(item.setting, "_days") {
			t.Fatalf("%s setting %q", item.table, item.setting)
		}
	}
	sort.Strings(granted)
	sort.Strings(managed)
	if strings.Join(granted, ",") != strings.Join(managed, ",") {
		t.Fatalf("granted %v, managed %v", granted, managed)
	}
}

func TestClickHouseHTTPExec(t *testing.T) {
	var gotQuery, gotBody, gotUser string
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		body, _ := io.ReadAll(request.Body)
		gotQuery, gotBody = request.URL.RawQuery, string(body)
		gotUser, _, _ = request.BasicAuth()
		if strings.Contains(gotBody, "fail") {
			http.Error(writer, "Code: 497. DB::Exception: Not enough privileges\nstack", http.StatusForbidden)
			return
		}
		_, _ = writer.Write([]byte("ok\n"))
	}))
	defer server.Close()
	clickHouse, err := NewClickHouseHTTP(server.URL, "cdnca_analytics", "ingest", "secret", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	body, err := clickHouse.Exec(context.Background(), "SELECT 1")
	if err != nil || string(body) != "ok\n" || gotQuery != "database=cdnca_analytics" || gotBody != "SELECT 1" || gotUser != "ingest" {
		t.Fatalf("body=%q err=%v query=%q sql=%q user=%q", body, err, gotQuery, gotBody, gotUser)
	}
	if _, err := clickHouse.Exec(context.Background(), "fail"); err == nil || !strings.Contains(err.Error(), "Not enough privileges") ||
		strings.Contains(err.Error(), "stack") {
		t.Fatalf("error = %v", err)
	}
	for _, endpoint := range []string{"ftp://x", "http://user:pw@127.0.0.1", "http://127.0.0.1/?a=1", ""} {
		if _, err := NewClickHouseHTTP(endpoint, "db", "", "", time.Second); err == nil {
			t.Errorf("accepted %q", endpoint)
		}
	}
}
