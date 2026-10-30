package analyticslog

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// fix-upstreamaddr：访问日志读回源地址 upstream_addr（payload 状态 upstream_addr_state，CH 028），
// 与诊断码 upstream_result 并存；>64 字节的存储行按无效响应拒绝。
func TestAccessLogReturnsUpstreamAddr(t *testing.T) {
	if !strings.Contains(accessPageSQL, "argMaxMerge(upstream_addr_state) AS upstream_addr") ||
		!strings.Contains(accessPageSQL, "ifNull(upstream_addr, '') AS upstream_addr") {
		t.Fatal("access page query does not read upstream_addr_state")
	}
	now := time.Date(2026, 7, 23, 12, 0, 0, 0, time.UTC)
	filter := Filter{From: now.Add(-time.Hour), To: now}
	for value, ok := range map[string]bool{"10.0.0.1:80, 10.0.0.2:80": true, strings.Repeat("a", 65): false} {
		server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
			row := accessTestRow("event-a", now.Add(-time.Minute), "/a")
			row.UpstreamAddr = value
			_ = json.NewEncoder(writer).Encode(row)
		}))
		client := newUnitClient(t, server, time.Second)
		page, err := client.ListAccess(context.Background(), scope{tenantID: tenantA}, filter, 2, "")
		server.Close()
		if !ok {
			if err == nil {
				t.Fatalf("upstream_addr of %d bytes accepted", len(value))
			}
			continue
		}
		if err != nil || len(page.Items) != 1 || page.Items[0].UpstreamAddr != value || page.Items[0].UpstreamResult != "ok" {
			t.Fatalf("page=%#v err=%v", page, err)
		}
		encoded, _ := json.Marshal(page.Items[0])
		if !strings.Contains(string(encoded), `"upstream_addr":"10.0.0.1:80, 10.0.0.2:80"`) {
			t.Fatalf("response %s", encoded)
		}
	}
}

// CH 028：access_events 加 upstream_addr 列、payload 状态加 upstream_addr_state 并重建 MV；
// 摘要元组不变（已入库事件不会被判为新版本）；down 恢复 014 的 MV。
func TestUpstreamAddrMigrationContract(t *testing.T) {
	repoRoot := filepath.Clean(filepath.Join("..", "..", "..", ".."))
	read := func(name string) string {
		contents, err := os.ReadFile(filepath.Join(repoRoot, "infra", "clickhouse", "migrations", name))
		if err != nil {
			t.Fatal(err)
		}
		return string(contents)
	}
	up, down := read("028_access_upstream_addr.up.sql"), read("028_access_upstream_addr.down.sql")
	for _, want := range []string{
		"ALTER TABLE access_events\n    ADD COLUMN IF NOT EXISTS upstream_addr String DEFAULT '' AFTER upstream_result;",
		"ADD COLUMN IF NOT EXISTS upstream_addr_state AggregateFunction(argMax, String, DateTime64(3, 'UTC'));",
		"argMaxState(upstream_addr, ingested_at) AS upstream_addr_state",
		"argMaxState(listen_port, ingested_at) AS listen_port_state",
	} {
		if !strings.Contains(up, want) {
			t.Fatalf("028 up lacks %q", want)
		}
	}
	legacy := read("014_analytics_access_listen_port_projection.up.sql")
	digest := legacy[strings.Index(legacy, "SELECT *, hex(SHA256"):strings.Index(legacy, "FROM access_events")]
	if !strings.Contains(up, digest) {
		t.Fatal("028 changes the payload digest tuple")
	}
	if !strings.Contains(down, "DROP COLUMN IF EXISTS upstream_addr_state") || !strings.Contains(down, "DROP COLUMN IF EXISTS upstream_addr;") ||
		strings.Contains(down, "upstream_addr_state AggregateFunction") || !strings.Contains(down, "argMaxState(listen_port, ingested_at) AS listen_port_state") {
		t.Fatal("028 down does not restore the 014 projection")
	}
}
