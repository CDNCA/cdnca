package analyticslog

import (
	"bytes"
	"context"
	"encoding/csv"
	"testing"
	"time"
)

// TF-C03：访问者可控的文本（UA、路径、Host 等）以公式前缀开头时，导出单元格
// 必须被中和；普通文本与数值列保持原样。用 CSV 解析器读回单元格判断，不运行公式。
func TestAccessExportCSVNeutralizesFormulaPrefixes(t *testing.T) {
	snapshot := time.Date(2026, 10, 28, 2, 0, 0, 0, time.UTC)
	agents := []string{"=1+1", "+1+1", "-1+1", "@SUM(1,1)", "Mozilla/5.0, \"quoted\""}
	items := make([]AccessLog, 0, len(agents))
	for index, agent := range agents {
		items = append(items, AccessLog{
			EventID: "event-" + string(rune('a'+index)), OccurredAt: snapshot.Add(-time.Duration(index+1) * time.Minute),
			SiteID: siteA, NodeID: nodeA, Host: "example.test", URIPath: "/=cmd", Method: "GET", Protocol: "HTTP/1.1",
			StatusCode: 200, CountryCode: "CN", Carrier: "-carrier", UpstreamResult: "success", RequestBytes: 12,
			RequestHeaders: map[string]string{"User-Agent": agent},
		})
	}
	store := &obs05PagedStore{pages: []AccessPage{{Items: items, SnapshotAt: snapshot}}}
	artifact, err := buildAccessExportCSV(context.Background(), store, scope{tenantID: tenantA}, Filter{
		From: snapshot.Add(-time.Hour), To: snapshot,
	}, ExportLimits{MaxRows: 10, MaxBytes: 64 << 10, PageSize: 10}, nil)
	if err != nil {
		t.Fatalf("buildAccessExportCSV() error = %v", err)
	}
	records, err := csv.NewReader(bytes.NewReader(artifact.Bytes)).ReadAll()
	if err != nil {
		t.Fatalf("parse csv: %v", err)
	}
	column := func(name string) int {
		for index, header := range records[0] {
			if header == name {
				return index
			}
		}
		t.Fatalf("missing column %q", name)
		return -1
	}
	ua, path, carrier, requestBytes := column("user_agent"), column("uri_path"), column("carrier"), column("request_bytes")
	if len(records) != len(agents)+1 {
		t.Fatalf("rows = %d", len(records))
	}
	for index, agent := range agents {
		row := records[index+1]
		want := agent
		if agent != "" && bytes.ContainsAny([]byte{agent[0]}, "=+-@") {
			want = "'" + agent
		}
		if row[ua] != want {
			t.Fatalf("row %d user_agent = %q, want %q", index, row[ua], want)
		}
		if row[path] != "'/=cmd" && row[path] != "/=cmd" {
			t.Fatalf("row %d uri_path = %q", index, row[path])
		}
		if row[carrier] != "'-carrier" {
			t.Fatalf("row %d carrier = %q, want neutralized", index, row[carrier])
		}
		if row[requestBytes] != "12" {
			t.Fatalf("row %d request_bytes = %q, numeric column must stay numeric", index, row[requestBytes])
		}
	}
}
