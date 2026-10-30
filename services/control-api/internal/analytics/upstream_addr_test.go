package analytics

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/libs/edgeconfig"
)

// fix-upstreamaddr：回源地址是独立列 upstream_addr（不复用诊断码 upstream_result）；
// 入库写该列，≤64 字节；平台未勾选“回源地址”时入库置空。
func TestAccessEventUpstreamAddrIngest(t *testing.T) {
	event := validAccessEvent("upstream-addr")
	event.UpstreamAddr = "10.0.0.1:80, 10.0.0.2:80"
	if validateAccessEvent(event) != nil {
		t.Fatal("valid upstream_addr rejected")
	}
	for _, bad := range []string{strings.Repeat("a", 65), " 10.0.0.1:80"} {
		invalid := event
		invalid.UpstreamAddr = bad
		if validateAccessEvent(invalid) == nil {
			t.Fatalf("upstream_addr %q accepted", bad)
		}
	}
	row, err := accessInsertFrom(event)
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(row)
	var fields map[string]any
	_ = json.Unmarshal(encoded, &fields)
	if fields["upstream_addr"] != event.UpstreamAddr || fields["upstream_result"] != "" {
		t.Fatalf("insert row %s", encoded)
	}
	if !slices.ContainsFunc(accessIngestSchema, func(column ingestColumn) bool {
		return column == ingestColumn{Name: "upstream_addr", Type: "String", DefaultKind: "DEFAULT"}
	}) {
		t.Fatal("accessIngestSchema lacks upstream_addr String DEFAULT")
	}

	cleared := event
	clearUnrecordedAccessFields(edgeconfig.AccessLogFields{Fields: []string{edgeconfig.AccessLogFieldReferer}}, &cleared)
	if cleared.UpstreamAddr != "" {
		t.Fatal("unselected upstream_addr kept")
	}
	kept := event
	clearUnrecordedAccessFields(edgeconfig.AccessLogFields{Fields: []string{edgeconfig.AccessLogFieldUpstreamAddr}}, &kept)
	if kept.UpstreamAddr != event.UpstreamAddr {
		t.Fatal("selected upstream_addr cleared")
	}
}

// 规范摘要（回执/水位）：未带 upstream_addr 的事件摘要不变，带了则不同。
func TestCanonicalAccessDigestUpstreamAddr(t *testing.T) {
	plain := validAccessEvent("digest")
	before, err := CanonicalAccessEventDigestV1(plain)
	if err != nil {
		t.Fatal(err)
	}
	if value := canonicalAccessEventsV1([]AccessEvent{plain})[0].(map[string]any); value["upstream_addr"] != nil {
		t.Fatal("empty upstream_addr changes the canonical form")
	}
	withAddr := plain
	withAddr.UpstreamAddr = "127.0.0.1:8080"
	after, err := CanonicalAccessEventDigestV1(withAddr)
	if err != nil || after == before {
		t.Fatalf("digest unchanged by upstream_addr (err %v)", err)
	}
}
