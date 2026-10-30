package eventspool

import (
	"strings"
	"testing"
	"time"
)

// L4F-E03：nginx 的 $time_iso8601 输出数值时区（+00:00/+08:00），不是 Z。
// 同一瞬间的不同 RFC3339 表示必须解析为同一 UTC 事件；非法时间仍拒绝。
func TestL4SourceAcceptsNumericOffsetTimeAsSameInstant(t *testing.T) {
	identity := TrustedIdentity{
		EnrollmentNodeID: nodeOne, TenantID: tenantOne, SiteID: siteOne,
		ConfigVersionID: "55555555-5555-4555-8555-555555555555",
		StreamID:        "66666666-6666-4666-8666-666666666666",
		ListenerID:      "77777777-7777-4777-8777-777777777777", ConfigRevision: 9,
	}
	// 真实节点原生日志行（审测 timezone-source.jsonl），仅替换时间表示。
	const native = `{"time":"2026-10-27T17:35:38+00:00","connection":"1","protocol":"TCP","server_port":"18623","status":"200","bytes_sent":4096,"bytes_received":4096,"session_time":8.519}`
	want := time.Date(2026, 10, 27, 17, 35, 38, 0, time.UTC)
	for _, stamp := range []string{"2026-10-27T17:35:38+00:00", "2026-10-28T01:35:38+08:00", "2026-10-27T12:35:38-05:00", "2026-10-27T17:35:38Z"} {
		line := []byte(strings.Replace(native, "2026-10-27T17:35:38+00:00", stamp, 1))
		event, err := ParseL4SourceLineBound(line, identity)
		if err != nil {
			t.Fatalf("%s: %v", stamp, err)
		}
		if !event.FinalizedAt.Equal(want) || event.FinalizedAt.Location() != time.UTC ||
			event.OccurredAt.Location() != time.UTC || event.StartedAt.Location() != time.UTC ||
			event.RequestBytes != 4096 || event.ResponseBytes != 4096 {
			t.Fatalf("%s: event = %#v", stamp, event)
		}
		if stamp == "2026-10-27T17:35:38+00:00" && event.EvidenceSHA256 == "" {
			t.Fatal("evidence hash missing")
		}
	}
	for _, bad := range []string{"2026-10-27 17:35:38", "27/Oct/2026:17:35:38 +0000", "2026-10-27T25:35:38+00:00", ""} {
		line := []byte(strings.Replace(native, "2026-10-27T17:35:38+00:00", bad, 1))
		if _, err := ParseL4SourceLineBound(line, identity); err == nil {
			t.Fatalf("%q accepted", bad)
		}
	}
}
