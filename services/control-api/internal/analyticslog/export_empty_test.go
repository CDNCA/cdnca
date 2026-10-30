package analyticslog

import (
	"context"
	"errors"
	"testing"
	"time"
)

// TF-C04：合法条件 0 行时首页没有快照，导出应得到仅表头的 CSV（0 行、快照为
// 窗口结束与当前时间较早者），不是 ErrInvalidResponse；后续页丢快照仍拒绝。
func TestAccessExportEmptyResultIsHeaderOnlyCSV(t *testing.T) {
	now := time.Date(2026, 10, 28, 3, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	for name, to := range map[string]time.Time{"past window": now.Add(-time.Hour), "future window": now.Add(time.Hour)} {
		t.Run(name, func(t *testing.T) {
			store := &obs05PagedStore{pages: []AccessPage{{}}}
			artifact, err := buildAccessExportCSV(context.Background(), store, scope{tenantID: tenantA},
				Filter{From: to.Add(-time.Hour), To: to}, ExportLimits{MaxRows: 10, MaxBytes: 4096, PageSize: 10}, clock)
			if err != nil {
				t.Fatalf("buildAccessExportCSV() error = %v", err)
			}
			want := to
			if to.After(now) {
				want = now
			}
			if artifact.RowCount != 0 || !artifact.SnapshotAt.Equal(want) || artifact.SHA256 == "" ||
				string(artifact.Bytes[:9]) != "event_id," {
				t.Fatalf("artifact = rows %d snapshot %s bytes %q", artifact.RowCount, artifact.SnapshotAt, artifact.Bytes)
			}
		})
	}
	snapshot := now.Add(-time.Minute)
	store := &obs05PagedStore{pages: []AccessPage{
		{Items: []AccessLog{{EventID: "event-a", OccurredAt: snapshot.Add(-time.Minute), SiteID: siteA, NodeID: nodeA,
			Host: "example.test", URIPath: "/", Method: "GET", Protocol: "HTTP/1.1", StatusCode: 200, UpstreamResult: "success"}},
			NextCursor: "cursor-b", SnapshotAt: snapshot},
		{},
	}}
	if _, err := buildAccessExportCSV(context.Background(), store, scope{tenantID: tenantA},
		Filter{From: now.Add(-time.Hour), To: now}, ExportLimits{MaxRows: 10, MaxBytes: 4096, PageSize: 1}, clock); !errors.Is(err, ErrInvalidResponse) {
		t.Fatalf("later page without snapshot error = %v, want ErrInvalidResponse", err)
	}
}
