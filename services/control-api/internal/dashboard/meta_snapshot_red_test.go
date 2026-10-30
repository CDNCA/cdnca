package dashboard

import (
	"testing"
	"time"
)

func TestMetaForPublishesCanonicalSnapshotAt(t *testing.T) {
	query := Query{
		Range: "today", Timezone: "Asia/Shanghai",
		From: time.Date(2026, 8, 7, 16, 0, 0, 0, time.UTC),
		To:   time.Date(2026, 8, 8, 16, 0, 0, 0, time.UTC),
		AsOf: time.Date(2026, 8, 8, 1, 2, 3, 987654321, time.FixedZone("fixture", 8*60*60)),
	}

	meta := MetaFor(query)
	want := query.AsOf.UTC().Truncate(time.Millisecond)
	if !meta.SnapshotAt.Equal(want) {
		t.Fatalf("snapshot_at = %s, want canonical UTC millisecond snapshot %s", meta.SnapshotAt, want)
	}
}
