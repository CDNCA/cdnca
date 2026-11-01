package analyticslog

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"sync"
	"testing"
	"time"
)

// a page query runs on growing segments from the page top;
// later segments pin the first one's snapshot and skip the conflict scan, and
// the walk stops at the first segment with limit+1 rows, with a conflicting
// row, or at the whole window.
func TestSegmentedPageGrowsSegmentsPinsSnapshotAndStops(t *testing.T) {
	now := time.Date(2026, 7, 23, 12, 0, 0, 0, time.UTC)
	filter := Filter{From: now.Add(-30 * 24 * time.Hour), To: now}
	const snapshotMS = int64(1_784_000_000_000)
	for _, test := range []struct {
		name string
		// rowsBySegment: rows the fake returns for the n-th attempt
		rowsBySegment []int
		conflictAt    int // attempt whose first row is ambiguous, -1 none
		wantAttempts  int
		wantFroms     []time.Duration // lookback of segment_from from filter.To, 0 = filter.From
	}{
		{name: "first segment full", rowsBySegment: []int{3}, conflictAt: -1, wantAttempts: 1,
			wantFroms: []time.Duration{time.Hour}},
		{name: "grows to whole window", rowsBySegment: []int{0, 1, 1, 2, 2}, conflictAt: -1, wantAttempts: 5,
			wantFroms: []time.Duration{time.Hour, 6 * time.Hour, 36 * time.Hour, 216 * time.Hour, 0}},
		{name: "conflict stops the walk", rowsBySegment: []int{1, 2}, conflictAt: 1, wantAttempts: 2,
			wantFroms: []time.Duration{time.Hour, 6 * time.Hour}},
	} {
		t.Run(test.name, func(t *testing.T) {
			var mu sync.Mutex
			var seen []url.Values
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				mu.Lock()
				attempt := len(seen)
				seen = append(seen, request.URL.Query())
				mu.Unlock()
				for index := 0; index < test.rowsBySegment[attempt]; index++ {
					row := accessTestRow("event-"+strconv.Itoa(9-index), now.Add(-time.Duration(index+1)*time.Minute), "/a")
					row.SnapshotMS = snapshotMS
					if attempt == test.conflictAt && index == 0 {
						row.VersionCount = 2
					}
					_ = json.NewEncoder(writer).Encode(row)
				}
			}))
			defer server.Close()
			client := newUnitClient(t, server, time.Second)
			parameters := url.Values{"param_has_cursor": {"0"}, "param_has_snapshot": {"0"}, "param_snapshot_ms": {"0"}}
			rows, err := querySegmentedPage(client, context.Background(), accessPageSQL, parameters, filter, 2,
				func(row accessRow) (int64, bool) { return row.SnapshotMS, row.VersionCount > 1 })
			if err != nil || len(rows) != test.rowsBySegment[test.wantAttempts-1] {
				t.Fatalf("rows=%d err=%v", len(rows), err)
			}
			if len(seen) != test.wantAttempts {
				t.Fatalf("attempts=%d, want %d", len(seen), test.wantAttempts)
			}
			pinned := false
			for index, query := range seen {
				wantFrom := filter.From
				if test.wantFroms[index] > 0 {
					wantFrom = filter.To.Add(-test.wantFroms[index])
				}
				if query.Get("param_segment_from_ms") != strconv.FormatInt(wantFrom.UnixMilli(), 10) {
					t.Fatalf("attempt %d segment_from=%s, want %d", index, query.Get("param_segment_from_ms"), wantFrom.UnixMilli())
				}
				wantScan, wantSnapshot := "1", "0"
				if pinned {
					wantScan, wantSnapshot = "0", strconv.FormatInt(snapshotMS, 10)
				}
				if query.Get("param_conflict_scan") != wantScan || query.Get("param_snapshot_ms") != wantSnapshot {
					t.Fatalf("attempt %d conflict_scan=%s snapshot=%s, want %s/%s", index,
						query.Get("param_conflict_scan"), query.Get("param_snapshot_ms"), wantScan, wantSnapshot)
				}
				pinned = pinned || test.rowsBySegment[index] > 0
			}
		})
	}
}

// A cursor page measures its segments from the cursor, not from filter.To.
func TestSegmentedPageMeasuresSegmentsFromCursor(t *testing.T) {
	now := time.Date(2026, 7, 23, 12, 0, 0, 0, time.UTC)
	filter := Filter{From: now.Add(-7 * 24 * time.Hour), To: now}
	cursorMS := now.Add(-48 * time.Hour).UnixMilli()
	var got string
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		got = request.URL.Query().Get("param_segment_from_ms")
		for index := 0; index < 3; index++ {
			row := accessTestRow("event-"+strconv.Itoa(9-index), time.UnixMilli(cursorMS).Add(-time.Duration(index+1)*time.Minute), "/a")
			row.SnapshotMS = cursorMS
			_ = json.NewEncoder(writer).Encode(row)
		}
	}))
	defer server.Close()
	parameters := url.Values{"param_has_cursor": {"1"}, "param_cursor_occurred_at_ms": {strconv.FormatInt(cursorMS, 10)}}
	if _, err := querySegmentedPage(newUnitClient(t, server, time.Second), context.Background(), accessPageSQL, parameters, filter, 2,
		func(row accessRow) (int64, bool) { return row.SnapshotMS, row.VersionCount > 1 }); err != nil {
		t.Fatal(err)
	}
	if want := strconv.FormatInt(cursorMS+1-time.Hour.Milliseconds(), 10); got != want {
		t.Fatalf("segment_from=%s, want %s", got, want)
	}
}
