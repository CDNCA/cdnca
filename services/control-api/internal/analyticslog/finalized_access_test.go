package analyticslog

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/analyticsrealtime"
)

func TestFinalizedAccessSourceUsesOneQueryAndPinsCursorToAuthority(t *testing.T) {
	now := time.Date(2026, 8, 8, 12, 0, 0, 0, time.UTC)
	request := finalizedAccessTestRequest(now)
	wantSnapshot := analyticsrealtime.Snapshot{
		At: now.Add(-time.Millisecond), SourceWatermark: 44,
		FinalizedThrough: request.To, ExpiresAt: now.Add(5 * time.Minute),
	}
	var calls atomic.Int64
	var queries []url.Values
	var bodies []string
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, httpRequest *http.Request) {
		calls.Add(1)
		encoded, _ := io.ReadAll(httpRequest.Body)
		bodies = append(bodies, string(encoded))
		queries = append(queries, httpRequest.URL.Query())
		rows := []finalizedAccessWireRow{finalizedAccessMetadataRow(wantSnapshot, 2)}
		if httpRequest.URL.Query().Get("param_has_cursor") == "0" {
			rows = append(rows,
				finalizedAccessEventRow("event-b", request, wantSnapshot, request.To.Add(-time.Minute)),
				finalizedAccessEventRow("event-a", request, wantSnapshot, request.To.Add(-2*time.Minute)),
			)
		} else {
			rows = append(rows, finalizedAccessEventRow("event-a", request, wantSnapshot, request.To.Add(-2*time.Minute)))
		}
		for _, row := range rows {
			if err := json.NewEncoder(writer).Encode(row); err != nil {
				t.Error(err)
				return
			}
		}
	}))
	defer server.Close()

	source := newFinalizedAccessTestSource(t, server, FinalizedAccessConfig{
		QueryTimeout: time.Second, MaxConcurrent: 2, Now: func() time.Time { return now },
	})
	first, err := source.ReadFinalizedAccess(t.Context(), request)
	if err != nil {
		t.Fatal(err)
	}
	if len(first.Facts) != 1 || first.Facts[0].TenantID != request.TenantID ||
		first.Facts[0].Log.EventID != "event-b" || first.NextCursor == "" || first.Snapshot != wantSnapshot {
		t.Fatalf("first page = %#v", first)
	}
	if calls.Load() != 1 || len(queries) != 1 || len(bodies) != 1 {
		t.Fatalf("first page ClickHouse calls = %d", calls.Load())
	}
	if query := queries[0]; query.Get("param_tenant_id") != request.TenantID ||
		query.Get("param_site_id") != request.SiteID || query.Get("param_node_id") != request.NodeID ||
		query.Get("param_category") != request.Category || query.Get("param_has_snapshot") != "0" {
		t.Fatalf("first query parameters = %v", query)
	}
	if body := bodies[0]; !strings.Contains(body, "access_event_latest_state_v1") ||
		!strings.Contains(body, "site_realtime_access_facts_v1") ||
		!strings.Contains(body, "FORMAT JSONEachRow") {
		t.Fatalf("authority query is incomplete: %s", body)
	}

	request.Cursor = first.NextCursor
	request.Snapshot = &first.Snapshot
	second, err := source.ReadFinalizedAccess(t.Context(), request)
	if err != nil {
		t.Fatal(err)
	}
	if len(second.Facts) != 1 || second.Facts[0].Log.EventID != "event-a" ||
		second.NextCursor != "" || second.Snapshot != wantSnapshot || calls.Load() != 2 {
		t.Fatalf("second page = %#v, calls = %d", second, calls.Load())
	}
	if query := queries[1]; query.Get("param_has_snapshot") != "1" ||
		query.Get("param_snapshot_ms") != strconv.FormatInt(wantSnapshot.At.UnixMilli(), 10) ||
		query.Get("param_cursor_event_id") != "event-b" {
		t.Fatalf("continuation query parameters = %v", query)
	}

	request.Category = "no_host"
	if _, err := source.ReadFinalizedAccess(t.Context(), request); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("dimension-mismatched cursor error = %v", err)
	}
	if calls.Load() != 2 {
		t.Fatal("invalid cursor reached ClickHouse")
	}
}

func TestFinalizedAccessSourceFencesCapacityTimeoutAndInvalidAuthority(t *testing.T) {
	now := time.Date(2026, 8, 8, 12, 0, 0, 0, time.UTC)
	request := finalizedAccessTestRequest(now)
	entered := make(chan struct{}, 1)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		entered <- struct{}{}
		time.Sleep(100 * time.Millisecond)
		writer.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	source := newFinalizedAccessTestSource(t, server, FinalizedAccessConfig{
		QueryTimeout: 25 * time.Millisecond, MaxConcurrent: 1, Now: func() time.Time { return now },
	})
	first := make(chan error, 1)
	go func() {
		_, err := source.ReadFinalizedAccess(context.Background(), request)
		first <- err
	}()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("first query did not start")
	}
	if _, err := source.ReadFinalizedAccess(t.Context(), request); !errors.Is(err, ErrStorageUnavailable) {
		t.Fatalf("capacity error = %v", err)
	}
	if err := <-first; !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("timeout error = %v", err)
	}

	validSnapshot := analyticsrealtime.Snapshot{
		At: now.Add(-time.Millisecond), SourceWatermark: 44,
		FinalizedThrough: request.To, ExpiresAt: now.Add(time.Minute),
	}
	for _, test := range []struct {
		name   string
		mutate func(*finalizedAccessWireRow)
	}{
		{name: "tenant identity", mutate: func(row *finalizedAccessWireRow) { row.TenantID = testOtherTenantIDString }},
		{name: "snapshot watermark", mutate: func(row *finalizedAccessWireRow) { row.SourceWatermark++ }},
		{name: "schema version conflict", mutate: func(row *finalizedAccessWireRow) { row.VersionCount = 2 }},
	} {
		t.Run(test.name, func(t *testing.T) {
			rows := []finalizedAccessWireRow{
				finalizedAccessMetadataRow(validSnapshot, 1),
				finalizedAccessEventRow("event-a", request, validSnapshot, request.To.Add(-time.Minute)),
			}
			test.mutate(&rows[1])
			rowServer := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
				for _, row := range rows {
					_ = json.NewEncoder(writer).Encode(row)
				}
			}))
			defer rowServer.Close()
			reader := newFinalizedAccessTestSource(t, rowServer, FinalizedAccessConfig{
				QueryTimeout: time.Second, MaxConcurrent: 1, Now: func() time.Time { return now },
			})
			if _, err := reader.ReadFinalizedAccess(t.Context(), request); !errors.Is(err, ErrInvalidResponse) {
				t.Fatalf("invalid authority error = %v", err)
			}
		})
	}
}

func finalizedAccessTestRequest(now time.Time) FinalizedAccessRequest {
	return FinalizedAccessRequest{
		TenantID: testTenantIDString, From: now.Add(-time.Hour), To: now.Add(-time.Minute),
		SiteID: testSiteIDString, NodeID: testNodeIDString,
		Category: "edge_530", Limit: 1,
	}
}

func newFinalizedAccessTestSource(t *testing.T, server *httptest.Server, config FinalizedAccessConfig) *FinalizedAccessSource {
	t.Helper()
	source, err := NewFinalizedAccessSource(newUnitClient(t, server, config.QueryTimeout), config)
	if err != nil {
		t.Fatal(err)
	}
	return source
}

func finalizedAccessMetadataRow(snapshot analyticsrealtime.Snapshot, count uint64) finalizedAccessWireRow {
	return finalizedAccessWireRow{
		RowKind: "meta", TenantID: testTenantIDString,
		SnapshotMS: snapshot.At.UnixMilli(), SourceWatermark: snapshot.SourceWatermark,
		FinalizedThroughMS: snapshot.FinalizedThrough.UnixMilli(), ExpiresAtMS: snapshot.ExpiresAt.UnixMilli(),
		LatestCount: count, AuthorityCount: count, EvidenceDigest: strings.Repeat("ab", 32),
	}
}

func finalizedAccessEventRow(
	eventID string,
	request FinalizedAccessRequest,
	snapshot analyticsrealtime.Snapshot,
	occurredAt time.Time,
) finalizedAccessWireRow {
	row := finalizedAccessMetadataRow(snapshot, 2)
	row.RowKind = "event"
	row.EventID = eventID
	row.OccurredAtMS = occurredAt.UnixMilli()
	row.SiteID = request.SiteID
	row.NodeID = request.NodeID
	row.RequestID = "request-" + eventID
	row.TraceID = "trace-" + eventID
	row.ConfigVersion = testConfigIDString
	row.Host = "cdn.example.test"
	row.StatusCode = 530
	row.InstallationID = testInstallationString
	row.VersionCount = 1
	return row
}

const (
	testTenantIDString      = "018f0000-0000-7000-8000-000000000001"
	testOtherTenantIDString = "018f0000-0000-7000-8000-000000000002"
	testSiteIDString        = "018f0000-0000-7000-8000-000000000003"
	testNodeIDString        = "018f0000-0000-7000-8000-000000000004"
	testConfigIDString      = "018f0000-0000-7000-8000-000000000005"
	testInstallationString  = "018f0000-0000-7000-8000-000000000006"
)
