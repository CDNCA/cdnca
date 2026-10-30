package analyticslog

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

type obs05PagedStore struct {
	pages []AccessPage
	calls []string
}

func (store *obs05PagedStore) ListAccess(
	_ context.Context,
	_ scope,
	_ Filter,
	_ uint16,
	cursor string,
) (AccessPage, error) {
	store.calls = append(store.calls, cursor)
	if len(store.pages) == 0 {
		return AccessPage{}, errors.New("unexpected export page")
	}
	page := store.pages[0]
	store.pages = store.pages[1:]
	return page, nil
}

func (*obs05PagedStore) ListBlockEvents(context.Context, scope, Filter, uint16, string) (BlockEventPage, error) {
	return BlockEventPage{}, errors.New("unexpected block query")
}

func TestOBS05AccessFilterCoversUpstreamAndContentType(t *testing.T) {
	filter := Filter{
		From:           time.Date(2026, 8, 7, 1, 0, 0, 0, time.UTC),
		To:             time.Date(2026, 8, 7, 2, 0, 0, 0, time.UTC),
		UpstreamResult: "success",
		ContentType:    "application/json",
		UserAgent:      "Mozilla/5.0",
	}
	requestMin, requestMax := uint64(10), uint64(20)
	responseMin, responseMax := uint64(30), uint64(40)
	filter.RequestBytesMin, filter.RequestBytesMax = &requestMin, &requestMax
	filter.ResponseBytesMin, filter.ResponseBytesMax = &responseMin, &responseMax
	if err := validateFilter(filter); err != nil {
		t.Fatalf("validateFilter() error = %v", err)
	}
	filter.ContentType = "text/csv\r\nX-Injected: yes"
	if err := validateFilter(filter); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("content-type injection error = %v, want invalid input", err)
	}
	filter.ContentType = "application/json"
	filter.UserAgent = strings.Repeat("x", 513)
	if err := validateFilter(filter); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("user-agent capacity error = %v, want invalid input", err)
	}
}

func TestOBS05BuildAccessExportIsSnapshotBoundBoundedRFC4180(t *testing.T) {
	snapshot := time.Date(2026, 8, 7, 2, 0, 0, 0, time.UTC)
	store := &obs05PagedStore{pages: []AccessPage{
		{
			Items: []AccessLog{{
				EventID: "event-a", OccurredAt: snapshot.Add(-time.Minute), SiteID: siteA, NodeID: nodeA,
				Host: "example.test", URIPath: "/comma,value", Method: "GET", Protocol: "HTTP/2",
				StatusCode: 200, CountryCode: "CN", Carrier: "carrier", UpstreamResult: "success",
				ResponseHeaders: map[string]string{"Content-Type": "text/csv; charset=utf-8"},
			}},
			NextCursor: "cursor-b", SnapshotAt: snapshot,
		},
		{
			Items: []AccessLog{{
				EventID: "event-b", OccurredAt: snapshot.Add(-2 * time.Minute), SiteID: siteA, NodeID: nodeA,
				Host: "example.test", URIPath: "/quote\"line\n", Method: "POST", Protocol: "HTTP/1.1",
				StatusCode: 201, CountryCode: "US", Carrier: "carrier", UpstreamResult: "retry",
			}},
			SnapshotAt: snapshot,
		},
	}}
	artifact, err := buildAccessExportCSV(context.Background(), store, scope{tenantID: tenantA}, Filter{
		From: snapshot.Add(-time.Hour), To: snapshot,
	}, ExportLimits{MaxRows: 2, MaxBytes: 16 << 10, PageSize: 1}, nil)
	if err != nil {
		t.Fatalf("buildAccessExportCSV() error = %v", err)
	}
	if artifact.RowCount != 2 || artifact.SnapshotAt != snapshot || artifact.SHA256 == "" {
		t.Fatalf("artifact = %#v", artifact)
	}
	if got, want := store.calls, []string{"", "cursor-b"}; strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("cursors = %#v, want %#v", got, want)
	}
	csv := string(artifact.Bytes)
	if !strings.Contains(csv, "\r\n") || !strings.Contains(csv, `"/comma,value"`) ||
		!strings.Contains(csv, `"/quote""line`) {
		t.Fatalf("artifact is not RFC4180 CSV: %q", csv)
	}
}

func TestOBS05ExportRoutesAndSchemaAuthority(t *testing.T) {
	for _, path := range []string{
		"/v1/analytics/logs/access/exports",
		"/v1/admin/analytics/logs/access/exports",
		"/v1/analytics/logs/access/exports/018f0000-0000-7000-8000-000000000001",
		"/v1/analytics/logs/access/exports/018f0000-0000-7000-8000-000000000001/download-grants",
		"/v1/analytics/logs/access/exports/018f0000-0000-7000-8000-000000000001/download",
	} {
		if route, ok := resolveRoute(path); !ok || route.kind < routeAccessExportCollection {
			t.Fatalf("resolveRoute(%q) = (%#v, %v)", path, route, ok)
		}
	}
	if exportSchemaAuthority != "MIGRATION_132" {
		t.Fatalf("export schema authority = %q", exportSchemaAuthority)
	}
}
