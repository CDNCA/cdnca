package analyticslog

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

type captureCardinalityFields struct {
	requestHeaders  map[string]string
	responseHeaders map[string]string
	requestBody     *string
	responseBody    *string
}

type captureCardinalityPath struct {
	name string
	row  func(time.Time, captureCardinalityFields) any
	list func(*Client, Filter) (bool, int, error)
}

func TestClientCapturedMapCardinalityRejectsOverflow(t *testing.T) {
	now := time.Date(2026, time.August, 6, 12, 0, 0, 0, time.UTC)
	filter := Filter{From: now.Add(-time.Hour), To: now}
	tooManyBodyKeys := captureCardinalityBody(t, 129)
	tooManyArrayBodyKeys := captureCardinalityArrayBody(t, 129)

	for _, path := range captureCardinalityPaths() {
		path := path
		for _, test := range []struct {
			name   string
			fields captureCardinalityFields
		}{
			{name: "canonical_headers_129", fields: captureCardinalityFields{
				requestHeaders: captureCardinalityHeaders(129),
			}},
			{name: "body_top_and_nested_aggregate_129", fields: captureCardinalityFields{
				requestBody: tooManyBodyKeys,
			}},
			{name: "body_array_map_aggregate_129", fields: captureCardinalityFields{
				requestBody: tooManyArrayBodyKeys,
			}},
		} {
			t.Run(path.name+"/"+test.name, func(t *testing.T) {
				client := captureCardinalityClient(t, path.row(now, test.fields))
				zero, items, err := path.list(client, filter)
				if !errors.Is(err, ErrInvalidResponse) {
					t.Fatalf("error=%v, want ErrInvalidResponse", err)
				}
				if !zero || items != 0 {
					t.Fatalf("zero=%v items=%d, want zero page", zero, items)
				}
			})
		}
	}
}

func TestClientCapturedMapCardinalityAcceptsBoundaryUnicodeEmptyAndNil(t *testing.T) {
	now := time.Date(2026, time.August, 6, 12, 0, 0, 0, time.UTC)
	filter := Filter{From: now.Add(-time.Hour), To: now}
	exactBodyKeys := captureCardinalityBody(t, 128)
	exactArrayBodyKeys := captureCardinalityArrayBody(t, 128)
	emptyBody := captureCardinalityBody(t, 0)

	for _, path := range captureCardinalityPaths() {
		path := path
		for _, test := range []struct {
			name   string
			fields captureCardinalityFields
		}{
			{name: "exact_128_and_unicode", fields: captureCardinalityFields{
				requestHeaders: captureCardinalityHeaders(128), requestBody: exactBodyKeys,
			}},
			{name: "array_map_exact_128", fields: captureCardinalityFields{
				requestBody: exactArrayBodyKeys,
			}},
			{name: "empty", fields: captureCardinalityFields{
				requestHeaders: map[string]string{}, responseHeaders: map[string]string{},
				requestBody: emptyBody, responseBody: emptyBody,
			}},
			{name: "nil"},
		} {
			t.Run(path.name+"/"+test.name, func(t *testing.T) {
				client := captureCardinalityClient(t, path.row(now, test.fields))
				zero, items, err := path.list(client, filter)
				if err != nil {
					t.Fatalf("error=%v, want success", err)
				}
				if zero || items != 1 {
					t.Fatalf("zero=%v items=%d, want one item", zero, items)
				}
			})
		}
	}
}

func captureCardinalityPaths() []captureCardinalityPath {
	return []captureCardinalityPath{
		{
			name: "access",
			row: func(now time.Time, fields captureCardinalityFields) any {
				row := accessTestRow("capture-cardinality-access", now.Add(-time.Minute), "/capture")
				row.RequestHeaders, row.ResponseHeaders = fields.requestHeaders, fields.responseHeaders
				row.RequestBody, row.ResponseBody = fields.requestBody, fields.responseBody
				row.SnapshotMS = now.UnixMilli()
				return row
			},
			list: func(client *Client, filter Filter) (bool, int, error) {
				page, err := client.ListAccess(context.Background(), scope{tenantID: tenantA}, filter, 10, "")
				return len(page.Items) == 0 && page.NextCursor == "" && page.SnapshotAt.IsZero(), len(page.Items), err
			},
		},
		{
			name: "block",
			row: func(now time.Time, fields captureCardinalityFields) any {
				return blockEventRow{
					EventID: "capture-cardinality-block", OccurredAtMS: now.Add(-time.Minute).UnixMilli(),
					SiteID: siteA, NodeID: nodeA, RequestID: "request", TraceID: "trace", ConfigVersion: requiredString(configA),
					Host: "example.test", URIPath: "/capture", ClientIP: "2001:db8::1", CountryCode: "CN", Carrier: "carrier-a",
					EventType: "waf", Action: "block", Severity: "high", RuleID: "rule-a", StatusCode: http.StatusForbidden,
					RequestHeaders: fields.requestHeaders, ResponseHeaders: fields.responseHeaders,
					RequestBody: fields.requestBody, ResponseBody: fields.responseBody,
					VersionCount: 1, SnapshotMS: now.UnixMilli(),
				}
			},
			list: func(client *Client, filter Filter) (bool, int, error) {
				page, err := client.ListBlockEvents(context.Background(), scope{tenantID: tenantA}, filter, 10, "")
				return len(page.Items) == 0 && page.NextCursor == "" && page.SnapshotAt.IsZero(), len(page.Items), err
			},
		},
	}
}

func captureCardinalityClient(t *testing.T, row any) *Client {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		if err := json.NewEncoder(writer).Encode(row); err != nil {
			t.Error(err)
		}
	}))
	t.Cleanup(server.Close)
	return newUnitClient(t, server, time.Second)
}

func captureCardinalityHeaders(count int) map[string]string {
	headers := make(map[string]string, count)
	for index := 0; index < count; index++ {
		headers[fmt.Sprintf("X-Capture-%03d", index)] = "合法值"
	}
	return headers
}

func captureCardinalityBody(t *testing.T, totalKeys int) *string {
	t.Helper()
	body := make(map[string]any)
	if totalKeys > 0 {
		nested := make(map[string]any)
		body["嵌套"] = nested
		topLevelKeys := (totalKeys - 1) / 2
		for index := 0; index < topLevelKeys; index++ {
			body[fmt.Sprintf("top_%03d", index)] = "合法值"
		}
		for index := 0; index < totalKeys-1-topLevelKeys; index++ {
			nested[fmt.Sprintf("nested_%03d", index)] = "合法值"
		}
	}
	encoded, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	value := string(encoded)
	return &value
}

func captureCardinalityArrayBody(t *testing.T, totalKeys int) *string {
	t.Helper()
	nested := make(map[string]any, totalKeys-1)
	for index := 0; index < totalKeys-1; index++ {
		nested[fmt.Sprintf("nested_%03d", index)] = "合法值"
	}
	body := map[string]any{"数组": []any{nested}}
	encoded, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	value := string(encoded)
	return &value
}
