package analyticslog

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

type sensitiveCaptureFields struct {
	requestHeaders  map[string]string
	responseHeaders map[string]string
	requestBody     *string
	responseBody    *string
}

type sensitiveCapturePage struct {
	items           int
	nextCursor      string
	snapshotAt      time.Time
	requestHeaders  map[string]string
	responseHeaders map[string]string
	requestBody     map[string]any
	responseBody    map[string]any
}

type sensitiveCapturePath struct {
	name string
	row  func(string, time.Time, int64, sensitiveCaptureFields) any
	list func(*Client, Filter, uint16) (sensitiveCapturePage, error)
}

func TestClientCaptureSensitiveNameAuthorityParity(t *testing.T) {
	for _, test := range []struct {
		name      string
		sensitive bool
	}{
		{name: "clientSecret", sensitive: true},
		{name: "accessToken", sensitive: true},
		{name: "URLToken", sensitive: true},
		{name: "caféToken", sensitive: true},
		{name: "X-Api-Secret", sensitive: true},
		{name: "Authorization", sensitive: true},
		{name: "Set-Cookie", sensitive: true},
		{name: "privateKey", sensitive: true},
		{name: "clientSecretary"},
		{name: "accessTokens"},
		{name: "URLTokenizer"},
		{name: "caféTokenizer"},
		{name: "X-Api-Secretary"},
		{name: "monkey"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := captureSensitiveName(test.name); got != test.sensitive {
				t.Fatalf("captureSensitiveName(%q)=%v, want %v", test.name, got, test.sensitive)
			}
		})
	}
}

func TestClientRejectsUnredactedSegmentedSensitiveCapture(t *testing.T) {
	now := time.Date(2026, time.August, 6, 12, 0, 0, 0, time.UTC)
	filter := Filter{From: now.Add(-time.Hour), To: now}
	for _, path := range sensitiveCapturePaths() {
		path := path
		for _, test := range []struct {
			name   string
			fields sensitiveCaptureFields
		}{
			{name: "request_header_x_api_secret", fields: sensitiveCaptureFields{
				requestHeaders: map[string]string{"X-Api-Secret": "leaked"},
			}},
			{name: "response_header_x_api_secret", fields: sensitiveCaptureFields{
				responseHeaders: map[string]string{"X-Api-Secret": "leaked"},
			}},
			{name: "request_body_top_client_secret", fields: sensitiveCaptureFields{
				requestBody: sensitiveCaptureBody(t, map[string]any{"clientSecret": "leaked"}),
			}},
			{name: "response_body_nested_access_token", fields: sensitiveCaptureFields{
				responseBody: sensitiveCaptureBody(t, map[string]any{"nested": map[string]any{"accessToken": "leaked"}}),
			}},
			{name: "request_body_array_url_token", fields: sensitiveCaptureFields{
				requestBody: sensitiveCaptureBody(t, map[string]any{"items": []any{map[string]any{"URLToken": "leaked"}}}),
			}},
			{name: "response_body_unicode_cafe_token", fields: sensitiveCaptureFields{
				responseBody: sensitiveCaptureBody(t, map[string]any{"caféToken": "leaked"}),
			}},
		} {
			t.Run(path.name+"/"+test.name, func(t *testing.T) {
				row := path.row("sensitive-"+path.name, now.Add(-time.Minute), 0, test.fields)
				client := sensitiveCaptureClient(t, []any{row})
				page, err := path.list(client, filter, 10)
				if !errors.Is(err, ErrInvalidResponse) {
					t.Fatalf("error=%v, want ErrInvalidResponse", err)
				}
				if page.items != 0 || page.nextCursor != "" || !page.snapshotAt.IsZero() {
					t.Fatalf("page=%#v, want zero page", page)
				}
			})
		}
	}
}

func TestClientAcceptsRedactedSensitiveCaptureAndLegalNearMatches(t *testing.T) {
	now := time.Date(2026, time.August, 6, 12, 0, 0, 0, time.UTC)
	filter := Filter{From: now.Add(-time.Hour), To: now}
	fields := sensitiveCaptureFields{
		requestHeaders: map[string]string{
			"X-Api-Secret":    redactedCaptureValue,
			"X-Api-Secretary": "visible",
		},
		responseHeaders: map[string]string{
			"X-Access-Token": redactedCaptureValue,
			"X-Tokenized":    "visible",
		},
		requestBody: sensitiveCaptureBody(t, map[string]any{
			"URLToken":        redactedCaptureValue,
			"clientSecret":    redactedCaptureValue,
			"clientSecretary": "visible",
			"items": []any{map[string]any{
				"caféToken":     redactedCaptureValue,
				"caféTokenizer": "visible",
			}},
		}),
		responseBody: sensitiveCaptureBody(t, map[string]any{
			"nested": map[string]any{
				"accessToken":  redactedCaptureValue,
				"accessTokens": "visible",
			},
		}),
	}
	for _, path := range sensitiveCapturePaths() {
		t.Run(path.name, func(t *testing.T) {
			snapshotMS := now.UnixMilli()
			rows := []any{
				path.row("redacted-"+path.name+"-b", now.Add(-time.Minute), snapshotMS, fields),
				path.row("redacted-"+path.name+"-a", now.Add(-2*time.Minute), snapshotMS, fields),
			}
			client := sensitiveCaptureClient(t, rows)
			page, err := path.list(client, filter, 1)
			if err != nil {
				t.Fatalf("error=%v, want success", err)
			}
			if page.items != 1 || page.nextCursor == "" || page.snapshotAt.UnixMilli() != snapshotMS {
				t.Fatalf("page=%#v, want one item and stable cursor", page)
			}
			if page.requestHeaders["X-Api-Secret"] != redactedCaptureValue ||
				page.requestHeaders["X-Api-Secretary"] != "visible" ||
				page.responseHeaders["X-Access-Token"] != redactedCaptureValue ||
				page.responseHeaders["X-Tokenized"] != "visible" ||
				page.requestBody["clientSecret"] != redactedCaptureValue ||
				page.requestBody["clientSecretary"] != "visible" {
				t.Fatalf("capture changed: %#v", page)
			}
		})
	}
}

func sensitiveCapturePaths() []sensitiveCapturePath {
	return []sensitiveCapturePath{
		{
			name: "access",
			row: func(eventID string, occurredAt time.Time, snapshotMS int64, fields sensitiveCaptureFields) any {
				row := accessTestRow(eventID, occurredAt, "/capture")
				row.RequestHeaders, row.ResponseHeaders = fields.requestHeaders, fields.responseHeaders
				row.RequestBody, row.ResponseBody = fields.requestBody, fields.responseBody
				row.SnapshotMS = snapshotMS
				return row
			},
			list: func(client *Client, filter Filter, limit uint16) (sensitiveCapturePage, error) {
				page, err := client.ListAccess(context.Background(), scope{tenantID: tenantA}, filter, limit, "")
				result := sensitiveCapturePage{items: len(page.Items), nextCursor: page.NextCursor, snapshotAt: page.SnapshotAt}
				if len(page.Items) == 1 {
					result.requestHeaders, result.responseHeaders = page.Items[0].RequestHeaders, page.Items[0].ResponseHeaders
					result.requestBody, result.responseBody = page.Items[0].RequestBody, page.Items[0].ResponseBody
				}
				return result, err
			},
		},
		{
			name: "block",
			row: func(eventID string, occurredAt time.Time, snapshotMS int64, fields sensitiveCaptureFields) any {
				return blockEventRow{
					EventID: eventID, OccurredAtMS: occurredAt.UnixMilli(), SiteID: siteA, NodeID: nodeA,
					RequestID: requiredString(eventID + "-request"), TraceID: requiredString(eventID + "-trace"),
					ConfigVersion: requiredString(configA), Host: "example.test", URIPath: "/capture",
					ClientIP: "2001:db8::1", CountryCode: "CN", Carrier: "carrier-a", EventType: "waf",
					Action: "block", Severity: "high", RuleID: "rule-a", StatusCode: http.StatusForbidden,
					RequestHeaders: fields.requestHeaders, ResponseHeaders: fields.responseHeaders,
					RequestBody: fields.requestBody, ResponseBody: fields.responseBody,
					VersionCount: 1, SnapshotMS: snapshotMS,
				}
			},
			list: func(client *Client, filter Filter, limit uint16) (sensitiveCapturePage, error) {
				page, err := client.ListBlockEvents(context.Background(), scope{tenantID: tenantA}, filter, limit, "")
				result := sensitiveCapturePage{items: len(page.Items), nextCursor: page.NextCursor, snapshotAt: page.SnapshotAt}
				if len(page.Items) == 1 {
					result.requestHeaders, result.responseHeaders = page.Items[0].RequestHeaders, page.Items[0].ResponseHeaders
					result.requestBody, result.responseBody = page.Items[0].RequestBody, page.Items[0].ResponseBody
				}
				return result, err
			},
		},
	}
}

func sensitiveCaptureClient(t *testing.T, rows []any) *Client {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		encoder := json.NewEncoder(writer)
		for _, row := range rows {
			if err := encoder.Encode(row); err != nil {
				t.Error(err)
				return
			}
		}
	}))
	t.Cleanup(server.Close)
	return newUnitClient(t, server, time.Second)
}

func sensitiveCaptureBody(t *testing.T, body map[string]any) *string {
	t.Helper()
	encoded, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	value := string(encoded)
	return &value
}
