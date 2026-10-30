package analyticslog

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestAccessCursorProvidesStableTwoPageTotalOrderAndBindsQuery(t *testing.T) {
	now := time.Date(2026, 7, 28, 4, 0, 0, 0, time.UTC)
	snapshotMS := now.UnixMilli()
	filter := Filter{From: now.Add(-time.Hour), To: now, SiteID: siteA, URIPath: "/filtered", StatusCode: 200, HasStatus: true}
	var mu sync.Mutex
	var queries []url.Values
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		encoded, _ := io.ReadAll(request.Body)
		if !strings.Contains(string(encoded), "snapshot_at") || !strings.Contains(string(encoded), "cursor_occurred_at_ms") {
			t.Errorf("query is missing stable snapshot/keyset boundary: %s", encoded)
		}
		query := request.URL.Query()
		mu.Lock()
		queries = append(queries, query)
		call := len(queries)
		mu.Unlock()
		rows := []accessRow{}
		if call == 1 {
			rows = []accessRow{
				accessTestRow("event-c", now.Add(-time.Minute), "/c"),
				accessTestRow("event-b", now.Add(-2*time.Minute), "/b"),
				accessTestRow("event-a", now.Add(-3*time.Minute), "/a"),
			}
		} else {
			rows = []accessRow{accessTestRow("event-a", now.Add(-3*time.Minute), "/a")}
		}
		for index := range rows {
			rows[index].SiteID = siteA
			rows[index].URIPath = filter.URIPath
			rows[index].StatusCode = 200
			rows[index].SnapshotMS = snapshotMS
			_ = json.NewEncoder(writer).Encode(rows[index])
		}
	}))
	defer server.Close()
	client := newUnitClient(t, server, time.Second)

	first, err := client.ListAccess(context.Background(), scope{tenantID: tenantA}, filter, 2, "")
	if err != nil || len(first.Items) != 2 || first.Items[0].EventID != "event-c" || first.Items[1].EventID != "event-b" ||
		first.NextCursor == "" || !first.SnapshotAt.Equal(time.UnixMilli(snapshotMS).UTC()) {
		t.Fatalf("first page = %#v, error=%v", first, err)
	}
	second, err := client.ListAccess(context.Background(), scope{tenantID: tenantA}, filter, 2, first.NextCursor)
	if err != nil || len(second.Items) != 1 || second.Items[0].EventID != "event-a" || second.NextCursor != "" ||
		!second.SnapshotAt.Equal(first.SnapshotAt) {
		t.Fatalf("second page = %#v, error=%v", second, err)
	}
	mu.Lock()
	gotQueries := append([]url.Values(nil), queries...)
	mu.Unlock()
	if len(gotQueries) != 2 || gotQueries[0].Get("param_has_snapshot") != "0" || gotQueries[0].Get("param_has_cursor") != "0" ||
		gotQueries[1].Get("param_has_snapshot") != "1" || gotQueries[1].Get("param_snapshot_ms") != strconv.FormatInt(snapshotMS, 10) ||
		gotQueries[1].Get("param_has_cursor") != "1" || gotQueries[1].Get("param_cursor_event_id") != "event-b" ||
		gotQueries[1].Get("param_cursor_occurred_at_ms") != strconv.FormatInt(now.Add(-2*time.Minute).UnixMilli(), 10) {
		t.Fatalf("cursor query parameters = %#v", gotQueries)
	}

	before := len(gotQueries)
	packet, err := base64.RawURLEncoding.DecodeString(first.NextCursor)
	if err != nil {
		t.Fatal(err)
	}
	var envelope logCursorEnvelope
	if err := json.Unmarshal(packet, &envelope); err != nil {
		t.Fatal(err)
	}
	rawCursor, err := base64.RawURLEncoding.DecodeString(envelope.Payload)
	if err != nil {
		t.Fatal(err)
	}
	var cursorFields map[string]any
	if err := json.Unmarshal(rawCursor, &cursorFields); err != nil {
		t.Fatal(err)
	}
	tampered := make(map[string]string, 3)
	for name, field := range map[string]string{"snapshot": "s", "order": "o", "event_id": "e"} {
		copy := make(map[string]any, len(cursorFields))
		for key, value := range cursorFields {
			copy[key] = value
		}
		switch field {
		case "e":
			copy[field] = "attacker-event"
		default:
			copy[field] = copy[field].(float64) - 1
		}
		encoded, marshalErr := json.Marshal(copy)
		if marshalErr != nil {
			t.Fatal(marshalErr)
		}
		tamperedEnvelope := envelope
		tamperedEnvelope.Payload = base64.RawURLEncoding.EncodeToString(encoded)
		tamperedPacket, marshalErr := json.Marshal(tamperedEnvelope)
		if marshalErr != nil {
			t.Fatal(marshalErr)
		}
		tampered[name] = base64.RawURLEncoding.EncodeToString(tamperedPacket)
	}
	changed := filter
	changed.SiteID = "20000000-0000-4000-8000-00000000000b"
	changedPath := filter
	changedPath.URIPath = "/changed"
	for name, invoke := range map[string]func() error{
		"filter": func() error {
			_, err := client.ListAccess(context.Background(), scope{tenantID: tenantA}, changed, 2, first.NextCursor)
			return err
		},
		"uri_filter": func() error {
			_, err := client.ListAccess(context.Background(), scope{tenantID: tenantA}, changedPath, 2, first.NextCursor)
			return err
		},
		"tenant": func() error {
			_, err := client.ListAccess(context.Background(), scope{tenantID: tenantB}, filter, 2, first.NextCursor)
			return err
		},
		"kind_direction": func() error {
			_, err := client.ListBlockEvents(context.Background(), scope{tenantID: tenantA}, Filter{From: filter.From, To: filter.To, SiteID: siteA}, 2, first.NextCursor)
			return err
		},
		"overlong": func() error {
			_, err := client.ListAccess(context.Background(), scope{tenantID: tenantA}, filter, 2, strings.Repeat("x", maximumRawQueryBytes+1))
			return err
		},
		"tampered_snapshot": func() error {
			_, err := client.ListAccess(context.Background(), scope{tenantID: tenantA}, filter, 2, tampered["snapshot"])
			return err
		},
		"tampered_order": func() error {
			_, err := client.ListAccess(context.Background(), scope{tenantID: tenantA}, filter, 2, tampered["order"])
			return err
		},
		"tampered_event_id": func() error {
			_, err := client.ListAccess(context.Background(), scope{tenantID: tenantA}, filter, 2, tampered["event_id"])
			return err
		},
	} {
		t.Run(name, func(t *testing.T) {
			if err := invoke(); !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("cursor binding error = %v", err)
			}
		})
	}
	mu.Lock()
	after := len(queries)
	mu.Unlock()
	if after != before {
		t.Fatalf("rejected cursor reached storage: before=%d after=%d", before, after)
	}
}

func TestSecurityCursorUsesExistingBlockEventRoute(t *testing.T) {
	now := time.Date(2026, 7, 28, 4, 0, 0, 0, time.UTC)
	filter := Filter{From: now.Add(-time.Hour), To: now, StatusCode: 403, HasStatus: true}
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		row := blockEventRow{
			EventID: "security-a", OccurredAtMS: now.Add(-time.Minute).UnixMilli(), SnapshotMS: now.UnixMilli(),
			RequestID: requiredString("request-security"), TraceID: requiredString("trace-security"), ConfigVersion: requiredString(configA),
			SiteID: siteA, NodeID: nodeA, Host: "example.test", URIPath: "/blocked", ClientIP: "2001:db8::1",
			CountryCode: "CN", Carrier: "carrier-a", EventType: "waf", Action: "block", Severity: "high",
			RuleID: "rule-a", StatusCode: 403, VersionCount: 1,
		}
		_ = json.NewEncoder(writer).Encode(row)
	}))
	defer server.Close()
	client := newUnitClient(t, server, time.Second)
	service, err := NewService(client)
	if err != nil {
		t.Fatal(err)
	}
	page, err := service.ListBlockEvents(context.Background(), Actor{
		ScopeKind: "tenant", TenantID: tenantA, Permissions: []string{ReadPermission},
	}, QueryRequest{Audience: AudienceTenant, Filter: filter, Limit: 2})
	if err != nil || len(page.Items) != 1 || page.Items[0].EventID != "security-a" {
		t.Fatalf("security page = %#v, error=%v", page, err)
	}
}
