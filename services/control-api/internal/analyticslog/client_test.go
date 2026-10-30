package analyticslog

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestLogCursorKeyringRotationReplicaStabilityAndInputClone(t *testing.T) {
	oldKey := bytes.Repeat([]byte{0x11}, 32)
	newKey := bytes.Repeat([]byte{0x22}, 64)
	oldRing, ok := validatedLogCursorKeyring(CursorKeyring{
		ActiveKID: "old", Keys: map[string][]byte{"old": oldKey},
	})
	if !ok {
		t.Fatal("valid old keyring rejected")
	}
	state := logCursor{Version: 1, Query: "query", SnapshotMS: 10, OccurredAtMS: 9, EventID: "event-a"}
	oldCursor, err := encodeLogCursor(oldRing, state)
	if err != nil {
		t.Fatal(err)
	}

	rotated, ok := validatedLogCursorKeyring(CursorKeyring{
		ActiveKID: "new", Keys: map[string][]byte{"old": oldKey, "new": newKey},
	})
	if !ok {
		t.Fatal("valid rotated keyring rejected")
	}
	if got, err := decodeLogCursor(rotated, oldCursor, state.Query); err != nil || got != state {
		t.Fatalf("old-key cursor after rotation = (%#v, %v)", got, err)
	}
	newCursor, err := encodeLogCursor(rotated, state)
	if err != nil {
		t.Fatal(err)
	}
	if got := logCursorKID(t, newCursor); got != "new" {
		t.Fatalf("new cursor kid = %q", got)
	}
	replica, ok := validatedLogCursorKeyring(CursorKeyring{
		ActiveKID: "new", Keys: map[string][]byte{"new": append([]byte(nil), newKey...), "old": append([]byte(nil), oldKey...)},
	})
	if !ok {
		t.Fatal("replica keyring rejected")
	}
	replicaCursor, err := encodeLogCursor(replica, state)
	if err != nil || replicaCursor != newCursor {
		t.Fatalf("replica cursor = (%q, %v), want %q", replicaCursor, err, newCursor)
	}
	clear(oldKey)
	clear(newKey)
	if got, err := decodeLogCursor(rotated, oldCursor, state.Query); err != nil || got != state {
		t.Fatalf("caller key mutation changed cloned ring = (%#v, %v)", got, err)
	}
	newOnly, _ := validatedLogCursorKeyring(CursorKeyring{
		ActiveKID: "new", Keys: map[string][]byte{"new": bytes.Repeat([]byte{0x22}, 64)},
	})
	if _, err := decodeLogCursor(newOnly, oldCursor, state.Query); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("removed old key accepted cursor: %v", err)
	}
}

func TestLogCursorRejectsWrongDomainKidCanonicalFormAndSize(t *testing.T) {
	key := bytes.Repeat([]byte{0x31}, 32)
	ring, ok := validatedLogCursorKeyring(CursorKeyring{
		ActiveKID: "active", Keys: map[string][]byte{"active": key},
	})
	if !ok {
		t.Fatal("valid keyring rejected")
	}
	state := logCursor{Version: 1, Query: "query", SnapshotMS: 10, OccurredAtMS: 9, EventID: "event-a"}
	valid, err := encodeLogCursor(ring, state)
	if err != nil {
		t.Fatal(err)
	}
	packet, err := base64.RawURLEncoding.DecodeString(valid)
	if err != nil {
		t.Fatal(err)
	}
	var envelope logCursorEnvelope
	if err := json.Unmarshal(packet, &envelope); err != nil {
		t.Fatal(err)
	}
	payload, err := base64.RawURLEncoding.DecodeString(envelope.Payload)
	if err != nil {
		t.Fatal(err)
	}
	duplicate := append(append([]byte(nil), payload[:len(payload)-1]...), []byte(`,"e":"event-b"}`)...)
	noncanonicalPacket := envelope
	noncanonicalPacket.Payload += "="
	noncanonicalPacketJSON, err := json.Marshal(noncanonicalPacket)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name   string
		cursor string
	}{
		{name: "wrong domain", cursor: signLogCursorForTest(payload, "active", key, "wrong-domain")},
		{name: "unknown kid", cursor: signLogCursorForTest(payload, "unknown", key, logCursorDomain)},
		{name: "noncanonical payload", cursor: signLogCursorForTest(append([]byte{' '}, payload...), "active", key, logCursorDomain)},
		{name: "duplicate payload field", cursor: signLogCursorForTest(duplicate, "active", key, logCursorDomain)},
		{name: "noncanonical payload base64", cursor: base64.RawURLEncoding.EncodeToString(noncanonicalPacketJSON)},
		{name: "truncated", cursor: valid[:len(valid)-1]},
		{name: "oversize", cursor: strings.Repeat("x", maxLogCursorBytes+1)},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := decodeLogCursor(ring, test.cursor, state.Query); !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("decode error = %v", err)
			}
		})
	}
}

func TestLogCursorKeyringRejectsInvalidConfiguration(t *testing.T) {
	validKey := bytes.Repeat([]byte{0x44}, 32)
	nineKeys := make(map[string][]byte, 9)
	for index := 0; index < 9; index++ {
		nineKeys[string(rune('a'+index))] = validKey
	}
	for _, ring := range []CursorKeyring{
		{ActiveKID: "missing", Keys: map[string][]byte{"active": validKey}},
		{ActiveKID: ".invalid", Keys: map[string][]byte{".invalid": validKey}},
		{ActiveKID: "short", Keys: map[string][]byte{"short": bytes.Repeat([]byte{1}, 31)}},
		{ActiveKID: "long", Keys: map[string][]byte{"long": bytes.Repeat([]byte{1}, 65)}},
		{ActiveKID: "a", Keys: nineKeys},
	} {
		if _, ok := validatedLogCursorKeyring(ring); ok {
			t.Fatalf("invalid keyring accepted: %#v", ring)
		}
	}
	if _, err := NewClient(ClientConfig{
		Endpoint: "http://127.0.0.1:8123", Database: "task_missing_cursor_keyring",
	}, http.DefaultClient); !errors.Is(err, ErrInvalidConfiguration) {
		t.Fatalf("missing cursor keyring error = %v", err)
	}
}

func TestLogCursorKeyringFormattingRedactsKeyMaterial(t *testing.T) {
	const secret = "analytics-log-cursor-secret-material"
	ring := CursorKeyring{ActiveKID: "active", Keys: map[string][]byte{"active": []byte(secret)}}
	encoded, err := json.Marshal(ring)
	if err != nil {
		t.Fatal(err)
	}
	for _, output := range []string{
		fmt.Sprintf("%v", ring), fmt.Sprintf("%+v", ring), fmt.Sprintf("%#v", ring),
		ring.String(), ring.GoString(), string(encoded),
	} {
		if strings.Contains(output, secret) {
			t.Fatalf("cursor key leaked through formatting")
		}
	}
}

func logCursorKID(t *testing.T, cursor string) string {
	t.Helper()
	packet, err := base64.RawURLEncoding.DecodeString(cursor)
	if err != nil {
		t.Fatal(err)
	}
	var envelope logCursorEnvelope
	if err := json.Unmarshal(packet, &envelope); err != nil {
		t.Fatal(err)
	}
	return envelope.KID
}

func signLogCursorForTest(payload []byte, kid string, key []byte, domain string) string {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(domain))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write([]byte(kid))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write(payload)
	packet, _ := json.Marshal(logCursorEnvelope{
		Payload: base64.RawURLEncoding.EncodeToString(payload),
		KID:     kid,
		Tag:     base64.RawURLEncoding.EncodeToString(mac.Sum(nil)),
	})
	return base64.RawURLEncoding.EncodeToString(packet)
}

type nilResponseHTTPClient struct{}

func (nilResponseHTTPClient) Do(*http.Request) (*http.Response, error) { return nil, nil }

type nilBodyHTTPClient struct{}

func (nilBodyHTTPClient) Do(*http.Request) (*http.Response, error) {
	return &http.Response{StatusCode: http.StatusOK}, nil
}

func TestClientSinglePageParametersAndFailClosedPagination(t *testing.T) {
	now := time.Date(2026, 7, 23, 12, 0, 0, 0, time.UTC)
	filter := Filter{From: now.Add(-time.Hour), To: now, URIPath: "/asset.js", Carrier: "carrier') OR 1=1 --"}
	var calls atomic.Int64
	var body string
	var query url.Values
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		calls.Add(1)
		encoded, _ := io.ReadAll(request.Body)
		body = string(encoded)
		query = request.URL.Query()
		rows := []accessRow{
			accessTestRow("event-c", now.Add(-time.Minute), "/c"),
			accessTestRow("event-b", now.Add(-2*time.Minute), "/b"),
		}
		for index := range rows {
			rows[index].URIPath = filter.URIPath
			rows[index].Carrier = filter.Carrier
			_ = json.NewEncoder(writer).Encode(rows[index])
		}
	}))
	defer server.Close()

	client := newUnitClient(t, server, time.Second)
	page, err := client.ListAccess(context.Background(), scope{tenantID: tenantA}, filter, 2, "")
	if err != nil || len(page.Items) != 2 || page.Items[0].EventID != "event-c" ||
		page.Items[0].RequestID != "event-c-request" || page.Items[0].TraceID != "event-c-trace" ||
		page.Items[0].ConfigVersion != configA {
		t.Fatalf("page=%#v err=%v", page, err)
	}
	if calls.Load() != 1 || strings.Contains(body, filter.Carrier) || strings.Contains(body, filter.URIPath) ||
		query.Get("param_carrier") != filter.Carrier || query.Get("param_uri_path") != filter.URIPath ||
		query.Get("param_has_uri_path") != "1" ||
		!strings.Contains(body, "request_id") || !strings.Contains(body, "trace_id") ||
		!strings.Contains(body, "config_version_id") ||
		query.Get("param_tenant_id") != tenantA || query.Get("param_row_limit") != "3" ||
		query.Get("param_has_snapshot") != "0" || query.Get("param_snapshot_ms") != "0" ||
		query.Get("param_has_cursor") != "0" || query.Get("param_cursor_occurred_at_ms") != "0" ||
		query.Get("param_cursor_event_id") != "" {
		t.Fatalf("calls=%d body=%q query=%#v", calls.Load(), body, query)
	}

	for name, cursor := range map[string]string{
		"payload": `{"v":1}`, "mac": "payload.invalid-mac", "query": "changed-query",
		"scope": "changed-scope", "time": "changed-time", "keyset": "changed-keyset",
	} {
		t.Run("cursor_"+name, func(t *testing.T) {
			if _, err := client.ListAccess(context.Background(), scope{tenantID: tenantA}, filter, 2, cursor); !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("cursor error=%v", err)
			}
		})
	}
	if calls.Load() != 1 {
		t.Fatalf("unsupported cursors reached storage: calls=%d", calls.Load())
	}
}

func TestClientFailsClosedOnCapacityAndEqualVersion(t *testing.T) {
	now := time.Date(2026, 7, 23, 12, 0, 0, 0, time.UTC)
	filter := Filter{From: now.Add(-time.Hour), To: now}
	for _, test := range []struct {
		name string
		rows []accessRow
	}{
		{name: "more_than_limit", rows: []accessRow{
			accessTestRow("event-c", now.Add(-time.Minute), "/c"),
			accessTestRow("event-b", now.Add(-2*time.Minute), "/b"),
			accessTestRow("event-a", now.Add(-3*time.Minute), "/a"),
		}},
		{name: "equal_version", rows: func() []accessRow {
			row := accessTestRow("event-a", now.Add(-time.Minute), "/a")
			row.VersionCount = 2
			return []accessRow{row}
		}()},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := rowServer(t, test.rows)
			defer server.Close()
			client := newUnitClient(t, server, time.Second)
			if _, err := client.ListAccess(context.Background(), scope{tenantID: tenantA}, filter, 2, ""); !errors.Is(err, ErrCapabilityUnsupported) {
				t.Fatalf("error=%v", err)
			}
		})
	}
}

func TestClientRejectsInvalidStorageRows(t *testing.T) {
	now := time.Date(2026, 7, 23, 12, 0, 0, 0, time.UTC)
	filter := Filter{From: now.Add(-time.Hour), To: now}
	valid := accessTestRow("event-a", now.Add(-time.Minute), "/a")
	tests := map[string][]accessRow{
		"event_id":       mutateAccess(valid, func(row *accessRow) { row.EventID = "bad id" }),
		"time":           mutateAccess(valid, func(row *accessRow) { row.OccurredAtMS = now.UnixMilli() }),
		"site_uuid":      mutateAccess(valid, func(row *accessRow) { row.SiteID = nilUUID }),
		"node_uuid":      mutateAccess(valid, func(row *accessRow) { row.NodeID = "bad" }),
		"config_uuid":    mutateAccess(valid, func(row *accessRow) { row.ConfigVersion = requiredString(strings.ToUpper(configA)) }),
		"host":           mutateAccess(valid, func(row *accessRow) { row.Host = strings.Repeat("h", 254) }),
		"uri_query":      mutateAccess(valid, func(row *accessRow) { row.URIPath = "/a?token=secret" }),
		"client_ip":      mutateAccess(valid, func(row *accessRow) { row.ClientIP = "not-an-ip" }),
		"country":        mutateAccess(valid, func(row *accessRow) { row.CountryCode = strings.Repeat("C", 9) }),
		"carrier":        mutateAccess(valid, func(row *accessRow) { row.Carrier = "bad\ncarrier" }),
		"method":         mutateAccess(valid, func(row *accessRow) { row.Method = "" }),
		"protocol":       mutateAccess(valid, func(row *accessRow) { row.Protocol = "" }),
		"cache_status":   mutateAccess(valid, func(row *accessRow) { row.CacheStatus = "" }),
		"upstream":       mutateAccess(valid, func(row *accessRow) { row.UpstreamResult = strings.Repeat("x", 65) }),
		"status":         mutateAccess(valid, func(row *accessRow) { row.StatusCode = 99 }),
		"version_count":  mutateAccess(valid, func(row *accessRow) { row.VersionCount = 0 }),
		"duplicate":      {valid, valid},
		"unstable_order": {accessTestRow("event-a", now.Add(-2*time.Minute), "/a"), accessTestRow("event-b", now.Add(-time.Minute), "/b")},
	}
	for name, rows := range tests {
		t.Run(name, func(t *testing.T) {
			server := rowServer(t, rows)
			defer server.Close()
			client := newUnitClient(t, server, time.Second)
			if _, err := client.ListAccess(context.Background(), scope{tenantID: tenantA}, filter, 10, ""); !errors.Is(err, ErrInvalidResponse) {
				t.Fatalf("error=%v", err)
			}
		})
	}

	t.Run("unknown_json_field", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
			_, _ = writer.Write([]byte(`{"event_id":"event-a","unknown":"secret"}`))
		}))
		defer server.Close()
		client := newUnitClient(t, server, time.Second)
		if _, err := client.ListAccess(context.Background(), scope{tenantID: tenantA}, filter, 10, ""); !errors.Is(err, ErrInvalidResponse) {
			t.Fatalf("error=%v", err)
		}
	})

	t.Run("null_request_identity", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
			row := accessTestRow("event-a", now.Add(-time.Minute), "/a")
			encoded, _ := json.Marshal(row)
			var raw map[string]any
			_ = json.Unmarshal(encoded, &raw)
			raw["request_id"] = nil
			_ = json.NewEncoder(writer).Encode(raw)
		}))
		defer server.Close()
		client := newUnitClient(t, server, time.Second)
		if _, err := client.ListAccess(context.Background(), scope{tenantID: tenantA}, filter, 10, ""); !errors.Is(err, ErrInvalidResponse) {
			t.Fatalf("error=%v", err)
		}
	})

	t.Run("block_action", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
			_ = json.NewEncoder(writer).Encode(blockEventRow{
				EventID: "block-a", OccurredAtMS: now.Add(-time.Minute).UnixMilli(), SiteID: siteA, NodeID: nodeA,
				RequestID: requiredString("request-block"), TraceID: requiredString("trace-block"), ConfigVersion: requiredString(configA),
				Host: "example.test", URIPath: "/blocked", ClientIP: "2001:db8::1", CountryCode: "CN",
				Carrier: "carrier-a", EventType: "waf", Action: "allow", Severity: "high", VersionCount: 1,
			})
		}))
		defer server.Close()
		client := newUnitClient(t, server, time.Second)
		if _, err := client.ListBlockEvents(context.Background(), scope{tenantID: tenantA}, filter, 10, ""); !errors.Is(err, ErrInvalidResponse) {
			t.Fatalf("error=%v", err)
		}
	})
}

func TestClientFailuresCancellationTimeoutAndConfiguration(t *testing.T) {
	now := time.Date(2026, 7, 23, 12, 0, 0, 0, time.UTC)
	filter := Filter{From: now.Add(-time.Hour), To: now}
	t.Run("storage", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
			writer.WriteHeader(http.StatusServiceUnavailable)
			_, _ = writer.Write([]byte("database secret SELECT"))
		}))
		defer server.Close()
		client := newUnitClient(t, server, time.Second)
		if _, err := client.ListAccess(context.Background(), scope{tenantID: tenantA}, filter, 10, ""); !errors.Is(err, ErrStorageUnavailable) {
			t.Fatalf("error=%v", err)
		}
	})

	for _, test := range []struct {
		name    string
		timeout time.Duration
		cancel  bool
	}{
		{name: "cancel", timeout: time.Second, cancel: true},
		{name: "timeout", timeout: 15 * time.Millisecond},
	} {
		t.Run(test.name, func(t *testing.T) {
			entered := make(chan struct{})
			release := make(chan struct{})
			server := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, request *http.Request) {
				close(entered)
				select {
				case <-request.Context().Done():
				case <-release:
				}
			}))
			defer func() {
				close(release)
				server.Close()
			}()
			client := newUnitClient(t, server, test.timeout)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan error, 1)
			go func() {
				_, err := client.ListAccess(ctx, scope{tenantID: tenantA}, filter, 10, "")
				done <- err
			}()
			<-entered
			if test.cancel {
				cancel()
			}
			err := <-done
			if test.cancel && !errors.Is(err, context.Canceled) {
				t.Fatalf("cancel error=%v", err)
			}
			if !test.cancel && !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("timeout error=%v", err)
			}
		})
	}

	for _, config := range []ClientConfig{
		{Endpoint: "http://example.com:8123", Database: "task_test"},
		{Endpoint: "http://user:secret@127.0.0.1:8123", Database: "task_test"},
		{Endpoint: "http://127.0.0.1:8123/?token=secret", Database: "task_test"},
		{Endpoint: "http://127.0.0.1:8123", Database: "bad-name"},
	} {
		config.CursorKeyring = testLogCursorKeyring()
		if _, err := NewClient(config, http.DefaultClient); !errors.Is(err, ErrInvalidConfiguration) {
			t.Fatalf("config %#v error=%v", config, err)
		}
	}
}

func TestClientFailsClosedOnNilHTTPResponse(t *testing.T) {
	now := time.Date(2026, 7, 23, 12, 0, 0, 0, time.UTC)
	client, err := NewClient(ClientConfig{
		Endpoint: "http://127.0.0.1:8123", Database: "task_analyticslog_nil_response",
		CursorKeyring: testLogCursorKeyring(),
	}, nilResponseHTTPClient{})
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.ListAccess(context.Background(), scope{tenantID: tenantA}, Filter{
		From: now.Add(-time.Hour), To: now,
	}, 10, "")
	if !errors.Is(err, ErrInvalidResponse) {
		t.Fatalf("error=%v, want invalid response", err)
	}
}

func TestClientFailsClosedOnNonNilHTTPResponseWithNilBody(t *testing.T) {
	now := time.Date(2026, 7, 23, 12, 0, 0, 0, time.UTC)
	client, err := NewClient(ClientConfig{
		Endpoint: "http://127.0.0.1:8123", Database: "task_analyticslog_nil_body",
		CursorKeyring: testLogCursorKeyring(),
	}, nilBodyHTTPClient{})
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.ListAccess(context.Background(), scope{tenantID: tenantA}, Filter{
		From: now.Add(-time.Hour), To: now,
	}, 10, "")
	if !errors.Is(err, ErrInvalidResponse) {
		t.Fatalf("error=%v, want invalid response", err)
	}
}

func newUnitClient(t *testing.T, server *httptest.Server, timeout time.Duration) *Client {
	t.Helper()
	client, err := NewClient(ClientConfig{
		Endpoint: server.URL, Database: "task_analyticslog_unit", QueryTimeout: timeout,
		CursorKeyring: testLogCursorKeyring(),
	}, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func testLogCursorKeyring() CursorKeyring {
	return CursorKeyring{
		ActiveKID: "test-active",
		Keys:      map[string][]byte{"test-active": bytes.Repeat([]byte{0x5a}, 32)},
	}
}

func rowServer(t *testing.T, rows []accessRow) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		encoder := json.NewEncoder(writer)
		for _, row := range rows {
			if err := encoder.Encode(row); err != nil {
				t.Error(err)
				return
			}
		}
	}))
}

func mutateAccess(row accessRow, mutate func(*accessRow)) []accessRow {
	mutate(&row)
	return []accessRow{row}
}

func accessTestRow(eventID string, occurredAt time.Time, path string) accessRow {
	return accessRow{
		EventID: eventID, OccurredAtMS: occurredAt.UnixMilli(), SiteID: siteA, NodeID: nodeA,
		RequestID: requiredString(eventID + "-request"), TraceID: requiredString(eventID + "-trace"), ConfigVersion: requiredString(configA),
		Host: "example.test", URIPath: path, ClientIP: "2001:db8::1", CountryCode: "CN", Carrier: "carrier-a",
		Method: "GET", Protocol: "HTTP/2", CacheStatus: "HIT", UpstreamResult: "ok", StatusCode: 200,
		ResponseBytes: 100, VersionCount: 1,
	}
}
