package analytics

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const (
	testTenantID = "10000000-0000-0000-0000-000000000001"
	testSiteID   = "20000000-0000-0000-0000-000000000001"
	testNodeID   = "30000000-0000-0000-0000-000000000001"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (function roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}

func TestClientCheckRequiresConfirmedResponse(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name       string
		statusCode int
		body       string
		wantError  error
	}{
		{name: "success", statusCode: http.StatusOK, body: "{\"ok\":1}\n"},
		{name: "unexpected row", statusCode: http.StatusOK, body: "{\"ok\":0}\n", wantError: ErrInvalidResponse},
		{name: "unavailable", statusCode: http.StatusServiceUnavailable, wantError: &HTTPError{}},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				body, _ := io.ReadAll(request.Body)
				if string(body) != "SELECT 1 AS ok FORMAT JSONEachRow" {
					t.Errorf("check query = %q", body)
				}
				writer.WriteHeader(test.statusCode)
				_, _ = io.WriteString(writer, test.body)
			}))
			defer server.Close()
			client := mustClient(t, Config{Endpoint: server.URL, Database: "analytics_test"}, server.Client())
			err := client.Check(context.Background())
			if test.wantError == nil && err != nil {
				t.Fatal(err)
			}
			if errors.Is(test.wantError, ErrInvalidResponse) && !errors.Is(err, ErrInvalidResponse) {
				t.Fatalf("Check() error = %v", err)
			}
			if _, ok := test.wantError.(*HTTPError); ok {
				var httpError *HTTPError
				if !errors.As(err, &httpError) || httpError.StatusCode != test.statusCode {
					t.Fatalf("Check() HTTP error = %v", err)
				}
			}
		})
	}
}

func TestClientCheckIngestVerifiesSchemasAndInsertPermissions(t *testing.T) {
	t.Parallel()
	type observedRequest struct {
		body  string
		table string
	}
	var observed []observedRequest
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		body, _ := io.ReadAll(request.Body)
		table := request.URL.Query().Get("param_table")
		observed = append(observed, observedRequest{body: string(body), table: table})
		switch table {
		case "access_events":
			_, _ = writer.Write(encodeIngestColumns(t, accessIngestSchema))
		case "security_events":
			_, _ = writer.Write(encodeIngestColumns(t, securityIngestSchema))
		default:
			writer.WriteHeader(http.StatusOK)
		}
	}))
	defer server.Close()
	client := mustClient(t, Config{Endpoint: server.URL, Database: "analytics_test"}, server.Client())
	if err := client.CheckIngest(context.Background()); err != nil {
		t.Fatal(err)
	}
	want := []observedRequest{
		{body: ingestSchemaSQL, table: "access_events"},
		{body: insertAccessEventsSQL + "\n"},
		{body: ingestSchemaSQL, table: "security_events"},
		{body: insertSecurityEventSQL + "\n"},
	}
	if len(observed) != len(want) {
		t.Fatalf("CheckIngest requests = %#v", observed)
	}
	for index := range want {
		if observed[index] != want[index] {
			t.Fatalf("CheckIngest request[%d] = %#v, want %#v", index, observed[index], want[index])
		}
	}
}

func TestClientCheckIngestRejectsSchemaDrift(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name   string
		mutate func([]ingestColumn) []ingestColumn
	}{
		{"type", func(columns []ingestColumn) []ingestColumn { columns[0].Type = "String"; return columns }},
		{"missing column", func(columns []ingestColumn) []ingestColumn { return columns[:len(columns)-1] }},
		{"extra column", func(columns []ingestColumn) []ingestColumn {
			return append(columns, ingestColumn{Name: "unexpected", Type: "String"})
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			columns := test.mutate(append([]ingestColumn(nil), accessIngestSchema...))
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
				_, _ = writer.Write(encodeIngestColumns(t, columns))
			}))
			defer server.Close()
			client := mustClient(t, Config{Endpoint: server.URL, Database: "analytics_test"}, server.Client())
			if err := client.CheckIngest(context.Background()); !errors.Is(err, ErrInvalidResponse) {
				t.Fatalf("CheckIngest schema drift error = %v", err)
			}
		})
	}
}

func TestClientCheckIngestRejectsInsertPermissionAndProtocolFailures(t *testing.T) {
	t.Parallel()
	for _, table := range []struct {
		name   string
		failAt int
	}{{"access", 2}, {"security", 4}} {
		for _, status := range []int{
			http.StatusBadRequest,
			http.StatusUnauthorized,
			http.StatusForbidden,
			http.StatusNotFound,
			http.StatusRequestEntityTooLarge,
			http.StatusTooManyRequests,
			http.StatusServiceUnavailable,
		} {
			t.Run(fmt.Sprintf("%s/%d", table.name, status), func(t *testing.T) {
				requests := 0
				server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
					requests++
					if requests == table.failAt {
						writer.WriteHeader(status)
						_, _ = io.WriteString(writer, "clickhouse-storage-secret")
						return
					}
					switch request.URL.Query().Get("param_table") {
					case "access_events":
						_, _ = writer.Write(encodeIngestColumns(t, accessIngestSchema))
					case "security_events":
						_, _ = writer.Write(encodeIngestColumns(t, securityIngestSchema))
					}
				}))
				defer server.Close()
				client := mustClient(t, Config{Endpoint: server.URL, Database: "analytics_test"}, server.Client())
				err := client.CheckIngest(context.Background())
				var httpError *HTTPError
				if !errors.As(err, &httpError) || httpError.StatusCode != status ||
					strings.Contains(err.Error(), "clickhouse-storage-secret") {
					t.Fatalf("CheckIngest insert error = %v", err)
				}
			})
		}
	}
}

func encodeIngestColumns(t *testing.T, columns []ingestColumn) []byte {
	t.Helper()
	var encoded bytes.Buffer
	encoder := json.NewEncoder(&encoded)
	for _, column := range columns {
		if err := encoder.Encode(column); err != nil {
			t.Fatal(err)
		}
	}
	return encoded.Bytes()
}

func TestWriteAccessEventsUsesStableJSONEachRowBatch(t *testing.T) {
	t.Parallel()
	var mu sync.Mutex
	var bodies [][]byte
	var parameters []url.Values
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		body, err := io.ReadAll(request.Body)
		if err != nil {
			t.Error(err)
			writer.WriteHeader(http.StatusInternalServerError)
			return
		}
		username, password, ok := request.BasicAuth()
		if !ok || username != "analytics" || password != "client-secret" {
			t.Error("missing ClickHouse basic authentication")
		}
		mu.Lock()
		bodies = append(bodies, body)
		parameters = append(parameters, request.URL.Query())
		mu.Unlock()
		writer.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := mustClient(t, Config{
		Endpoint: server.URL, Database: "analytics_test", Username: "analytics", Password: "client-secret",
	}, server.Client())
	events := []AccessEvent{validAccessEvent("event-1"), validAccessEvent("event-2")}
	for attempt := 0; attempt < 2; attempt++ {
		if err := client.WriteAccessEvents(context.Background(), "batch-42", events); err != nil {
			t.Fatalf("WriteAccessEvents() attempt %d error = %v", attempt, err)
		}
	}

	if len(bodies) != 2 || !bytes.Equal(bodies[0], bodies[1]) {
		t.Fatalf("retry bodies differ: count=%d", len(bodies))
	}
	if parameters[0].Get("insert_deduplication_token") != "batch-42" ||
		parameters[1].Get("insert_deduplication_token") != "batch-42" {
		t.Fatalf("deduplication tokens = %q, %q", parameters[0].Get("insert_deduplication_token"), parameters[1].Get("insert_deduplication_token"))
	}
	lines := bytes.Split(bytes.TrimSpace(bodies[0]), []byte{'\n'})
	if len(lines) != 3 || string(lines[0]) != insertAccessEventsSQL {
		t.Fatalf("JSONEachRow request lines = %q", lines)
	}
	for index, encoded := range lines[1:] {
		var event AccessEvent
		if err := json.Unmarshal(encoded, &event); err != nil {
			t.Fatalf("row %d is not JSON: %v", index, err)
		}
		if event.EventID != events[index].EventID {
			t.Fatalf("row %d event ID = %q", index, event.EventID)
		}
	}
	if bytes.Contains(bodies[0], []byte("client-secret")) {
		t.Fatal("write body leaked the ClickHouse password")
	}
}

func TestWriteSecurityEventsUsesSecurityTable(t *testing.T) {
	t.Parallel()
	var body []byte
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		body, _ = io.ReadAll(request.Body)
		writer.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	client := mustClient(t, Config{Endpoint: server.URL, Database: "analytics_test"}, server.Client())
	if err := client.WriteSecurityEvents(context.Background(), "security-batch", []SecurityEvent{validSecurityEvent("security-1")}); err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(body, []byte(insertSecurityEventSQL+"\n")) {
		t.Fatalf("security body starts with %q", body)
	}
}

func TestWriteTransportFailureIsClassifiedAsUnknownOutcome(t *testing.T) {
	t.Parallel()
	transport := roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if _, err := io.ReadAll(request.Body); err != nil {
			t.Fatalf("read dispatched write body: %v", err)
		}
		return nil, errors.New("connection lost after request dispatch")
	})
	client := mustClient(t, Config{
		Endpoint: "https://clickhouse.example.test", Database: "analytics_test",
	}, &http.Client{Transport: transport})
	tests := []struct {
		name  string
		write func() error
	}{
		{name: "access", write: func() error {
			return client.WriteAccessEvents(context.Background(), "unknown-access", []AccessEvent{validAccessEvent("unknown-access")})
		}},
		{name: "security", write: func() error {
			return client.WriteSecurityEvents(context.Background(), "unknown-security", []SecurityEvent{validSecurityEvent("unknown-security")})
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := test.write(); !errors.Is(err, ErrIngestWriteOutcomeUnknown) {
				t.Fatalf("write error = %v, want %v", err, ErrIngestWriteOutcomeUnknown)
			}
		})
	}
}

func TestWriteBatchBoundaries(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	t.Run("empty", func(t *testing.T) {
		client := mustClient(t, Config{Endpoint: server.URL, Database: "analytics_test"}, server.Client())
		if err := client.WriteAccessEvents(context.Background(), "batch", nil); !errors.Is(err, ErrInvalidInput) {
			t.Fatalf("error = %v", err)
		}
	})
	t.Run("event count", func(t *testing.T) {
		client := mustClient(t, Config{Endpoint: server.URL, Database: "analytics_test", MaxBatchEvents: 1}, server.Client())
		err := client.WriteAccessEvents(context.Background(), "batch", []AccessEvent{validAccessEvent("one"), validAccessEvent("two")})
		if !errors.Is(err, ErrInvalidInput) {
			t.Fatalf("error = %v", err)
		}
	})
	t.Run("encoded bytes", func(t *testing.T) {
		client := mustClient(t, Config{Endpoint: server.URL, Database: "analytics_test", MaxBatchBytes: 16}, server.Client())
		if err := client.WriteAccessEvents(context.Background(), "batch", []AccessEvent{validAccessEvent("one")}); !errors.Is(err, ErrInvalidInput) {
			t.Fatalf("error = %v", err)
		}
	})
	t.Run("duplicate event identity", func(t *testing.T) {
		client := mustClient(t, Config{Endpoint: server.URL, Database: "analytics_test"}, server.Client())
		event := validAccessEvent("duplicate")
		if err := client.WriteAccessEvents(context.Background(), "batch", []AccessEvent{event, event}); !errors.Is(err, ErrInvalidInput) {
			t.Fatalf("error = %v", err)
		}
	})
	t.Run("bad batch id", func(t *testing.T) {
		client := mustClient(t, Config{Endpoint: server.URL, Database: "analytics_test"}, server.Client())
		if err := client.WriteAccessEvents(context.Background(), "bad batch", []AccessEvent{validAccessEvent("one")}); !errors.Is(err, ErrInvalidInput) {
			t.Fatalf("error = %v", err)
		}
	})
}

func TestSummaryBindsTenantAndResourceScope(t *testing.T) {
	t.Parallel()
	var observedBody string
	var observedParameters url.Values
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		encoded, _ := io.ReadAll(request.Body)
		observedBody = string(encoded)
		observedParameters = request.URL.Query()
		writer.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(writer, summaryResponse())
	}))
	defer server.Close()
	client := mustClient(t, Config{Endpoint: server.URL, Database: "analytics_test"}, server.Client())
	scope, err := TenantScope(testTenantID)
	if err != nil {
		t.Fatal(err)
	}
	filter := validFilter()
	filter.SiteID = testSiteID
	filter.NodeID = testNodeID
	summary, err := client.Summary(context.Background(), scope, filter)
	if err != nil {
		t.Fatal(err)
	}
	if summary.RequestCount != 7 || summary.TotalBytes != 900 || summary.SecurityEvents != 2 {
		t.Fatalf("summary = %#v", summary)
	}
	for _, value := range []string{testTenantID, testSiteID, testNodeID} {
		if strings.Contains(observedBody, value) {
			t.Fatalf("query SQL interpolated scope value %q", value)
		}
	}
	if !strings.Contains(observedBody, "{tenant_id:String}") || !strings.Contains(observedBody, "{site_id:String}") {
		t.Fatal("query does not contain ClickHouse named parameters")
	}
	checks := map[string]string{
		"param_tenant_scoped": "1", "param_tenant_id": testTenantID,
		"param_has_site": "1", "param_site_id": testSiteID,
		"param_has_node": "1", "param_node_id": testNodeID,
	}
	for key, expected := range checks {
		if actual := observedParameters.Get(key); actual != expected {
			t.Fatalf("%s = %q, want %q", key, actual, expected)
		}
	}
}

func TestAdminScopeIsExplicitAndUnscoped(t *testing.T) {
	t.Parallel()
	var parameters url.Values
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		parameters = request.URL.Query()
		_, _ = io.WriteString(writer, summaryResponse())
	}))
	defer server.Close()
	client := mustClient(t, Config{Endpoint: server.URL, Database: "analytics_test"}, server.Client())
	if _, err := client.Summary(context.Background(), Scope{}, validFilter()); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("zero scope error = %v", err)
	}
	if _, err := client.Summary(context.Background(), AdminScope(), validFilter()); err != nil {
		t.Fatal(err)
	}
	if parameters.Get("param_tenant_scoped") != "0" || parameters.Get("param_tenant_id") != nilUUIDValue {
		t.Fatalf("admin parameters = %v", parameters)
	}
}

func TestQueryTimeoutAndCancellation(t *testing.T) {
	t.Parallel()
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, request *http.Request) {
		select {
		case <-request.Context().Done():
		case <-release:
		}
	}))
	defer server.Close()
	defer close(release)
	client := mustClient(t, Config{
		Endpoint: server.URL, Database: "analytics_test", QueryTimeout: 25 * time.Millisecond,
	}, server.Client())

	if _, err := client.Summary(context.Background(), AdminScope(), validFilter()); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("timeout error = %v", err)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := client.Summary(cancelled, AdminScope(), validFilter()); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancel error = %v", err)
	}
}

func TestHTTPFailureResponseLimitAndBadResponses(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name        string
		status      int
		body        string
		responseMax int64
		want        error
	}{
		{name: "server error", status: http.StatusServiceUnavailable, body: "storage-secret", want: &HTTPError{}},
		{name: "response limit", status: http.StatusOK, body: strings.Repeat("x", 65), responseMax: 64, want: ErrResponseTooLarge},
		{name: "malformed JSON", status: http.StatusOK, body: "{", want: ErrInvalidResponse},
		{name: "unknown response field", status: http.StatusOK, body: summaryResponseWith(`,"unknown":1`), want: ErrInvalidResponse},
		{name: "missing summary row", status: http.StatusOK, body: "", want: ErrInvalidResponse},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
				writer.WriteHeader(test.status)
				_, _ = io.WriteString(writer, test.body)
			}))
			defer server.Close()
			client := mustClient(t, Config{
				Endpoint: server.URL, Database: "analytics_test", MaxResponseBytes: test.responseMax,
			}, server.Client())
			_, err := client.Summary(context.Background(), AdminScope(), validFilter())
			var httpError *HTTPError
			if errors.As(test.want, &httpError) {
				if !errors.As(err, &httpError) || httpError.StatusCode != test.status || !httpError.Retryable() {
					t.Fatalf("HTTP error = %v", err)
				}
			} else if !errors.Is(err, test.want) {
				t.Fatalf("error = %v, want %v", err, test.want)
			}
			if err != nil && strings.Contains(err.Error(), "storage-secret") {
				t.Fatalf("error leaked response body: %v", err)
			}
		})
	}
}

func TestSecretsAreRedactedFromClientAndTransportErrors(t *testing.T) {
	t.Parallel()
	const secret = "do-not-log-this-password"
	transport := roundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, errors.New(secret)
	})
	client := mustClient(t, Config{
		Endpoint: "https://clickhouse.example.test", Database: "analytics_test", Username: "analytics", Password: secret,
	}, &http.Client{Transport: transport})
	for _, rendered := range []string{fmt.Sprint(client), fmt.Sprintf("%#v", client)} {
		if strings.Contains(rendered, secret) {
			t.Fatalf("rendered client leaked secret: %s", rendered)
		}
	}
	_, err := client.Summary(context.Background(), AdminScope(), validFilter())
	if !errors.Is(err, ErrTransport) || strings.Contains(err.Error(), secret) {
		t.Fatalf("transport error = %v", err)
	}
}

func TestTrendAndTopModels(t *testing.T) {
	t.Parallel()
	var call atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		body, _ := io.ReadAll(request.Body)
		if call.Add(1) == 1 {
			_, _ = io.WriteString(writer, `{"bucket_unix":4070908800,"metric_version":1,"request_count":3,"request_bytes":30,"response_bytes":300,"total_bytes":330,"average_bandwidth_bps":0.6666666667,"status_2xx":2,"status_3xx":0,"status_4xx":1,"status_5xx":0,"security_events":1,"security_event_rows":1,"cache_hit_requests":0,"cache_hit_bytes":0,"unique_client_ips":1}`+"\n")
			return
		}
		if !strings.Contains(string(body), "GROUP BY status_code") || request.URL.Query().Get("param_row_limit") != "5" {
			t.Error("top query did not use the fixed status template and bound limit")
		}
		_, _ = io.WriteString(writer, `{"key":"200","request_count":2,"response_bytes":250,"security_events":0}`+"\n")
	}))
	defer server.Close()
	client := mustClient(t, Config{Endpoint: server.URL, Database: "analytics_test"}, server.Client())
	trend, err := client.Trend(context.Background(), AdminScope(), validFilter())
	if err != nil || len(trend) != 1 || trend[0].RequestCount != 3 || trend[0].Hour.Location() != time.UTC {
		t.Fatalf("trend=%#v error=%v", trend, err)
	}
	top, err := client.Top(context.Background(), AdminScope(), validFilter(), TopByStatusCode, 5)
	if err != nil || len(top) != 1 || top[0].Key != "200" {
		t.Fatalf("top=%#v error=%v", top, err)
	}
	if _, err := client.Top(context.Background(), AdminScope(), validFilter(), TopDimension(99), 5); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("invalid dimension error = %v", err)
	}
}

func TestConfigurationAndInputValidation(t *testing.T) {
	t.Parallel()
	if !ValidDatabaseIdentifier("a"+strings.Repeat("b", MaxDatabaseIdentifierBytes-1)) ||
		ValidDatabaseIdentifier("a"+strings.Repeat("b", MaxDatabaseIdentifierBytes)) {
		t.Fatal("database identifier byte boundary is inconsistent")
	}
	for _, config := range []Config{
		{},
		{Endpoint: "ftp://localhost", Database: "analytics"},
		{Endpoint: "http://clickhouse.example.test", Database: "analytics"},
		{Endpoint: "https://user:password@localhost", Database: "analytics"},
		{Endpoint: "https://localhost/path", Database: "analytics"},
		{Endpoint: "https://localhost", Database: "bad-name"},
		{Endpoint: "https://localhost", Database: "a" + strings.Repeat("b", MaxDatabaseIdentifierBytes)},
		{Endpoint: "https://localhost", Database: "analytics", Password: "password-without-user"},
	} {
		if _, err := NewClient(config, nil); !errors.Is(err, ErrInvalidConfiguration) {
			t.Fatalf("config %#v error = %v", config, err)
		}
	}
	if _, err := TenantScope("not-a-uuid"); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("tenant scope error = %v", err)
	}
	client := mustClient(t, Config{Endpoint: "https://localhost", Database: "analytics"}, &http.Client{})
	filter := validFilter()
	filter.From = filter.From.Add(time.Second) // summary 要求分钟对齐
	if _, err := client.Summary(context.Background(), AdminScope(), filter); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("unaligned filter error = %v", err)
	}
	event := validAccessEvent("invalid-version")
	event.MetricVersion = 2
	if err := client.WriteAccessEvents(context.Background(), "batch", []AccessEvent{event}); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("metric version error = %v", err)
	}
}

func mustClient(t *testing.T, config Config, httpClient HTTPClient) *Client {
	t.Helper()
	client, err := NewClient(config, httpClient)
	if err != nil {
		t.Fatal(err)
	}
	// Fixtures use one ID as both scope and facts' tenant; the scope → tenant
	// mapping itself is covered by scope_tenant_test.go.
	return client.WithTenantResolver(sameTenant{})
}

// sameTenant maps a scope to a tenant with the same ID (test fixtures only).
type sameTenant struct{}

func (sameTenant) TenantOfScope(_ context.Context, scopeID string) (string, error) { return scopeID, nil }

func validAccessEvent(eventID string) AccessEvent {
	return AccessEvent{
		MetricVersion: MetricVersion, EventID: eventID, OccurredAt: time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC),
		TenantID: testTenantID, SiteID: testSiteID, NodeID: testNodeID, InstallationID: "test-installation",
		Host: "example.test", Path: "/asset.js", ClientIP: "2001:db8::1",
		Method: "GET", Protocol: "HTTP/2", CacheStatus: "HIT", StatusCode: 200,
		RequestBytes: 10, ResponseBytes: 100, DurationUS: 1000,
	}
}

func validSecurityEvent(eventID string) SecurityEvent {
	return SecurityEvent{
		MetricVersion: MetricVersion, EventID: eventID, OccurredAt: time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC),
		TenantID: testTenantID, SiteID: testSiteID, NodeID: testNodeID, InstallationID: "test-installation",
		Host: "example.test", Path: "/login", ClientIP: "2001:db8::2",
		EventType: "waf", Action: "block", Severity: "high", StatusCode: 403,
		RequestBytes: 20, ResponseBytes: 30,
	}
}

func validFilter() Filter {
	return Filter{
		From: time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC),
		To:   time.Date(2099, 1, 1, 2, 0, 0, 0, time.UTC),
	}
}

func summaryResponse() string {
	return summaryResponseWith("")
}

func summaryResponseWith(extra string) string {
	return `{"metric_version":1,"request_count":7,"request_bytes":100,"response_bytes":800,"total_bytes":900,"average_bandwidth_bps":0.8888888889,"status_2xx":5,"status_3xx":0,"status_4xx":1,"status_5xx":1,"security_events":2,"security_event_rows":2,"cache_hit_requests":0,"cache_hit_bytes":0,"unique_client_ips":1` + extra + "}\n"
}
