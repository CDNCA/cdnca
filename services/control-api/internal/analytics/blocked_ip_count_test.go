package analytics

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

type blockedIPHandlerStore struct {
	QueryStore
	count uint64
	trend []BlockedIPTrendPoint
}

func (store *blockedIPHandlerStore) BlockedIPCount(context.Context, Scope, Filter) (uint64, error) {
	return store.count, nil
}

func (store *blockedIPHandlerStore) BlockedIPTrend(context.Context, Scope, Filter) ([]BlockedIPTrendPoint, error) {
	return store.trend, nil
}

func TestBlockedIPCountBindsSnapshotAndResourceScope(t *testing.T) {
	t.Parallel()
	var observedBody string
	var observedParameters url.Values
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		body, _ := io.ReadAll(request.Body)
		observedBody = string(body)
		observedParameters = request.URL.Query()
		writer.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(writer, `{"blocked_ip_count":3}`)
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
	count, err := client.BlockedIPCount(context.Background(), scope, filter)
	if err != nil || count != 3 {
		t.Fatalf("BlockedIPCount() = %d, %v", count, err)
	}
	for _, value := range []string{testTenantID, testSiteID, testNodeID} {
		if strings.Contains(observedBody, value) {
			t.Fatalf("query SQL interpolated scope value %q", value)
		}
	}
	for _, token := range []string{"event_type = 'global_firewall'", "action = 'block'", "uniqExact(client_ip)", "{snapshot_ms:UInt64}"} {
		if !strings.Contains(observedBody, token) {
			t.Fatalf("query missing %q: %s", token, observedBody)
		}
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

func TestBlockedIPCountHandlerUsesTheSameScopeContract(t *testing.T) {
	store := &blockedIPHandlerStore{QueryStore: &recordingQueryStore{}, count: 5}
	handler := mustHandler(t, store, Actor{ScopeKind: "platform", Permissions: []string{"platform.admin"}}, HandlerConfig{})
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet,
		handlerURL("/v1/admin/analytics/blocked-ip-count", ""), nil))
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d body = %s", response.Code, response.Body.String())
	}
	var body struct {
		Count uint64        `json:"blocked_ip_count"`
		Meta  queryMetadata `json:"meta"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Count != 5 || body.Meta.Timezone != "UTC" {
		t.Fatalf("body = %#v", body)
	}
}

func TestBlockedIPTrendBindsSnapshotAndReturnsOrderedBuckets(t *testing.T) {
	t.Parallel()
	var observedBody string
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		body, _ := io.ReadAll(request.Body)
		observedBody = string(body)
		writer.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(writer, `{"bucket_unix":1782864000,"blocked_ip_count":2}
{"bucket_unix":1782867600,"blocked_ip_count":1}
`)
	}))
	defer server.Close()
	client := mustClient(t, Config{Endpoint: server.URL, Database: "analytics_test"}, server.Client())
	scope, err := TenantScope(testTenantID)
	if err != nil {
		t.Fatal(err)
	}
	filter := validFilter()
	filter.From = time.Unix(1782864000, 0).UTC()
	filter.To = filter.From.Add(2 * time.Hour)
	points, err := client.BlockedIPTrend(context.Background(), scope, filter)
	if err != nil || len(points) != 2 || points[0].BlockedIPCount != 2 || points[1].BlockedIPCount != 1 {
		t.Fatalf("BlockedIPTrend() = %#v, %v", points, err)
	}
	for _, token := range []string{"event_type = 'global_firewall'", "action = 'block'", "uniqExact(client_ip)", "GROUP BY bucket_unix", "{snapshot_ms:UInt64}"} {
		if !strings.Contains(observedBody, token) {
			t.Fatalf("query missing %q: %s", token, observedBody)
		}
	}
}

func TestBlockedIPTrendHandlerReturnsStableSeriesEnvelope(t *testing.T) {
	from := time.Unix(1782864000, 0).UTC()
	store := &blockedIPHandlerStore{QueryStore: &recordingQueryStore{}, trend: []BlockedIPTrendPoint{{Hour: from, BlockedIPCount: 4}}}
	handler := mustHandler(t, store, Actor{ScopeKind: "platform", Permissions: []string{"platform.admin"}}, HandlerConfig{})
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet,
		handlerURL("/v1/admin/analytics/blocked-ip-trend", ""), nil))
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d body = %s", response.Code, response.Body.String())
	}
	var body struct {
		Data []struct {
			Hour  string `json:"hour"`
			Count uint64 `json:"blocked_ip_count"`
		} `json:"data"`
		Meta queryMetadata `json:"meta"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if len(body.Data) != 1 || body.Data[0].Count != 4 || body.Data[0].Hour != from.Format(time.RFC3339Nano) || body.Meta.Timezone != "UTC" {
		t.Fatalf("body = %#v", body)
	}
}
