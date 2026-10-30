package qualitydiagnosticshttp

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/analyticslog"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/qualitydiagnostics"
	"github.com/google/uuid"
)

func TestNewProductionHandlerUsesFinalizedAuthorityAndMapsSourceFailure(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 8, 12, 0, 0, 0, time.UTC)
	from, to := now.Add(-time.Hour), now.Add(-time.Minute)
	const (
		productionTenantID       = "018f0000-0000-7000-8000-000000000011"
		productionScopeID        = "018f0000-0000-7000-8000-000000000012"
		productionUserID         = "018f0000-0000-7000-8000-000000000013"
		productionSiteID         = "018f0000-0000-7000-8000-000000000014"
		productionNodeID         = "018f0000-0000-7000-8000-000000000015"
		productionConfigID       = "018f0000-0000-7000-8000-000000000016"
		productionInstallationID = "018f0000-0000-7000-8000-000000000017"
		productionTaskID         = "018f0000-0000-7000-8000-000000000018"
	)

	var failed atomic.Bool
	var captured struct {
		sync.Mutex
		query url.Values
		body  string
	}
	clickhouse := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if failed.Load() {
			http.Error(writer, "raw clickhouse password secret", http.StatusServiceUnavailable)
			return
		}
		body, _ := io.ReadAll(request.Body)
		captured.Lock()
		captured.query = request.URL.Query()
		captured.body = string(body)
		captured.Unlock()

		snapshotMS := now.Add(-time.Millisecond).UnixMilli()
		finalizedMS := to.UnixMilli()
		expiresMS := now.Add(5 * time.Minute).UnixMilli()
		metadata := map[string]any{
			"row_kind": "meta", "tenant_id": productionTenantID,
			"snapshot_ms": snapshotMS, "source_watermark": uint64(44),
			"finalized_through_ms": finalizedMS, "expires_at_ms": expiresMS,
			"latest_count": uint64(1), "authority_count": uint64(1), "conflict_count": uint64(0),
			"evidence_digest": strings.Repeat("ab", 32),
		}
		event := map[string]any{
			"row_kind": "event", "tenant_id": productionTenantID, "event_id": "event-production-1",
			"occurred_at_ms": to.Add(-time.Minute).UnixMilli(), "site_id": productionSiteID, "node_id": productionNodeID,
			"request_id": "request-production-1", "trace_id": "trace-production-1",
			"config_version_id": productionConfigID, "host": "cdn.example.test",
			"upstream_result": "origin-password-secret", "status_code": uint16(502),
			"task_id": productionTaskID, "installation_id": productionInstallationID,
			"latest_version_count": uint64(1), "snapshot_ms": snapshotMS, "source_watermark": uint64(44),
			"finalized_through_ms": finalizedMS, "expires_at_ms": expiresMS,
			"latest_count": uint64(1), "authority_count": uint64(1), "conflict_count": uint64(0),
			"evidence_digest": strings.Repeat("ab", 32),
		}
		_ = json.NewEncoder(writer).Encode(metadata)
		_ = json.NewEncoder(writer).Encode(event)
	}))
	defer clickhouse.Close()

	client, err := analyticslog.NewClient(analyticslog.ClientConfig{
		Endpoint: clickhouse.URL, Database: "quality_diagnostics_production", QueryTimeout: time.Second,
		CursorKeyring: analyticslog.CursorKeyring{ActiveKID: "production", Keys: map[string][]byte{
			"production": []byte(strings.Repeat("k", 32)),
		}},
	}, clickhouse.Client())
	if err != nil {
		t.Fatal(err)
	}
	tenant := uuid.MustParse(productionTenantID)
	handler, err := NewProductionHandler(ProductionConfig{
		Source:  analyticslog.FinalizedAccessConfig{QueryTimeout: time.Second, MaxConcurrent: 1, Now: func() time.Time { return now }},
		Service: qualitydiagnostics.RuntimeConfig{CursorKey: []byte(strings.Repeat("c", 32)), Now: func() time.Time { return now }},
		Handler: Config{QueryTimeout: time.Second},
	}, ProductionDependencies{
		Client: client,
		Authenticate: func(*http.Request) (identity.Principal, error) {
			return identity.Principal{
				UserID: uuid.MustParse(productionUserID), ScopeID: uuid.MustParse(productionScopeID),
				ScopeKind: "tenant", TenantID: &tenant, Permissions: []string{analyticslog.ReadPermission},
			}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	query := url.Values{
		"from": {from.Format(time.RFC3339Nano)}, "to": {to.Format(time.RFC3339Nano)},
		"site_id": {productionSiteID}, "node_id": {productionNodeID},
		"category": {string(qualitydiagnostics.CategoryUpstream5xx)}, "limit": {"20"},
	}
	request := httptest.NewRequest(http.MethodGet, "/v1/analytics/quality-diagnostics?"+query.Encode(), nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"source_watermark":44`) ||
		!strings.Contains(response.Body.String(), `"cause_code":"upstream_result_unknown"`) ||
		!strings.Contains(response.Body.String(), `"action_code":"inspect_upstream"`) ||
		strings.Contains(response.Body.String(), "origin-password-secret") {
		t.Fatalf("production response = %d %s", response.Code, response.Body.String())
	}
	captured.Lock()
	if captured.query.Get("param_tenant_id") != productionTenantID || captured.query.Get("param_site_id") != productionSiteID ||
		captured.query.Get("param_node_id") != productionNodeID || captured.query.Get("param_category") != "upstream_5xx" ||
		!strings.Contains(captured.body, "access_event_latest_state_v1") ||
		!strings.Contains(captured.body, "site_realtime_access_facts_v1") {
		t.Fatalf("finalized query = %v body=%s", captured.query, captured.body)
	}
	captured.Unlock()

	failed.Store(true)
	failure := httptest.NewRecorder()
	handler.ServeHTTP(failure, httptest.NewRequest(http.MethodGet, "/v1/analytics/quality-diagnostics?"+query.Encode(), nil))
	if failure.Code != http.StatusServiceUnavailable ||
		!strings.Contains(failure.Body.String(), `"code":"quality_diagnostics_unavailable"`) ||
		strings.Contains(failure.Body.String(), "password") {
		t.Fatalf("source failure = %d %s", failure.Code, failure.Body.String())
	}
}
