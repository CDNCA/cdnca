package analyticslog

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

// stats-platform-l7: the platform operator opens access logs, block events
// and CC bans without a tenant and reads every tenant; the tenant filter only
// narrows. Tenants still read their own tenant only.

func TestPlatformScopeWithoutTenantReadsEveryTenant(t *testing.T) {
	platform := Actor{ScopeKind: "platform", Permissions: []string{"platform.admin"}}
	tenant := Actor{ScopeKind: "tenant", TenantID: tenantA, Permissions: []string{ReadPermission}}

	got, err := authorizeScope(platform, AudiencePlatform, "")
	if err != nil || !got.platform() {
		t.Fatalf("platform without tenant = %#v, %v", got, err)
	}
	if got, err := authorizeScope(platform, AudiencePlatform, tenantB); err != nil || got.tenantID != tenantB {
		t.Fatalf("platform tenant filter = %#v, %v", got, err)
	}
	if _, err := authorizeScope(platform, AudiencePlatform, "not-a-uuid"); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("invalid tenant filter error = %v", err)
	}
	// A tenant can neither widen to the platform nor name another tenant.
	if got, err := authorizeScope(tenant, AudienceTenant, ""); err != nil || got.tenantID != tenantA {
		t.Fatalf("tenant scope = %#v, %v", got, err)
	}
	if _, err := authorizeScope(tenant, AudiencePlatform, ""); !errors.Is(err, ErrScopeForbidden) {
		t.Fatalf("tenant on platform audience error = %v", err)
	}
	if _, err := authorizeScope(tenant, AudienceTenant, tenantB); !errors.Is(err, ErrScopeForbidden) {
		t.Fatalf("tenant naming another tenant error = %v", err)
	}
	// Exports are tenant-owned artifacts and still require a tenant.
	if _, err := authorizeExportScope(platform, AudiencePlatform, ""); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("platform-wide export error = %v", err)
	}
	if got, err := authorizeExportScope(platform, AudiencePlatform, tenantB); err != nil || got.tenantID != tenantB {
		t.Fatalf("platform export tenant = %#v, %v", got, err)
	}
}

func TestPlatformScopeQueryParametersDropTenantPredicate(t *testing.T) {
	now := time.Date(2026, 7, 23, 12, 0, 0, 0, time.UTC)
	filter := Filter{From: now.Add(-time.Hour), To: now}

	platform := filterParameters(scope{}, filter, 50)
	if platform.Get("param_tenant_scoped") != "0" || platform.Get("param_tenant_id") != nilUUID {
		t.Fatalf("platform parameters = %#v", platform)
	}
	tenant := filterParameters(scope{tenantID: tenantA}, filter, 50)
	if tenant.Get("param_tenant_scoped") != "1" || tenant.Get("param_tenant_id") != tenantA {
		t.Fatalf("tenant parameters = %#v", tenant)
	}
	// Cursors cannot be replayed across scopes.
	if logFingerprint(scope{}, filter, "access.desc") == logFingerprint(scope{tenantID: tenantA}, filter, "access.desc") {
		t.Fatal("platform and tenant cursors share a fingerprint")
	}
	// Every page query keeps the time window and row limit with the optional
	// tenant predicate, so a platform read stays bounded.
	for name, query := range map[string]string{"access": accessPageSQL, "security": blockEventPageSQL, "cc_bans": ccBanHistorySQL} {
		if strings.Contains(query, "AND tenant_id = toUUID({tenant_id:String})") {
			t.Fatalf("%s still forces a tenant predicate", name)
		}
		for _, required := range []string{
			"({tenant_scoped:UInt8} = 0 OR tenant_id = toUUID({tenant_id:String}))",
			"occurred_at >= fromUnixTimestamp64Milli({from_ms:Int64}, 'UTC')",
			"occurred_at < fromUnixTimestamp64Milli({to_ms:Int64}, 'UTC')",
			"LIMIT {row_limit:UInt16}",
		} {
			if !strings.Contains(query, required) {
				t.Fatalf("%s query is missing %q", name, required)
			}
		}
	}
}

func TestPlatformWideClientReadsSendUnscopedParameters(t *testing.T) {
	now := time.Date(2026, 7, 23, 12, 0, 0, 0, time.UTC)
	var mutex sync.Mutex
	var queries []url.Values
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		_, _ = io.Copy(io.Discard, request.Body)
		mutex.Lock()
		queries = append(queries, request.URL.Query())
		mutex.Unlock()
	}))
	defer server.Close()
	client := newUnitClient(t, server, time.Second)
	filter := Filter{From: now.Add(-time.Hour), To: now}

	if page, err := client.ListAccess(context.Background(), scope{}, filter, 20, ""); err != nil || len(page.Items) != 0 {
		t.Fatalf("platform ListAccess = %#v, %v", page, err)
	}
	if page, err := client.ListBlockEvents(context.Background(), scope{}, filter, 20, ""); err != nil || len(page.Items) != 0 {
		t.Fatalf("platform ListBlockEvents = %#v, %v", page, err)
	}
	if page, err := client.ListCCBans(context.Background(), scope{}, filter, 20); err != nil || len(page.Items) != 0 {
		t.Fatalf("platform ListCCBans = %#v, %v", page, err)
	}
	if len(queries) != 3 {
		t.Fatalf("queries = %d", len(queries))
	}
	for index, query := range queries {
		if query.Get("param_tenant_scoped") != "0" || query.Get("param_tenant_id") != nilUUID || query.Get("param_row_limit") != "21" {
			t.Fatalf("query %d = %#v", index, query)
		}
	}
	// A malformed tenant is still rejected before ClickHouse.
	if _, err := client.ListAccess(context.Background(), scope{tenantID: "bad"}, filter, 20, ""); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("malformed tenant error = %v", err)
	}
}

func TestPlatformHandlerListsBlockEventsWithoutTenant(t *testing.T) {
	now := time.Date(2026, 7, 23, 12, 0, 0, 0, time.UTC)
	store := &recordingStore{blockPage: BlockEventPage{Items: []BlockEvent{}}}
	platform := Actor{ScopeKind: "platform", Permissions: []string{"platform.admin"}}
	handler := newTestHandler(t, store, platform, HandlerConfig{})
	response := doGET(handler, "/v1/admin/analytics/logs/block-events", queryValues(now.Add(-time.Hour), now))
	if response.Code != http.StatusOK || store.blockCalls != 1 || !store.lastScope.platform() {
		t.Fatalf("platform block events = %d scope=%q body=%s", response.Code, store.lastScope.tenantID, response.Body.String())
	}
	tenant := Actor{ScopeKind: "tenant", TenantID: tenantA, Permissions: []string{ReadPermission}}
	tenantHandler := newTestHandler(t, store, tenant, HandlerConfig{})
	if response := doGET(tenantHandler, "/v1/analytics/logs/block-events", queryValues(now.Add(-time.Hour), now)); response.Code != http.StatusOK ||
		store.lastScope.tenantID != tenantA {
		t.Fatalf("tenant block events = %d scope=%q", response.Code, store.lastScope.tenantID)
	}
}
