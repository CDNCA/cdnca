package main

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/analytics"
	"github.com/google/uuid"
)

// Market settlement buckets follow the platform block-page setting (FX60).
func TestMarketUsageSourceFollowsBlockPageSetting(t *testing.T) {
	t.Parallel()
	var excludeParam, tenantParam string
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		if strings.Contains(string(raw), "subscription_minutes_v1") {
			// usage v2 peaks: the second bucket has only node minutes.
			_, _ = io.WriteString(w, `{"bucket_start":1760500800,"peak_bps":9,"max_concurrent":2,"max_requests":1,"max_qps":5,"max_new_cps":1}`+
				"\n"+`{"bucket_start":1760501100,"peak_bps":0,"max_concurrent":1,"max_requests":0,"max_qps":3,"max_new_cps":0}`)
			return
		}
		calls++
		excludeParam = r.URL.Query().Get("param_exclude_blocked")
		tenantParam = r.URL.Query().Get("param_tenant_id")
		_, _ = io.WriteString(w, `{"bucket_start":1760500800,"bytes_out":1000,"requests":3}`)
	}))
	defer server.Close()
	client, err := analytics.NewClient(analytics.Config{Endpoint: server.URL, Database: "analytics_test",
		QueryTimeout: time.Second, MaxResponseBytes: 1 << 20}, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	tenant, subscription := uuid.New(), uuid.New()
	// The facts carry tenants.id, a different UUID from the access scope.
	factsTenant := uuid.New()
	client.WithTenantResolver(marketScopeTenants{tenant.String(): factsTenant.String()})
	start := time.Unix(1760500800, 0).UTC()
	for _, exclude := range []bool{true, false} {
		source := marketUsageSource{analytics: client,
			excludeBlocked: func(context.Context) (bool, error) { return exclude, nil }}
		items, err := source.TrafficBuckets(context.Background(), tenant, subscription, start, start.Add(time.Hour))
		want := map[bool]string{true: "1", false: "0"}[exclude]
		if err != nil || len(items) != 2 || items[0].BytesOut != 1000 || items[0].MaxQPS != 5 || items[0].PeakBPS != 9 ||
			items[1].BytesOut != 0 || items[1].MaxQPS != 3 || items[1].MaxConcurrent != 1 || excludeParam != want ||
			tenantParam != factsTenant.String() {
			t.Fatalf("exclude=%v: items=%+v err=%v param=%q tenant=%q want %s", exclude, items, err, excludeParam, tenantParam, factsTenant)
		}
	}
	// An unreadable setting must not report the bucket either way.
	before := calls
	source := marketUsageSource{analytics: client,
		excludeBlocked: func(context.Context) (bool, error) { return false, errors.New("setting unavailable") }}
	if _, err := source.TrafficBuckets(context.Background(), tenant, subscription, start, start.Add(time.Hour)); err == nil ||
		calls != before {
		t.Fatalf("unreadable setting: err=%v queries=%d", err, calls-before)
	}
}

// marketScopeTenants maps access scopes to tenants (access_scopes.tenant_id).
type marketScopeTenants map[string]string

func (tenants marketScopeTenants) TenantOfScope(_ context.Context, scopeID string) (string, error) {
	if tenant, ok := tenants[scopeID]; ok {
		return tenant, nil
	}
	return "", analytics.ErrInvalidInput
}
