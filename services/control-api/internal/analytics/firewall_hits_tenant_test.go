package analytics

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/firewallcontrol"
	"github.com/google/uuid"
)

// Global firewall hits are stored under the site's tenant (tenants.id, what
// the gateway accepts), while the hit API is keyed by the policy's scope.
// The read must query the tenant and report the hits under the scope.
func TestListFirewallHitsQueriesTheScopesTenant(t *testing.T) {
	scopeID, tenantID := uuid.MustParse(scopeTenantTestScopeID), uuid.MustParse(scopeTenantTestTenantID)
	siteID, nodeID := uuid.New(), uuid.New()
	var mu sync.Mutex
	var queried []string
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		body, _ := io.ReadAll(request.Body)
		tenant := request.URL.Query().Get("param_tenant_id")
		mu.Lock()
		queried = append(queried, tenant)
		mu.Unlock()
		if tenant != tenantID.String() {
			return // facts carry tenants.id: a scope ID matches no row
		}
		if strings.Contains(string(body), "LIMIT 1") && !strings.Contains(string(body), "row_limit") {
			_, _ = io.WriteString(writer, `{"occurred_at_ms":1800000000000,"event_id":"hit-1"}`+"\n")
			return
		}
		_, _ = io.WriteString(writer, `{"event_id":"hit-1","occurred_at_ms":1800000000000,"tenant_id":"`+tenantID.String()+
			`","site_id":"`+siteID.String()+`","node_id":"`+nodeID.String()+
			`","rule_id":"","client_ip":"198.51.100.8","protocol":"tcp","destination_port":443,"action":"block"}`+"\n")
	}))
	defer server.Close()
	client := mustClient(t, Config{Endpoint: server.URL, Database: "analytics_test"}, server.Client()).
		WithTenantResolver(mapTenants{scopeID.String(): tenantID.String()})

	page, err := client.ListFirewallHits(t.Context(), firewallcontrol.HitFilter{TargetScopeID: scopeID, Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Items) != 1 || page.Items[0].TenantScopeID != scopeID || page.Items[0].SiteID != siteID {
		t.Fatalf("page = %+v, queried tenants = %v", page, queried)
	}
	for _, tenant := range queried {
		if tenant != tenantID.String() {
			t.Fatalf("ClickHouse queried with tenant %s, want tenants.id %s", tenant, tenantID)
		}
	}

	// The platform scope has no tenant, so no hit of it is stored.
	empty, err := client.ListFirewallHits(t.Context(), firewallcontrol.HitFilter{TargetScopeID: uuid.New(), Limit: 10})
	if err != nil || len(empty.Items) != 0 {
		t.Fatalf("scope without tenant: page=%+v err=%v", empty, err)
	}
	// Without a resolver the read fails instead of querying the scope ID.
	bare := mustClient(t, Config{Endpoint: server.URL, Database: "analytics_test"}, server.Client())
	bare.tenants = nil
	if _, err := bare.ListFirewallHits(t.Context(), firewallcontrol.HitFilter{TargetScopeID: scopeID, Limit: 10}); !errors.Is(err, firewallcontrol.ErrUnavailable) {
		t.Fatalf("unresolved read error = %v", err)
	}
}
