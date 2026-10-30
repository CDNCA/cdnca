//go:build integration

package analytics

import (
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/firewallcontrol"
	"github.com/google/uuid"
)

// TestFirewallHitsReadProductionFacts (待出包前全量跑; needs
// TEST_DATABASE_URL and TEST_CLICKHOUSE_URL/TEST_CLICKHOUSE_DATABASE): a
// global firewall hit is stored the way the gateway accepts it, under
// access_scopes.tenant_id (agents/edge-agent telemetry_sources.go
// bindFirewallHits, agent-gateway telemetry_validation.go), and the hit API,
// keyed by the policy's scope, reads it back through the production
// PostgresTenants resolver. Before the fix the read queried the scope ID.
func TestFirewallHitsReadProductionFacts(t *testing.T) {
	if os.Getenv("TEST_DATABASE_URL") == "" {
		t.Skip("TEST_DATABASE_URL is not set")
	}
	chDatabase := newRankTestDatabase(t)
	chDatabase.reset(t)
	applyAllClickHouseMigrations(t, chDatabase)
	pool := scopeTenantIntegrationPool(t)
	ctx := t.Context()

	tenantID, scopeID := uuid.New(), uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO tenants(id,display_name) VALUES($1,'fw-tenantid')`, tenantID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO access_scopes(id,kind,tenant_id) VALUES($1,'tenant',$2)`, scopeID, tenantID); err != nil {
		t.Fatal(err)
	}
	client, err := NewClient(Config{Endpoint: chDatabase.endpoint, Database: chDatabase.name,
		Username: chDatabase.username, Password: chDatabase.password, QueryTimeout: 5 * time.Second},
		&http.Client{Timeout: 10 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	client.WithTenantResolver(PostgresTenants{Query: pool})

	siteID, nodeID, ruleID := uuid.New(), uuid.New(), uuid.New()
	event := validSecurityEvent("fw-tenantid-hit")
	event.OccurredAt = time.Now().UTC().Add(-time.Minute).Truncate(time.Millisecond)
	event.TenantID, event.SiteID, event.NodeID = tenantID.String(), siteID.String(), nodeID.String()
	event.Host, event.Path, event.Method, event.ClientIP = "-", "/", "NETWORK", "198.51.100.8"
	event.ListenPort, event.DestinationPort, event.Protocol, event.RequestClass = 443, 443, "tcp", "network"
	event.EventType, event.Action, event.Severity, event.RuleID = "global_firewall", "block", "medium", ruleID.String()
	event.StatusCode, event.RequestBytes, event.ResponseBytes = 0, 0, 0
	if err := client.WriteSecurityEvents(ctx, "fw-tenantid-batch", []SecurityEvent{event}); err != nil {
		t.Fatal(err)
	}

	page, err := client.ListFirewallHits(ctx, firewallcontrol.HitFilter{TargetScopeID: scopeID, Limit: 10})
	if err != nil || len(page.Items) != 1 || page.Items[0].TenantScopeID != scopeID || page.Items[0].SiteID != siteID ||
		page.Items[0].RuleID != ruleID {
		t.Fatalf("ListFirewallHits = %+v, %v; want the hit under scope %s", page, err, scopeID)
	}
	bySite, err := client.ListFirewallHits(ctx, firewallcontrol.HitFilter{TargetScopeID: scopeID, SiteID: siteID, Limit: 10})
	if err != nil || len(bySite.Items) != 1 {
		t.Fatalf("ListFirewallHits by site = %+v, %v", bySite, err)
	}
	// Another tenant's scope sees nothing of it.
	otherTenant, otherScope := uuid.New(), uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO tenants(id,display_name) VALUES($1,'fw-tenantid-other')`, otherTenant); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO access_scopes(id,kind,tenant_id) VALUES($1,'tenant',$2)`, otherScope, otherTenant); err != nil {
		t.Fatal(err)
	}
	if other, err := client.ListFirewallHits(ctx, firewallcontrol.HitFilter{TargetScopeID: otherScope, Limit: 10}); err != nil || len(other.Items) != 0 {
		t.Fatalf("other tenant's scope = %+v, %v; want no hit", other, err)
	}
}
