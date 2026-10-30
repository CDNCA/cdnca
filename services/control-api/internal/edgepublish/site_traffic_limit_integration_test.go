//go:build integration

package edgepublish

import (
	"encoding/json"
	"testing"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/google/uuid"
)

// TestSiteRuntimeV2CarriesSiteTrafficLimit (ge-analytics): a site over its
// own traffic cap is released with traffic_limit (period + notice page) and
// the node accepts the document; within its caps, or with the limit
// disabled, nothing is carried.
func TestSiteRuntimeV2CarriesSiteTrafficLimit(t *testing.T) {
	fixture := newL4V2ContractFixture(t)
	site := fixture.createSite(t, "traffic-limit-v2.example.com", 18094, false).Site
	revision := fixture.sourceRevision()
	seedSiteRuntimeV2Capabilities(t, fixture, "", append(siteRuntimeV2CapabilitiesWithoutSiteRuntime(),
		&agentv1.Capability{Name: agentv1.CapabilityName_CAPABILITY_NAME_SITE_RUNTIME, ApiVersion: edgeconfig.DynamicRoutingSiteRuntimeVersion}))
	compile := func() *siteRuntimeV2Document {
		t.Helper()
		tx, err := fixture.pool.Begin(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(t.Context())
		if _, err := tx.Exec(t.Context(), `INSERT INTO node_config_state(node_id,configuration_scope_id,updated_at)
			VALUES($1,$2,now()) ON CONFLICT DO NOTHING`, fixture.nodeID, fixture.scopeID); err != nil {
			t.Fatal(err)
		}
		canonical, _, _, _, _, _, err := fixture.service.compileSiteRuntimeV2Facts(t.Context(), tx, fixture.scopeID, uuid.New(),
			revision, TargetSnapshot{NodeIDs: []uuid.UUID{fixture.nodeID}}, publishTestClock, nil)
		if err != nil {
			t.Fatalf("compile: %v", err)
		}
		var document siteRuntimeV2Document
		if err := json.Unmarshal(canonical, &document); err != nil {
			t.Fatal(err)
		}
		return &document
	}
	if document := compile(); document.Sites[0].TrafficLimit != nil {
		t.Fatalf("no limit row carried %+v", document.Sites[0].TrafficLimit)
	}
	if _, err := fixture.pool.Exec(t.Context(), `INSERT INTO site_traffic_limits(scope_id,site_id,enabled,daily_bytes,time_zone,
		notice_html,updated_by_user_id,updated_at) VALUES($1,$2,true,100,'UTC','<p>over</p>',$3,now())`,
		fixture.scopeID, site.ID, fixture.userID); err != nil {
		t.Fatal(err)
	}
	if document := compile(); document.Sites[0].TrafficLimit != nil {
		t.Fatalf("a site within its caps carried %+v", document.Sites[0].TrafficLimit)
	}
	if _, err := fixture.pool.Exec(t.Context(), `UPDATE site_traffic_limits SET exceeded_period='daily',exceeded_at=now(),
		exceeded_period_start=date_trunc('day',now()) WHERE site_id=$1`, site.ID); err != nil {
		t.Fatal(err)
	}
	document := compile()
	limit := document.Sites[0].TrafficLimit
	if limit == nil || !limit.Exceeded || limit.Period != "daily" || limit.NoticeHTML != "<p>over</p>" {
		t.Fatalf("exceeded site traffic limit = %+v", limit)
	}
	if _, err := fixture.pool.Exec(t.Context(), `UPDATE site_traffic_limits SET enabled=false,exceeded_period=NULL,
		exceeded_at=NULL,exceeded_period_start=NULL WHERE site_id=$1`, site.ID); err != nil {
		t.Fatal(err)
	}
	if document := compile(); document.Sites[0].TrafficLimit != nil {
		t.Fatalf("a disabled limit carried %+v", document.Sites[0].TrafficLimit)
	}
}
