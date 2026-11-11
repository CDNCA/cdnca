//go:build integration

package edgepublish

import (
	"errors"
	"testing"
	"time"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/google/uuid"
)

// a site with server_timing on requires
// SITE_SERVER_TIMING v1; a node without it is refused (and named), with it
// the release requires it. A site held at attack escalation B publishes it
// off and requires nothing. The site fact follows the same rule.
func TestSiteServerTimingCapabilityGateFromDatabase(t *testing.T) {
	setup := func(t *testing.T, capable bool) (*publishFixture, uuid.UUID) {
		t.Helper()
		fixture := newL4V2ContractFixture(t)
		site := fixture.createSite(t, "server-timing.example.com", 18095, false).Site
		features := append(siteRuntimeV2CapabilitiesWithoutSiteRuntime(),
			&agentv1.Capability{Name: agentv1.CapabilityName_CAPABILITY_NAME_SITE_RUNTIME, ApiVersion: edgeconfig.DynamicRoutingSiteRuntimeVersion})
		if capable {
			features = append(features, &agentv1.Capability{Name: agentv1.CapabilityName_CAPABILITY_NAME_SITE_SERVER_TIMING, ApiVersion: 1})
		}
		seedSiteRuntimeV2Capabilities(t, fixture, "", features)
		return fixture, site.ID
	}
	compile := func(t *testing.T, fixture *publishFixture) ([]*agentv1.Capability, error) {
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
		_, _, _, _, capabilities, _, err := fixture.service.compileSiteRuntimeV2Facts(t.Context(), tx, fixture.scopeID, uuid.New(),
			fixture.sourceRevision(), TargetSnapshot{NodeIDs: []uuid.UUID{fixture.nodeID}}, publishTestClock, nil)
		return capabilities, err
	}
	fact := func(t *testing.T, fixture *publishFixture, siteID uuid.UUID) bool {
		t.Helper()
		tx, err := fixture.pool.Begin(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(t.Context())
		facts := map[string]siteObjectV2Facts{}
		if err := loadSiteCacheStatusHeaders(t.Context(), tx, fixture.scopeID, facts); err != nil {
			t.Fatal(err)
		}
		return facts[siteID.String()].ServerTiming
	}
	enable := func(t *testing.T, fixture *publishFixture, siteID uuid.UUID) {
		t.Helper()
		if _, err := fixture.pool.Exec(t.Context(), `UPDATE sites SET server_timing=true WHERE id=$1`, siteID); err != nil {
			t.Fatal(err)
		}
	}
	escalate := func(t *testing.T, fixture *publishFixture, siteID uuid.UUID, level string) {
		t.Helper()
		if _, err := fixture.pool.Exec(t.Context(), `INSERT INTO escalate_site_states(tenant_scope_id,site_id,level,applied_level,
				entered_at,revision,updated_at) VALUES($1,$2,$3,$3,$4,1,$4)`, fixture.scopeID, siteID, level, time.Now().UTC()); err != nil {
			t.Fatal(err)
		}
	}

	t.Run("off requires nothing", func(t *testing.T) {
		fixture, siteID := setup(t, false)
		capabilities, err := compile(t, fixture)
		if err != nil || siteRuntimeCapability(capabilities, agentv1.CapabilityName_CAPABILITY_NAME_SITE_SERVER_TIMING) != 0 {
			t.Fatalf("release with the switch off: %v %v", capabilities, err)
		}
		if fact(t, fixture, siteID) {
			t.Fatal("fact on with the switch off")
		}
	})
	t.Run("node without SITE_SERVER_TIMING is refused", func(t *testing.T) {
		fixture, siteID := setup(t, false)
		enable(t, fixture, siteID)
		var refusal *TargetCapabilityError
		if _, err := compile(t, fixture); !errors.As(err, &refusal) ||
			refusal.Capability != agentv1.CapabilityName_CAPABILITY_NAME_SITE_SERVER_TIMING || refusal.NodeID != fixture.nodeID {
			t.Fatalf("node without SITE_SERVER_TIMING: %v", err)
		}
	})
	t.Run("capable node gets a release that requires it", func(t *testing.T) {
		fixture, siteID := setup(t, true)
		enable(t, fixture, siteID)
		capabilities, err := compile(t, fixture)
		if err != nil || siteRuntimeCapability(capabilities, agentv1.CapabilityName_CAPABILITY_NAME_SITE_SERVER_TIMING) != 1 {
			t.Fatalf("release with the switch on: %v %v", capabilities, err)
		}
		if !fact(t, fixture, siteID) {
			t.Fatal("fact off with the switch on")
		}
	})
	t.Run("escalated to B publishes it off", func(t *testing.T) {
		fixture, siteID := setup(t, false)
		enable(t, fixture, siteID)
		escalate(t, fixture, siteID, "B")
		capabilities, err := compile(t, fixture)
		if err != nil || siteRuntimeCapability(capabilities, agentv1.CapabilityName_CAPABILITY_NAME_SITE_SERVER_TIMING) != 0 {
			t.Fatalf("escalated site: %v %v", capabilities, err)
		}
		if fact(t, fixture, siteID) {
			t.Fatal("fact on at level B")
		}
	})
}
