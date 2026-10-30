//go:build integration

package edgepublish

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/cdnca/cdnca/libs/edgeconfig/artifactset"
	"github.com/cdnca/cdnca/libs/entitlement/artifactcatalog"
	"github.com/cdnca/cdnca/libs/rulepack"
	"github.com/cdnca/cdnca/services/control-api/internal/rulepackcontrol"
	"github.com/google/uuid"
)

// ADR 0012 §20, ML-25 (U14): on a market tenant whose supply does not
// include the plugin a mounted pack needs (an official pack whose catalog
// entry requires pack.selfwaf), the site object carries no mounts while
// site_security_mounts stays as published; a grant including the plugin
// again puts the pack back. A tenant without a plugin row is not touched.
func TestDynamicRoutingSiteObjectsWithholdMarketPluginPacks(t *testing.T) {
	fixture := newPublishFixture(t)
	seedDynamicRoutingNode(t, fixture, fixture.nodeID)
	site := fixture.createSite(t, "market.example.test", 8080, false).Site.ID

	packs := rulepackcontrol.NewService(fixture.pool, func() time.Time { return publishTestClock })
	platform := rulepackcontrol.Actor{UserID: fixture.platformUserID, ScopeID: fixture.platformScopeID, ScopeKind: "platform"}
	tenant := rulepackcontrol.Actor{UserID: fixture.userID, ScopeID: fixture.scopeID, ScopeKind: "tenant"}
	content, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "libs", "rulepack", "testdata", "packs", "system-sqli.json"))
	if err != nil {
		t.Fatal(err)
	}
	pack, err := packs.Import(t.Context(), platform, content)
	if err != nil {
		t.Fatalf("import pack: %v", err)
	}
	for _, input := range []rulepackcontrol.OverrideInput{
		{Level: rulepack.LevelPlatform, PackID: pack.PackID, State: rulepack.StateDisabled, AllowLower: true},
		{Level: rulepack.LevelSite, LevelObjectID: &site, PackID: pack.PackID, State: rulepack.StateEnabled},
	} {
		if _, _, err := packs.PutOverride(t.Context(), platform, input); err != nil {
			t.Fatalf("override %+v: %v", input, err)
		}
	}
	published, err := packs.PublishSite(t.Context(), tenant, site)
	if err != nil || published.Published == nil {
		t.Fatalf("publish mounts: %v", err)
	}
	security := published.Published.Security
	applyRulePacks(t, fixture, security)
	// The pack is an official paid one: its catalog entry requires pack.selfwaf.
	mount := security.Mounts[0]
	mustExecPublish(t, fixture, `UPDATE rule_pack_artifacts SET source='catalog', created_by_user_id=NULL WHERE pack_id=$1`, pack.PackID)
	mustExecPublish(t, fixture, `INSERT INTO artifact_catalog_entries(artifact_id,kind,version,revision,sha256,size,media_type,
		requires_feature,resident,encryption,status,delivery_id,first_seen_at,updated_at)
		VALUES($1,'rule_pack',$2,1,$3,1,$5,'pack.selfwaf',true,'none','active',$4,now(),now())`,
		artifactcatalog.RulePackArtifactID(pack.PackID), mount.Version, mount.SHA256, uuid.New(), artifactset.MediaTypeRulePack)

	publish := func(name string) map[string]publishedSiteObject {
		t.Helper()
		(&SystemRepublishScope{Pool: fixture.pool, ScopeID: fixture.scopeID}).SettleDeployments(t)
		mustExecPublish(t, fixture, `SELECT advance_edge_configuration_scope_revision($1)`, fixture.scopeID)
		result, err := fixture.service.Publish(t.Context(), siteRuntimeV2PublishRequest(fixture, name, fixture.nodeID, siteRuntimeV2Schema))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		return dynamicRoutingSiteObjects(t, fixture, result.ConfigVersionID)
	}
	setPlugins := func(plugins []string) {
		mustExecPublish(t, fixture, `INSERT INTO market_supply_tenant_plugins(tenant_scope_id,grant_id,plugins,updated_at)
			VALUES($1,$2,$3,now()) ON CONFLICT (tenant_scope_id) DO UPDATE SET plugins=EXCLUDED.plugins`,
			fixture.scopeID, uuid.New(), plugins)
	}

	assertSiteMounts(t, publish("not-market")[site.String()].security, security)
	setPlugins([]string{"module.autodefense"})
	if got := publish("withheld")[site.String()]; got.security["mounts"] != nil || got.security["resolved_sha256"] != nil {
		t.Fatalf("withheld pack still mounted: %s", got.raw)
	}
	var stored int
	if err := fixture.pool.QueryRow(t.Context(), `SELECT jsonb_array_length(security->'mounts') FROM site_security_mounts
		WHERE site_id=$1`, site).Scan(&stored); err != nil || stored != 1 {
		t.Fatalf("published mounts changed: %d %v", stored, err)
	}
	setPlugins([]string{"pack.selfwaf"})
	assertSiteMounts(t, publish("restored")[site.String()].security, security)
}

func mustExecPublish(t *testing.T, fixture *publishFixture, sql string, args ...any) {
	t.Helper()
	if _, err := fixture.pool.Exec(t.Context(), sql, args...); err != nil {
		t.Fatalf("%s: %v", sql, err)
	}
}
