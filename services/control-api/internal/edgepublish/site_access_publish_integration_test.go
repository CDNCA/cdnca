//go:build integration

package edgepublish

import (
	"encoding/json"
	"testing"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/google/uuid"
)

// TestSiteRuntimeV2SiteAccessFromDatabase: a site's
// site_access_settings row and forced HTTPS status reach its v2 site as
// stored, under site_runtime v5; a site without a row publishes no access.
func TestSiteRuntimeV2SiteAccessFromDatabase(t *testing.T) {
	fixture := newL4V2ContractFixture(t)
	site := fixture.createSite(t, "access-v2.example.com", 18094, false).Site
	other := fixture.createSite(t, "access-v2-other.example.com", 18095, false).Site
	revision := fixture.sourceRevision()
	access := edgeconfig.SiteAccess{
		Compression: &edgeconfig.SiteCompression{Enabled: true, Types: []string{"application/json"}, MinLengthBytes: 64},
		Limits:      &edgeconfig.SiteRequestLimits{ConnectionsPerIP: 8},
		BasicAuth: &edgeconfig.SiteBasicAuth{Realm: "staff", Users: []edgeconfig.BasicAuthUser{
			edgeconfig.BasicAuthUserWithSalt("alice", "000102030405060708090a0b0c0d0e0f", "correct horse")}},
	}
	document, _ := json.Marshal(access)
	if _, err := fixture.pool.Exec(t.Context(), `INSERT INTO site_access_settings(scope_id,site_id,settings,updated_by_user_id,updated_at)
		VALUES($1,$2,$3,$4,now())`, fixture.scopeID, site.ID, string(document), fixture.userID); err != nil {
		t.Fatal(err)
	}
	seedSiteRuntimeV2Capabilities(t, fixture, "", append(siteRuntimeV2CapabilitiesWithoutSiteRuntime(),
		&agentv1.Capability{Name: agentv1.CapabilityName_CAPABILITY_NAME_SITE_RUNTIME, ApiVersion: edgeconfig.MaxSiteRuntimeVersion}))
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
	var runtimeDocument siteRuntimeV2Document
	if err := json.Unmarshal(canonical, &runtimeDocument); err != nil {
		t.Fatal(err)
	}
	found := 0
	for _, published := range runtimeDocument.Sites {
		switch published.ID {
		case site.ID.String():
			found++
			if published.Access == nil || published.Access.BasicAuth == nil ||
				published.Access.BasicAuth.Users[0] != access.BasicAuth.Users[0] ||
				published.Access.Limits.ConnectionsPerIP != 8 {
				t.Fatalf("published access = %+v", published.Access)
			}
		case other.ID.String():
			found++
			if published.Access != nil {
				t.Fatalf("site without settings publishes access %+v", published.Access)
			}
		}
	}
	runtime := uint32(0)
	for _, capability := range runtimeDocument.RequiredCapabilities {
		if capability.Name == "site_runtime" {
			runtime = capability.APIVersion
		}
	}
	if found != 2 || runtime < edgeconfig.MinSiteRuntimeVersion {
		t.Fatalf("sites found %d, site_runtime %d", found, runtime)
	}
}
