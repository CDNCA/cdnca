//go:build integration

package edgepublish

import (
	"bytes"
	"testing"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/cdnca/cdnca/services/control-api/internal/edgepublish/capabilitytest"
	"github.com/cdnca/cdnca/services/control-api/internal/nodeidentity"
	"github.com/google/uuid"
)

// G8-a 缺陷 3：多域名站点走 v2 完整发布（真实 PG）。修复前 compileSiteRuntimeV2Facts
// 在 buildSiteRuntimeV2TelemetryManifest 返回 ErrInvalidInput，整次发布失败。
func TestSiteRuntimeV2PublishesMultiDomainSiteWithTelemetryIdentity(t *testing.T) {
	fixture := newPublishFixture(t)
	site := fixture.createSite(t, "multi.example.test", 80, false)
	single := fixture.createSite(t, "single.example.test", 80, false)
	if _, err := fixture.pool.Exec(t.Context(), `
		INSERT INTO site_domain_facts(
			scope_id,site_id,site_revision,action,canonical_domain,
			actor_scope_id,actor_user_id,request_id,occurred_at
		) VALUES
			($1,$2,1,'activate','multi.example.test',$1,$3,'g8-multi-domain',$4),
			($1,$2,1,'activate','static.multi.example.test',$1,$3,'g8-multi-domain',$4),
			($1,$2,1,'activate','www.multi.example.test',$1,$3,'g8-multi-domain',$4)`,
		fixture.scopeID, site.Site.ID, fixture.userID, publishTestClock); err != nil {
		t.Fatal(err)
	}
	// The site's 所有域名共用缓存 option reaches its v2
	// cache binding; the other site keys by the request host (field omitted).
	if _, err := fixture.pool.Exec(t.Context(), `UPDATE sites SET cache_shared_across_domains=true WHERE id=$1`,
		site.Site.ID); err != nil {
		t.Fatal(err)
	}
	privateKey := capabilitytest.SeedNodePublicationIdentityForTest(t, fixture.pool, fixture.scopeID, fixture.userID,
		fixture.nodeID, &agentv1.AgentCapabilities{
			AgentVersion: "1.0.0", BuildId: "g8-multi-domain", OperatingSystem: "linux", Architecture: "amd64",
			Features: siteRuntimeV2NodeFeatures(),
		}, publishTestClock.Add(-10*time.Minute), true).ArtifactPrivateKey

	result, err := fixture.service.Publish(t.Context(), siteRuntimeV2PublishRequest(
		fixture, "g8-multi-domain", fixture.nodeID, siteRuntimeV2Schema))
	if err != nil {
		t.Fatalf("multi-domain v2 Publish() error = %v", err)
	}

	var canonical []byte
	var deploymentID uuid.UUID
	if err := fixture.pool.QueryRow(t.Context(), `SELECT config.canonical_snapshot,deployment.id
		FROM node_deployments deployment JOIN config_versions config ON config.id=deployment.config_version_id
		WHERE deployment.rollout_id=$1 AND deployment.node_id=$2`, result.RolloutID, fixture.nodeID).Scan(
		&canonical, &deploymentID); err != nil {
		t.Fatal(err)
	}
	release, err := OpenSiteObjectReleaseForTest(t.Context(), fixture.pool, deploymentID, privateKey)
	if err != nil {
		t.Fatalf("assembled release: %v", err)
	}
	if !bytes.Contains(canonical, []byte(`"domains":["multi.example.test","static.multi.example.test","www.multi.example.test"]`)) {
		t.Fatalf("v2 document lost the site's domains: %s", canonical)
	}
	if bytes.Count(canonical, []byte(`"shared_across_domains":true`)) != 1 {
		t.Fatalf("v2 document must carry exactly the shared site's cache option: %s", canonical)
	}
	// Each site object carries its telemetry identity: the primary name the
	// node reports usage under, on its one listener.
	want := map[string]string{site.Site.ID.String(): "multi.example.test", single.Site.ID.String(): "single.example.test"}
	if len(release.Sites) != 2 {
		t.Fatalf("site objects = %+v, want one per site", release.Sites)
	}
	for _, object := range release.Sites {
		if want[object.SiteID] != object.Hosts.Primary || object.Telemetry == nil || len(object.Listeners) != 1 ||
			object.Listeners[0].Port != 80 || object.TenantID != fixture.tenantID.String() {
			t.Fatalf("telemetry identity = %+v, want %v", object, want)
		}
	}

	// 服务端遥测名册（实时结算、节点遥测授权）读同一份快照，按同一代表域名。
	var digest []byte
	if err := fixture.pool.QueryRow(t.Context(), `SELECT canonical_snapshot_sha256 FROM config_versions WHERE id=$1`,
		result.ConfigVersionID).Scan(&digest); err != nil {
		t.Fatal(err)
	}
	listeners, err := nodeidentity.PublishedTelemetryListeners(canonical, digest, fixture.scopeID, fixture.tenantID, result.ConfigVersionID)
	if err != nil {
		t.Fatalf("PublishedTelemetryListeners(multi-domain) error = %v", err)
	}
	if len(listeners) != 2 {
		t.Fatalf("published listeners = %+v", listeners)
	}
	for _, listener := range listeners {
		if want[listener.SiteID] != listener.Domain || listener.ListenPort != 80 {
			t.Fatalf("published listener = %+v, want %v", listener, want)
		}
	}
	finishPublishDeployment(t, fixture, result, &result.ConfigVersionID, nil)
}
