//go:build integration

package edgepublish

import (
	"testing"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/cdnca/cdnca/services/control-api/internal/edgepublish/capabilitytest"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// SoldPackageFixture exposes the publish fixture to the external test of the
// sold-package publication path (packagesoldruntime imports this package, so
// that test lives in edgepublish_test).
type SoldPackageFixture struct {
	Pool            *pgxpool.Pool
	Service         *Service
	Clock           time.Time
	TenantScopeID   uuid.UUID
	PlatformScopeID uuid.UUID
	PlatformUserID  uuid.UUID
	SubscriptionID  uuid.UUID
	NodeID          uuid.UUID
	SiteID          uuid.UUID
	nodeKey         []byte
	fixture         *publishFixture
}

// NewSoldPackageHTTPSFixture is one v2-capable node and one HTTPS site of a
// sold package with ports 80 and 443 and the given domains (the first is the
// site's primary domain), its certificate covering them all.
func NewSoldPackageHTTPSFixture(t *testing.T, domains []string) *SoldPackageFixture {
	t.Helper()
	return newSoldPackageFixture(t, domains, true)
}

// NewSoldPackageHTTPFixture is NewSoldPackageHTTPSFixture with a plain HTTP
// site (port 80 only, no certificate).
func NewSoldPackageHTTPFixture(t *testing.T, domains []string) *SoldPackageFixture {
	t.Helper()
	return newSoldPackageFixture(t, domains, false)
}

func newSoldPackageFixture(t *testing.T, domains []string, https bool) *SoldPackageFixture {
	t.Helper()
	fixture := newPublishFixture(t)
	httpsPorts := []string{}
	if https {
		httpsPorts = []string{"443"}
	}
	site := fixture.createSiteWithPortSets(t, domains[0], []string{"80"}, httpsPorts, https)
	// Bind the site to the package directly (as telemetry_site_bindings does):
	// the package writers are not under test.
	if err := pgx.BeginFunc(t.Context(), fixture.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(t.Context(), `SET LOCAL session_replication_role='replica'`); err != nil {
			return err
		}
		_, err := tx.Exec(t.Context(), `UPDATE sites SET package_subscription_id=$2,
			package_id=(SELECT product_id FROM package_subscriptions WHERE id=$2) WHERE id=$1`,
			site.Site.ID, fixture.subscriptionID)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	for _, domain := range domains {
		if _, err := fixture.pool.Exec(t.Context(), `INSERT INTO site_domain_facts(
			scope_id,site_id,site_revision,action,canonical_domain,actor_scope_id,actor_user_id,request_id,occurred_at)
			VALUES($1,$2,1,'activate',$3,$1,$4,'sold-package-domain',$5)`,
			fixture.scopeID, site.Site.ID, domain, fixture.userID, publishTestClock); err != nil {
			t.Fatal(err)
		}
	}
	if https {
		seedSiteRuntimeV2CertificateBindingWithOptions(t, fixture, site.Site, siteRuntimeV2CertificateSeedOptions{sans: domains})
	}
	key := capabilitytest.SeedNodePublicationIdentityForTest(t, fixture.pool, fixture.scopeID, fixture.userID,
		fixture.nodeID, &agentv1.AgentCapabilities{
			AgentVersion: "1.0.0", BuildId: "sold-package-telemetry", OperatingSystem: "linux", Architecture: "amd64",
			Features: siteRuntimeV2NodeFeatures(),
		}, publishTestClock.Add(-10*time.Minute), true).ArtifactPrivateKey
	return &SoldPackageFixture{
		Pool: fixture.pool, Service: fixture.service, Clock: publishTestClock,
		TenantScopeID: fixture.scopeID, PlatformScopeID: fixture.platformScopeID, PlatformUserID: fixture.platformUserID,
		SubscriptionID: fixture.subscriptionID, NodeID: fixture.nodeID, SiteID: site.Site.ID,
		nodeKey: key, fixture: fixture,
	}
}

// PublishedRelease opens the release the node of the rollout receives, as
// the Agent does.
func (f *SoldPackageFixture) PublishedRelease(t *testing.T, rolloutID uuid.UUID) SiteObjectReleaseForTest {
	t.Helper()
	var deploymentID uuid.UUID
	if err := f.Pool.QueryRow(t.Context(), `SELECT id FROM node_deployments WHERE rollout_id=$1 AND node_id=$2`,
		rolloutID, f.NodeID).Scan(&deploymentID); err != nil {
		t.Fatal(err)
	}
	release, err := OpenSiteObjectReleaseForTest(t.Context(), f.Pool, deploymentID, f.nodeKey)
	if err != nil {
		t.Fatal(err)
	}
	return release
}
