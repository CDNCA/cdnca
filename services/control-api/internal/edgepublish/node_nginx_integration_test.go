//go:build integration

package edgepublish

import (
	"slices"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/systemconfig"
	"github.com/google/uuid"
)

// A region override reaches the nodes of that region
// (nodes.region name → region_catalog.display_id) and only them; a node
// moving into the region makes the scope's release stale.
func TestSiteRuntimeV2CarriesRegionNginxPerNode(t *testing.T) {
	fixture := newPublishFixture(t)
	ctx := t.Context()
	inside, outside := fixture.nodeID, uuid.New()
	insideKey := seedV2DefaultNode(t, fixture, inside)
	seedPublishNode(t, fixture.pool, fixture.scopeID, fixture.userID, outside)
	outsideKey := seedV2DefaultNode(t, fixture, outside)
	var displayID string
	if err := fixture.pool.QueryRow(ctx, `INSERT INTO region_catalog(id,platform_scope_id,name) VALUES($1,$2,'华东一区')
		RETURNING display_id::text`, uuid.New(), fixture.platformScopeID).Scan(&displayID); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.pool.Exec(ctx, `UPDATE nodes SET region='华东一区' WHERE id=$1`, inside); err != nil {
		t.Fatal(err)
	}
	fixture.createSite(t, "region-nginx.example.test", 80, false)
	level, version := 9, "1.0"
	activateTestSystemConfigurationWith(t, fixture, func(configuration *systemconfig.Configuration) {
		configuration.Nginx.Overrides = []systemconfig.ScopedNginxOverride{{ID: "region-east1", Scope: systemconfig.ConfigurationScopeRegion,
			ScopeID: displayID, Values: systemconfig.NginxOverride{HTTP: &systemconfig.NginxHTTPOverride{
				GzipLevel: &level, ProxyHTTPVersion: &version}}}}
	})
	request := siteRuntimeV2PublishRequest(fixture, "v2-region-nginx", inside, siteRuntimeV2Schema)
	request.NodeIDs = []uuid.UUID{inside, outside}
	slices.SortFunc(request.NodeIDs, func(a, b uuid.UUID) int { return strings.Compare(a.String(), b.String()) })
	result, err := fixture.service.Publish(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	for _, received := range []struct {
		node uuid.UUID
		key  []byte
	}{{inside, insideKey}, {outside, outsideKey}} {
		system := decodeReceivedV2Document(t, receivedV2Bundle(t, fixture, result, received.node, received.key)).System
		if system == nil || len(system.NodeNginx) != 1 ||
			!slices.Equal(system.NodeNginx[0].NodeIDs, []string{inside.String()}) {
			t.Fatalf("node %s system node_nginx = %+v", received.node, system)
		}
		if system.Nginx.GzipLevel != 6 || system.Nginx.ProxyHTTPVersion != "1.1" {
			t.Fatalf("base nginx changed: %+v", system.Nginx)
		}
		own := system.ForNode(inside.String()).Nginx
		if own.GzipLevel != 9 || own.ProxyHTTPVersion != "1.0" {
			t.Fatalf("region node nginx = %+v", own)
		}
		if other := system.ForNode(outside.String()).Nginx; other.GzipLevel != 6 {
			t.Fatalf("outside node nginx = %+v", other)
		}
	}

	tx, err := fixture.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	regions, err := NodeRegionsTx(ctx, tx)
	if err != nil || !slices.Contains(regions, inside.String()+"="+displayID) || !slices.Contains(regions, outside.String()+"=") {
		t.Fatalf("node regions = %v %v", regions, err)
	}
	if stale, err := StaleNodeNginxScopesTx(ctx, tx); err != nil || len(stale) != 0 {
		t.Fatalf("fresh release stale = %v %v", stale, err)
	}
	if _, err := tx.Exec(ctx, `UPDATE nodes SET region='华东一区' WHERE id=$1`, outside); err != nil {
		t.Fatal(err)
	}
	if stale, err := StaleNodeNginxScopesTx(ctx, tx); err != nil || !slices.Equal(stale, []uuid.UUID{fixture.scopeID}) {
		t.Fatalf("after a node changed region stale = %v %v", stale, err)
	}
}
