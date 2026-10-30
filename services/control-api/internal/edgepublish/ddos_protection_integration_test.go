//go:build integration

package edgepublish

import (
	"slices"
	"testing"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/cdnca/cdnca/services/control-api/internal/systemconfig"
	"github.com/google/uuid"
)

// A tenant v2 publication carries the platform's DDoS
// protection with every registered node's addresses exempt; with every
// limit off it carries none.
func TestSiteRuntimeV2CarriesDDoSProtectionWithNodeNetworks(t *testing.T) {
	fixture := newPublishFixture(t)
	key := seedV2DefaultNode(t, fixture, fixture.nodeID)
	if _, err := fixture.pool.Exec(t.Context(), `UPDATE nodes SET ipv4='203.0.113.40', ipv6='2001:db8:40::1',
		management_settings=jsonb_set(management_settings,'{secondary_ips}','["198.51.100.40"]'::jsonb)
		WHERE id=$1`, fixture.nodeID); err != nil {
		t.Fatal(err)
	}
	fixture.createSite(t, "ddos-v2.example.test", 80, false)
	activateTestSystemConfigurationWith(t, fixture, func(configuration *systemconfig.Configuration) {
		configuration.DDoSProtection = &edgeconfig.DDoSProtection{MaxConnectionsPerIP: 300, NewConnectionsPerSecond: 80,
			RateBanSeconds: 600, AllowNetworks: []string{"192.0.2.0/24"}, CCKernelBan: edgeconfig.CCKernelBanExclusivePorts}
	})
	result, err := fixture.service.Publish(t.Context(), siteRuntimeV2PublishRequest(fixture, "v2-ddos", fixture.nodeID, siteRuntimeV2Schema))
	if err != nil {
		t.Fatal(err)
	}
	document := decodeReceivedV2Document(t, receivedV2Bundle(t, fixture, result, fixture.nodeID, key))
	if document.System == nil || document.System.DDoS == nil {
		t.Fatalf("system block lacks DDoS protection: %+v", document.System)
	}
	ddos := document.System.DDoS
	if ddos.Protection.MaxConnectionsPerIP != 300 || ddos.Protection.NewConnectionsPerSecond != 80 ||
		ddos.Protection.CCKernelBan != edgeconfig.CCKernelBanExclusivePorts ||
		!slices.Equal(ddos.Protection.AllowNetworks, []string{"192.0.2.0/24"}) {
		t.Fatalf("protection = %+v", ddos.Protection)
	}
	for _, want := range []string{"203.0.113.40/32", "2001:db8:40::1/128", "198.51.100.40/32"} {
		if !slices.Contains(ddos.NodeNetworks, want) {
			t.Fatalf("node networks %v lack %s", ddos.NodeNetworks, want)
		}
	}

	activateTestSystemConfigurationWith(t, fixture, func(configuration *systemconfig.Configuration) {
		configuration.DDoSProtection = &edgeconfig.DDoSProtection{AllowNetworks: []string{}, CCKernelBan: edgeconfig.CCKernelBanOff}
	})
	fixture.createSite(t, "ddos-v2-off.example.test", 8080, false)
	// The first node still runs its deployment; publish to a second one.
	second := uuid.New()
	seedPublishNode(t, fixture.pool, fixture.scopeID, fixture.userID, second)
	secondKey := seedV2DefaultNode(t, fixture, second)
	result, err = fixture.service.Publish(t.Context(), siteRuntimeV2PublishRequest(fixture, "v2-ddos-off", second, siteRuntimeV2Schema))
	if err != nil {
		t.Fatal(err)
	}
	// every limit off: the block stays for its node networks (fix-l2trust),
	// with nothing on
	if document := decodeReceivedV2Document(t, receivedV2Bundle(t, fixture, result, second, secondKey)); document.System == nil ||
		document.System.DDoS == nil || document.System.DDoS.Protection.Active() || !slices.Contains(document.System.DDoS.NodeNetworks, "203.0.113.40/32") {
		t.Fatalf("every limit off lost the node networks: %+v", document.System)
	}
}
