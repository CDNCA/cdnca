package edgepublish

import (
	"context"
	"encoding/json"
	"slices"
	"testing"
	"time"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/google/uuid"
)

func TestSITE03IPv6DesiredStateCompilesLegacyAndRuntimeV2Listeners(t *testing.T) {
	for _, test := range []struct {
		name          string
		enabled       bool
		addressFamily string
		capabilities  []string
	}{
		{name: "disabled", addressFamily: "ipv4", capabilities: []string{"http1", "ipv4", "site_runtime", "websocket"}},
		{name: "enabled", enabled: true, addressFamily: "dual_stack", capabilities: []string{"http1", "ipv4", "ipv6", "site_runtime", "websocket"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			fact := siteFact{
				id: uuid.New(), revision: 7, domain: "ipv6-" + test.name + ".example.test",
				httpPorts: []string{"80"}, tlsProtocols: []string{"TLSv1.2", "TLSv1.3"},
				ipv6Enabled: test.enabled, ipv6DesiredSet: true, balance: string(edgeconfig.BalanceRoundRobin),
				failoverTries: 1, connectTimeoutMS: 3000, readTimeoutMS: 30000,
				origins: []snapshotOrigin{{Host: "192.0.2.10", Port: 8080, Weight: 1}},
			}
			snapshot, legacy, err := compileSiteFact(uuid.New(), fact, 80, nil, nil, nil)
			if err != nil {
				t.Fatal(err)
			}
			if (snapshot.IPv6Enabled == nil) != test.enabled ||
				snapshot.IPv6Enabled != nil && *snapshot.IPv6Enabled != test.enabled ||
				legacy.IPv6Enabled == nil || *legacy.IPv6Enabled != test.enabled {
				t.Fatalf("legacy desired state snapshot=%v site=%v", snapshot.IPv6Enabled, legacy.IPv6Enabled)
			}
			document, _, err := compileSiteRuntimeV2Source(
				context.Background(), nil, uuid.New(), uuid.New(), 11, []siteFact{fact}, nil, time.Unix(1, 0).UTC(),
			)
			if err != nil {
				t.Fatal(err)
			}
			if len(document.Sites) != 1 || len(document.Sites[0].Listeners) != 1 ||
				document.Sites[0].Listeners[0].AddressFamily != test.addressFamily {
				t.Fatalf("runtime listeners=%+v", document.Sites)
			}
			got := make([]string, len(document.RequiredCapabilities))
			for index, capability := range document.RequiredCapabilities {
				got[index] = capability.Name
			}
			if !slices.Equal(got, test.capabilities) {
				t.Fatalf("capabilities=%v want=%v", got, test.capabilities)
			}
		})
	}
}

func TestSITE03IPv6RolloutTargetsAreBoundToImmutableSiteRevision(t *testing.T) {
	siteID := uuid.New()
	for _, test := range []struct {
		name     string
		snapshot any
		enabled  bool
	}{
		{
			name: "runtime v2 disabled",
			snapshot: siteRuntimeV2Document{
				Schema: siteRuntimeV2Schema,
				Sites: []siteRuntimeV2Site{{
					ID: siteID.String(), Revision: 9,
					Listeners: []siteRuntimeV2Listener{{AddressFamily: "ipv4"}},
				}},
			},
		},
		{
			name:    "runtime v2 enabled",
			enabled: true,
			snapshot: siteRuntimeV2Document{
				Schema: siteRuntimeV2Schema,
				Sites: []siteRuntimeV2Site{{
					ID: siteID.String(), Revision: 9,
					Listeners: []siteRuntimeV2Listener{{AddressFamily: "dual_stack"}},
				}},
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			encoded, err := json.Marshal(test.snapshot)
			if err != nil {
				t.Fatal(err)
			}
			targets, err := siteIPv6TargetsFromSnapshot(encoded)
			if err != nil {
				t.Fatal(err)
			}
			if len(targets) != 1 || targets[0].siteID != siteID || targets[0].siteRevision != 9 ||
				targets[0].desiredEnabled != test.enabled {
				t.Fatalf("targets=%+v", targets)
			}
		})
	}
}
