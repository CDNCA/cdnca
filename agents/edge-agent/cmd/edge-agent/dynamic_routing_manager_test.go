package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/gatewayclient"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/objectstore"
	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/cdnca/cdnca/libs/edgeconfig/edgesite"
)

func dynamicTestSite(t *testing.T, scopeID, siteID, host string) (string, []byte) {
	t.Helper()
	raw, err := edgesite.Encode(edgesite.Site{
		Schema: edgesite.Schema, ConfigurationScopeID: scopeID, TenantID: "7e000000-0000-4000-8000-000000000001",
		SiteID: siteID, Revision: 1, Hosts: edgesite.Hosts{Primary: host, Aliases: []string{}},
		Listeners: []edgesite.Listener{{Port: 80, AddressFamily: edgesite.FamilyIPv4}},
		Origin: edgesite.Origin{DefaultPoolID: "primary", Routes: []edgesite.Route{}, Auth: []edgesite.OriginAuth{},
			Pools: []edgesite.Pool{{ID: "primary", Kind: edgesite.PoolOrigin, Algorithm: "round_robin",
				Endpoints: []edgesite.Endpoint{{ID: "origin-0", Scheme: "http", Host: "192.0.2.1", Port: 80, Weight: 1}},
				Retry:     edgesite.Retry{Methods: []string{"GET", "HEAD"}, MaxAttempts: 1, ConnectTimeoutMS: 10, ReadTimeoutMS: 10, TotalBudgetMS: 10}}}},
		Security: edgesite.Security{Rules: edgesite.RulePlan{HeaderOverflow: edgesite.HeaderOverflowNoMatch, Policies: []edgesite.RulePolicy{}}, CC: []edgesite.CCBinding{}},
		Errors:   []edgesite.ErrorPage{},
	})
	if err != nil {
		t.Fatal(err)
	}
	return edgesite.Digest(raw), raw
}

// The dynamic routing manager keeps per-scope state, so the gateway client
// declares MULTI_TENANT_RUNTIME for it (ScopedDeploymentManager); each
// scope's pointers are its own and telemetry maps a site to its scope.
func TestDynamicRoutingManagerServesSeveralScopes(t *testing.T) {
	root := t.TempDir()
	objects, err := objectstore.Open(filepath.Join(root, "objects"))
	if err != nil {
		t.Fatal(err)
	}
	manager := &dynamicRoutingManager{objects: objects, root: filepath.Join(root, "scopes")}
	var asManager any = manager
	if _, ok := asManager.(gatewayclient.ScopedDeploymentManager); !ok {
		t.Fatal("the dynamic routing manager is not a scoped deployment manager")
	}
	scopes := map[string]struct{ site, host, version string }{
		"11111111-1111-4111-8111-111111111111": {"a0000000-0000-4000-8000-000000000001", "a.example.test", "c0000000-0000-4000-8000-00000000000a"},
		"22222222-2222-4222-8222-222222222222": {"b0000000-0000-4000-8000-000000000002", "b.example.test", "c0000000-0000-4000-8000-00000000000b"},
	}
	if err := os.MkdirAll(manager.root, 0o700); err != nil {
		t.Fatal(err)
	}
	for scopeID, item := range scopes {
		digest, raw := dynamicTestSite(t, scopeID, item.site, item.host)
		if err := objects.Put(digest, raw); err != nil {
			t.Fatal(err)
		}
		if err := manager.save(scopeID, dynamicRoutingScope{Current: &dynamicRoutingRelease{
			ConfigVersionID: item.version, RootSHA256: digest, Sites: []string{digest}}}); err != nil {
			t.Fatal(err)
		}
	}
	if got := manager.Scopes(); len(got) != 2 {
		t.Fatalf("scopes %v", got)
	}
	if pointers, err := manager.Pointers(); err != nil || pointers.Current != "" {
		t.Fatalf("node-wide pointers with two scopes = %+v, %v", pointers, err)
	}
	for scopeID, item := range scopes {
		pointers, err := manager.ScopePointers(scopeID)
		if err != nil || pointers.Current != item.version {
			t.Fatalf("scope %s pointers %+v, %v", scopeID, pointers, err)
		}
		if got, ok := manager.ScopeForSite(item.site); !ok || got != scopeID {
			t.Fatalf("site %s scope %q %v, want %s", item.site, got, ok, scopeID)
		}
	}
	if _, ok := manager.ScopeForSite("f0000000-0000-4000-8000-000000000009"); ok {
		t.Fatal("an unknown site has a scope")
	}
	// each scope's system configuration reaches the runtime input (D13-c0)
	system := &edgeconfig.SiteRuntimeSystem{PlatformScopeID: "33333333-3333-4333-8333-333333333333", Revision: 7}
	scope, err := manager.load("22222222-2222-4222-8222-222222222222")
	if err != nil {
		t.Fatal(err)
	}
	scope.Current.System = system
	if err := manager.save("22222222-2222-4222-8222-222222222222", scope); err != nil {
		t.Fatal(err)
	}
	input, err := manager.input(nil, gatewayclient.DynamicRoutingRelease{})
	if err != nil || len(input.Systems) != 1 || input.Systems[0].Revision != 7 || len(input.Objects) != 2 {
		t.Fatalf("input systems %+v objects %d, %v", input.Systems, len(input.Objects), err)
	}
	// fz-x12: the node's region is the key document's. A reapply takes a
	// stored release's; the release being applied wins (it is the latest).
	if input.NodeRegion != "" {
		t.Fatalf("region without any key document region = %q", input.NodeRegion)
	}
	scope.Current.NodeRegion = "region-7"
	if err := manager.save("22222222-2222-4222-8222-222222222222", scope); err != nil {
		t.Fatal(err)
	}
	if input, err = manager.input(nil, gatewayclient.DynamicRoutingRelease{}); err != nil || input.NodeRegion != "region-7" {
		t.Fatalf("reapply region = %q, %v", input.NodeRegion, err)
	}
	supplied := gatewayclient.DynamicRoutingRelease{ConfigurationScopeID: "11111111-1111-4111-8111-111111111111", NodeRegion: "region-9"}
	if input, err = manager.input(nil, supplied); err != nil || input.NodeRegion != "region-9" {
		t.Fatalf("applied release region = %q, %v", input.NodeRegion, err)
	}
	supplied.NodeRegion = ""
	if input, err = manager.input(nil, supplied); err != nil || input.NodeRegion != "" {
		t.Fatalf("a release without a region (region removed) = %q, %v", input.NodeRegion, err)
	}
}
