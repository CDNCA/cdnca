package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/dynwaf"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/edgegolden/goldendyn"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/gatewayclient"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/objectstore"
	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/cdnca/cdnca/libs/edgeconfig/artifactset"
	"github.com/cdnca/cdnca/libs/edgeconfig/edgesite"
	"github.com/cdnca/cdnca/libs/entitlement/rulecatalog"
	"github.com/cdnca/cdnca/libs/rulepack"
)

// TestDynamicRoutingComposesManagedWAFOfTwoScopes (waf-share): two tenants'
// scopes on one node, each with a managed WAF site of its own CRS profile
// pack and exclusions (A: 默认防护 PL1 excluding 942100, B: 严格防护 PL2
// excluding 941100). The manager composes both scopes' releases into one
// input; the managed WAF prepares one tier per profile pack and renders
// both into the node skeleton. Nothing written names a site or a scope: the
// exclusions travel per request (cdnca_managed_waf.lua), so neither scope's
// exclusions reach the other's site.
func TestDynamicRoutingComposesManagedWAFOfTwoScopes(t *testing.T) {
	root := t.TempDir()
	objects, err := objectstore.Open(filepath.Join(root, "objects"))
	if err != nil {
		t.Fatal(err)
	}
	manager := &dynamicRoutingManager{objects: objects, root: filepath.Join(root, "scopes")}
	if err := os.MkdirAll(manager.root, 0o700); err != nil {
		t.Fatal(err)
	}
	catalog, err := rulecatalog.DecodeWAFEngineBundle(*rulecatalog.CRSRulesBundle())
	if err != nil {
		t.Fatal(err)
	}
	profile := func(name string) edgeconfig.CRSProfile {
		content, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "libs", "rulepack", "testdata", "crs-profiles", name+".json"))
		if err != nil {
			t.Fatal(err)
		}
		sha := artifactset.Digest(content)
		_, loaded, err := rulepack.LoadCRSProfile(content, sha)
		if err != nil {
			t.Fatal(err)
		}
		if err := objects.Put(sha, content); err != nil { // as the node artifact set leaves it
			t.Fatal(err)
		}
		return loaded
	}
	pl1, pl2 := profile("crs-pl1"), profile("crs-pl2")
	type tenant struct {
		scope, site, version string
		profile              edgeconfig.CRSProfile
		exclusion            int
	}
	tenants := []tenant{
		{"11111111-1111-4111-8111-111111111111", "a0000000-0000-4000-8000-000000000001", "c0000000-0000-4000-8000-00000000000a", pl1, 942100},
		{"22222222-2222-4222-8222-222222222222", "b0000000-0000-4000-8000-000000000002", "c0000000-0000-4000-8000-00000000000b", pl2, 941100},
	}
	for _, item := range tenants {
		// each release carries the CRS rule files its own profile pack loads
		// (edgepublish siteRuntimeV2CRSFiles): PL2 loads more files than PL1
		files, err := edgeconfig.CRSReleaseFiles([]edgeconfig.Site{{ID: item.site, ManagedWAF: &edgeconfig.ManagedWAF{Profile: item.profile.Ref}}},
			&edgeconfig.CRSRuleText{Files: catalog}, []edgeconfig.CRSProfile{item.profile})
		if err != nil {
			t.Fatal(err)
		}
		scopeFiles := map[string]string{}
		for path, content := range files {
			digest := artifactset.Digest(content)
			if err := objects.Put(digest, content); err != nil {
				t.Fatal(err)
			}
			scopeFiles[path] = digest
		}
		_, raw := dynamicTestSiteWAF(t, item.scope, item.site, item.profile.Ref)
		site, err := edgesite.Decode(raw)
		if err != nil {
			t.Fatal(err)
		}
		site.TenantID = strings.Replace(item.scope, "1111", "7e00", 1)
		site.Security.ManagedWAF.Exclusions = []int{item.exclusion}
		encoded, err := edgesite.Encode(site)
		if err != nil {
			t.Fatal(err)
		}
		digest := edgesite.Digest(encoded)
		if err := objects.Put(digest, encoded); err != nil {
			t.Fatal(err)
		}
		if err := manager.save(item.scope, dynamicRoutingScope{Current: &dynamicRoutingRelease{ConfigVersionID: item.version,
			RootSHA256: digest, Sites: []string{digest}, ScopeFiles: scopeFiles}}); err != nil {
			t.Fatal(err)
		}
	}

	input, err := manager.input(nil, gatewayclient.DynamicRoutingRelease{})
	if err != nil {
		t.Fatalf("compose two managed WAF scopes: %v", err)
	}
	if len(input.Objects) != 2 || len(input.ScopeVersions) != 2 || len(input.Profiles) != 2 {
		t.Fatalf("composed %d sites, %d scopes, %d profiles", len(input.Objects), len(input.ScopeVersions), len(input.Profiles))
	}
	sites := make([]edgesite.Site, len(input.Objects))
	for index, object := range input.Objects {
		sites[index] = object.Site
	}
	result, err := dynwaf.Prepare(dynwaf.Input{Sites: sites, CRSText: input.CRSText, Profiles: input.Profiles, Apps: input.Apps,
		Engine: &dynwaf.Engine{ModulePath: "/opt/waf/modules/ngx_http_modsecurity_module.so", UnicodeMapPath: "/opt/waf/unicode.mapping"},
		Root:   filepath.Join(root, "managed-waf"), AuditLog: "/var/lib/node/shared/modsecurity-audit.log"})
	if err != nil {
		t.Fatalf("managed WAF of two scopes: %v", err)
	}
	if len(result.Skeleton.Tiers) != 2 {
		t.Fatalf("%d tiers, want one per tenant's profile pack", len(result.Skeleton.Tiers))
	}
	for _, site := range sites {
		key := site.Security.ManagedWAF.Edge().TierOf().Key()
		if _, ok := result.Skeleton.Tiers[key]; !ok {
			t.Fatalf("site %s: no tier %s in %v", site.SiteID, key, result.Skeleton.Tiers)
		}
	}
	written := map[string]string{"node rules": result.Skeleton.RulesPath}
	for key, path := range result.Skeleton.Tiers {
		written["tier "+key] = path
	}
	for name, path := range written {
		content, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		for _, item := range tenants {
			if strings.Contains(string(content), item.site) || strings.Contains(string(content), item.scope) {
				t.Fatalf("%s names tenant %s's site or scope: a site's settings must travel per request", name, item.scope)
			}
		}
	}
	skeleton := renderNodeSkeleton(t, sites, result)
	for key, path := range result.Skeleton.Tiers {
		if !strings.Contains(skeleton, "location @cdnca_waf_"+key+" ") || !strings.Contains(skeleton, path) {
			t.Fatalf("skeleton has no tier location %s (%s)", key, path)
		}
	}
}

// renderNodeSkeleton is the node nginx.conf of sites with the managed WAF.
func renderNodeSkeleton(t *testing.T, sites []edgesite.Site, waf dynwaf.Result) string {
	t.Helper()
	ports, err := edgesite.PortProfiles(sites)
	if err != nil {
		t.Fatal(err)
	}
	keys := 0
	for _, site := range sites {
		keys += len(site.IndexEntries())
	}
	// the control socket path is bounded (sun_path): not under t.TempDir on macOS
	state, err := os.MkdirTemp("/tmp", "wafshare")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(state) })
	conf, err := goldendyn.Config(goldendyn.ConfigInput{Root: state, LuaRoot: "/usr/local/share/cdnca", Ports: ports,
		IndexKeys: keys, ManagedWAF: waf.Skeleton})
	if err != nil {
		t.Fatalf("node skeleton: %v", err)
	}
	return string(conf)
}
