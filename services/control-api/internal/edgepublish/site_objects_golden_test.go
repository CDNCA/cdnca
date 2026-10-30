package edgepublish

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"path/filepath"
	"slices"
	"testing"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/cdnca/cdnca/libs/edgeconfig/siteobject"
	"github.com/cdnca/cdnca/services/control-api/internal/sitecapture"
	"github.com/google/uuid"
)

// goldenSiteRuntimeV2Release compiles a release with every per-site file the
// production producers emit (HTTP policy, firewall action, origin routes,
// telemetry with a capture policy and a package subscription) for count
// sites, under configID.
func goldenSiteRuntimeV2Release(t *testing.T, configID uuid.UUID, sourceRevision int64, count int, stateRoot string) edgeconfig.Bundle {
	t.Helper()
	return goldenSiteRuntimeV2ReleaseWith(t, configID, sourceRevision, count, stateRoot, count)
}

// goldenSiteRuntimeV2ReleaseWith is goldenSiteRuntimeV2Release with at most
// maxPolicies HTTP policy sites (a scope's HTTP policies are bounded by
// httppolicycontrol.MaxSites; its sites are not).
func goldenSiteRuntimeV2ReleaseWith(t *testing.T, configID uuid.UUID, sourceRevision int64, count int, stateRoot string,
	maxPolicies int) edgeconfig.Bundle {
	t.Helper()
	base := mustHTTPPolicyRuntimeDocument(t)
	scopeID := uuid.MustParse(base.ConfigurationScopeID)
	tenantID := uuid.MustParse("018f47a2-5b9c-7d31-8a60-104c9c0b7d01")
	installationID := uuid.MustParse("018f47a2-5b9c-7d31-8a60-104c9c0b7d02")
	document := base
	document.ConfigVersionID, document.SourceRevision = configID.String(), sourceRevision
	document.Sites = nil
	for index := 0; index < count; index++ {
		site := base.Sites[0]
		site.ID = fmt.Sprintf("018f47a2-5b9c-7d31-8a60-%012x", 0x200000+index)
		site.Revision = int64(1 + index%5)
		site.Domains = []string{fmt.Sprintf("s%04d.example.test", index), fmt.Sprintf("www.s%04d.example.test", index)}
		document.Sites = append(document.Sites, site)
	}
	slices.SortFunc(document.Sites, func(left, right siteRuntimeV2Site) int { return bytes.Compare([]byte(left.ID), []byte(right.ID)) })

	var policies []httpPolicyFact
	var firewall []firewallActionFact
	subscriptions := map[uuid.UUID]uuid.UUID{}
	captures := map[uuid.UUID]*siteCapturePolicyFact{}
	var routes []siteOriginRouteFact
	for index, site := range document.Sites {
		siteID := uuid.MustParse(site.ID)
		if index%3 == 0 && len(policies) < maxPolicies {
			fact := httpPolicyFactFixture(t, scopeID, siteID, sourceRevision, 3)
			fact.policyID = uuid.NewSHA1(siteID, []byte("policy"))
			fact.document.PolicyID = fact.policyID
			fact.document.SiteOwnerUserID = uuid.NewSHA1(siteID, []byte("owner"))
			fact.document.RedirectAllowedHosts = []string{"a&b.example.test"}
			policies = append(policies, fact)
		}
		if index%4 == 1 {
			policyID := uuid.NewSHA1(siteID, []byte("firewall"))
			raw := firewallActionControlPolicy(t, scopeID, siteID, policyID, 7)
			firewall = append(firewall, firewallActionFact{siteID: siteID, policyID: policyID, revision: 7, document: raw,
				digest: sha256.Sum256(raw)})
		}
		if index%2 == 0 {
			subscriptions[siteID] = uuid.NewSHA1(siteID, []byte("subscription"))
		}
		if index%5 == 2 {
			raw, err := json.Marshal(sitecapture.PolicyDocument{Enabled: true, Methods: []string{"GET"}, URIPrefixes: []string{"/api/a&b<2>"},
				RequestHeaderAllowlist: []string{"Authorization"}, MaxValueBytes: 4096, MaxBodyBytes: 64 << 10, MaxEventBytes: 1 << 20})
			if err != nil {
				t.Fatal(err)
			}
			digest := sha256.Sum256(raw)
			if captures[siteID], err = decodeSiteCapturePolicyFact(siteID, 4, raw, digest[:]); err != nil {
				t.Fatal(err)
			}
		}
		route, err := basicSiteOriginRouteFact(site)
		if err != nil {
			t.Fatalf("%s: %v", "basicSiteOriginRouteFact", err)
		}
		routes = append(routes, route)
	}
	policyArtifact, _, err := compileHTTPPolicyArtifact(scopeID, sourceRevision, 12, &document, policies)
	if err != nil {
		t.Fatalf("%s: %v", "compileHTTPPolicyArtifact", err)
	}
	firewallArtifacts, err := compileFirewallActionArtifacts(scopeID, &document, firewall)
	if err != nil {
		t.Fatalf("%s: %v", "compileFirewallActionArtifacts", err)
	}
	manifest, err := buildSiteRuntimeV2TelemetryManifest(scopeID, tenantID, installationID, configID, sourceRevision,
		document, subscriptions, captures, noAccessLogFields, stateRoot)
	if err != nil {
		t.Fatalf("%s: %v", "buildSiteRuntimeV2TelemetryManifest", err)
	}
	originRoutes, err := compileSiteOriginRouteBundleWithTopology(scopeID, configID, sourceRevision, routes, nil)
	if err != nil {
		t.Fatalf("%s: %v", "compileSiteOriginRouteBundleWithTopology", err)
	}
	raw, err := json.Marshal(document)
	if err != nil {
		t.Fatalf("%s: %v", "json.Marshal(document)", err)
	}
	canonical, _, _, _, err := compileSiteRuntimeV2Document(raw)
	if err != nil {
		t.Fatalf("%s: %v", "compileSiteRuntimeV2Document", err)
	}
	bundle, err := buildSiteRuntimeV2Bundle(canonical, nil, originRoutes, policyArtifact, firewallArtifacts, nil, manifest)
	if err != nil {
		t.Fatalf("%s: %v", "buildSiteRuntimeV2Bundle", err)
	}
	return bundle
}

// goldenDynamicRoutingPublication is the dynamic routing publication of a
// golden release (the production conversion).
func goldenDynamicRoutingPublication(t *testing.T, bundle edgeconfig.Bundle) (siteobject.Publication, siteobject.RootV2) {
	t.Helper()
	source, err := siteObjectsV2SourceFromBundle(bundle)
	if err != nil {
		t.Fatal(err)
	}
	publication, _, err := buildDynamicRoutingPublication(source, goldenTenant, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	root, err := siteobject.ParseRootV2(publication.RootBytes)
	if err != nil {
		t.Fatal(err)
	}
	return publication, root
}

// A second publication of control's real release (the same sites under
// another config version) reuses every site object; only the root changes.
func TestSiteObjectsReuseObjectsAcrossConfigVersions(t *testing.T) {
	stateRoot := filepath.Join(t.TempDir(), "edge")
	first := goldenSiteRuntimeV2Release(t, uuid.MustParse("018f47a2-5b9c-7d31-8a60-104c9c0b7e01"), 41, 30, stateRoot)
	for _, path := range []string{siteRuntimeV2HTTPPolicyArtifactPath, siteOriginRouteBundlePath, edgeconfig.TelemetryIdentityManifestPath} {
		if _, present := first.Files[path]; !present {
			t.Fatalf("the golden release lacks %s", path)
		}
	}
	firstPublication, _ := goldenDynamicRoutingPublication(t, first)
	second := goldenSiteRuntimeV2Release(t, uuid.MustParse("018f47a2-5b9c-7d31-8a60-104c9c0b7e02"), 42, 30, stateRoot)
	secondPublication, _ := goldenDynamicRoutingPublication(t, second)
	reused := map[string]bool{}
	for _, object := range firstPublication.Objects {
		reused[object.SHA256] = true
	}
	for _, object := range secondPublication.Objects {
		if !reused[object.SHA256] {
			t.Fatalf("a %s object changed with only the config version", object.Kind)
		}
	}
	if firstPublication.RootSHA256 == secondPublication.RootSHA256 {
		t.Fatal("the root did not change with the config version")
	}
}

// A scope is not bounded by 1000 (or 128) sites: 5000 sites, a few with HTTP
// policies, compile through the production producers into one site object
// per site.
func TestSiteObjectsCompileFiveThousandSites(t *testing.T) {
	stateRoot := filepath.Join(t.TempDir(), "edge")
	bundle := goldenSiteRuntimeV2ReleaseWith(t, uuid.MustParse("018f47a2-5b9c-7d31-8a60-104c9c0b7e03"), 43, 5000, stateRoot, 20)
	publication, root := goldenDynamicRoutingPublication(t, bundle)
	sites := 0
	for _, object := range publication.Objects {
		if object.Kind == siteobject.KindSite {
			sites++
		}
	}
	if sites != 5000 || root.BucketCount != 32 {
		t.Fatalf("%d site objects in %d buckets", sites, root.BucketCount)
	}
}
