package edgepublish

import (
	"testing"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/cdnca/cdnca/libs/edgeconfig/edgesite"
	"github.com/cdnca/cdnca/libs/edgeconfig/siteobject"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
)

func TestDynamicRoutingPublicationCarriesEveryReference(t *testing.T) {
	v8 := richSiteRuntimeV2Publication(t, 0, 12, 3)
	publication, packs, err := buildDynamicRoutingPublication(v8, richTenantID, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	root, err := siteobject.ParseRootV2(publication.RootBytes)
	if err != nil || root.DocumentSHA256 != v8.DocumentSHA256 || root.ConfigVersionID != v8.ConfigVersionID {
		t.Fatalf("%+v %v", root, err)
	}
	objects := map[string][]byte{}
	for _, object := range publication.Objects {
		objects[object.SHA256] = object.Plaintext
	}
	scope, err := siteobject.ParseScopeV2(objects[root.ScopeSHA256])
	if err != nil {
		t.Fatal(err)
	}
	crs := 0
	for _, file := range scope.Files {
		if _, present := objects[file.SHA256]; !present {
			t.Fatalf("scope file %s missing", file.Path)
		}
		// CRS profile packs come with the node artifact set, not the release.
		if _, profile := edgeconfig.ListenerCRSProfileDigest(file.Path); profile {
			t.Fatalf("scope carries the CRS profile pack %s", file.Path)
		}
		crs++
	}
	if crs == 0 {
		t.Fatal("the managed WAF sites' CRS files are not in the scope")
	}
	// The managed WAF sites' profile packs are what the targets are gated on.
	if len(packs) == 0 {
		t.Fatal("no rule packs reported for the managed WAF sites")
	}
	for _, digest := range packs {
		if _, ok := edgeconfig.ListenerCRSProfileDigest(edgeconfig.ListenerCRSProfilePath(digest)); !ok {
			t.Fatalf("pack digest %q", digest)
		}
	}
	sites := 0
	for _, digest := range root.Buckets {
		bucket, err := siteobject.ParseBucketV2(objects[digest])
		if err != nil {
			t.Fatal(err)
		}
		for _, entry := range bucket.Sites {
			site, err := edgesite.Decode(objects[entry.SHA256])
			if err != nil || edgesite.Digest(objects[entry.SHA256]) != entry.SHA256 {
				t.Fatalf("site %s: %v", entry.SiteID, err)
			}
			// An origin trust anchor without its CA set in the release stays
			// unresolved on purpose (site_objects_v2.go: the node refuses it).
			anchors := map[string]bool{}
			for _, digest := range site.TrustAnchors() {
				anchors[digest] = true
			}
			for _, ref := range site.ReferencedDigests() {
				if _, present := objects[ref]; !present && !anchors[ref] {
					t.Fatalf("site %s references %s, not a member", entry.SiteID, ref)
				}
			}
			sites++
		}
	}
	if sites != 12 {
		t.Fatalf("%d sites", sites)
	}
	again, _, err := buildDynamicRoutingPublication(v8, richTenantID, nil, nil, nil)
	if err != nil || again.RootSHA256 != publication.RootSHA256 {
		t.Fatal("not deterministic")
	}
}

func TestReleaseRequiresDynamicRouting(t *testing.T) {
	at := func(version uint32) []*agentv1.Capability {
		return []*agentv1.Capability{{Name: agentv1.CapabilityName_CAPABILITY_NAME_SITE_RUNTIME, ApiVersion: version}}
	}
	if err := releaseRequiresDynamicRouting(at(9)); err != nil {
		t.Fatal(err)
	}
	for _, version := range []uint32{7, 8} {
		if err := releaseRequiresDynamicRouting(at(version)); err == nil {
			t.Fatalf("site_runtime %d release accepted", version)
		}
	}
}
