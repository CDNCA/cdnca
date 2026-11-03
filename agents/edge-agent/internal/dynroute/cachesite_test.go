package dynroute

import (
	"testing"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/cdnca/cdnca/libs/edgeconfig/edgecache"
	"github.com/cdnca/cdnca/libs/edgeconfig/edgesite"
)

// CACHEFLOW-E01: a site whose objects are slices (site slice_bytes or a
// rule's own slice_bytes) must be projected as Sliced, or an exact purge
// looks up the whole-object key, removes nothing and reports success.
func TestCacheSiteOfProjectsSlices(t *testing.T) {
	slice := int64(256 << 10)
	zero := int64(0)
	site := func(policy edgeconfig.CachePolicyDocument) edgesite.Site {
		policy.Mode = edgeconfig.CacheOverride
		policy.QueryMode = edgeconfig.CacheQueryPreserve
		return edgesite.Site{SiteID: "s", TenantID: "t", Hosts: edgesite.Hosts{Primary: "a.test"},
			Listeners: []edgesite.Listener{{Port: 80}}, Cache: &edgesite.Cache{KeyPrefix: "p", Policy: policy}}
	}
	cases := []struct {
		name   string
		policy edgeconfig.CachePolicyDocument
		sliced bool
	}{
		{"whole objects", edgeconfig.CachePolicyDocument{}, false},
		{"site slices", edgeconfig.CachePolicyDocument{SliceBytes: slice}, true},
		{"below the smallest variant", edgeconfig.CachePolicyDocument{SliceBytes: 128 << 10}, false},
		{"rule slices only", edgeconfig.CachePolicyDocument{Rules: []edgeconfig.CacheRuleDocument{
			{PathPrefix: "/video/", Action: edgeconfig.CacheRuleActionCache, TTLSeconds: 60,
				CacheRuleExtras: edgeconfig.CacheRuleExtras{SliceBytes: &slice}}}}, true},
		{"rule turns slices off", edgeconfig.CachePolicyDocument{SliceBytes: slice, Rules: []edgeconfig.CacheRuleDocument{
			{PathPrefix: "/", Action: edgeconfig.CacheRuleActionCache, TTLSeconds: 60,
				CacheRuleExtras: edgeconfig.CacheRuleExtras{SliceBytes: &zero}}}}, true},
		{"no-cache rule slices nothing", edgeconfig.CachePolicyDocument{Rules: []edgeconfig.CacheRuleDocument{
			{PathPrefix: "/", Action: edgeconfig.CacheRuleActionNoCache}}}, false},
	}
	for _, test := range cases {
		if got := cacheSiteOf(site(test.policy)).Sliced; got != test.sliced {
			t.Errorf("%s: Sliced = %v, want %v", test.name, got, test.sliced)
		}
	}
}

// ADR 0021: on a chunking node a large object is stored as chunks (keys end
// in |slice=<chunk>) whatever the policy says: an exact purge of every
// caching site finds them by path (dyncache.Site.ChunkBytes), no zone scan.
func TestCacheSiteChunkedNodeHasChunkBytes(t *testing.T) {
	site := edgesite.Site{SiteID: "s", TenantID: "t", Hosts: edgesite.Hosts{Primary: "a.test"}, Listeners: []edgesite.Listener{{Port: 80}},
		Cache: &edgesite.Cache{KeyPrefix: "p", Policy: edgeconfig.CachePolicyDocument{Mode: edgeconfig.CacheOverride, QueryMode: edgeconfig.CacheQueryPreserve}}}
	for _, chunked := range []bool{false, true} {
		runtime := &Runtime{config: Config{ChunkedRange: chunked}, sites: []edgesite.Site{site}}
		runtime.zones.Count = 4
		value, err := runtime.cacheSite("t", "s")
		if err != nil || (value.ChunkBytes == edgecache.ChunkBytes) != chunked || value.Sliced {
			t.Fatalf("chunked %v: ChunkBytes = %d Sliced = %v err %v", chunked, value.ChunkBytes, value.Sliced, err)
		}
	}
}
