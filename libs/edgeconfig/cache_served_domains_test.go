package edgeconfig

import (
	"encoding/json"
	"testing"
)

func cachedWildcardSpec(t *testing.T, domain string) Spec {
	t.Helper()
	spec := validSpec()
	spec.TenantID = "11111111-1111-4111-8111-111111111111"
	spec.ConfigRevision = 7
	spec.Sites[0].ID = "22222222-2222-4222-8222-222222222222"
	spec.Sites[0].Domain = domain
	spec.Sites[0].Cache = validCachePolicy(CacheFollowOrigin)
	spec.Sites[0].Cache.Revision = 1
	return spec
}

func editCacheManifest(t *testing.T, content []byte, edit func(*CachePolicyManifest)) []byte {
	t.Helper()
	manifest, err := ParseCachePolicyManifest(content)
	if err != nil {
		t.Fatal(err)
	}
	edit(&manifest)
	encoded, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	return append(encoded, '\n')
}
