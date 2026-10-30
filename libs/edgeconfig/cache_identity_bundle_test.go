package edgeconfig

import (
	"bytes"
	"time"
)

func productionCacheSpec() Spec {
	spec := validSpec()
	spec.ConfigVersionID = "22222222-2222-4222-8222-222222222222"
	spec.ConfigRevision = 7
	spec.TenantID = "11111111-1111-4111-8111-111111111111"
	spec.Sites[0].ID = "33333333-3333-4333-8333-333333333333"
	spec.Sites[0].Domain = "cache.example.test"
	spec.Sites[0].Cache = CachePolicy{
		Revision: 9, Mode: CacheFollowOrigin, ZoneSizeBytes: 1 << 20, MaxSizeBytes: 64 << 20,
		DefaultTTL: 60 * time.Second, QueryMode: CacheQueryPreserve,
	}
	return spec
}

func cloneBundleFiles(input map[string][]byte) map[string][]byte {
	result := make(map[string][]byte, len(input))
	for path, content := range input {
		result[path] = bytes.Clone(content)
	}
	return result
}
