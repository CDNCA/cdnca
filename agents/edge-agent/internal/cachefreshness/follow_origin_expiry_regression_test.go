package cachefreshness

import (
	"strings"
	"testing"
)

func TestCompileFollowOriginDelegatesCacheTTLToOriginHeaders(t *testing.T) {
	policy := validPolicy()
	policy.FollowOriginHeaders = true
	artifact, err := Compile(policy, testPaths())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(artifact.Nginx), "proxy_cache_valid ") {
		t.Fatal("follow-origin config still imposes a fixed cache TTL")
	}
}
