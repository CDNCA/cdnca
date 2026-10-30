package ccv2

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSEC11CompletedResponseUsesAccessWindow(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "edge", "openresty", "ccv2", "engine.lua"))
	if err != nil {
		t.Fatal(err)
	}
	source := string(raw)
	for _, required := range []string{
		"remember_404_observation(entry, prefix, bucket, ttl, match.status_404_count)",
		"observations[prefix] = { entry = entry, bucket = bucket, ttl = ttl, threshold = threshold }",
		"local bucket = observation.bucket",
		"local ttl = observation.ttl",
	} {
		if !strings.Contains(source, required) {
			t.Fatalf("completed-response window contract missing %q", required)
		}
	}

	logStart := strings.Index(source, "function _M.log()")
	logEnd := strings.Index(source[logStart:], "\nend\n\nreturn _M")
	if logStart < 0 || logEnd < 0 {
		t.Fatal("locate _M.log implementation")
	}
	logSource := source[logStart : logStart+logEnd]
	for _, forbidden := range []string{"ngx.now()", "matcher_bucket(", "matcher_ttl("} {
		if strings.Contains(logSource, forbidden) {
			t.Fatalf("log phase must not recompute the access window with %q", forbidden)
		}
	}
}
