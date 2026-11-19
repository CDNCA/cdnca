package dyntelemetry

import (
	"bufio"
	"errors"
	"os"
	"testing"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/eventspool"
)

// The port's default site (默认站点) serves a request whose Host no site
// names (cdnca_site.lua unknown_or_default): a node logged such requests
// (IP Host, market probes and scanners) under the default site, and every
// one was quarantined as TAIL_INVALID_JSON because the Host is not one of
// the site's names. testdata: two such lines (addresses and IDs replaced).
func TestDefaultSiteLineOfAnUnknownHost(t *testing.T) {
	const (
		scope  = "0190c0de-0000-7000-8000-00000000a002"
		tenant = "0190c0de-0000-7000-8000-00000000a001"
		siteID = "0190c0de-0000-7000-8000-00000000a003"
		digest = "5e1f0d2c5e1f0d2c5e1f0d2c5e1f0d2c5e1f0d2c5e1f0d2c5e1f0d2c5e1f0d2c"
	)
	site := testSite(scope, tenant, siteID, "m.demo.cdnca.com", []string{"shop.demo.cdnca.com"}, true, 80)
	site.Default = true
	registry := NewRegistry()
	if err := registry.Register(33, 33, map[string]string{scope: "cfg-default"}); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open("testdata/default-site-ip-host.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	scanner.Buffer(nil, 1<<20)
	lines := 0
	for scanner.Scan() {
		line := append([]byte(nil), scanner.Bytes()...)
		lines++
		result, err := Normalize(line, registry, mapSites{digest: site}, nodeID)
		if err != nil {
			t.Fatalf("line %d: %v", lines, err)
		}
		if _, err := eventspool.ParseSourceLineBound(result.Line, result.CapturePolicy, result.Identity); err != nil {
			t.Fatalf("line %d spool parse: %v", lines, err)
		}
		// A site that is not the port's default still refuses the Host.
		site.Default = false
		if _, err := Normalize(line, registry, mapSites{digest: site}, nodeID); !errors.Is(err, ErrInvalid) {
			t.Fatalf("line %d not default: %v", lines, err)
		}
		site.Default = true
		// The default site covers unknown Hosts on its own ports only.
		other := testSite(scope, tenant, siteID, "m.demo.cdnca.com", nil, true, 8080)
		other.Default = true
		if _, err := Normalize(line, registry, mapSites{digest: other}, nodeID); !errors.Is(err, ErrInvalid) {
			t.Fatalf("line %d port not served: %v", lines, err)
		}
	}
	if err := scanner.Err(); err != nil || lines != 2 {
		t.Fatalf("lines %d %v", lines, err)
	}
}
