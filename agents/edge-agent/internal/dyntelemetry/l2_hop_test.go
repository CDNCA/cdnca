package dyntelemetry

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/eventspool"
)

// fix-l2trust: an L2 node logs the L1's hop with "l2":true in the
// attribution. The L1's own line is the visitor's request: the hop never
// reaches the event spool (no second access event, no metering, no site
// usage), and it is not quarantined either.
func TestL2HopLinesAreSkipped(t *testing.T) {
	site := testSite(scopeA, tenantA, "0d120000-0000-4000-8000-000000000001", "a.example.test", nil, false, 80)
	digest := digestOf(t, site)
	registry := NewRegistry()
	_ = registry.Register(1, 1, map[string]string{scopeA: "cfg-a"})
	sites := mapSites{digest: site}
	visitor := accessLine(site, digest, "a.example.test", 1, 80)
	hop := strings.TrimSuffix(visitor, "}}") + `,"l2":true}}`
	plain := strings.TrimSuffix(visitor, "}}") + `,"l2":false}}`
	if _, attribution, err := Split([]byte(hop)); err != nil || !attribution.L2 {
		t.Fatalf("hop attribution %+v %v", attribution, err)
	}
	if _, err := Normalize([]byte(hop), registry, sites, nodeID); !errors.Is(err, ErrL2Hop) {
		t.Fatalf("hop normalized: %v", err)
	}
	if _, err := Normalize([]byte(plain), registry, sites, nodeID); err != nil {
		t.Fatalf("l2 false refused: %v", err)
	}

	root, _ := filepath.EvalSymlinks(t.TempDir())
	source := filepath.Join(root, "access.jsonl")
	if err := os.WriteFile(source, []byte(visitor+"\n"+hop+"\n"+plain+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	resolver := &Resolver{Registry: registry, Sites: sites, NodeID: nodeID}
	tailer, err := eventspool.NewTailer(eventspool.TailConfig{SourcePath: source, StateDir: filepath.Join(root, "state"),
		Identity: eventspool.TrustedIdentity{EnrollmentNodeID: nodeID}, MaxLineBytes: 16 << 10, MaxBatchEvents: 100,
		MaxQuarantineBytes: 1 << 20, Resolve: resolver.Resolve})
	if err != nil {
		t.Fatal(err)
	}
	collected := &sink{}
	result, err := tailer.TailOnce(context.Background(), collected)
	if err != nil || len(collected.events) != 2 || result.QuarantinedLines != 0 || result.SkippedLines != 1 || result.CompletedLines != 3 {
		t.Fatalf("tail %+v %v events %d", result, err, len(collected.events))
	}
	if counts := resolver.Counts(); counts.Attributed != 2 || counts.L2Hops != 1 || counts.Invalid != 0 {
		t.Fatalf("counts %+v", counts)
	}
	// read again: nothing new, the skipped line is not re-read
	if _, err := tailer.TailOnce(context.Background(), collected); err != nil || len(collected.events) != 2 {
		t.Fatalf("second tail %v events %d", err, len(collected.events))
	}
}
