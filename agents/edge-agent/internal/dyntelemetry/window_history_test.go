package dyntelemetry

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/eventspool"
)

// TF-E04：别的 scope 频繁发布把全节点代数推过 64 代，本 scope 版本没变时，
// 早期代数的合法积压仍按原版本归属；本 scope 自己换过版本、历史已裁掉的，
// 不能误归到新版本，宽限到期后按归属历史缺失（不是坏 JSON）隔离。
func TestRegistryStableScopeOutlivesNodeWindow(t *testing.T) {
	registry := NewRegistry()
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(registry.Register(1, 1, map[string]string{scopeA: "a1", scopeB: "b1"}))
	for generation := uint64(2); generation <= Window+2; generation++ {
		must(registry.Register(generation, generation, map[string]string{scopeA: "a1", scopeB: fmt.Sprintf("b%d", generation)}))
	}
	if got, ok := registry.ConfigVersion(1, scopeA); !ok || got != "a1" {
		t.Fatalf("stable scope generation 1 = %q %v, want a1", got, ok)
	}
	if got, ok := registry.ConfigVersion(1, scopeB); ok {
		t.Fatalf("changed scope generation 1 resolved to %q after its history was pruned", got)
	}
	if got, ok := registry.ConfigVersion(Window+2, scopeB); !ok || got != fmt.Sprintf("b%d", Window+2) {
		t.Fatalf("newest = %q %v", got, ok)
	}
}

func TestResolverQuarantinesMissingHistoryApartFromInvalid(t *testing.T) {
	registry := NewRegistry()
	now := time.Date(2026, 10, 28, 1, 0, 0, 0, time.UTC)
	resolver := &Resolver{Registry: registry, Sites: mapSites{}, NodeID: nodeID, Now: func() time.Time { return now }}
	site := testSite(scopeA, tenantA, "0d120000-0000-4000-8000-000000000001", "a.example.test", nil, false, 80)
	line := []byte(accessLine(site, digestOf(t, site), "a.example.test", 1, 80))
	if _, err := resolver.Resolve(line); !errors.Is(err, eventspool.ErrLineNotReady) {
		t.Fatalf("first resolve = %v, want not ready", err)
	}
	now = now.Add(DefaultGrace + time.Second)
	_, err := resolver.Resolve(line)
	if !errors.Is(err, eventspool.ErrLineUnattributable) || errors.Is(err, ErrInvalid) {
		t.Fatalf("after grace = %v, want ErrLineUnattributable", err)
	}
}
