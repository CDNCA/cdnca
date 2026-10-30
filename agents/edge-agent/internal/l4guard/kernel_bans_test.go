package l4guard

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/firewall"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/l4runtime"
	"github.com/cdnca/cdnca/libs/edgeconfig"
)

const (
	tenant  = "11111111-1111-4111-8111-111111111111"
	streamA = "33333333-3333-4333-8333-00000000000a"
	streamB = "33333333-3333-4333-8333-00000000000b"
	streamC = "33333333-3333-4333-8333-00000000000c"
)

// nft records the batches and answers the table listing the manager checks.
type nft struct {
	mu      sync.Mutex
	batches []string
	comment string
	fail    bool
}

func (runner *nft) Run(_ context.Context, arguments ...string) ([]byte, error) {
	runner.mu.Lock()
	defer runner.mu.Unlock()
	switch {
	case len(arguments) == 3 && arguments[0] == "--check":
		return nil, nil
	case len(arguments) == 2 && arguments[0] == "--file":
		if runner.fail {
			runner.fail = false // the apply fails, the rollback succeeds
			return nil, errors.New("nft failed")
		}
		batch, err := os.ReadFile(arguments[1])
		if err != nil {
			return nil, err
		}
		runner.batches = append(runner.batches, string(batch))
		runner.comment = ""
		if _, rest, ok := strings.Cut(string(batch), `comment "`); ok {
			runner.comment, _, _ = strings.Cut(rest, `"`)
		}
		return nil, nil
	case len(arguments) == 5 && arguments[1] == "list":
		return json.Marshal(map[string]any{"nftables": []any{
			map[string]any{"table": map[string]any{"family": firewall.TableFamily, "name": firewall.TableName, "comment": runner.comment}},
		}})
	}
	return nil, fmt.Errorf("unexpected nft %v", arguments)
}

func (runner *nft) last() string {
	runner.mu.Lock()
	defer runner.mu.Unlock()
	if len(runner.batches) == 0 {
		return ""
	}
	return runner.batches[len(runner.batches)-1]
}

type queue struct{ lines []string }

func (source *queue) Bans(context.Context) ([]string, error) {
	lines := source.lines
	source.lines = nil
	return lines, nil
}

type active struct{ config *l4runtime.ConfigV2 }

func (source active) ActiveConfigV2(context.Context) (*l4runtime.ConfigV2, error) {
	return source.config, nil
}

func stream(id string, protocol l4runtime.Protocol, port, portEnd int, rules []l4runtime.GuardRuleV2) l4runtime.StreamRuntimeSpecV2 {
	return l4runtime.StreamRuntimeSpecV2{
		SchemaVersion: l4runtime.SchemaVersionV2, TenantID: tenant, StreamID: id, Revision: 1,
		Listener:         l4runtime.ListenerSocketV2{Protocol: protocol, Address: "*", Port: port, PortEnd: portEnd},
		Endpoint:         l4runtime.EndpointV2{Address: "192.0.2.10", Port: 9000},
		Geo:              l4runtime.GeoPolicyV2{TenantID: tenant, StreamID: id, Revision: 1, UnknownRegionAction: l4runtime.GeoActionAllow},
		ConnectTimeoutMS: 1000, ResponseTimeoutMS: 5000, MaxConnectionsPerClient: 10, DrainTimeoutMS: 30000,
		GuardRules: rules,
	}
}

func fixture(t *testing.T) (*KernelBans, *queue, *nft, *firewall.Manager, *time.Time) {
	t.Helper()
	ban := []l4runtime.GuardRuleV2{{ID: "66666666-6666-4666-8666-666666666661", Action: edgeconfig.L4GuardActionBan, BanSeconds: 600,
		Threshold: 1, ClientIP: &edgeconfig.L4GuardClientIP{CIDRs: []string{"0.0.0.0/0", "::/0"}}}}
	drop := []l4runtime.GuardRuleV2{{ID: "66666666-6666-4666-8666-666666666662", Action: edgeconfig.L4GuardActionDrop,
		ClientIP: &edgeconfig.L4GuardClientIP{CIDRs: []string{"0.0.0.0/0"}}}}
	config, err := l4runtime.AggregateStreamRuntimeSpecsV2("guard-v1", 1, []l4runtime.StreamRuntimeSpecV2{
		stream(streamA, l4runtime.ProtocolTCP, 9443, 0, ban),
		stream(streamB, l4runtime.ProtocolUDP, 20000, 20010, ban),
		stream(streamC, l4runtime.ProtocolTCP, 9500, 0, drop),
	})
	if err != nil {
		t.Fatal(err)
	}
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	clock := time.Unix(1_800_000_000, 0).UTC()
	runner := &nft{}
	manager, err := firewall.NewManagerWithDependencies(filepath.Join(root, "firewall"), runner, func() time.Time { return clock })
	if err != nil {
		t.Fatal(err)
	}
	bans := &queue{}
	kernel, err := New(bans, active{&config}, manager, func() time.Time { return clock })
	if err != nil {
		t.Fatal(err)
	}
	return kernel, bans, runner, manager, &clock
}

func line(stream, client string, until time.Time) string {
	return fmt.Sprintf("%s|%s|%d", stream, client, until.Unix())
}

// A queued ban becomes deny entries for the stream's own ports that expire
// with it; later bans merge into the scope; a longer ban extends an entry;
// invalid lines, streams without a socket of their own and unknown streams
// are ignored.
func TestKernelBansWriteExpiringPortScopedEntries(t *testing.T) {
	kernel, bans, runner, manager, clock := fixture(t)
	bans.lines = []string{
		line(streamA, "203.0.113.9", clock.Add(10*time.Minute)),
		line(streamB, "2001:db8::9", clock.Add(5*time.Minute)),
		line(streamC, "203.0.113.9", clock.Add(10*time.Minute)), // drop only: not a target
		line("44444444-4444-4444-8444-444444444444", "203.0.113.9", clock.Add(time.Minute)),
		"garbage", streamA + "|not-an-ip|1900000000", line(streamA, "::ffff:1.2.3.4", clock.Add(time.Minute)),
		line(streamA, "198.51.100.1", clock.Add(time.Second)), // ends within the margin
	}
	var reported []string
	kernel.OnBan = func(client netip.Addr, count int, remaining time.Duration) {
		reported = append(reported, fmt.Sprintf("%s %d %s", client, count, remaining))
	}
	if err := kernel.Step(t.Context()); err != nil {
		t.Fatal(err)
	}
	// F4: only the bans that become kernel entries are reported.
	if strings.Join(reported, ",") != "203.0.113.9 1 10m0s,2001:db8::9 1 5m0s" {
		t.Fatalf("reported %q", reported)
	}
	version, entries, err := manager.ScopeEntries(t.Context(), tenant, streamA, firewall.PolicyKindL4Guard, streamA)
	if err != nil || version != 1 || len(entries) != 1 {
		t.Fatalf("stream A scope = v%d %+v %v", version, entries, err)
	}
	entry := entries[0]
	if entry.Network != "203.0.113.9/32" || entry.Protocol != firewall.ProtocolTCP || entry.PortStart != 9443 || entry.PortEnd != 9443 ||
		entry.Action != firewall.ActionDeny || entry.ExpiresAt == nil || !entry.ExpiresAt.Equal(clock.Add(10*time.Minute)) {
		t.Fatalf("stream A entry = %+v", entry)
	}
	if _, entries, _ := manager.ScopeEntries(t.Context(), tenant, streamB, firewall.PolicyKindL4Guard, streamB); len(entries) != 1 ||
		entries[0].Network != "2001:db8::9/128" || entries[0].Protocol != firewall.ProtocolUDP || entries[0].PortStart != 20000 || entries[0].PortEnd != 20010 {
		t.Fatalf("stream B entries = %+v", entries)
	}
	if version, _, _ := manager.ScopeEntries(t.Context(), tenant, streamC, firewall.PolicyKindL4Guard, streamC); version != 0 {
		t.Fatal("a stream without ban rules got kernel entries")
	}
	batch := runner.last()
	for _, want := range []string{"scoped_1 { 203.0.113.9/32 }", "ip saddr @scoped_1 tcp dport 9443", "scoped_2 { 2001:db8::9/128 }", "ip6 saddr @scoped_2 udp dport 20000-20010"} {
		if !strings.Contains(batch, want) {
			t.Fatalf("nft batch lacks %q:\n%s", want, batch)
		}
	}
	if strings.Contains(batch, "198.51.100.1") {
		t.Fatal("a ban ending within the margin was written")
	}

	// Another client, a longer ban of the first, a repeat: merged, extended.
	*clock = clock.Add(time.Minute)
	bans.lines = []string{line(streamA, "203.0.113.10", clock.Add(time.Hour)), line(streamA, "203.0.113.9", clock.Add(time.Hour)),
		line(streamA, "203.0.113.9", clock.Add(time.Minute))}
	if err := kernel.Step(t.Context()); err != nil {
		t.Fatal(err)
	}
	version, entries, _ = manager.ScopeEntries(t.Context(), tenant, streamA, firewall.PolicyKindL4Guard, streamA)
	if version != 2 || len(entries) != 2 {
		t.Fatalf("merged scope = v%d %+v", version, entries)
	}
	for _, entry := range entries {
		if !entry.ExpiresAt.Equal(clock.Add(time.Hour)) {
			t.Fatalf("entry not extended to the longer ban: %+v", entry)
		}
	}
	// A ban no longer than what is applied changes nothing.
	applied := len(runner.batches)
	bans.lines = []string{line(streamA, "203.0.113.9", clock.Add(30*time.Minute))}
	if err := kernel.Step(t.Context()); err != nil || len(runner.batches) != applied {
		t.Fatalf("no-op ban applied again: %v (%d batches)", err, len(runner.batches)-applied)
	}
}

// A failed apply keeps the bans for the next drain; the dictionary ban
// still refuses the client meanwhile.
func TestKernelBansRetryAfterAFailedApply(t *testing.T) {
	kernel, bans, runner, manager, clock := fixture(t)
	runner.fail = true
	bans.lines = []string{line(streamA, "203.0.113.9", clock.Add(10*time.Minute))}
	if err := kernel.Step(t.Context()); err == nil {
		t.Fatal("failed apply reported success")
	}
	if version, _, _ := manager.ScopeEntries(t.Context(), tenant, streamA, firewall.PolicyKindL4Guard, streamA); version != 0 {
		t.Fatal("a rolled back apply left a scope")
	}
	if err := kernel.Step(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, entries, _ := manager.ScopeEntries(t.Context(), tenant, streamA, firewall.PolicyKindL4Guard, streamA); len(entries) != 1 {
		t.Fatalf("retried ban not applied: %+v", entries)
	}
}

// The scope is bounded: beyond MaxEntriesPerStream the bans that end first
// are left to the OpenResty ban.
func TestKernelBansAreBounded(t *testing.T) {
	kernel, bans, _, manager, clock := fixture(t)
	for index := 0; index < MaxEntriesPerStream+10; index++ {
		bans.lines = append(bans.lines, line(streamA, fmt.Sprintf("10.%d.%d.%d", index/65536, index/256%256, index%256),
			clock.Add(time.Duration(index+60)*time.Second)))
	}
	if err := kernel.Step(t.Context()); err != nil {
		t.Fatal(err)
	}
	_, entries, _ := manager.ScopeEntries(t.Context(), tenant, streamA, firewall.PolicyKindL4Guard, streamA)
	if len(entries) != MaxEntriesPerStream {
		t.Fatalf("%d entries, want %d", len(entries), MaxEntriesPerStream)
	}
	for _, entry := range entries {
		if entry.Network == "10.0.0.0/32" {
			t.Fatal("the shortest ban was kept over a longer one")
		}
	}
}
