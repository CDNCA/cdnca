package ddos

import (
	"context"
	"net/netip"
	"strconv"
	"strings"
	"testing"
	"time"
)

// setRunner serves `nft --json list set` from sets (by set name) and
// delegates the rest.
type setRunner struct {
	*fakeRunner
	sets map[string]string
}

func (runner *setRunner) Run(ctx context.Context, arguments ...string) ([]byte, error) {
	joined := strings.Join(arguments, " ")
	if strings.HasPrefix(joined, "--json list set inet cdnca_ddos ") {
		name := arguments[len(arguments)-1]
		return []byte(`{"nftables":[{"metainfo":{}},{"set":{"name":"` + name + `","elem":[` + runner.sets[name] + `]}}]}`), nil
	}
	return runner.fakeRunner.Run(ctx, arguments...)
}

type seenBan struct {
	client    string
	count     int
	remaining time.Duration
}

func TestRateBanWatchReportsOnlyNewKernelBans(t *testing.T) {
	runner := &setRunner{fakeRunner: &fakeRunner{}, sets: map[string]string{}}
	manager, err := NewManager(t.Context(), runner, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_800_000_000, 0)
	watch := NewRateBanWatch(manager, func() time.Time { return now })
	var seen []seenBan
	watch.OnBan = func(client netip.Addr, count int, remaining time.Duration) {
		name := ""
		if client.IsValid() {
			name = client.String()
		}
		seen = append(seen, seenBan{name, count, remaining})
	}
	// No table: nothing listed.
	if err := watch.Step(t.Context()); err != nil || len(seen) != 0 {
		t.Fatalf("without a table: %v %v", seen, err)
	}
	spec, _ := NewSpec(testDDoS(t), []PortRange{{80, 80}})
	if err := manager.Apply(t.Context(), spec); err != nil {
		t.Fatal(err)
	}
	// An agent ban (empty connections / CC / auto defense) is not a rate ban.
	if _, err := manager.Ban(t.Context(), []netip.Addr{netip.MustParseAddr("198.51.100.200")}, time.Hour); err != nil {
		t.Fatal(err)
	}
	runner.sets[BanSetIPv4] = `{"elem":{"val":"198.51.100.7","timeout":120,"expires":118}},{"elem":{"val":"198.51.100.200","timeout":3600,"expires":3599}}`
	runner.sets[BanSetIPv6] = `"2001:db8:5::"`
	if err := watch.Step(t.Context()); err != nil {
		t.Fatal(err)
	}
	if len(seen) != 2 || seen[0] != (seenBan{"198.51.100.7", 1, 118 * time.Second}) || seen[1].client != "2001:db8:5::" {
		t.Fatalf("first step %+v", seen)
	}
	// The same bans listed again (time passed, expiry counts down): no repeat.
	now = now.Add(10 * time.Second)
	runner.sets[BanSetIPv4] = `{"elem":{"val":"198.51.100.7","timeout":120,"expires":108}}`
	if err := watch.Step(t.Context()); err != nil || len(seen) != 2 {
		t.Fatalf("repeated %+v %v", seen, err)
	}
	// After it expired the kernel bans it again: a new ban.
	now = now.Add(200 * time.Second)
	runner.sets[BanSetIPv4] = `{"elem":{"val":"198.51.100.7","timeout":120,"expires":119}}`
	if err := watch.Step(t.Context()); err != nil || len(seen) != 3 || seen[2].client != "198.51.100.7" {
		t.Fatalf("reban %+v %v", seen, err)
	}
	// A flood: MaxRateBanReports individual calls and one summary.
	var elements []string
	for index := 0; index < MaxRateBanReports+10; index++ {
		elements = append(elements, `{"elem":{"val":"203.0.`+strconv.Itoa(index/256)+`.`+strconv.Itoa(index%256)+`","timeout":60,"expires":59}}`)
	}
	runner.sets[BanSetIPv4] = strings.Join(elements, ",")
	runner.sets[BanSetIPv6] = ""
	seen = nil
	if err := watch.Step(t.Context()); err != nil {
		t.Fatal(err)
	}
	if len(seen) != MaxRateBanReports+1 || seen[len(seen)-1] != (seenBan{"", 10, 0}) {
		t.Fatalf("flood: %d calls, last %+v", len(seen), seen[len(seen)-1])
	}
	// The ones beyond the budget are not reported again either.
	seen = nil
	if err := watch.Step(t.Context()); err != nil || len(seen) != 0 {
		t.Fatalf("flood repeated %d", len(seen))
	}
}
