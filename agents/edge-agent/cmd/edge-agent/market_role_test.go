package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
)

const (
	roleJoin  = agentv1.MarketProbeRole_MARKET_PROBE_ROLE_JOIN_MARKET
	roleProbe = agentv1.MarketProbeRole_MARKET_PROBE_ROLE_PROBE_ONLY
)

// The controller joins and withdraws the node; the benchmark
// object follows; the assignment survives a restart.
func TestMarketRoleFollowsAssignmentAndPersists(t *testing.T) {
	journal := t.TempDir()
	role, err := newMarketRole(marketProbeSettings{Enabled: true}, journal)
	if err != nil {
		t.Fatal(err)
	}
	var applied []bool
	role.apply = func(_ context.Context, joined bool) error { applied = append(applied, joined); return nil }
	if got, source := role.AssignMarketRole(context.Background(), roleJoin); got != roleJoin || source != "assigned" || !role.Joined() {
		t.Fatalf("join = %v %q", got, source)
	}
	// The same assignment again does not reload.
	role.AssignMarketRole(context.Background(), roleJoin)
	if len(applied) != 1 || !applied[0] {
		t.Fatalf("applied %v", applied)
	}
	if info, err := os.Stat(filepath.Join(journal, "market-role")); err != nil || info.Mode().Perm() != 0o700 {
		t.Fatalf("role directory: %v %v", info, err)
	}
	restarted, err := newMarketRole(marketProbeSettings{Enabled: true}, journal)
	if err != nil || restarted.Role() != roleJoin {
		t.Fatalf("restart lost the assignment: %v %v", restarted.Role(), err)
	}
	if got, _ := role.AssignMarketRole(context.Background(), roleProbe); got != roleProbe || len(applied) != 2 || applied[1] {
		t.Fatalf("leave = %v, applied %v", got, applied)
	}
	if restarted, _ = newMarketRole(marketProbeSettings{Enabled: true}, journal); restarted.Role() != roleProbe {
		t.Fatalf("restart after leave = %v", restarted.Role())
	}
}

func TestMarketRoleLocalSettingsWin(t *testing.T) {
	for _, test := range []struct {
		settings marketProbeSettings
		want     agentv1.MarketProbeRole
		source   string
	}{
		{marketProbeSettings{Enabled: true, LeaveMarket: true}, roleProbe, "local_leave"},
		{marketProbeSettings{Enabled: true, JoinMarket: true}, roleJoin, "local_join"},
	} {
		role, err := newMarketRole(test.settings, t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		role.apply = func(context.Context, bool) error { t.Fatal("local setting must not reload"); return nil }
		for _, assigned := range []agentv1.MarketProbeRole{roleJoin, roleProbe} {
			if got, source := role.AssignMarketRole(context.Background(), assigned); got != test.want || source != test.source {
				t.Fatalf("%+v assigned %v = %v %q", test.settings, assigned, got, source)
			}
		}
	}
	// market_probe.enabled false: nothing is taken, nothing is written.
	journal := t.TempDir()
	role, err := newMarketRole(marketProbeSettings{}, journal)
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := role.AssignMarketRole(context.Background(), roleJoin); got != agentv1.MarketProbeRole_MARKET_PROBE_ROLE_DISABLED {
		t.Fatalf("disabled node joined: %v", got)
	}
	if _, err := os.Stat(filepath.Join(journal, "market-role")); !os.IsNotExist(err) {
		t.Fatalf("disabled node wrote a role: %v", err)
	}
}

func TestMarketRoleFailedReloadKeepsPreviousRole(t *testing.T) {
	journal := t.TempDir()
	role, err := newMarketRole(marketProbeSettings{Enabled: true}, journal)
	if err != nil {
		t.Fatal(err)
	}
	role.apply = func(context.Context, bool) error { return errors.New("reload failed") }
	if got, _ := role.AssignMarketRole(context.Background(), roleJoin); got != roleProbe || role.Joined() {
		t.Fatalf("failed reload joined: %v", got)
	}
	if _, err := os.Stat(filepath.Join(journal, "market-role", "role.json")); !os.IsNotExist(err) {
		t.Fatalf("failed reload saved: %v", err)
	}
	// A corrupt file restores probe-only.
	if err := os.WriteFile(filepath.Join(journal, "market-role", "role.json"), []byte(`{"assigned":"x"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if restarted, err := newMarketRole(marketProbeSettings{Enabled: true}, journal); err != nil || restarted.Role() != roleProbe {
		t.Fatalf("corrupt file = %v %v", restarted.Role(), err)
	}
}
