package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
)

// marketRole is the node's node-market role: the local
// market_probe settings bound it, the controller's assignment
// (MARKET_ROLE) picks it within them.
//
//   - market_probe.enabled false: disabled, no assignment is taken (the
//     node does not declare MARKET_ROLE).
//   - market_probe.leave_market: probe-only whatever is assigned.
//   - market_probe.join_market: joined whatever is assigned.
//   - otherwise: the last assignment, kept in role.json across restarts
//     (none yet: probe-only, the installer default).
//
// A change of "joined" serves or withdraws the benchmark object (apply); the
// assignment is saved only after apply succeeded, so a failed reload keeps
// the previous role and the controller asks again.
type marketRole struct {
	settings marketProbeSettings
	path     string
	apply    func(ctx context.Context, joined bool) error

	mu       sync.Mutex
	assigned bool // the controller assigned JOIN_MARKET
}

type marketRoleFile struct {
	Assigned string `json:"assigned"`
}

const (
	marketRoleSourceAssigned   = "assigned"
	marketRoleSourceLocalJoin  = "local_join"
	marketRoleSourceLocalLeave = "local_leave"
)

// newMarketRole restores the saved assignment under journal/market-role. A
// missing or unreadable file is probe-only (logged): never joined by accident.
func newMarketRole(settings marketProbeSettings, journal string) (*marketRole, error) {
	role := &marketRole{settings: settings, path: filepath.Join(journal, "market-role", "role.json")}
	if !settings.Enabled {
		return role, nil
	}
	if err := os.MkdirAll(filepath.Dir(role.path), 0o700); err != nil {
		return nil, fmt.Errorf("market role directory: %w", err)
	}
	if err := os.Chmod(filepath.Dir(role.path), 0o700); err != nil {
		return nil, fmt.Errorf("market role directory: %w", err)
	}
	content, err := os.ReadFile(role.path)
	if errors.Is(err, os.ErrNotExist) {
		return role, nil
	}
	var saved marketRoleFile
	if err != nil || len(content) > 4096 || json.Unmarshal(content, &saved) != nil ||
		(saved.Assigned != "join_market" && saved.Assigned != "probe_only") {
		slog.Default().Warn("market role file unreadable; node stays probe-only until the controller assigns again", "path", role.path)
		return role, nil
	}
	role.assigned = saved.Assigned == "join_market"
	return role, nil
}

// effective is the role in effect and why; mu is held.
func (role *marketRole) effective() (agentv1.MarketProbeRole, string) {
	switch {
	case !role.settings.Enabled:
		return agentv1.MarketProbeRole_MARKET_PROBE_ROLE_DISABLED, ""
	case role.settings.LeaveMarket:
		return agentv1.MarketProbeRole_MARKET_PROBE_ROLE_PROBE_ONLY, marketRoleSourceLocalLeave
	case role.settings.JoinMarket:
		return agentv1.MarketProbeRole_MARKET_PROBE_ROLE_JOIN_MARKET, marketRoleSourceLocalJoin
	case role.assigned:
		return agentv1.MarketProbeRole_MARKET_PROBE_ROLE_JOIN_MARKET, marketRoleSourceAssigned
	}
	return agentv1.MarketProbeRole_MARKET_PROBE_ROLE_PROBE_ONLY, marketRoleSourceAssigned
}

// Role is the role the heartbeat reports (EdgeRuntimeStatus.market_probe).
func (role *marketRole) Role() agentv1.MarketProbeRole {
	role.mu.Lock()
	defer role.mu.Unlock()
	current, _ := role.effective()
	return current
}

// Joined: the node serves the benchmark object (dynroute MarketBenchmark).
func (role *marketRole) Joined() bool {
	return role.Role() == agentv1.MarketProbeRole_MARKET_PROBE_ROLE_JOIN_MARKET
}

// AssignMarketRole applies a controller assignment (gatewayclient.MarketRoleAssigner).
func (role *marketRole) AssignMarketRole(ctx context.Context, assigned agentv1.MarketProbeRole) (agentv1.MarketProbeRole, string) {
	role.mu.Lock()
	defer role.mu.Unlock()
	join := assigned == agentv1.MarketProbeRole_MARKET_PROBE_ROLE_JOIN_MARKET
	if !role.settings.Enabled || role.settings.LeaveMarket || role.settings.JoinMarket || join == role.assigned {
		return role.effective() // a local setting decides, or nothing changes
	}
	if role.apply != nil {
		if err := role.apply(ctx, join); err != nil {
			slog.Default().Warn("market role change not applied; previous role kept", "join_market", join, "err", err)
			return role.effective()
		}
	}
	name := "probe_only"
	if join {
		name = "join_market"
	}
	content, _ := json.Marshal(marketRoleFile{Assigned: name})
	if err := writePrivateFileAtomic(role.path, content); err != nil {
		// Running with the new role; after a restart the controller assigns again.
		slog.Default().Warn("market role not saved", "path", role.path, "err", err)
	}
	role.assigned = join
	return role.effective()
}
