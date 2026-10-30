package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"os"
	"strings"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/gatewayclient"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/nodemonitoring"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/xdp"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
)

// xdpSettings is the Agent configuration's xdp block. The mode
// is detected at every start (native, generic, else nftables); disabled
// turns XDP off (install-node.sh --disable-xdp), interfaces pins the
// uplinks (default: every physical interface that is up with an address).
type xdpSettings struct {
	Disabled   bool     `json:"disabled,omitempty"`
	Interfaces []string `json:"interfaces,omitempty"`
}

// xdpMaxInterfaces bounds xdp.interfaces.
const xdpMaxInterfaces = 64

func (s xdpSettings) validate() error {
	if len(s.Interfaces) > xdpMaxInterfaces {
		return errors.New("xdp.interfaces has too many entries")
	}
	seen := map[string]bool{}
	for _, name := range s.Interfaces {
		if name == "" || len(name) > 15 || strings.ContainsAny(name, "/= \x00\r\n\t") || seen[name] {
			return fmt.Errorf("xdp.interfaces entry %q is not an interface name", name)
		}
		seen[name] = true
	}
	return nil
}

// probeXDP detects and attaches the node XDP filter; the node runs
// nftables alone when it cannot (the DDoS table enforces everything
// either way).
func probeXDP(settings xdpSettings, output io.Writer) *xdp.Manager {
	manager := xdp.Probe(xdp.Options{Disabled: settings.Disabled, Interfaces: settings.Interfaces})
	logXDPStatus(output, manager.Status())
	return manager
}

func logXDPStatus(output io.Writer, status xdp.Status) {
	if status.Mode.XDP() {
		fmt.Fprintf(output, "edge-agent: XDP filter %s on %s (kernel %s)\n", status.Mode, strings.Join(status.Interfaces, ","), status.Kernel)
		return
	}
	fmt.Fprintf(output, "edge-agent: XDP filter not attached, mode %s (%s): %s\n", status.Mode, status.Reason, status.Detail)
}

// xdpCapability declares XDP_FILTER v1 while the filter runs: it is withdrawn
// as soon as the filter falls back to nftables and declared again once it
// reattaches (the Gateway session reconnects with a new hello on each change).
func xdpCapability(manager *xdp.Manager) gatewayclient.LiveCapability {
	return gatewayclient.LiveCapability{Name: agentv1.CapabilityName_CAPABILITY_NAME_XDP_FILTER, APIVersion: 1,
		Ready: manager.Running, Changed: manager.Changed()}
}

// xdpStatusMetrics is the node telemetry view of the filter.
func xdpStatusMetrics(manager *xdp.Manager) func(context.Context) *nodemonitoring.XDPStatusMetrics {
	return func(context.Context) *nodemonitoring.XDPStatusMetrics {
		status := manager.Status()
		metrics := &nodemonitoring.XDPStatusMetrics{Mode: string(status.Mode), Reason: status.Reason,
			Detail: strings.Map(func(r rune) rune {
				if r < 0x20 {
					return ' '
				}
				return r
			}, status.Detail), Interfaces: status.Interfaces}
		if counters, err := manager.Counters(); err == nil {
			for _, counter := range counters {
				metrics.Drops = append(metrics.Drops, nodemonitoring.DDoSDropMetrics{Kind: counter.Kind, Packets: counter.Packets, Bytes: counter.Bytes})
			}
		}
		return metrics
	}
}

// xdpVerifyInterval is how often the attached filter is verified and its
// expired entries swept.
const xdpVerifyInterval = 30 * time.Second

// xdpWatch verifies the filter (links attached, config map intact) and
// sweeps expired entries. A run time fallback (failed verification, map
// write or attach) leaves the node on nftables, which enforces every rule
// already; the watch logs it once and retries the attach (xdp.Manager.
// Reattach) with a backoff from xdpVerifyInterval to xdpRetryMax, then
// re-configures the DDoS spec on it (reattached: SetFront).
type xdpWatch struct {
	manager xdpWatched
	// reattached runs after a successful retry (ddos.Manager.SetFront).
	reattached func()
	// events reports each transition once as a node security event (nil:
	// log only).
	events xdpTransitionEvents
	// fellBack, retryAt, backoff: the retry state (step's caller only).
	fellBack bool
	retryAt  time.Time
	backoff  time.Duration
}

// xdpRetryMax bounds the reattach backoff.
const xdpRetryMax = 10 * time.Minute

// xdpWatched is the part of *xdp.Manager the watch drives.
type xdpWatched interface {
	Running() bool
	Verify() error
	Sweep() (int, error)
	Status() xdp.Status
	Reattach() error
}

// xdpTransitionEvents is the part of nodeSecurityEvents the watch reports to.
type xdpTransitionEvents interface {
	XDPFallback(reason string)
	XDPReattached(mode string)
}

func newXDPWatch(manager xdpWatched, reattached func(), events xdpTransitionEvents) *xdpWatch {
	return &xdpWatch{manager: manager, reattached: reattached, events: events}
}

func (watch *xdpWatch) Run(ctx context.Context) error {
	ticker := time.NewTicker(xdpVerifyInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
		watch.step(time.Now())
	}
}

func (watch *xdpWatch) step(now time.Time) {
	if watch.manager.Running() {
		if err := watch.manager.Verify(); err == nil {
			if _, err := watch.manager.Sweep(); err != nil {
				slog.Warn("XDP filter sweep failed", "error", err)
			}
			return
		}
	}
	if !watch.fellBack {
		status := watch.manager.Status()
		slog.Warn("XDP filter fell back, the node runs nftables (kernel bans) until it reattaches",
			"reason", status.Reason, "detail", status.Detail)
		watch.fellBack, watch.backoff, watch.retryAt = true, xdpVerifyInterval, now.Add(xdpVerifyInterval)
		if watch.events != nil {
			watch.events.XDPFallback(status.Reason)
		}
		return
	}
	if now.Before(watch.retryAt) {
		return
	}
	if err := watch.manager.Reattach(); err != nil {
		watch.backoff = min(2*watch.backoff, xdpRetryMax)
		watch.retryAt = now.Add(watch.backoff)
		slog.Warn("XDP filter reattach failed, still on nftables", "error", err, "next_retry", watch.backoff.String())
		return
	}
	watch.fellBack = false
	if watch.reattached != nil {
		watch.reattached()
	}
	status := watch.manager.Status()
	slog.Info("XDP filter reattached", "mode", string(status.Mode), "interfaces", strings.Join(status.Interfaces, ","))
	if watch.events != nil {
		watch.events.XDPReattached(string(status.Mode))
	}
}

// xdpPortBans mirrors the CC kernel bans (site ports) to the filter.
func xdpPortBans(manager *xdp.Manager) func(clients map[netip.Addr]time.Time, ports []uint16) {
	return func(clients map[netip.Addr]time.Time, ports []uint16) {
		if !manager.Running() {
			return
		}
		for client, until := range clients {
			if err := manager.BanPorts([]netip.Addr{client}, ports, until); err != nil {
				slog.Warn("XDP filter port ban not written", "error", err)
				return
			}
		}
	}
}

// xdpPortUnbans withdraws XDP port bans the narrowed kernel bans dropped
// (card 5).
func xdpPortUnbans(manager *xdp.Manager) func(map[netip.Addr][]uint16) {
	return func(clients map[netip.Addr][]uint16) {
		if !manager.Running() {
			return
		}
		for client, ports := range clients {
			if err := manager.UnbanPorts(client, ports); err != nil {
				slog.Warn("XDP filter port ban not withdrawn", "error", err)
				return
			}
		}
	}
}

// xdpProbeCommand is "edge-agent xdp-probe": the installer's detection
// (no program stays attached: the probe detaches on exit). It prints the
// status as JSON and exits 0 whatever the mode.
func xdpProbeCommand(args []string, output io.Writer) int {
	settings := xdpSettings{}
	for _, arg := range args {
		name, ok := strings.CutPrefix(arg, "--interface=")
		if !ok {
			fmt.Fprintf(os.Stderr, "edge-agent xdp-probe: unknown argument %q\n", arg)
			return 2
		}
		settings.Interfaces = append(settings.Interfaces, name)
	}
	if err := settings.validate(); err != nil {
		fmt.Fprintln(os.Stderr, "edge-agent xdp-probe:", err)
		return 2
	}
	manager := xdp.Probe(xdp.Options{Interfaces: settings.Interfaces})
	status := manager.Status()
	manager.Close()
	encoded, _ := json.Marshal(status)
	fmt.Fprintln(output, string(encoded))
	return 0
}
