// Package l4guard raises the bans of L4 guard rules (guard_rules, tcp/udp
// v10, G4-d) to kernel bans: the L4 OpenResty queues a ban of a client
// that is the socket peer of a stream's own socket (cdnca_l4_geo guard());
// this runner drains the queue over the control socket and writes, per
// stream, a firewall scope of deny entries for the stream's ports that
// expire with the ban. The firewall manager applies them to the node's
// nftables table (inet cdnca_firewall), the channel website bans use; its
// expiry scheduler removes them. The OpenResty ban (shared dictionary) stays
// in force either way, so a failed or skipped kernel ban only costs work.
package l4guard

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/firewall"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/l4runtime"
	"github.com/google/uuid"
)

const (
	// Interval between drains of the queue.
	Interval = 5 * time.Second
	// MaxEntriesPerStream bounds one stream's kernel entries (each ban is an
	// entry per socket); the bans that expire first are dropped beyond it.
	MaxEntriesPerStream = 4096
	// Source and reason of the entries.
	entrySource = "l4_guard"
	// expiryMargin: entries closer to their end are not written.
	expiryMargin = firewall.BanMergeMargin
	maxBanLines  = 20000
	// MaxReportsPerStep bounds the OnBan calls of one drain.
	MaxReportsPerStep = 256
)

// BanSource drains the queued bans: "<stream>|<client>|<until epoch>" lines.
type BanSource interface {
	Bans(context.Context) ([]string, error)
}

// ConfigSource is the applied L4 runtime configuration (nil when none).
type ConfigSource interface {
	ActiveConfigV2(context.Context) (*l4runtime.ConfigV2, error)
}

// Firewall is the node firewall (firewall.Manager).
type Firewall interface {
	ScopeEntries(ctx context.Context, tenantID, siteID, policyKind, policyID string) (uint64, []firewall.Entry, error)
	Apply(context.Context, firewall.FirewallVersion) (firewall.Result, error)
}

// KernelBans is the runner.
type KernelBans struct {
	bans     BanSource
	config   ConfigSource
	firewall Firewall
	now      func() time.Time
	// pending holds bans not applied yet (retried until they expire).
	pending map[string]map[netip.Addr]time.Time
	// attempts numbers the applies (with the time, a task ID per attempt).
	attempts uint64
	// OnBan, when set, is called for each drained ban of a stream with a
	// kernel target (F4 node security events), at most MaxReportsPerStep a
	// step; OnBan(netip.Addr{}, n, 0) counts the n beyond.
	OnBan func(client netip.Addr, count int, remaining time.Duration)
}

var ErrInvalid = errors.New("invalid L4 kernel ban runner")

func New(bans BanSource, config ConfigSource, firewall Firewall, now func() time.Time) (*KernelBans, error) {
	if bans == nil || config == nil || firewall == nil || now == nil {
		return nil, ErrInvalid
	}
	return &KernelBans{bans: bans, config: config, firewall: firewall, now: now, pending: map[string]map[netip.Addr]time.Time{}}, nil
}

// Run drains the queue every Interval until ctx ends.
func (runner *KernelBans) Run(ctx context.Context) error {
	ticker := time.NewTicker(Interval)
	defer ticker.Stop()
	for {
		_ = runner.Step(ctx)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

// Step drains the queue once and applies the streams that have new bans.
func (runner *KernelBans) Step(ctx context.Context) error {
	lines, err := runner.bans.Bans(ctx)
	now := runner.now().UTC()
	for _, line := range lines {
		stream, client, until, ok := parseBan(line)
		if !ok || !until.After(now.Add(expiryMargin)) {
			continue
		}
		if runner.pending[stream] == nil {
			runner.pending[stream] = map[netip.Addr]time.Time{}
		}
		if until.After(runner.pending[stream][client]) {
			runner.pending[stream][client] = until
		}
	}
	if len(runner.pending) == 0 {
		return err
	}
	config, configErr := runner.config.ActiveConfigV2(ctx)
	if configErr != nil {
		return errors.Join(err, configErr)
	}
	targets := map[string]l4runtime.KernelBanTarget{}
	if config != nil {
		if targets, configErr = l4runtime.KernelBanTargets(*config); configErr != nil {
			return errors.Join(err, configErr)
		}
	}
	runner.report(lines, targets, now)
	streams := make([]string, 0, len(runner.pending))
	for stream := range runner.pending {
		streams = append(streams, stream)
	}
	sort.Strings(streams)
	for _, stream := range streams {
		target, ok := targets[stream]
		if !ok {
			delete(runner.pending, stream) // no longer banning on a socket of its own
			continue
		}
		if applyErr := runner.apply(ctx, target, runner.pending[stream], now); applyErr != nil {
			err = errors.Join(err, applyErr)
			for client, until := range runner.pending[stream] {
				if !until.After(now.Add(expiryMargin)) {
					delete(runner.pending[stream], client)
				}
			}
			if len(runner.pending[stream]) == 0 {
				delete(runner.pending, stream)
			}
			continue
		}
		delete(runner.pending, stream)
	}
	return err
}

func parseBan(line string) (string, netip.Addr, time.Time, bool) {
	parts := strings.Split(line, "|")
	if len(parts) != 3 {
		return "", netip.Addr{}, time.Time{}, false
	}
	stream, err := uuid.Parse(parts[0])
	if err != nil || stream.String() != parts[0] {
		return "", netip.Addr{}, time.Time{}, false
	}
	client, err := netip.ParseAddr(parts[1])
	if err != nil || client.Zone() != "" || client.Is4In6() || client.IsUnspecified() {
		return "", netip.Addr{}, time.Time{}, false
	}
	seconds, err := strconv.ParseInt(parts[2], 10, 64)
	if err != nil || seconds < 1 {
		return "", netip.Addr{}, time.Time{}, false
	}
	return parts[0], client, time.Unix(seconds, 0).UTC(), true
}

// apply merges bans into the stream's scope and applies it.
func (runner *KernelBans) apply(ctx context.Context, target l4runtime.KernelBanTarget, bans map[netip.Addr]time.Time, now time.Time) error {
	sockets := make([]firewall.BanSocket, len(target.Sockets))
	for index, socket := range target.Sockets {
		sockets[index] = firewall.BanSocket{Protocol: firewall.Protocol(socket.Protocol), Port: uint16(socket.Port), PortEnd: uint16(socket.PortEnd)}
	}
	runner.attempts++
	return firewall.MergeBans(ctx, runner.firewall, firewall.BanScope{
		TenantID: target.TenantID, SiteID: target.SiteID, Kind: firewall.PolicyKindL4Guard, PolicyID: target.StreamID,
		Source: entrySource, Reason: "stream " + target.StreamID, MaxEntries: MaxEntriesPerStream,
	}, sockets, bans, runner.now().UTC(), runner.attempts)
}

// ControlBans drains the queue through the L4 OpenResty control socket
// (l4runtime.L4ControlSocketPath, engine.lua control() "bans").
type ControlBans struct {
	Path string
}

var errControl = errors.New("L4 control socket reply is invalid")

func (source ControlBans) Bans(ctx context.Context) ([]string, error) {
	dialer := net.Dialer{Timeout: time.Second}
	connection, err := dialer.DialContext(ctx, "unix", source.Path)
	if err != nil {
		return nil, err
	}
	defer connection.Close()
	deadline := time.Now().Add(5 * time.Second)
	if value, ok := ctx.Deadline(); ok && value.Before(deadline) {
		deadline = value
	}
	_ = connection.SetDeadline(deadline)
	if _, err := connection.Write([]byte("bans\n")); err != nil {
		return nil, err
	}
	var lines []string
	scanner := bufio.NewScanner(connection)
	scanner.Buffer(make([]byte, 512), 512)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "end" {
			return lines, nil
		}
		if line == "error" || len(lines) >= maxBanLines {
			return nil, errControl
		}
		lines = append(lines, line)
	}
	// Lines read before an interrupted reply were removed from the queue.
	return lines, fmt.Errorf("%w: %v", errControl, scanner.Err())
}

// report calls OnBan for the drained bans that go to a kernel target; the
// queue drains each ban once, so nothing repeats.
func (runner *KernelBans) report(lines []string, targets map[string]l4runtime.KernelBanTarget, now time.Time) {
	if runner.OnBan == nil {
		return
	}
	reported, beyond := 0, 0
	for _, line := range lines {
		stream, client, until, ok := parseBan(line)
		if _, target := targets[stream]; !ok || !target || !until.After(now.Add(expiryMargin)) {
			continue
		}
		if reported >= MaxReportsPerStep {
			beyond++
			continue
		}
		reported++
		runner.OnBan(client, 1, until.Sub(now))
	}
	if beyond > 0 {
		runner.OnBan(netip.Addr{}, beyond, 0)
	}
}
