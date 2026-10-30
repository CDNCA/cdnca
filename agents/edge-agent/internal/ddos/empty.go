package ddos

import (
	"context"
	"errors"
	"log/slog"
	"net/netip"
	"sort"
	"time"
)

// EmptySocket is an established TCP connection on a protected port that has
// not received one byte from its client.
type EmptySocket struct {
	Client netip.Addr
	Local  netip.AddrPort
	Remote netip.AddrPort
	// Cookie identifies the socket (sock_diag), so a connection is counted
	// once however many scans see it.
	Cookie uint64
	// Idle is how long since the connection was established without data.
	Idle time.Duration
}

// SocketSource lists the empty sockets of ports idle at least idle, and
// closes sockets (SOCK_DESTROY).
type SocketSource interface {
	EmptySockets(ctx context.Context, ports []PortRange, idle time.Duration) ([]EmptySocket, error)
	Destroy(ctx context.Context, sockets []EmptySocket) error
}

// ErrDestroyUnsupported: the kernel cannot close sockets on request.
var ErrDestroyUnsupported = errors.New("the kernel does not support SOCK_DESTROY")

// EmptyConnectionInterval is the scan period.
const EmptyConnectionInterval = 2 * time.Second

// maxTrackedClients bounds the detector's memory under a flood from many
// clients (the oldest windows are dropped first).
const maxTrackedClients = 200_000

// EmptyConnections bans clients that hold empty connections (a SYN
// flood check, done here on the kernel's own sockets, so it covers every
// protected port, websites and L4 forwards, and needs nothing in nginx). A
// connection established IdleSeconds without data is empty; a client with
// Threshold of them within WindowSeconds is banned in the DDoS table for
// BanSeconds and its empty connections are closed. Half open handshakes
// (SYN flood proper) are the kernel's: SYN cookies (install-node.sh sysctl
// baseline) answer them without state.
type EmptyConnections struct {
	manager *Manager
	source  SocketSource
	now     func() time.Time
	// counted: socket cookies already counted (with when, for expiry).
	counted map[uint64]time.Time
	// windows: per client (IPv6 /64) the times of its empty connections.
	windows map[netip.Prefix][]time.Time
	// OnBan is told of each ban (the security event).
	OnBan func(client netip.Addr, count int, ban time.Duration)
	// noDestroy: the kernel refused SOCK_DESTROY once; not asked again.
	noDestroy bool
}

func NewEmptyConnections(manager *Manager, source SocketSource, now func() time.Time) *EmptyConnections {
	return &EmptyConnections{manager: manager, source: source, now: now,
		counted: map[uint64]time.Time{}, windows: map[netip.Prefix][]time.Time{}}
}

// Run scans every EmptyConnectionInterval until ctx ends.
func (detector *EmptyConnections) Run(ctx context.Context) error {
	ticker := time.NewTicker(EmptyConnectionInterval)
	defer ticker.Stop()
	for {
		if err := detector.Step(ctx); err != nil && ctx.Err() == nil {
			slog.Warn("empty connection scan failed", "error", err)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

func clientKey(address netip.Addr) netip.Prefix {
	address = address.Unmap()
	bits := 32
	if address.Is6() {
		bits = 64
	}
	return netip.PrefixFrom(address, bits).Masked()
}

// Step scans once: counts new empty connections, bans the clients over the
// threshold and closes their empty connections.
func (detector *EmptyConnections) Step(ctx context.Context) error {
	spec := detector.manager.Active()
	if spec == nil || spec.EffectiveProtection().EmptyConnection == nil {
		clear(detector.counted)
		clear(detector.windows)
		return nil
	}
	policy := *spec.EffectiveProtection().EmptyConnection
	idle := time.Duration(policy.IdleSeconds) * time.Second
	window := time.Duration(policy.WindowSeconds) * time.Second
	now := detector.now()
	sockets, err := detector.source.EmptySockets(ctx, spec.Ports, idle)
	if err != nil {
		return err
	}
	for cookie, at := range detector.counted {
		if now.Sub(at) > window+idle {
			delete(detector.counted, cookie)
		}
	}
	byClient := map[netip.Prefix][]EmptySocket{}
	for _, socket := range sockets {
		client := socket.Client.Unmap()
		if !client.IsValid() || spec.exempt(client) {
			continue
		}
		key := clientKey(client)
		byClient[key] = append(byClient[key], socket)
		if _, seen := detector.counted[socket.Cookie]; seen {
			continue
		}
		detector.counted[socket.Cookie] = now
		detector.windows[key] = append(detector.windows[key], now)
	}
	var banned []netip.Addr
	var destroy []EmptySocket
	keys := make([]netip.Prefix, 0, len(detector.windows))
	for key := range detector.windows {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i].Addr().Less(keys[j].Addr()) })
	for _, key := range keys {
		times := detector.windows[key]
		kept := times[:0]
		for _, at := range times {
			if now.Sub(at) <= window {
				kept = append(kept, at)
			}
		}
		if len(kept) == 0 {
			delete(detector.windows, key)
			continue
		}
		detector.windows[key] = kept
		if uint32(len(kept)) >= policy.Threshold {
			banned = append(banned, key.Addr())
			destroy = append(destroy, byClient[key]...)
			if detector.OnBan != nil {
				detector.OnBan(key.Addr(), len(kept), time.Duration(policy.BanSeconds)*time.Second)
			}
			delete(detector.windows, key)
		}
	}
	if len(detector.windows) > maxTrackedClients {
		detector.trim()
	}
	if len(banned) == 0 {
		return nil
	}
	if _, err := detector.manager.Ban(ctx, banned, time.Duration(policy.BanSeconds)*time.Second); err != nil {
		return err
	}
	if detector.noDestroy {
		return nil
	}
	if err := detector.source.Destroy(ctx, destroy); errors.Is(err, ErrDestroyUnsupported) {
		detector.noDestroy = true
		slog.Info("empty connections of banned clients are left to time out", "reason", err)
	} else if err != nil {
		return err
	}
	return nil
}

// trim drops the clients whose last empty connection is oldest.
func (detector *EmptyConnections) trim() {
	type entry struct {
		key  netip.Prefix
		last time.Time
	}
	entries := make([]entry, 0, len(detector.windows))
	for key, times := range detector.windows {
		entries = append(entries, entry{key, times[len(times)-1]})
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].last.Before(entries[j].last) })
	for _, entry := range entries[:len(entries)-maxTrackedClients] {
		delete(detector.windows, entry.key)
	}
}
