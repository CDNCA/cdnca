package l4runtime

import (
	"context"
	"errors"
)

// ActiveConfigV2 is the v2 configuration the runtime serves, nil when none
// (or the active version is v1). The live connection list reads it.
func (m *Manager) ActiveConfigV2(ctx context.Context) (*ConfigV2, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	unlock, err := m.store.lock(ctx)
	if err != nil {
		return nil, err
	}
	defer unlock()
	active, err := m.store.loadActive()
	if err != nil || active == nil {
		return nil, err
	}
	compiled, versionDir, err := m.store.loadVersion(active.VersionID, active.Digest)
	if err != nil || versionDir != active.VersionDir {
		return nil, errors.Join(ErrCorruptState, err)
	}
	if compiled.v2 == nil {
		return nil, nil
	}
	config := *compiled.v2
	return &config, nil
}

// WorkerPIDs lists the owned master's worker processes, retiring
// generations included: a live session may be served by any of them.
func (r *OpenResty) WorkerPIDs() ([]int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	handle, record, running, err := r.openOwnedProcess()
	if err != nil || !running {
		return nil, errors.Join(errProcessNotRunning, err)
	}
	defer handle.Close()
	workers, err := r.workerGeneration(record)
	if err != nil {
		return nil, err
	}
	pids := make([]int, 0, len(workers))
	for worker := range workers {
		pids = append(pids, worker.PID)
	}
	return pids, nil
}

// LiveSocketV2 is one TCP listening socket of a stream as the live
// connection list sees it. Shared ports are served behind a dispatcher: a
// connection there belongs to the stream only by its registry entry.
// PortEnd is the last port of a port range (0: the single Port).
type LiveSocketV2 struct {
	ListenerID string
	Port       int
	PortEnd    int
	Shared     bool
}

// LiveSocketsV2 returns the TCP sockets of streamID in config.
func LiveSocketsV2(config ConfigV2, streamID string) ([]LiveSocketV2, *ListenerV2, error) {
	var sockets []ListenerV2
	var stream *ListenerV2
	for index, listener := range config.Listeners {
		if listener.StreamID == streamID {
			stream = &config.Listeners[index]
		}
		for _, socket := range listenerSocketsV2(listener) {
			physical := listener
			physical = physical.onSocket(socket)
			sockets = append(sockets, physical)
		}
	}
	if stream == nil {
		return nil, nil, ErrInvalidConfig
	}
	plan, err := planSharedSocketsV2(sockets, config.SiteSockets, config.dispatchDirectory())
	if err != nil {
		return nil, nil, err
	}
	var result []LiveSocketV2
	for _, socket := range listenerSocketsV2(*stream) {
		if socket.Protocol != ProtocolTCP {
			continue
		}
		result = append(result, LiveSocketV2{ListenerID: socket.ID, Port: socket.Port, PortEnd: socket.PortEnd,
			Shared: plan.modes[socket.ID] == socketDispatched})
	}
	return result, stream, nil
}

// UsageSocketV2 is one TCP socket of a listener with the telemetry identity
// its sessions' facts carry: in-progress usage checkpoints (L4-USAGE-01,
// internal/l4usage) bill a live session under it. PortEnd is the last port
// of a port range (0: the single Port).
type UsageSocketV2 struct {
	ListenerID, StreamID, TenantID, SiteID string
	ConfigVersionID, PackageSubscriptionID string
	ConfigRevision                         uint64
	Port, PortEnd                          int
}

// UsageSocketsV2 returns the TCP sockets config serves, by listener ID (UDP
// sessions end with their reply: no checkpoints).
func UsageSocketsV2(config ConfigV2) map[string]UsageSocketV2 {
	result := map[string]UsageSocketV2{}
	for _, listener := range config.Listeners {
		versionID, revision := listener.telemetryIdentity(config)
		for _, socket := range listenerSocketsV2(listener) {
			if socket.Protocol != ProtocolTCP || revision < 1 {
				continue
			}
			result[socket.ID] = UsageSocketV2{ListenerID: socket.ID, StreamID: listener.StreamID, TenantID: listener.TenantID,
				SiteID: listener.SiteID, ConfigVersionID: versionID, PackageSubscriptionID: listener.PackageSubscriptionID,
				ConfigRevision: uint64(revision), Port: socket.Port, PortEnd: socket.PortEnd}
		}
	}
	return result
}
