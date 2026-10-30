package l4runtime

// KernelBanSocket is a socket a stream's kernel bans cover: the protocol and
// ports (PortEnd == Port for a single port) of a listener the stream alone
// serves.
type KernelBanSocket struct {
	Protocol Protocol
	Port     int
	PortEnd  int
}

// KernelBanTarget names a stream whose guard rules ban and the sockets a
// kernel ban of its clients covers (G4-d, guard()). Sockets behind a
// shared port's dispatcher are left out: the port also serves other streams
// or websites, so only the stream's own refusal applies there.
type KernelBanTarget struct {
	TenantID string
	SiteID   string
	StreamID string
	Sockets  []KernelBanSocket
}

// KernelBanTargets returns, by stream ID, the streams of config with a ban
// rule and at least one socket of their own.
func KernelBanTargets(config ConfigV2) (map[string]KernelBanTarget, error) {
	normalized, err := normalizeConfigV2(config)
	if err != nil {
		return nil, err
	}
	var sockets []ListenerV2
	for _, listener := range normalized.Listeners {
		for _, socket := range listenerSocketsV2(listener) {
			sockets = append(sockets, listener.onSocket(socket))
		}
	}
	plan, err := planSharedSocketsV2(sockets, normalized.SiteSockets, normalized.dispatchDirectory())
	if err != nil {
		return nil, err
	}
	targets := map[string]KernelBanTarget{}
	for _, listener := range normalized.Listeners {
		if !bansClients(listener) {
			continue
		}
		target := KernelBanTarget{TenantID: listener.TenantID, SiteID: listener.SiteID, StreamID: listener.StreamID}
		for _, socket := range listenerSocketsV2(listener) {
			if plan.modes[socket.ID] == socketDispatched {
				continue
			}
			physical := listener.onSocket(socket)
			target.Sockets = append(target.Sockets, KernelBanSocket{Protocol: socket.Protocol, Port: socket.Port, PortEnd: physical.lastPort()})
		}
		if len(target.Sockets) != 0 {
			targets[listener.StreamID] = target
		}
	}
	return targets, nil
}
