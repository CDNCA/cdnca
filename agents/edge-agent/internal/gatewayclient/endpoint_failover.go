package gatewayclient

// Ordered gateway endpoints with failover (ADR 0013 §4.5/§5.2, GW-07).
// The first endpoint is the port-transition managed one (SwitchingDialer);
// then the configured ones, then the list the control plane publishes in
// GatewayHello (persisted, so it survives restarts). A failed dial moves to
// the next entry and the list wraps; a grpc entry is retried once as ws on
// the same address (the gateway port serves both transports, §4.2), a ws
// entry is never retried as grpc (a CDN does not forward client
// certificates). While a later entry is in use, RunFallbackProbe tries the
// earlier ones every few minutes and, when one answers, makes the next
// session start there; the healthy session is never interrupted.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/gatewaytunnel"
)

type GatewayEndpoint struct {
	Address    string
	ServerName string
	Transport  string
	TunnelHost string
	// EnrollmentAddress is the enrollment port of a published grpc entry's
	// Gateway (persisted for re-enrollment); empty otherwise.
	EnrollmentAddress string `json:",omitempty"`
}

// MaxLearnedGatewayEndpoints bounds the published list a node keeps.
const MaxLearnedGatewayEndpoints = 32

// FallbackProbeInterval is how often earlier endpoints are retried (§4.5).
const FallbackProbeInterval = 5 * time.Minute

type FailoverDialer struct {
	primary Dialer
	base    MTLSDialerConfig
	extra   []GatewayEndpoint
	mu      sync.Mutex
	next    int
	newMTLS func(MTLSDialerConfig) (Dialer, error)
	// learned is the control plane's list (GatewayHello), deduplicated
	// against the primary and configured entries; learnedFile persists it.
	learned        []GatewayEndpoint
	learnedVersion string
	learnedFile    string
	// dialed is the index of the last successful dial (the session's
	// endpoint); avoided holds endpoints of a disabled Gateway (address|
	// transport) skipped by the fallback probe until a new list names them.
	dialed  int
	avoided map[string]bool
}

type learnedEndpointsFile struct {
	Version   string            `json:"version"`
	Endpoints []GatewayEndpoint `json:"endpoints"`
}

func validateEndpoint(base MTLSDialerConfig, endpoint GatewayEndpoint, newMTLS func(MTLSDialerConfig) (Dialer, error)) error {
	if endpoint.Address == "" || endpoint.ServerName == "" || !gatewaytunnel.ValidTransport(endpoint.Transport) {
		return fmt.Errorf("%w: gateway endpoint is invalid", ErrInvalidConfiguration)
	}
	_, err := newMTLS(endpointConfig(base, endpoint))
	return err
}

// NewFailoverDialer validates the configured endpoints. learnedFile (empty:
// not persisted) holds the last published list; an unreadable or invalid
// file is ignored (the next GatewayHello rewrites it).
func NewFailoverDialer(primary Dialer, base MTLSDialerConfig, extra []GatewayEndpoint, learnedFile ...string) (*FailoverDialer, error) {
	if primary == nil {
		return nil, fmt.Errorf("%w: primary gateway dialer is required", ErrInvalidConfiguration)
	}
	for _, endpoint := range extra {
		if err := validateEndpoint(base, endpoint, NewMTLSDialer); err != nil {
			return nil, err
		}
	}
	d := &FailoverDialer{primary: primary, base: base, extra: extra, newMTLS: NewMTLSDialer}
	if len(learnedFile) > 0 && learnedFile[0] != "" {
		d.loadLearned(learnedFile[0])
	}
	return d, nil
}

func (d *FailoverDialer) loadLearned(path string) {
	d.learnedFile = path
	if raw, err := os.ReadFile(path); err == nil {
		var stored learnedEndpointsFile
		if json.Unmarshal(raw, &stored) == nil {
			d.setLearned(stored.Endpoints, stored.Version)
		}
	}
}

// entries is the list after the primary (configured, then learned).
func (d *FailoverDialer) entries() []GatewayEndpoint {
	return append(append([]GatewayEndpoint(nil), d.extra...), d.learned...)
}

// setLearned keeps the valid, new entries (caller holds no lock or the lock
// is not yet shared).
func (d *FailoverDialer) setLearned(endpoints []GatewayEndpoint, version string) bool {
	seen := map[string]bool{d.base.Address + "|" + d.base.Transport: true}
	for _, endpoint := range d.extra {
		seen[endpoint.Address+"|"+endpoint.Transport] = true
	}
	kept := []GatewayEndpoint{}
	for _, endpoint := range endpoints {
		key := endpoint.Address + "|" + endpoint.Transport
		if seen[key] || validateEndpoint(d.base, endpoint, d.newMTLS) != nil || len(kept) == MaxLearnedGatewayEndpoints {
			continue
		}
		seen[key] = true
		kept = append(kept, endpoint)
	}
	if version == d.learnedVersion && len(kept) == len(d.learned) {
		return false
	}
	current := d.next
	var currentEntry *GatewayEndpoint
	if current > 0 && current <= len(d.extra)+len(d.learned) {
		entry := d.entries()[current-1]
		currentEntry = &entry
	}
	d.learned, d.learnedVersion = kept, version
	// Keep pointing at the same endpoint when it is still listed.
	d.next = 0
	if currentEntry != nil {
		for i, entry := range d.entries() {
			if entry == *currentEntry {
				d.next = i + 1
			}
		}
	}
	return true
}

// Learn applies a GatewayHello list. An empty version means the Gateway has
// no list yet: the stored one stays.
func (d *FailoverDialer) Learn(endpoints []*agentv1.GatewayEndpointV1, version string) {
	if version == "" {
		return
	}
	converted := make([]GatewayEndpoint, 0, len(endpoints))
	for _, endpoint := range endpoints {
		converted = append(converted, GatewayEndpoint{Address: endpoint.GetAddress(), ServerName: endpoint.GetServerName(),
			Transport: endpoint.GetTransport(), TunnelHost: endpoint.GetTunnelHost(), EnrollmentAddress: endpoint.GetEnrollmentAddress()})
	}
	d.mu.Lock()
	if version != d.learnedVersion {
		// A Gateway named again by a new list (re-enabled) is no longer avoided.
		for _, endpoint := range converted {
			delete(d.avoided, endpoint.Address+"|"+endpoint.Transport)
		}
	}
	changed := d.setLearned(converted, version)
	stored := learnedEndpointsFile{Version: d.learnedVersion, Endpoints: append([]GatewayEndpoint(nil), d.learned...)}
	d.mu.Unlock()
	if !changed || d.learnedFile == "" {
		return
	}
	if err := writeLearnedEndpoints(d.learnedFile, stored); err != nil {
		slog.Warn("persist gateway endpoint list failed", "error", err)
	}
}

// LoadLearnedEndpoints reads the persisted GatewayHello list (re-enrollment
// without an explicit enrollment address uses its EnrollmentAddress entries).
func LoadLearnedEndpoints(path string) ([]GatewayEndpoint, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var stored learnedEndpointsFile
	if err := json.Unmarshal(raw, &stored); err != nil {
		return nil, fmt.Errorf("decode gateway endpoint list: %w", err)
	}
	return stored.Endpoints, nil
}

func writeLearnedEndpoints(path string, stored learnedEndpointsFile) error {
	raw, err := json.Marshal(stored)
	if err != nil {
		return err
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), ".gateway-endpoints-*")
	if err != nil {
		return err
	}
	defer os.Remove(temporary.Name())
	if _, err := temporary.Write(raw); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(temporary.Name(), path)
}

// RunFallbackProbe tries the endpoints before the current one every
// interval; the first that connects becomes the start of the next session.
func (d *FailoverDialer) RunFallbackProbe(ctx context.Context, interval, timeout time.Duration) {
	if interval <= 0 {
		interval = FallbackProbeInterval
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		d.probeEarlier(ctx, timeout)
	}
}

func (d *FailoverDialer) probeEarlier(ctx context.Context, timeout time.Duration) {
	d.mu.Lock()
	current := d.next
	d.mu.Unlock()
	for index := 0; index < current; index++ {
		if d.isAvoided(index) {
			continue
		}
		probeCtx, cancel := context.WithTimeout(ctx, timeout)
		connection, err := d.dialIndex(probeCtx, index)
		cancel()
		if err != nil {
			continue
		}
		_ = connection.Close()
		d.mu.Lock()
		if d.next == current {
			d.next = index
		}
		d.mu.Unlock()
		slog.Info("earlier gateway endpoint is reachable again; the next session starts there", "endpoint_index", index)
		return
	}
}

func endpointConfig(base MTLSDialerConfig, endpoint GatewayEndpoint) MTLSDialerConfig {
	config := base
	config.Address, config.ServerName, config.Transport, config.TunnelHost = endpoint.Address, endpoint.ServerName, endpoint.Transport, endpoint.TunnelHost
	return config
}

// Dial tries the current entry; on failure it advances so the next session
// starts at the following endpoint (the client loop applies backoff).
func (d *FailoverDialer) Dial(ctx context.Context) (Connection, error) {
	d.mu.Lock()
	index := d.next
	d.mu.Unlock()
	connection, err := d.dialIndex(ctx, index)
	if err == nil {
		d.mu.Lock()
		d.dialed = index
		d.mu.Unlock()
		return connection, nil
	}
	d.mu.Lock()
	if d.next == index {
		d.next = (index + 1) % (len(d.extra) + len(d.learned) + 1)
	}
	d.mu.Unlock()
	slog.Warn("gateway endpoint failed", "endpoint_index", index, "error", err)
	return nil, err
}

// endpointKey is address|transport of entry index (0: the primary).
func (d *FailoverDialer) endpointKey(index int) string {
	if index == 0 {
		config := d.base
		if active, ok := d.primary.(*SwitchingDialer); ok {
			state := active.store.Active()
			config.Address = state.Address
		}
		return config.Address + "|" + config.Transport
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	entries := d.entries()
	if index > len(entries) {
		return ""
	}
	return entries[index-1].Address + "|" + entries[index-1].Transport
}

func (d *FailoverDialer) isAvoided(index int) bool {
	key := d.endpointKey(index)
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.avoided[key]
}

// SessionRefused moves on after a dial that connected but whose session was
// refused before the GatewayHello (e.g. a disabled Gateway still completes
// TLS): the next dial tries the next entry (§4.5 "one failure, next one").
func (d *FailoverDialer) SessionRefused() {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.next == d.dialed {
		d.next = (d.dialed + 1) % (len(d.extra) + len(d.learned) + 1)
	}
}

// Migrate handles GatewayEndpointMigration (ADR 0013 §5.2): the session's
// Gateway was disabled. It learns the list, avoids the current endpoint and
// probes the others in order within timeout; true when the next session
// starts on a reachable one (the caller then reconnects).
func (d *FailoverDialer) Migrate(ctx context.Context, endpoints []*agentv1.GatewayEndpointV1, version string, timeout time.Duration) bool {
	d.mu.Lock()
	current := d.dialed
	d.mu.Unlock()
	leaving := d.endpointKey(current)
	d.Learn(endpoints, version)
	d.mu.Lock()
	if d.avoided == nil {
		d.avoided = map[string]bool{}
	}
	d.avoided[leaving] = true
	count := len(d.extra) + len(d.learned) + 1
	d.mu.Unlock()
	probeCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	for step := 0; step < count; step++ {
		index := (current + step) % count
		if d.endpointKey(index) == leaving || d.isAvoided(index) {
			continue
		}
		connection, err := d.dialIndex(probeCtx, index)
		if err != nil {
			if probeCtx.Err() != nil {
				break
			}
			continue
		}
		_ = connection.Close()
		d.mu.Lock()
		d.next = index
		d.mu.Unlock()
		slog.Info("gateway is disabled; the next session moves to another endpoint", "endpoint_index", index)
		return true
	}
	slog.Warn("gateway is disabled but no other endpoint answered; staying until the gateway closes the session")
	return false
}

func (d *FailoverDialer) dialIndex(ctx context.Context, index int) (Connection, error) {
	var (
		config MTLSDialerConfig
		dialer Dialer
		err    error
	)
	if index == 0 {
		dialer = d.primary
		config = d.base
		if active, ok := d.primary.(*SwitchingDialer); ok {
			state := active.store.Active()
			config.Address, config.ServerName = state.Address, state.ServerName
		}
	} else {
		d.mu.Lock()
		entries := d.entries()
		d.mu.Unlock()
		if index > len(entries) {
			return nil, fmt.Errorf("gateway endpoint %d is no longer listed", index)
		}
		config = endpointConfig(d.base, entries[index-1])
		if dialer, err = d.newMTLS(config); err != nil {
			return nil, err
		}
	}
	connection, err := dialer.Dial(ctx)
	if err == nil || config.Transport == gatewaytunnel.TransportWS || config.TunnelAudience == "" || ctx.Err() != nil {
		return connection, err
	}
	// Same address, other transport: a misconfigured grpc entry still works
	// when the path in between only speaks HTTP/1.1 (PoC s9b).
	config.Transport = gatewaytunnel.TransportWS
	tunnel, tunnelErr := d.newMTLS(config)
	if tunnelErr != nil {
		return nil, err
	}
	connection, tunnelErr = tunnel.Dial(ctx)
	if tunnelErr != nil {
		return nil, errors.Join(err, tunnelErr)
	}
	return connection, nil
}

// endpointMigrator is a dialer that follows a disabled Gateway's migration
// (FailoverDialer); with it the node advertises GATEWAY_ENDPOINT_MIGRATION v1.
type endpointMigrator interface {
	Migrate(ctx context.Context, endpoints []*agentv1.GatewayEndpointV1, version string, timeout time.Duration) bool
	SessionRefused()
}

func negotiateEndpointMigrationV1(gateway *agentv1.GatewayHello, local *agentv1.AgentCapabilities) (bool, error) {
	localV1, err := singleCapabilityV1(local.GetFeatures(), agentv1.CapabilityName_CAPABILITY_NAME_GATEWAY_ENDPOINT_MIGRATION, "local gateway endpoint migration")
	if err != nil {
		return false, err
	}
	gatewayV1, err := singleCapabilityV1(gateway.GetEnabledCapabilities(), agentv1.CapabilityName_CAPABILITY_NAME_GATEWAY_ENDPOINT_MIGRATION, "Gateway endpoint migration")
	if err != nil {
		return false, err
	}
	if gatewayV1 && !localV1 {
		return false, fmt.Errorf("%w: Gateway enabled an unadvertised endpoint migration capability", ErrInvalidMessage)
	}
	return gatewayV1 && localV1, nil
}

// WithGatewayEndpointLearner hands every GatewayHello endpoint list to learn
// (FailoverDialer.Learn).
func WithGatewayEndpointLearner(learn func([]*agentv1.GatewayEndpointV1, string)) ClientOption {
	return func(client *Client) error {
		if learn == nil {
			return fmt.Errorf("%w: gateway endpoint learner required", ErrInvalidConfiguration)
		}
		client.learnEndpoints = learn
		return nil
	}
}
