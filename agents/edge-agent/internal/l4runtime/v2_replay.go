package l4runtime

import (
	"bytes"
	"context"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"time"
)

func (m *Manager) PrecheckV2(ctx context.Context, config ConfigV2, coordinator *DNSCoordinator) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	unlock, err := m.store.lock(ctx)
	if err != nil {
		return err
	}
	defer unlock()
	compiled, _, err := m.prepareV2(ctx, config, coordinator)
	if err != nil {
		return err
	}
	stage, err := m.store.stageV2(*compiled)
	if err != nil {
		return err
	}
	defer os.RemoveAll(stage)
	if err := m.runtime.Precheck(ctx, stage); err != nil {
		// logged here; the deployment manager reports the same line (PrecheckSummary)
		return logPrecheckFailure("precheck", config.VersionID, err)
	}
	return nil
}

// prepareV2 compiles config with resolved address sets and returns the
// per-forward reason codes of that resolution (nil: a stored snapshot of the
// version was reused, its recorded reasons stand).
func (m *Manager) prepareV2(ctx context.Context, config ConfigV2, coordinator *DNSCoordinator) (*CompiledConfigV2, map[string]string, error) {
	canonical, err := CanonicalV2(config)
	if err != nil {
		return nil, nil, err
	}
	stored, err := m.store.findVersionV2(config.VersionID, canonical)
	if err != nil || stored != nil {
		return stored, nil, err
	}
	if coordinator == nil {
		return nil, nil, ErrDNSUnavailable
	}
	addressSets, reasons, err := resolveAddressSetsV2(ctx, config, coordinator, nil)
	if err != nil {
		return nil, nil, err
	}
	compiled, err := m.compileWithDirectoriesV2(config, addressSets)
	if err != nil {
		return nil, nil, err
	}
	return compiled, reasons, nil
}

// resolveAddressSetsV2 resolves the forwards of config (only those skip
// returns false for when skip is set). A forward without an address set
// (unresolvable, or a stale LKG) gets none: it is deployed refusing
// connections and reported; unsafe answers stay hard errors.
func resolveAddressSetsV2(ctx context.Context, config ConfigV2, coordinator *DNSCoordinator,
	skip func(ListenerV2) bool) (map[string][]netip.Addr, map[string]string, error) {
	addressSets := make(map[string][]netip.Addr, len(config.Listeners))
	reasons := make(map[string]string, len(config.Listeners))
	for _, listener := range config.Listeners {
		if skip != nil && skip(listener) {
			continue
		}
		resolved, err := coordinator.Resolve(ctx, config, listener.StreamID)
		if errors.Is(err, ErrDNSUnavailable) || errors.Is(err, ErrDNSStale) {
			reasons[listener.StreamID] = DNSReasonUnavailable
			continue
		}
		if err != nil {
			return nil, nil, err
		}
		addressSets[listener.StreamID] = resolved.Addresses
		reasons[listener.StreamID] = resolved.ReasonCode
	}
	return addressSets, reasons, nil
}

func (m *Manager) compileWithDirectoriesV2(config ConfigV2, addressSets map[string][]netip.Addr) (*CompiledConfigV2, error) {
	compiled, err := CompileV2(config, addressSets)
	if err != nil {
		return nil, err
	}
	if directory := compiled.Config.dispatchDirectory(); bytes.Contains(compiled.NginxConfig, []byte("listen unix:"+directory+"/")) {
		if err := prepareDispatchDirectory(directory); err != nil {
			return nil, err
		}
	}
	if bytes.Contains(compiled.NginxConfig, []byte("listen unix:"+L4ControlSocketPath+";")) {
		if err := prepareControlDirectory(); err != nil {
			return nil, err
		}
	}
	return &compiled, nil
}

// A release reuses its immutable DNS snapshot, including after rollback or
// restart. Resolving the same version again could change its digest. After a
// DNS refresh a version has more than one snapshot: the active
// one wins, otherwise the newest.
func (s *diskStore) findVersionV2(versionID string, canonical []byte) (*CompiledConfigV2, error) {
	entries, err := os.ReadDir(s.versionsDir)
	if err != nil {
		return nil, err
	}
	active, err := s.loadActive()
	if err != nil {
		return nil, err
	}
	var found *CompiledConfigV2
	var foundTime time.Time
	foundActive := false
	for _, entry := range entries {
		version, digest, ok := parseVersionDirectoryName(entry.Name())
		if !ok || version != versionID || foundActive {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			return nil, err
		}
		isActive := active != nil && active.VersionDir == entry.Name()
		if found != nil && !isActive && !info.ModTime().After(foundTime) {
			continue
		}
		compiled, _, err := s.loadVersion(version, digest)
		if err != nil {
			return nil, err
		}
		if compiled.v2 == nil {
			return nil, ErrConflict
		}
		content, err := readRegularFile(filepath.Join(s.versionsDir, entry.Name(), "runtime.json"))
		if err != nil {
			return nil, err
		}
		stored, err := decodeStoredRuntimeV2(content)
		if err != nil || !bytes.Equal(stored.CanonicalJSON, canonical) {
			return nil, ErrConflict
		}
		found, foundTime, foundActive = &stored, info.ModTime(), isActive
	}
	return found, nil
}

func (m *Manager) healthy(ctx context.Context, compiled CompiledConfig) error {
	if compiled.v2 != nil {
		runtime, ok := m.runtime.(interface {
			HealthyV2(context.Context, ConfigV2) error
		})
		if !ok {
			return ErrUnsupported
		}
		return runtime.HealthyV2(ctx, *compiled.v2)
	}
	return m.runtime.Healthy(ctx, compiled.Config)
}

// V2 keeps its scoped validation and verifies that the owned master has a
// confirmed worker generation. V1 compilation cannot validate a V2 snapshot.
func (r *OpenResty) HealthyV2(ctx context.Context, config ConfigV2) error {
	if _, err := normalizeConfigV2(config); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	handle, record, running, err := r.openOwnedProcess()
	if err != nil {
		return err
	}
	if !running {
		return ErrActivation
	}
	defer handle.Close()
	workers, err := r.workerGeneration(record)
	if err != nil {
		return err
	}
	if len(workers) == 0 {
		return ErrActivation
	}
	return nil
}

var degradedReasons = map[string]bool{
	DNSReasonStaticUnreachable: true, DNSReasonHealthUnverified: true,
	DNSReasonHealthRejected: true, DNSReasonUnavailable: true,
}

// DegradedStreams lists the forwards of the active V2 release that run
// degraded, sorted by stream ID; none without a V2 release. The
// reasons are the persisted ones (state/l4-streams.json, l4-isolate2), so they
// survive an agent restart and clear when the DNS refresh reaches the origin.
func (m *Manager) DegradedStreams(ctx context.Context) ([]DegradedStream, error) {
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
	compiled, _, err := m.store.loadVersion(active.VersionID, active.Digest)
	if err != nil || compiled.v2 == nil {
		return nil, err
	}
	pools := make(map[string]int, len(compiled.Config.UpstreamPools))
	for _, pool := range compiled.Config.UpstreamPools {
		pools[pool.ID] = len(pool.Endpoints)
	}
	reasons := m.store.streamReasons(active.VersionDir)
	var degraded []DegradedStream
	for _, listener := range compiled.v2.Listeners {
		reason := reasons[listener.StreamID]
		if pools["v2_"+listener.StreamID] == 0 {
			reason = DNSReasonUnavailable
		}
		if degradedReasons[reason] {
			degraded = append(degraded, DegradedStream{StreamID: listener.StreamID, ReasonCode: reason})
		}
	}
	sort.Slice(degraded, func(i, j int) bool { return degraded[i].StreamID < degraded[j].StreamID })
	return degraded, nil
}
