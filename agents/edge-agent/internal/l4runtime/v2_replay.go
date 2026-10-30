package l4runtime

import (
	"bytes"
	"context"
	"net/netip"
	"os"
	"path/filepath"
)

func (m *Manager) PrecheckV2(ctx context.Context, config ConfigV2, coordinator *DNSCoordinator) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	unlock, err := m.store.lock(ctx)
	if err != nil {
		return err
	}
	defer unlock()
	compiled, err := m.prepareV2(ctx, config, coordinator)
	if err != nil {
		return err
	}
	stage, err := m.store.stageV2(*compiled)
	if err != nil {
		return err
	}
	defer os.RemoveAll(stage)
	return m.runtime.Precheck(ctx, stage)
}

func (m *Manager) prepareV2(ctx context.Context, config ConfigV2, coordinator *DNSCoordinator) (*CompiledConfigV2, error) {
	canonical, err := CanonicalV2(config)
	if err != nil {
		return nil, err
	}
	stored, err := m.store.findVersionV2(config.VersionID, canonical)
	if err != nil || stored != nil {
		return stored, err
	}
	if coordinator == nil {
		return nil, ErrDNSUnavailable
	}
	addressSets := make(map[string][]netip.Addr, len(config.Listeners))
	for _, listener := range config.Listeners {
		resolved, err := coordinator.Resolve(ctx, config, listener.StreamID)
		if err != nil {
			return nil, err
		}
		addressSets[listener.StreamID] = resolved.Addresses
	}
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

// A release reuses its first immutable DNS snapshot, including after rollback
// or restart. Resolving the same version again could change its digest.
func (s *diskStore) findVersionV2(versionID string, canonical []byte) (*CompiledConfigV2, error) {
	entries, err := os.ReadDir(s.versionsDir)
	if err != nil {
		return nil, err
	}
	var found *CompiledConfigV2
	for _, entry := range entries {
		version, digest, ok := parseVersionDirectoryName(entry.Name())
		if !ok || version != versionID {
			continue
		}
		if found != nil {
			return nil, ErrConflict
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
		found = &stored
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
