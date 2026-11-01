package l4runtime

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"
)

// the active V2 release's forwards are re-resolved / re-probed in
// the background. A changed address set re-activates only the L4 runtime (a
// sibling snapshot of the same release version ID; the site release is not
// touched). The DNS coordinator keeps every rule of a release: TTL clamp,
// private / mixed-class answers rejected, LKG, stale bound, negative TTL.
const (
	DNSRefreshMinInterval = 30 * time.Second
	DNSRefreshMaxInterval = 10 * time.Minute
)

// DNSRefreshResult is one refresh pass.
type DNSRefreshResult struct {
	// Reloaded: the address sets changed and the L4 runtime runs the new set.
	Reloaded bool
	// NextRefresh: when the earliest host answer expires (zero: no host forwards).
	NextRefresh time.Time
	// Skipped: no active V2 release, or a release / activation is in progress.
	Skipped bool
	// Degraded: some forward runs degraded; it is retried at the minimum interval.
	Degraded bool
}

// RefreshDNS re-resolves the forwards of the active V2 release. Resolution
// and probes run outside the manager lock (a release is not held up by
// them); the result is applied only if the same version is still active and
// no release or activation started meanwhile.
func (m *Manager) RefreshDNS(ctx context.Context, coordinator *DNSCoordinator) (DNSRefreshResult, error) {
	if coordinator == nil {
		return DNSRefreshResult{Skipped: true}, nil
	}
	active, config, err := m.refreshTarget(ctx)
	if err != nil || active == nil {
		return DNSRefreshResult{Skipped: true}, err
	}
	addressSets, reasons, err := resolveAddressSetsV2(ctx, *config, coordinator, nil)
	if errors.Is(err, ErrConflict) {
		// A newer release already owns the DNS state of a forward.
		return DNSRefreshResult{Skipped: true}, nil
	}
	if err != nil {
		return DNSRefreshResult{}, err
	}
	result := DNSRefreshResult{NextRefresh: coordinator.nextRefresh(*config)}
	for _, reason := range reasons {
		result.Degraded = result.Degraded || degradedReasons[reason]
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	unlock, err := m.store.lock(ctx)
	if err != nil {
		return result, err
	}
	defer unlock()
	if still, err := m.refreshTargetLocked(); err != nil || still == nil || !sameActiveRecord(still, active) {
		result.Skipped = true
		return result, err
	}
	compiled, err := m.compileWithDirectoriesV2(*config, addressSets)
	if err != nil {
		return result, err
	}
	if compiled.Digest == active.Digest {
		// Same address sets: only the probe outcomes may have changed.
		return result, m.store.recordStreamReasons(active.VersionDir, reasons)
	}
	applied, err := m.applyCompiledLocked(ctx, compatibleCompiledV2(*compiled), compiled, true)
	if err != nil {
		return result, err
	}
	if applied.State != StateApplied {
		return result, fmt.Errorf("%w: %s", ErrActivation, applied.ErrorCode)
	}
	result.Reloaded = true
	versionDir := compiled.Config.VersionID + "-" + compiled.Digest
	if err := m.store.recordStreamReasons(versionDir, reasons); err != nil {
		return result, err
	}
	// The superseded snapshot of the same release is no rollback target (no
	// release is pending); drop it so address churn does not pile up.
	if active.VersionDir != versionDir {
		path := filepath.Join(m.store.versionsDir, active.VersionDir)
		if err := makeRemovable(path); err == nil {
			if err := os.RemoveAll(path); err != nil {
				slog.Warn("remove superseded L4 snapshot failed", "version_dir", active.VersionDir, "error", err)
			}
		}
	}
	return result, nil
}

func (m *Manager) refreshTarget(ctx context.Context) (*activeRecord, *ConfigV2, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	unlock, err := m.store.lock(ctx)
	if err != nil {
		return nil, nil, err
	}
	defer unlock()
	active, err := m.refreshTargetLocked()
	if err != nil || active == nil {
		return nil, nil, err
	}
	current, _, err := m.store.loadVersion(active.VersionID, active.Digest)
	if err != nil {
		return nil, nil, err
	}
	if current.v2 == nil {
		return nil, nil, nil
	}
	config := *current.v2
	return active, &config, nil
}

// refreshTargetLocked is the active record a refresh may replace: nil while
// an activation or an enclosing release owns the runtime, or with none.
func (m *Manager) refreshTargetLocked() (*activeRecord, error) {
	if journal, err := m.store.loadActivationJournal(); err != nil || journal != nil {
		return nil, err
	}
	if pending, err := m.store.loadReleaseJournal(); err != nil || pending != nil {
		return nil, err
	}
	return m.store.loadActive()
}

// nextRefresh is when the earliest stored host answer of config is due again
// (its refresh time, or its retry time while it is held back).
func (c *DNSCoordinator) nextRefresh(config ConfigV2) time.Time {
	var next time.Time
	for _, listener := range config.Listeners {
		if listener.Endpoint.Host == "" {
			continue
		}
		state, exists, err := c.loadState(listener)
		if err != nil || !exists {
			continue
		}
		due := state.RefreshAfter
		if state.RetryAfter.After(due) {
			due = state.RetryAfter
		}
		if !due.IsZero() && (next.IsZero() || due.Before(next)) {
			next = due
		}
	}
	return next
}

// RunDNSRefresh refreshes until ctx ends: at the earliest answer expiry,
// never sooner than DNSRefreshMinInterval nor later than DNSRefreshMaxInterval
// after the previous pass. now and wait are injectable for tests.
func (m *Manager) RunDNSRefresh(ctx context.Context, coordinator *DNSCoordinator, now func() time.Time,
	wait func(context.Context, time.Duration) error) error {
	if now == nil {
		now = time.Now
	}
	if wait == nil {
		wait = sleepContext
	}
	delay := DNSRefreshMinInterval
	for {
		if err := wait(ctx, delay); err != nil {
			return err
		}
		result, err := m.RefreshDNS(ctx, coordinator)
		if err != nil && ctx.Err() == nil {
			slog.Warn("L4 DNS refresh failed, the active address sets stay", "error", err)
		} else if result.Reloaded {
			slog.Info("L4 DNS refresh activated new origin address sets")
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		delay = refreshDelay(now(), result.NextRefresh)
		if result.Degraded {
			delay = DNSRefreshMinInterval
		}
	}
}

func refreshDelay(now, next time.Time) time.Duration {
	if next.IsZero() {
		return DNSRefreshMaxInterval
	}
	return min(max(next.Sub(now), DNSRefreshMinInterval), DNSRefreshMaxInterval)
}

func sleepContext(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
