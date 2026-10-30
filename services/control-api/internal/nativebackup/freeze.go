package nativebackup

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// WriterUnits are the native processes that write PostgreSQL, ClickHouse,
// JetStream or the object store, in stop order. The upgrade runner goes first
// so it cannot restart the control API while it is frozen.
var WriterUnits = []string{
	"cdnca-native-control-upgrade-runner.service",
	"cdnca-agent-gateway.service",
	"cdnca-control-api.service",
}

type FreezeMode string

const (
	// FreezeBackup stops the writers for one backup and restarts them after.
	FreezeBackup FreezeMode = "backup"
	// FreezeHold also disables them, so a reboot keeps the old control plane
	// down after a migration. Only an explicit unfreeze ends it.
	FreezeHold FreezeMode = "hold"
)

const freezeSchema = "cdnca.control-native-freeze/v1"

var ErrFreezeFailed = errors.New("write freeze failed; writers were restarted")

type FrozenUnit struct {
	Name       string `json:"name"`
	WasLoaded  bool   `json:"was_loaded"`
	WasActive  bool   `json:"was_active"`
	WasEnabled bool   `json:"was_enabled"`
}

type FreezeRecord struct {
	Schema     string       `json:"schema"`
	Mode       FreezeMode   `json:"mode"`
	ID         string       `json:"id"`
	AcquiredAt time.Time    `json:"acquired_at"`
	Units      []FrozenUnit `json:"units"`
}

// FrozenConsoleUnit serves a minimal console on the control-api port while a
// migration hold is in force: sign-in, migration status/logs and rollback.
// It never writes business data (fix-migrollback).
const FrozenConsoleUnit = "cdnca-control-frozen-console.service"

type Freezer struct {
	Layout  Layout
	Systemd Systemd
	Now     func() time.Time
	// Console, when set, is started after a hold stopped the writers and
	// stopped before they start again. Best effort: a console failure never
	// fails the freeze.
	Console string
}

// FreezeLease is the active freeze; Release undoes exactly what it changed.
type FreezeLease interface {
	Record() FreezeRecord
	Release(context.Context) error
}

func (freezer Freezer) recordPath() string {
	return filepath.Join(freezer.Layout.Path(AgentRoot), "freeze.json")
}

// Current returns the persisted freeze, or nil when the writers are not frozen.
func (freezer Freezer) Current() (*FreezeRecord, error) {
	encoded, err := readPrivateFile(freezer.recordPath(), 64<<10)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var record FreezeRecord
	if err := json.Unmarshal(encoded, &record); err != nil || record.Schema != freezeSchema ||
		(record.Mode != FreezeBackup && record.Mode != FreezeHold) || len(record.Units) != len(WriterUnits) {
		return nil, errors.New("freeze record is invalid")
	}
	for index, unit := range record.Units {
		if unit.Name != WriterUnits[index] {
			return nil, errors.New("freeze record is invalid")
		}
	}
	return &record, nil
}

// Acquire freezes the writers. A stale backup freeze left by a crashed run is
// released first. Under an existing hold a backup freeze is a no-op lease (the
// writers are already down) and a second hold returns the existing one.
func (freezer Freezer) Acquire(ctx context.Context, mode FreezeMode, id string) (FreezeLease, error) {
	if mode != FreezeBackup && mode != FreezeHold {
		return nil, errors.New("invalid freeze mode")
	}
	if err := ensurePrivateDirectory(freezer.Layout.Path(AgentRoot)); err != nil {
		return nil, err
	}
	current, err := freezer.Current()
	if err != nil {
		return nil, err
	}
	if current != nil {
		if current.Mode == FreezeHold {
			if mode == FreezeBackup {
				return heldLease{record: *current}, nil
			}
			return &lease{freezer: freezer, record: *current}, nil
		}
		// A backup record is never left behind by a finished run.
		if err := freezer.restore(context.WithoutCancel(ctx), *current); err != nil {
			return nil, fmt.Errorf("reconcile stale freeze: %w", err)
		}
	}
	record := FreezeRecord{Schema: freezeSchema, Mode: mode, ID: id, AcquiredAt: freezer.Now().UTC()}
	for _, unit := range WriterUnits {
		state, err := freezer.Systemd.State(ctx, unit)
		if err != nil {
			return nil, ErrFreezeFailed
		}
		record.Units = append(record.Units, FrozenUnit{Name: unit, WasLoaded: state.Loaded, WasActive: state.Active, WasEnabled: state.Enabled})
	}
	if err := freezer.persist(record); err != nil {
		return nil, err
	}
	for index, unit := range record.Units {
		if !unit.WasLoaded {
			continue
		}
		stopErr := freezer.Systemd.Stop(ctx, unit.Name)
		if stopErr == nil && mode == FreezeHold && unit.WasEnabled {
			stopErr = freezer.Systemd.Disable(ctx, unit.Name)
		}
		if stopErr != nil {
			return nil, freezer.rollback(ctx, record, index)
		}
	}
	for _, unit := range record.Units {
		if !unit.WasLoaded {
			continue
		}
		if state, err := freezer.Systemd.State(ctx, unit.Name); err != nil || state.Active {
			return nil, freezer.rollback(ctx, record, len(record.Units))
		}
	}
	// Enabled too, so a reboot during the hold brings the console back.
	if mode == FreezeHold && freezer.consoleLoaded(ctx) {
		_ = freezer.Systemd.Enable(ctx, freezer.Console)
		_ = freezer.Systemd.Start(ctx, freezer.Console)
	}
	return &lease{freezer: freezer, record: record}, nil
}

// rollback restores the units processed before index and removes the record.
func (freezer Freezer) rollback(ctx context.Context, record FreezeRecord, index int) error {
	partial := record
	partial.Units = record.Units[:index]
	if err := freezer.restoreUnits(context.WithoutCancel(ctx), record.Mode, partial.Units); err != nil {
		return errors.Join(ErrFreezeFailed, err)
	}
	if err := freezer.remove(); err != nil {
		return errors.Join(ErrFreezeFailed, err)
	}
	return ErrFreezeFailed
}

// Unfreeze ends any freeze (backup or hold) from its persisted record.
func (freezer Freezer) Unfreeze(ctx context.Context) error {
	current, err := freezer.Current()
	if err != nil || current == nil {
		return err
	}
	return freezer.restore(ctx, *current)
}

func (freezer Freezer) restore(ctx context.Context, record FreezeRecord) error {
	if err := freezer.restoreUnits(ctx, record.Mode, record.Units); err != nil {
		return err
	}
	return freezer.remove()
}

// restoreUnits re-enables and restarts units in reverse stop order. It tries
// every unit and reports all failures; the caller keeps the record on error.
func (freezer Freezer) restoreUnits(ctx context.Context, mode FreezeMode, units []FrozenUnit) error {
	var joined error
	// The frozen console holds the control-api port; free it first.
	if mode == FreezeHold && freezer.consoleLoaded(ctx) {
		if err := freezer.Systemd.Stop(ctx, freezer.Console); err != nil {
			joined = fmt.Errorf("stop %s: %w", freezer.Console, err)
		}
		if err := freezer.Systemd.Disable(ctx, freezer.Console); err != nil {
			joined = errors.Join(joined, fmt.Errorf("disable %s: %w", freezer.Console, err))
		}
	}
	for index := len(units) - 1; index >= 0; index-- {
		unit := units[index]
		if !unit.WasLoaded {
			continue
		}
		if mode == FreezeHold && unit.WasEnabled {
			if err := freezer.Systemd.Enable(ctx, unit.Name); err != nil {
				joined = errors.Join(joined, fmt.Errorf("enable %s: %w", unit.Name, err))
			}
		}
		if unit.WasActive {
			if err := freezer.Systemd.Start(ctx, unit.Name); err != nil {
				joined = errors.Join(joined, fmt.Errorf("start %s: %w", unit.Name, err))
			}
		}
	}
	return joined
}

// consoleLoaded: hosts installed before the frozen console have no unit.
func (freezer Freezer) consoleLoaded(ctx context.Context) bool {
	if freezer.Console == "" {
		return false
	}
	state, err := freezer.Systemd.State(ctx, freezer.Console)
	return err == nil && state.Loaded
}

func (freezer Freezer) persist(record FreezeRecord) error {
	encoded, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(freezer.recordPath(), append(encoded, '\n'), 0o600)
}

func (freezer Freezer) remove() error {
	if err := os.Remove(freezer.recordPath()); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return syncDirectory(filepath.Dir(freezer.recordPath()))
}

type lease struct {
	freezer Freezer
	record  FreezeRecord
}

func (lease *lease) Record() FreezeRecord { return lease.record }
func (lease *lease) Release(ctx context.Context) error {
	return lease.freezer.restore(ctx, lease.record)
}

// heldLease is a backup taken while a migration hold is in force.
type heldLease struct{ record FreezeRecord }

func (held heldLease) Record() FreezeRecord          { return held.record }
func (held heldLease) Release(context.Context) error { return nil }
