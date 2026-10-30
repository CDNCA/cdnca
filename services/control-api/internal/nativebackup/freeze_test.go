package nativebackup

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

type fakeSystemd struct {
	t         *testing.T
	states    map[string]*UnitState
	calls     []string
	fail      map[string]error
	sticky    map[string]bool // units that stay active after stop
	onStop    func(unit string)
	reloadErr error
}

func newFakeSystemd(t *testing.T) *fakeSystemd {
	return &fakeSystemd{t: t, states: map[string]*UnitState{
		"cdnca-native-control-upgrade-runner.service": {Loaded: true, Active: true, Enabled: true},
		"cdnca-agent-gateway.service":                 {Loaded: true, Active: true, Enabled: true},
		"cdnca-control-api.service":                   {Loaded: true, Active: true, Enabled: true},
	}, fail: map[string]error{}, sticky: map[string]bool{}}
}

func (fake *fakeSystemd) record(verb, unit string) error {
	fake.calls = append(fake.calls, verb+" "+unit)
	return fake.fail[verb+" "+unit]
}

func (fake *fakeSystemd) state(unit string) *UnitState {
	if state, ok := fake.states[unit]; ok {
		return state
	}
	state := &UnitState{}
	fake.states[unit] = state
	return state
}

func (fake *fakeSystemd) State(_ context.Context, unit string) (UnitState, error) {
	return *fake.state(unit), nil
}
func (fake *fakeSystemd) Start(_ context.Context, unit string) error {
	if err := fake.record("start", unit); err != nil {
		return err
	}
	fake.state(unit).Active = true
	return nil
}
func (fake *fakeSystemd) Stop(_ context.Context, unit string) error {
	if fake.onStop != nil {
		fake.onStop(unit)
	}
	if err := fake.record("stop", unit); err != nil {
		return err
	}
	if !fake.sticky[unit] {
		fake.state(unit).Active = false
	}
	return nil
}
func (fake *fakeSystemd) Enable(_ context.Context, unit string) error {
	if err := fake.record("enable", unit); err != nil {
		return err
	}
	fake.state(unit).Enabled = true
	return nil
}
func (fake *fakeSystemd) Disable(_ context.Context, unit string) error {
	if err := fake.record("disable", unit); err != nil {
		return err
	}
	fake.state(unit).Enabled = false
	return nil
}
func (fake *fakeSystemd) DaemonReload(context.Context) error {
	fake.calls = append(fake.calls, "daemon-reload")
	return fake.reloadErr
}

func testFreezer(t *testing.T, systemd Systemd) Freezer {
	root := t.TempDir()
	return Freezer{Layout: Layout{Root: root}, Systemd: systemd, Now: func() time.Time { return time.Unix(1700000000, 0).UTC() }}
}

func TestFreezeRecordsBeforeStoppingAndRestoresInReverse(t *testing.T) {
	fake := newFakeSystemd(t)
	freezer := testFreezer(t, fake)
	fake.onStop = func(string) {
		if _, err := os.Stat(freezer.recordPath()); err != nil {
			t.Fatalf("freeze record must be durable before the first stop: %v", err)
		}
	}
	lease, err := freezer.Acquire(context.Background(), FreezeBackup, "b1")
	if err != nil {
		t.Fatal(err)
	}
	wantStop := []string{"stop cdnca-native-control-upgrade-runner.service", "stop cdnca-agent-gateway.service", "stop cdnca-control-api.service"}
	if !reflect.DeepEqual(fake.calls, wantStop) {
		t.Fatalf("stop order = %v", fake.calls)
	}
	fake.calls = nil
	if err := lease.Release(context.Background()); err != nil {
		t.Fatal(err)
	}
	wantStart := []string{"start cdnca-control-api.service", "start cdnca-agent-gateway.service", "start cdnca-native-control-upgrade-runner.service"}
	if !reflect.DeepEqual(fake.calls, wantStart) {
		t.Fatalf("start order = %v", fake.calls)
	}
	if _, err := os.Stat(freezer.recordPath()); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("record must be removed after a complete release: %v", err)
	}
}

func TestFreezeDoesNotStartUnitsThatWereStopped(t *testing.T) {
	fake := newFakeSystemd(t)
	fake.states["cdnca-native-control-upgrade-runner.service"].Active = false
	delete(fake.states, "cdnca-agent-gateway.service") // not installed
	freezer := testFreezer(t, fake)
	lease, err := freezer.Acquire(context.Background(), FreezeBackup, "b1")
	if err != nil {
		t.Fatal(err)
	}
	fake.calls = nil
	if err := lease.Release(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(fake.calls, []string{"start cdnca-control-api.service"}) {
		t.Fatalf("release calls = %v", fake.calls)
	}
}

func TestFreezeStopFailureRollsBackStoppedUnits(t *testing.T) {
	fake := newFakeSystemd(t)
	fake.fail["stop cdnca-control-api.service"] = errors.New("boom")
	freezer := testFreezer(t, fake)
	if _, err := freezer.Acquire(context.Background(), FreezeBackup, "b1"); !errors.Is(err, ErrFreezeFailed) {
		t.Fatalf("err = %v", err)
	}
	want := []string{"stop cdnca-native-control-upgrade-runner.service", "stop cdnca-agent-gateway.service",
		"stop cdnca-control-api.service", "start cdnca-agent-gateway.service", "start cdnca-native-control-upgrade-runner.service"}
	if !reflect.DeepEqual(fake.calls, want) {
		t.Fatalf("calls = %v", fake.calls)
	}
	if _, err := os.Stat(freezer.recordPath()); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("record must be removed after a complete rollback")
	}
}

func TestFreezeUnitStillActiveAfterStopFailsClosed(t *testing.T) {
	fake := newFakeSystemd(t)
	fake.sticky["cdnca-agent-gateway.service"] = true
	freezer := testFreezer(t, fake)
	if _, err := freezer.Acquire(context.Background(), FreezeBackup, "b1"); !errors.Is(err, ErrFreezeFailed) {
		t.Fatalf("err = %v", err)
	}
	if !fake.states["cdnca-control-api.service"].Active || !fake.states["cdnca-native-control-upgrade-runner.service"].Active {
		t.Fatal("rollback must restart the writers it stopped")
	}
}

func TestFreezeReconcilesStaleBackupRecordFirst(t *testing.T) {
	fake := newFakeSystemd(t)
	freezer := testFreezer(t, fake)
	if _, err := freezer.Acquire(context.Background(), FreezeBackup, "crashed"); err != nil {
		t.Fatal(err)
	}
	// The process died here: units stopped, record left behind.
	fake.calls = nil
	lease, err := freezer.Acquire(context.Background(), FreezeBackup, "next")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"start cdnca-control-api.service", "start cdnca-agent-gateway.service", "start cdnca-native-control-upgrade-runner.service",
		"stop cdnca-native-control-upgrade-runner.service", "stop cdnca-agent-gateway.service", "stop cdnca-control-api.service"}
	if !reflect.DeepEqual(fake.calls, want) {
		t.Fatalf("calls = %v", fake.calls)
	}
	if lease.Record().ID != "next" {
		t.Fatalf("record = %+v", lease.Record())
	}
}

func TestHoldDisablesAndSurvivesBackups(t *testing.T) {
	fake := newFakeSystemd(t)
	freezer := testFreezer(t, fake)
	hold, err := freezer.Acquire(context.Background(), FreezeHold, "m1")
	if err != nil {
		t.Fatal(err)
	}
	for _, unit := range WriterUnits {
		if state := fake.states[unit]; state.Active || state.Enabled {
			t.Fatalf("%s must be stopped and disabled: %+v", unit, state)
		}
	}
	fake.calls = nil
	backup, err := freezer.Acquire(context.Background(), FreezeBackup, "b-under-hold")
	if err != nil {
		t.Fatal(err)
	}
	if err := backup.Release(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(fake.calls) != 0 {
		t.Fatalf("a backup under a hold must not touch units: %v", fake.calls)
	}
	if current, err := freezer.Current(); err != nil || current == nil || current.Mode != FreezeHold {
		t.Fatalf("hold must remain: %+v %v", current, err)
	}
	_ = hold
	if err := freezer.Unfreeze(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, unit := range WriterUnits {
		if state := fake.states[unit]; !state.Active || !state.Enabled {
			t.Fatalf("%s must be enabled and running after unfreeze: %+v", unit, state)
		}
	}
}

func TestReleaseFailureKeepsRecord(t *testing.T) {
	fake := newFakeSystemd(t)
	freezer := testFreezer(t, fake)
	lease, err := freezer.Acquire(context.Background(), FreezeBackup, "b1")
	if err != nil {
		t.Fatal(err)
	}
	fake.fail["start cdnca-agent-gateway.service"] = errors.New("boom")
	if err := lease.Release(context.Background()); err == nil {
		t.Fatal("release must report the failed start")
	}
	if !fake.states["cdnca-native-control-upgrade-runner.service"].Active {
		t.Fatal("release must still try the remaining units")
	}
	if current, err := freezer.Current(); err != nil || current == nil {
		t.Fatalf("record must stay for a retry: %v", err)
	}
	delete(fake.fail, "start cdnca-agent-gateway.service")
	if err := freezer.Unfreeze(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(freezer.Layout.Root, AgentRoot, "freeze.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("record must be removed after the retried release")
	}
}
