package nativebackup

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type fakeMigrator struct {
	got MigrationTarget
	err error
	env string
}

func (fake *fakeMigrator) Migrate(_ context.Context, target MigrationTarget, log func(string)) (MigrationResult, error) {
	fake.got = target
	log("password=hunter2-should-not-appear step")
	return MigrationResult{BackupID: "20261017T030000Z-abcdefgh", TargetEnv: fake.env}, fake.err
}

func (rig *testRig) agent(migrator Migrator) Agent {
	backuper := rig.backuper(nil)
	return Agent{Layout: rig.host.Layout, Backuper: backuper, Migrator: migrator, Now: rig.now}
}

func TestAgentRunsQueuedBackupAndRefusesConcurrentRequests(t *testing.T) {
	rig := newRig(t)
	run, err := SubmitRequest(rig.host.Layout, Request{Kind: RequestBackup, RequestedBy: "admin"}, rig.now())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := SubmitRequest(rig.host.Layout, Request{Kind: RequestBackup}, rig.now()); !errors.Is(err, ErrBusy) {
		t.Fatalf("a second queued backup must be refused: %v", err)
	}
	if err := rig.agent(nil).Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	finished, err := ReadRun(rig.host.Layout, run.ID)
	if err != nil || finished.State != RunSucceeded || finished.BackupID == "" || len(finished.Log) == 0 {
		t.Fatalf("run = %+v %v", finished, err)
	}
	if entries, _ := os.ReadDir(requestsDirectory(rig.host.Layout)); len(entries) != 0 {
		t.Fatal("the request must be consumed")
	}
	if _, err := os.Stat(filepath.Join(rig.host.Layout.Path(BackupRoot), finished.BackupID, manifestFile)); err != nil {
		t.Fatal(err)
	}
}

func TestAgentMigrationRemovesCredentialAndRedactsLog(t *testing.T) {
	rig := newRig(t)
	target := MigrationTarget{Host: "203.0.113.9", Port: 22, User: "root", HostKeySHA256: "SHA256:" + strings.Repeat("A", 43), Password: "ssh-secret-value"}
	run, err := SubmitRequest(rig.host.Layout, Request{Kind: RequestMigrate, Migration: &target}, rig.now())
	if err != nil {
		t.Fatal(err)
	}
	if encoded, _ := os.ReadFile(filepath.Join(runsDirectory(rig.host.Layout), run.ID+".json")); strings.Contains(string(encoded), "ssh-secret-value") {
		t.Fatal("the run record must never contain the credential")
	}
	migrator := &fakeMigrator{}
	if err := rig.agent(migrator).Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	if migrator.got.Password != "ssh-secret-value" {
		t.Fatal("the migrator must receive the credential")
	}
	err = filepath.Walk(rig.host.Layout.Path(AgentRoot), func(path string, info os.FileInfo, err error) error {
		if err == nil && info.Mode().IsRegular() {
			if data, _ := os.ReadFile(path); strings.Contains(string(data), "ssh-secret-value") || strings.Contains(string(data), "hunter2") {
				t.Fatalf("%s still contains a secret", path)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	finished, _ := ReadRun(rig.host.Layout, run.ID)
	if finished.State != RunSucceeded || finished.Target != "203.0.113.9" {
		t.Fatalf("run = %+v", finished)
	}
}

func TestAgentScheduleRunsOncePerSlotAndSkipsStaleSlots(t *testing.T) {
	rig := newRig(t)
	settings := DefaultSettings()
	settings.Schedule = Schedule{Enabled: true, Weekdays: []int{0, 1, 2, 3, 4, 5, 6}, Hour: 4, Minute: 0}
	if err := SaveSettings(rig.host.Layout, settings); err != nil {
		t.Fatal(err)
	}
	agent := rig.agent(nil)
	at := time.Date(2026, 10, 17, 4, 3, 0, 0, time.Local)
	agent.Now = func() time.Time { return at }
	agent.Backuper.Now = func() time.Time { at = at.Add(time.Second); return at }
	agent.Backuper.Freezer.Now = agent.Backuper.Now
	if err := agent.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := agent.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	runs, _ := ListRuns(rig.host.Layout, 10)
	if len(runs) != 1 || runs[0].Reason != "scheduled" || runs[0].State != RunSucceeded {
		t.Fatalf("runs = %+v", runs)
	}
	at = time.Date(2026, 10, 18, 11, 0, 0, 0, time.Local) // 7h late
	if _, due := agent.dueSlot(settings); due {
		t.Fatal("a slot missed by more than six hours must be skipped")
	}
}

func TestAgentRetentionKeepsNewestLocalBundles(t *testing.T) {
	rig := newRig(t)
	settings := DefaultSettings()
	settings.KeepLocal = 2
	if err := SaveSettings(rig.host.Layout, settings); err != nil {
		t.Fatal(err)
	}
	agent := rig.agent(nil)
	for index := 0; index < 3; index++ {
		if _, err := agent.Backuper.Run(context.Background(), BackupRequest{Reason: "manual", OutputDirectory: rig.host.Layout.Path(BackupRoot)}); err != nil {
			t.Fatal(err)
		}
		rig.clock = rig.clock.Add(time.Minute)
	}
	if err := agent.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	left, _ := ListBundles(rig.host.Layout.Path(BackupRoot), rig.keys.Fingerprint())
	if len(left) != 2 {
		t.Fatalf("left = %d", len(left))
	}
}

func TestSettingsValidation(t *testing.T) {
	settings := DefaultSettings()
	settings.Schedule = Schedule{Enabled: true, Hour: 25}
	if settings.Validate() == nil {
		t.Fatal("invalid hour accepted")
	}
	settings = DefaultSettings()
	settings.Targets = []Target{{Name: "a", Kind: "ftp"}}
	if settings.Validate() == nil {
		t.Fatal("invalid target accepted")
	}
}

func TestInstallUnitsIsIdempotent(t *testing.T) {
	rig := newRig(t)
	if err := InstallUnits(context.Background(), rig.host); err != nil {
		t.Fatal(err)
	}
	unit, err := os.ReadFile(rig.host.Layout.Path("/etc/systemd/system/cdnca-control-backup.service"))
	if err != nil || !strings.Contains(string(unit), NativeRoot+"/current/bin/control-api native-backup agent") {
		t.Fatalf("unit = %s %v", unit, err)
	}
	rig.systemd.calls = nil
	if err := InstallUnits(context.Background(), rig.host); err != nil {
		t.Fatal(err)
	}
	for _, call := range rig.systemd.calls {
		if call == "daemon-reload" {
			t.Fatal("unchanged units must not reload systemd")
		}
	}
}

func TestHeldHostSkipsScheduledBackups(t *testing.T) {
	rig := newRig(t)
	settings := DefaultSettings()
	settings.Schedule = Schedule{Enabled: true, Weekdays: []int{0, 1, 2, 3, 4, 5, 6}, Hour: 4}
	_ = SaveSettings(rig.host.Layout, settings)
	if _, err := rig.freezer.Acquire(context.Background(), FreezeHold, "m"); err != nil {
		t.Fatal(err)
	}
	agent := rig.agent(nil)
	agent.Now = func() time.Time { return time.Date(2026, 10, 17, 4, 1, 0, 0, time.Local) }
	if err := agent.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	if runs, _ := ListRuns(rig.host.Layout, 5); len(runs) != 0 {
		t.Fatalf("a held host must not run scheduled backups: %+v", runs)
	}
}

// b04 遗留：失败的计划备份不自动重试，下一次就是下一个计划时间；界面据此显示。
func TestNextSlotIsTheNextScheduledTime(t *testing.T) {
	now := time.Date(2026, 10, 25, 4, 30, 0, 0, time.UTC) // Sunday
	settings := DefaultSettings()
	if _, ok := NextSlot(settings, now); ok {
		t.Fatal("disabled schedule has a next slot")
	}
	settings.Schedule.Enabled = true
	if got, ok := NextSlot(settings, now); !ok || !got.Equal(time.Date(2026, 10, 26, 4, 0, 0, 0, time.UTC)) {
		t.Fatalf("daily next = %v %v", got, ok)
	}
	settings.Schedule.Weekdays = []int{3} // Wednesday
	if got, ok := NextSlot(settings, now); !ok || !got.Equal(time.Date(2026, 10, 28, 4, 0, 0, 0, time.UTC)) {
		t.Fatalf("weekly next = %v %v", got, ok)
	}
	settings.Schedule.Weekdays, settings.Schedule.Hour = []int{0}, 5
	if got, ok := NextSlot(settings, now); !ok || !got.Equal(time.Date(2026, 10, 25, 5, 0, 0, 0, time.UTC)) {
		t.Fatalf("later today = %v %v", got, ok)
	}
}
