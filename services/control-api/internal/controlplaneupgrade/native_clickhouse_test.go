//go:build !windows

package controlplaneupgrade

import (
	"errors"
	"fmt"
	"path/filepath"
	"testing"
)

func nativeClickHouseFiles(files map[string][]byte, count int) {
	files[nativeClickHouseScript] = []byte("#!/usr/bin/env python3\n# fixture\n")
	for version := 1; version <= count; version++ {
		files[fmt.Sprintf("%s%03d_step_%d.up.sql", nativeClickHouseMigrations, version, version)] =
			[]byte(fmt.Sprintf("CREATE TABLE IF NOT EXISTS t%d (x UInt8) ENGINE = Memory;", version))
	}
}

// newClickHouseFixture: the current release carries CH 001..002, the candidate
// 001..003; change edits the candidate's files.
func newClickHouseFixture(t *testing.T, change func(files map[string][]byte)) *nativeFixture {
	t.Helper()
	return newNativeFixtureWith(t, func(index int, files map[string][]byte) {
		nativeClickHouseFiles(files, 2+index)
		if index == 1 {
			files[nativeClickHouseScript] = []byte("#!/usr/bin/env python3\n# candidate fixture\n")
			if change != nil {
				change(files)
			}
		}
	})
}

func TestNativeClickHouseLineageIsAppendOnly(t *testing.T) {
	manifest := func(change func(map[string][]byte), count int) NativeManifest {
		files := map[string][]byte{"bin/control-api": nativeELF("c"), "bin/agent-gateway": nativeELF("g"),
			"static/web/index.html": []byte("<html></html>"), "migrations/001_base.up.sql": []byte("SELECT 1;"),
			"migrations/001_base.down.sql": []byte("SELECT 1;")}
		if count > 0 {
			nativeClickHouseFiles(files, count)
		}
		if change != nil {
			change(files)
		}
		manifest, _ := nativeManifestFixture()
		manifest.Files = nativeFilesForTest(files)
		return manifest
	}
	current := manifest(nil, 16)
	for name, test := range map[string]struct {
		candidate NativeManifest
		accepted  bool
	}{
		"unchanged":           {manifest(nil, 16), true},
		"appended":            {manifest(nil, 18), true},
		"script updated":      {manifest(func(f map[string][]byte) { f[nativeClickHouseScript] = []byte("# new\n") }, 17), true},
		"applied one changed": {manifest(func(f map[string][]byte) { f[nativeClickHouseMigrations+"003_step_3.up.sql"] = []byte("DROP TABLE x;") }, 17), false},
		"applied one removed": {manifest(func(f map[string][]byte) { delete(f, nativeClickHouseMigrations+"016_step_16.up.sql") }, 16), false},
		"gap after head":      {manifest(func(f map[string][]byte) { f[nativeClickHouseMigrations+"018_gap.up.sql"] = []byte("SELECT 1;") }, 16), false},
		"inserted below head": {manifest(func(f map[string][]byte) { f[nativeClickHouseMigrations+"003_extra.up.sql"] = []byte("SELECT 1;") }, 16), false},
		"empty new migration": {manifest(func(f map[string][]byte) { f[nativeClickHouseMigrations+"017_step_17.up.sql"] = nil }, 17), false},
		"down script shipped": {manifest(func(f map[string][]byte) { f[nativeClickHouseMigrations+"017_step_17.down.sql"] = []byte("SELECT 1;") }, 17), false},
		"script removed":      {manifest(func(f map[string][]byte) { delete(f, nativeClickHouseScript) }, 17), false},
	} {
		t.Run(name, func(t *testing.T) {
			_, ok := nativeAppendedClickHouseMigrations(current, test.candidate)
			if ok != test.accepted {
				t.Fatalf("accepted=%v want %v", ok, test.accepted)
			}
			if test.accepted && !nativeCompatibleFiles(current, test.candidate) {
				t.Fatal("accepted CH change must also be a compatible file change")
			}
		})
	}
	// A release without CH files may introduce them (the first ledgered release),
	// but never migrations without the helper that applies them.
	plain := manifest(nil, 0)
	if added, ok := nativeAppendedClickHouseMigrations(plain, current); !ok || len(added) != 16 || !nativeCompatibleFiles(plain, current) {
		t.Fatalf("first CH release rejected: %v %v", added, ok)
	}
	orphan := manifest(func(f map[string][]byte) { delete(f, nativeClickHouseScript) }, 2)
	if _, ok := nativeAppendedClickHouseMigrations(plain, orphan); ok {
		t.Fatal("CH migrations without their helper accepted")
	}
	if added, ok := nativeAppendedClickHouseMigrations(current, manifest(nil, 18)); !ok || len(added) != 2 || added[0] != "017_step_17" {
		t.Fatalf("appended=%v ok=%v", added, ok)
	}
}

func TestNativeClickHouseMigratesBeforeSwitchAndChecksInPreflight(t *testing.T) {
	fixture := newClickHouseFixture(t, nil)
	fixture.commands.clickhouseOutput = map[string]string{
		"check": `{"status": "migrations_checked", "pending": ["003_step_3.up.sql"], "applied": []}`,
		"apply": `{"status": "migrations_applied", "pending": ["003_step_3.up.sql"], "applied": ["003_step_3.up.sql"]}`,
	}
	receipt, err := fixture.runner.Run(t.Context(), fixture.bundle)
	if err != nil || receipt.Result != ResultApplied {
		t.Fatalf("Run() = %+v %v", receipt, err)
	}
	calls := fixture.commands.clickhouse
	if len(calls) != 2 {
		t.Fatalf("calls=%+v", calls)
	}
	release := fixture.runner.executor.release(fixture.next)
	want := []string{"-I", "-B", filepath.Join(release, nativeClickHouseScript), "migrate", "--migrations", filepath.Join(release, nativeClickHouseMigrations)}
	if fmt.Sprint(calls[0].args) != fmt.Sprint(append(append([]string(nil), want...), "--check")) || fmt.Sprint(calls[1].args) != fmt.Sprint(want) {
		t.Fatalf("calls=%+v", calls)
	}
	// Both run while current is still the old release: control-api starts only after.
	if calls[0].current != fixture.old.Digest || calls[1].current != fixture.old.Digest || fixture.commands.restarts != 1 {
		t.Fatalf("CH migration must precede the switch: %+v restarts=%d", calls, fixture.commands.restarts)
	}
	log := nativeRunLog(t, fixture, "")
	if entry := runLogEntry(t, log, "clickhouse_migrated"); entry.Count != 1 || fmt.Sprint(entry.Migrations) != "[003_step_3]" {
		t.Fatalf("run log: %+v", entry)
	}
	if entry := runLogEntry(t, log, "clickhouse_migrations_checked"); entry.Count != 1 {
		t.Fatalf("run log: %+v", entry)
	}
}

func TestNativeClickHouseLedgerConflictRejectsCandidateBeforeDrain(t *testing.T) {
	for reason, terminal := range map[string]bool{"checksum_mismatch": true, "ledger_ahead": true, "clickhouse_error": false, "ledger_gap": false} {
		t.Run(reason, func(t *testing.T) {
			fixture := newClickHouseFixture(t, nil)
			fixture.commands.clickhouseOutput = map[string]string{"check": `{"status": "migration_failed", "reason": "` + reason + `"}`}
			receipt, err := fixture.runner.Run(t.Context(), fixture.bundle)
			state, stateErr := fixture.runner.runner.store.Load()
			if terminal {
				if !errors.Is(err, ErrCandidateRejected) || receipt.Result != ResultFailed || receipt.ErrorCode != "clickhouse_preflight_failed" {
					t.Fatalf("Run() = %+v %v", receipt, err)
				}
			} else if err == nil || stateErr != nil || state.Phase != PhaseExpanded || state.ErrorCode != "clickhouse_preflight_failed" || state.Receipt != nil {
				t.Fatalf("retryable preflight: err=%v state=%+v", err, state)
			}
			maintenance, maintenanceErr := readNativeMaintenance(fixture.runner.executor.config.MaintenanceFile, fixture.installationID(), fixture.runner.executor.owner)
			if maintenanceErr != nil || maintenance.Phase != "active" || fixture.commands.restarts != 0 || len(fixture.commands.clickhouse) != 1 {
				t.Fatalf("rejected CH ledger touched live state: %+v restarts=%d calls=%d", maintenance, fixture.commands.restarts, len(fixture.commands.clickhouse))
			}
			if entry := runLogEntry(t, nativeRunLog(t, fixture, ""), "clickhouse_check_failed"); entry.Reason != reason {
				t.Fatalf("run log: %+v", entry)
			}
		})
	}
}

func TestNativeClickHouseMigrationFailureRollsBackAndRetrySucceeds(t *testing.T) {
	fixture := newClickHouseFixture(t, nil)
	fixture.commands.clickhouseOutput = map[string]string{"apply": `{"status": "migration_failed", "reason": "clickhouse_error"}`}
	receipt, err := fixture.runner.Run(t.Context(), fixture.bundle)
	if !errors.Is(err, ErrRolledBack) || receipt.Result != ResultRolledBack || receipt.ErrorCode != "clickhouse_migration_failed" {
		t.Fatalf("Run() = %+v %v", receipt, err)
	}
	fixture.assertCurrent(t, fixture.old.Digest)
	if status, err := fixture.runner.Probe(t.Context()); err != nil || !status.Ready {
		t.Fatalf("old release not healthy: %+v %v", status, err)
	}
	if entry := runLogEntry(t, nativeRunLog(t, fixture, ""), "clickhouse_migration_failed"); entry.Reason != "clickhouse_error" {
		t.Fatalf("run log: %+v", entry)
	}
}

func TestNativeReleaseWithoutClickHouseFilesSkipsMigration(t *testing.T) {
	fixture := newNativeFixture(t)
	if receipt, err := fixture.runner.Run(t.Context(), fixture.bundle); err != nil || receipt.Result != ResultApplied || len(fixture.commands.clickhouse) != 0 {
		t.Fatalf("Run() = %+v %v calls=%d", receipt, err, len(fixture.commands.clickhouse))
	}
}
