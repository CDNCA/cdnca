//go:build !windows

package controlplaneupgrade

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// nativeFakeDatabase models the ledger head and one "application row"
// (marker) so a restore can be seen undoing both schema and data.
type nativeFakeDatabase struct {
	mu                       sync.Mutex
	head, target             int
	marker                   string
	failAt                   int
	failDump, failRestore    bool
	size                     int64
	foreign                  string
	dumps, migrates, restore int
	ensured                  []string
	ensureErr                error
}

func (database *nativeFakeDatabase) Query(_ context.Context, dsn, sql string) (string, error) {
	database.mu.Lock()
	defer database.mu.Unlock()
	if dsn != "postgres://cdnca:secret@127.0.0.1:5432/cdnca?sslmode=disable" {
		return "", errors.New("unexpected dsn")
	}
	switch {
	case strings.Contains(sql, "schema_migrations"):
		return fmt.Sprintf("%d:%d", database.head, database.head), nil
	case strings.Contains(sql, "pg_database_size"):
		return fmt.Sprint(database.size), nil
	case sql == nativeOwnershipSQL:
		if database.foreign != "" {
			return database.foreign, nil
		}
		return "0", nil
	}
	return "", fmt.Errorf("unexpected query %q", sql)
}

func (*nativeFakeDatabase) Compatible(context.Context, string) error { return nil }

func (database *nativeFakeDatabase) Dump(_ context.Context, _, filename string) error {
	database.mu.Lock()
	defer database.mu.Unlock()
	database.dumps++
	if database.failDump {
		return errors.New("injected pg_dump failure")
	}
	return os.WriteFile(filename, []byte(fmt.Sprintf("%d|%s", database.head, database.marker)), 0o600)
}

func (*nativeFakeDatabase) Verify(_ context.Context, filename string) error {
	encoded, err := os.ReadFile(filename)
	if err != nil || !strings.Contains(string(encoded), "|") {
		return errors.New("invalid dump")
	}
	return nil
}

func (database *nativeFakeDatabase) Restore(_ context.Context, _, filename string) error {
	database.mu.Lock()
	defer database.mu.Unlock()
	database.restore++
	if database.failRestore {
		return errors.New("injected pg_restore failure")
	}
	encoded, err := os.ReadFile(filename)
	if err != nil {
		return err
	}
	head, marker, _ := strings.Cut(string(encoded), "|")
	_, err = fmt.Sscan(head, &database.head)
	database.marker = marker
	return err
}

func (database *nativeFakeDatabase) EnsureRoles(_ context.Context, dsn string) error {
	database.mu.Lock()
	defer database.mu.Unlock()
	database.ensured = append(database.ensured, fmt.Sprintf("ensure@%d", database.migrates))
	return database.ensureErr
}

func (database *nativeFakeDatabase) Migrate(_ context.Context, _, binary string) error {
	database.mu.Lock()
	defer database.mu.Unlock()
	database.migrates++
	if filepath.Base(binary) != "control-api" {
		return errors.New("unexpected binary")
	}
	for database.head < database.target {
		if database.head+1 == database.failAt {
			return fmt.Errorf("apply migration %d: injected failure", database.failAt)
		}
		database.head++
		database.marker = "candidate-schema"
	}
	return nil
}

func nativeMigrationFiles(files map[string][]byte, versions ...int) {
	for _, version := range versions {
		for _, direction := range []string{"up", "down"} {
			files[fmt.Sprintf("migrations/%03d_step_%d.%s.sql", version, version, direction)] = []byte(fmt.Sprintf("-- %d %s\n", version, direction))
		}
	}
}

// newMigratingFixture: current carries migrations 001-003, the candidate
// appends 004-005, and the database sits at head 3.
func newMigratingFixture(t *testing.T, change func(files map[string][]byte)) (*nativeFixture, *nativeFakeDatabase) {
	t.Helper()
	fixture := newNativeFixtureWith(t, func(index int, files map[string][]byte) {
		nativeMigrationFiles(files, 1, 2, 3)
		if index == 1 {
			nativeMigrationFiles(files, 4, 5)
			if change != nil {
				change(files)
			}
		}
	})
	database := &nativeFakeDatabase{head: 3, target: 5, marker: "original", size: 1 << 20}
	executor := fixture.runner.executor
	executor.database = database
	executor.controlDSN = func(context.Context) (string, error) {
		return "postgres://cdnca:secret@127.0.0.1:5432/cdnca?sslmode=disable", nil
	}
	executor.freeSpace = func(string) (int64, error) { return 1 << 40, nil }
	return fixture, database
}

func nativeHistoryPhases(t *testing.T, fixture *nativeFixture) []string {
	t.Helper()
	history, err := fixture.runner.runner.store.LoadHistory()
	if err != nil {
		t.Fatal(err)
	}
	var phases []string
	for _, entry := range history.Entries {
		phases = append(phases, string(entry.Phase))
	}
	return phases
}

func TestNativeAppendedMigrationsAppliedFromBackup(t *testing.T) {
	fixture, database := newMigratingFixture(t, nil)
	receipt, err := fixture.runner.Run(t.Context(), fixture.bundle)
	if err != nil || receipt.Result != ResultApplied {
		t.Fatalf("apply: %+v %v", receipt, err)
	}
	migration := receipt.Migration
	if migration == nil || strings.Join(migration.Applied, ",") != "004_step_4,005_step_5" || !migration.Migrated ||
		migration.Restored || migration.BackupBytes < 1 || !digestPattern.MatchString(migration.BackupSHA256) ||
		migration.BackupPath != filepath.Join(fixture.runner.runner.store.root, "database-backups", receipt.PlanID+".dump") {
		t.Fatalf("receipt migration evidence: %+v", migration)
	}
	if database.head != 5 || database.dumps != 1 || database.migrates != 1 || database.restore != 0 {
		t.Fatalf("database: %+v", database)
	}
	// FX01: the superuser-only roles are ensured before the candidate migrates.
	if strings.Join(database.ensured, ",") != "ensure@0" {
		t.Fatalf("roles ensured = %v, want once before migrate", database.ensured)
	}
	fixture.assertLinks(t, fixture.next.Digest, fixture.old.Digest)
	if fixture.commands.stops != 1 || fixture.commands.restarts != 1 {
		t.Fatalf("stops=%d restarts=%d", fixture.commands.stops, fixture.commands.restarts)
	}
	info, err := os.Stat(migration.BackupPath)
	directory, dirErr := os.Stat(filepath.Dir(migration.BackupPath))
	if err != nil || info.Mode().Perm()&0o077 != 0 || dirErr != nil || directory.Mode().Perm() != 0o700 {
		t.Fatalf("backup must stay in the protected state directory: %v %v %v", info, err, dirErr)
	}
	want := "verified,expanded,preflighted,drained,control_stopped,database_backed_up,database_migrated,activated,healthy,contracted,completed"
	if phases := strings.Join(nativeHistoryPhases(t, fixture), ","); phases != want {
		t.Fatalf("history = %s", phases)
	}
	history, _ := fixture.runner.runner.store.LoadHistory()
	for _, entry := range history.Entries {
		if entry.Phase == PhaseDatabaseBackedUp && (entry.Migration == nil || entry.Migration.BackupPath != migration.BackupPath) {
			t.Fatalf("history lacks backup evidence: %+v", entry)
		}
	}
	if status, err := fixture.runner.Probe(t.Context()); err != nil || !status.Ready {
		t.Fatalf("probe after migration: %+v %v", status, err)
	}
}

func TestNativeMigrationChangesOtherThanAppendAreRejectedBeforeDrain(t *testing.T) {
	for reason, change := range map[string]func(map[string][]byte){
		"tampered old migration": func(files map[string][]byte) {
			files["migrations/002_step_2.up.sql"] = []byte("ALTER TABLE real_data DROP COLUMN required;")
		},
		"missing down": func(files map[string][]byte) { delete(files, "migrations/005_step_5.down.sql") },
		"missing up":   func(files map[string][]byte) { delete(files, "migrations/004_step_4.up.sql") },
		"version gap":  func(files map[string][]byte) { nativeMigrationFiles(files, 7) },
		"name mismatch": func(files map[string][]byte) {
			files["migrations/005_other.down.sql"] = files["migrations/005_step_5.down.sql"]
			delete(files, "migrations/005_step_5.down.sql")
		},
		"removed old migration": func(files map[string][]byte) {
			delete(files, "migrations/003_step_3.up.sql")
			delete(files, "migrations/003_step_3.down.sql")
		},
		"inserted below head": func(files map[string][]byte) { files["migrations/002_extra.up.sql"] = []byte("SELECT 1;") },
		"empty new migration": func(files map[string][]byte) { files["migrations/005_step_5.up.sql"] = nil },
	} {
		t.Run(reason, func(t *testing.T) {
			fixture, database := newMigratingFixture(t, change)
			receipt, err := fixture.runner.Run(t.Context(), fixture.bundle)
			if !errors.Is(err, ErrCandidateRejected) || receipt.Result != ResultFailed || receipt.ErrorCode != "expand_failed" {
				t.Fatalf("Run() = %+v %v", receipt, err)
			}
			current, _, err := fixture.runner.executor.current()
			if err != nil || current.Digest != fixture.old.Digest || database.dumps != 0 || database.migrates != 0 ||
				fixture.commands.stops != 0 || fixture.commands.restarts != 0 {
				t.Fatalf("rejected candidate touched live state: %+v %v %+v", current, err, database)
			}
		})
	}
}

func TestNativeMigrationFailureRestoresBackupAndOldRelease(t *testing.T) {
	fixture, database := newMigratingFixture(t, nil)
	database.failAt = 5 // 004 commits, 005 fails: a partially migrated database
	receipt, err := fixture.runner.Run(t.Context(), fixture.bundle)
	if !errors.Is(err, ErrRolledBack) || receipt.Result != ResultRolledBack || receipt.ErrorCode != "database_migration_failed" {
		t.Fatalf("Run() = %+v %v", receipt, err)
	}
	if database.head != 3 || database.marker != "original" || database.restore != 1 {
		t.Fatalf("database not restored: %+v", database)
	}
	if receipt.Migration == nil || !receipt.Migration.Restored || receipt.Migration.Migrated {
		t.Fatalf("receipt: %+v", receipt.Migration)
	}
	fixture.assertCurrent(t, fixture.old.Digest)
	if status, err := fixture.runner.Probe(t.Context()); err != nil || !status.Ready {
		t.Fatalf("old release not healthy after restore: %+v %v", status, err)
	}
}

func TestNativeHealthFailureRollbackRestoresDatabase(t *testing.T) {
	fixture, database := newMigratingFixture(t, nil)
	fixture.commands.failHealth = fixture.next.Digest
	receipt, err := fixture.runner.Run(t.Context(), fixture.bundle)
	if !errors.Is(err, ErrRolledBack) || receipt.ErrorCode != "target_health_failed" {
		t.Fatalf("Run() = %+v %v", receipt, err)
	}
	if database.head != 3 || database.marker != "original" || database.restore != 1 || database.migrates != 1 {
		t.Fatalf("health rollback must restore the database: %+v", database)
	}
	if receipt.Migration == nil || !receipt.Migration.Migrated || !receipt.Migration.Restored || receipt.Migration.RestoreMillis < 0 {
		t.Fatalf("receipt: %+v", receipt.Migration)
	}
	fixture.assertLinks(t, fixture.old.Digest, fixture.old.Digest)
	// control-api was stopped before restore and both services restarted on the old release.
	if fixture.commands.stops != 2 || fixture.commands.restarts != 2 {
		t.Fatalf("stops=%d restarts=%d", fixture.commands.stops, fixture.commands.restarts)
	}
}

func TestNativeBackupFailureRollsBackWithoutRestore(t *testing.T) {
	fixture, database := newMigratingFixture(t, nil)
	database.failDump = true
	receipt, err := fixture.runner.Run(t.Context(), fixture.bundle)
	if !errors.Is(err, ErrRolledBack) || receipt.ErrorCode != "database_backup_failed" || database.restore != 0 || database.migrates != 0 {
		t.Fatalf("Run() = %+v %v %+v", receipt, err, database)
	}
	fixture.assertCurrent(t, fixture.old.Digest)
	entries, _ := os.ReadDir(filepath.Join(fixture.runner.runner.store.root, "database-backups"))
	if len(entries) != 0 {
		t.Fatalf("failed dump left files: %v", entries)
	}
}

func TestNativeRestoreFailureIsTerminalAndKeepsMaintenance(t *testing.T) {
	fixture, database := newMigratingFixture(t, nil)
	database.failAt, database.failRestore = 5, true
	receipt, err := fixture.runner.Run(t.Context(), fixture.bundle)
	if err == nil || receipt.Result != ResultFailed || receipt.ErrorCode != "database_restore_failed" {
		t.Fatalf("Run() = %+v %v", receipt, err)
	}
	state, err := readNativeMaintenance(fixture.runner.executor.config.MaintenanceFile, fixture.installationID(), uint32(os.Getuid()))
	if err != nil || state.Phase != "draining" || fixture.commands.restarts != 0 {
		t.Fatalf("restore failure must stay drained for manual recovery: %+v %v", state, err)
	}
	if _, err := os.Stat(receipt.Migration.BackupPath); err != nil {
		t.Fatalf("backup must remain for manual restore: %v", err)
	}
}

func TestNativeBackupSpaceShortageFailsBeforeDrainAndRetries(t *testing.T) {
	fixture, database := newMigratingFixture(t, nil)
	fixture.runner.executor.freeSpace = func(string) (int64, error) { return database.size, nil }
	if _, err := fixture.runner.Run(t.Context(), fixture.bundle); !errors.Is(err, ErrBackupSpaceInsufficient) {
		t.Fatalf("space shortage accepted: %v", err)
	}
	state, err := fixture.runner.runner.store.Load()
	maintenance, maintenanceErr := readNativeMaintenance(fixture.runner.executor.config.MaintenanceFile, fixture.installationID(), uint32(os.Getuid()))
	if err != nil || state.Phase != PhaseExpanded || state.ErrorCode != "database_backup_space_insufficient" || state.Receipt != nil ||
		maintenanceErr != nil || maintenance.Phase != "active" || fixture.commands.stops != 0 {
		t.Fatalf("state=%+v maintenance=%+v", state, maintenance)
	}
	fixture.runner.executor.freeSpace = func(string) (int64, error) { return 1 << 40, nil }
	if receipt, err := fixture.runner.Run(t.Context(), fixture.bundle); err != nil || receipt.Result != ResultApplied {
		t.Fatalf("retry after freeing space: %+v %v", receipt, err)
	}
}

func TestNativeMigrationRefusesDatabaseItCannotRestore(t *testing.T) {
	fixture, database := newMigratingFixture(t, nil)
	database.foreign = "1"
	if _, err := fixture.runner.Run(t.Context(), fixture.bundle); err == nil {
		t.Fatal("foreign-owned database accepted")
	}
	state, _ := fixture.runner.runner.store.Load()
	if state.Phase != PhaseExpanded || state.ErrorCode != "database_preflight_failed" || database.dumps != 0 {
		t.Fatalf("state=%+v database=%+v", state, database)
	}
}

// TestNativeMigrationResumesEveryCheckpointAfterCrash replays the side effects
// up to a checkpoint, persists exactly that checkpoint (as a crashed runner
// would have), then lets a fresh Run resume.
func TestNativeMigrationResumesEveryCheckpointAfterCrash(t *testing.T) {
	for _, crash := range []string{"drained", "control_stopped", "backup_written_unrecorded", "database_backed_up",
		"partially_migrated", "database_migrated", "activated", "restore_interrupted", "restored_unlinked"} {
		t.Run(crash, func(t *testing.T) {
			fixture, database := newMigratingFixture(t, nil)
			executor := fixture.runner.executor
			plan, err := fixture.runner.runner.verifyBundle(fixture.bundle)
			if err != nil {
				t.Fatal(err)
			}
			must := func(err error) {
				t.Helper()
				if err != nil {
					t.Fatal(err)
				}
			}
			for _, step := range []func(context.Context, Plan) error{executor.Expand, executor.Preflight, executor.Drain} {
				must(step(t.Context(), plan))
			}
			record := &MigrationRecord{Applied: []string{"004_step_4", "005_step_5"}}
			state := State{Schema: StateSchema, PlanID: plan.ID, BundleSHA256: plan.BundleSHA256, Sequence: plan.Sequence,
				Phase: PhaseDrained, PreviousDigest: fixture.old.Digest, TargetDigest: fixture.next.Digest, Migration: record}
			wantResult, wantHead, wantMarker, wantRestores := ResultApplied, 5, "candidate-schema", 0
			if crash != "drained" {
				must(executor.StopControl(t.Context(), plan))
				state.Phase = PhaseControlStopped
			}
			switch crash {
			case "backup_written_unrecorded":
				scratch := *record
				must(executor.BackupDatabase(t.Context(), plan, &scratch)) // durable file, checkpoint not saved
			case "database_backed_up", "partially_migrated", "database_migrated", "activated", "restore_interrupted", "restored_unlinked":
				must(executor.BackupDatabase(t.Context(), plan, record))
				state.Phase = PhaseDatabaseBackedUp
			}
			switch crash {
			case "partially_migrated":
				database.head, database.marker = 4, "candidate-schema"
			case "database_migrated", "activated", "restore_interrupted", "restored_unlinked":
				must(executor.MigrateDatabase(t.Context(), plan, record))
				state.Phase = PhaseDatabaseMigrated
			}
			switch crash {
			case "activated":
				must(executor.Activate(t.Context(), plan))
				state.Phase = PhaseActivated
			case "restore_interrupted", "restored_unlinked":
				must(executor.Activate(t.Context(), plan))
				fixture.commands.failHealth = fixture.next.Digest
				state.Phase, state.ErrorCode = PhaseRollingBack, "target_health_failed"
				wantResult, wantHead, wantMarker = ResultRolledBack, 3, "original"
				database.marker = "written-by-candidate"
				if crash == "restore_interrupted" {
					database.head = 0 // wiped, replay not finished
					wantRestores = 1
				} else {
					must(executor.StopControl(t.Context(), plan))
					must(executor.RestoreDatabase(t.Context(), plan, record))
					record.Restored = true
					database.restore = 0
					// The old release must keep rows it writes after the restore.
					database.marker, wantMarker = "written-by-old-release", "written-by-old-release"
				}
			}
			dumps := database.dumps
			must(fixture.runner.runner.store.Save(state))
			receipt, err := fixture.runner.Run(t.Context(), fixture.bundle)
			if receipt.Result != wantResult || (wantResult == ResultApplied && err != nil) {
				t.Fatalf("resume from %s: %+v %v", crash, receipt, err)
			}
			if database.head != wantHead || database.marker != wantMarker || database.restore != wantRestores {
				t.Fatalf("database after resume from %s: %+v", crash, database)
			}
			redumped := map[string]bool{"drained": true, "control_stopped": true, "backup_written_unrecorded": true}[crash]
			if (database.dumps > dumps) != redumped {
				t.Fatalf("backup rerun=%v after %s", database.dumps > dumps, crash)
			}
			if receipt.Migration == nil || receipt.Migration.BackupPath == "" {
				t.Fatalf("receipt lost migration evidence: %+v", receipt)
			}
		})
	}
}

func TestNativeDatabaseURLAndEnvironmentParsing(t *testing.T) {
	dsn, err := parseNativeDSN("postgres://cdnca:p%40ss%2Fword@127.0.0.1:5432/cdnca?sslmode=disable")
	if err != nil || dsn.password != "p@ss/word" || dsn.host != "127.0.0.1" || dsn.port != "5432" || dsn.database != "cdnca" || dsn.sslmode != "disable" {
		t.Fatalf("dsn = %+v %v", dsn, err)
	}
	environment := strings.Join(nativePGTools{}.environment(dsn), "\n")
	if !strings.Contains(environment, "PGPASSWORD=p@ss/word") || strings.Contains(environment, "DATABASE_URL") {
		t.Fatalf("environment = %s", environment)
	}
	if dsn, err := parseNativeDSN("postgresql://cdnca@/cdnca?host=/run/postgresql"); err != nil || dsn.host != "/run/postgresql" || dsn.port != "5432" {
		t.Fatalf("socket dsn = %+v %v", dsn, err)
	}
	for _, raw := range []string{"", "mysql://u:p@h/db", "postgres://u:p@h/db?options=-c", "postgres://u:p@h/db?sslmode=bogus",
		"postgres://u:p@h/db%3Bx", "postgres://u:p@h:0/db", "postgres:opaque", "postgres://h/db"} {
		if _, err := parseNativeDSN(raw); err == nil {
			t.Fatalf("accepted %q", raw)
		}
	}
	directory := t.TempDir()
	filename := filepath.Join(directory, "control.env")
	write := func(content string) {
		if err := os.WriteFile(filename, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	owner := uint32(os.Getuid())
	write("# comment\nDATABASE_URL=postgres://a:b@h/one\nOTHER=1\nexport DATABASE_URL=\"postgres://a:b@h/two\"\n")
	if value, present, err := readNativeEnvironmentValue(filename, owner, "DATABASE_URL"); err != nil || !present || value != "postgres://a:b@h/two" {
		t.Fatalf("last assignment must win: %q %v %v", value, present, err)
	}
	write("DATABASE_URL=\"postgres://a:b@h/one\" trailing\n")
	if _, _, err := readNativeEnvironmentValue(filename, owner, "DATABASE_URL"); err == nil {
		t.Fatal("ambiguous quoting accepted")
	}
	write("DATABASE_URL=postgres://a:b@h/one\n")
	if err := os.Chmod(filename, 0o666); err != nil {
		t.Fatal(err)
	}
	if _, _, err := readNativeEnvironmentValue(filename, owner, "DATABASE_URL"); err == nil {
		t.Fatal("world-writable environment file accepted")
	}
	if err := os.Chmod(filename, 0o600); err != nil {
		t.Fatal(err)
	}
	other := filepath.Join(directory, "later.env")
	if err := os.WriteFile(other, []byte("UNRELATED=1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	executor := &nativeExecutor{owner: owner, config: NativeStandaloneConfig{ControlUnit: "cdnca-control-api.service"},
		commands: nativeUnitCommands(fmt.Sprintf("Environment=DATABASE_URL=postgres://x:y@h/inline\nEnvironmentFiles=%s (ignore_errors=no)\nEnvironmentFiles=%s/missing.env (ignore_errors=yes)\nEnvironmentFiles=%s (ignore_errors=no)\n", filename, directory, other))}
	if value, err := executor.databaseURL(t.Context()); err != nil || value != "postgres://a:b@h/one" {
		t.Fatalf("unit DATABASE_URL = %q %v", value, err)
	}
	executor.commands = nativeUnitCommands(fmt.Sprintf("Environment=\nEnvironmentFiles=%s/missing.env (ignore_errors=no)\n", directory))
	if _, err := executor.databaseURL(t.Context()); err == nil {
		t.Fatal("missing required environment file accepted")
	}
}

func (fixture *nativeFixture) assertCurrent(t *testing.T, digest string) {
	t.Helper()
	actual, err := os.Readlink(filepath.Join(fixture.runner.executor.config.ReleaseRoot, "current"))
	if err != nil || filepath.Base(actual) != digest || fixture.commands.active != digest {
		t.Fatalf("current=%s active=%s err=%v", actual, fixture.commands.active, err)
	}
}

type nativeUnitCommands string

func (output nativeUnitCommands) Run(context.Context, string, ...string) ([]byte, error) {
	return []byte(output), nil
}

// nativeRunLog reads the run log back through PublishStatus and the
// unprivileged API reader, as the console sees it.
func nativeRunLog(t *testing.T, fixture *nativeFixture, golden string) RunLog {
	t.Helper()
	log, _ := (&nativeRunLogScenario{fixture: fixture}).publish(t, golden)
	return log
}

func runLogEntry(t *testing.T, log RunLog, event string) RunLogEntry {
	t.Helper()
	for _, entry := range log.Entries {
		if entry.Event == event {
			return entry
		}
	}
	t.Fatalf("no %s entry in %v", event, runLogEvents(log))
	return RunLogEntry{}
}

// The script log shows the backup, migration and (on failure) restore with
// the same evidence the history journals.
func TestNativeRunLogRecordsDatabaseMigration(t *testing.T) {
	t.Run("applied", func(t *testing.T) {
		fixture, _ := newMigratingFixture(t, nil)
		receipt, err := fixture.runner.Run(t.Context(), fixture.bundle)
		if err != nil {
			t.Fatalf("apply: %+v %v", receipt, err)
		}
		log := nativeRunLog(t, fixture, "migration-applied")
		assertRunLogEvents(t, log, "migrations_pending", "maintenance_draining", "step_succeeded:drain",
			"step_started:control_stop", "step_succeeded:control_stop", "step_started:database_backup", "database_backed_up",
			"step_succeeded:database_backup", "step_started:database_migrate", "database_migrated", "step_succeeded:database_migrate",
			"step_started:activate", "release_switched", "run_completed")
		if pending := runLogEntry(t, log, "migrations_pending"); pending.Count != 2 || strings.Join(pending.Migrations, ",") != "004_step_4,005_step_5" {
			t.Fatalf("pending entry %+v", pending)
		}
		if backup := runLogEntry(t, log, "database_backed_up"); backup.Bytes != receipt.Migration.BackupBytes || backup.Bytes < 1 {
			t.Fatalf("backup entry %+v, receipt %+v", backup, receipt.Migration)
		}
		if migrated := runLogEntry(t, log, "database_migrated"); strings.Join(migrated.Migrations, ",") != "004_step_4,005_step_5" {
			t.Fatalf("migrated entry %+v", migrated)
		}
		if strings.Contains(strings.Join(runLogEvents(log), " "), "database_restore") {
			t.Fatalf("successful upgrade logged a restore: %v", runLogEvents(log))
		}
	})
	t.Run("migration failure restores", func(t *testing.T) {
		fixture, database := newMigratingFixture(t, nil)
		database.failAt = 5
		if _, err := fixture.runner.Run(t.Context(), fixture.bundle); !errors.Is(err, ErrRolledBack) {
			t.Fatal(err)
		}
		log := nativeRunLog(t, fixture, "migration-rolled-back")
		assertRunLogEvents(t, log, "database_backed_up", "step_started:database_migrate", "step_failed:database_migrate",
			"rollback_started", "database_restore_started", "database_restored", "rollback_succeeded", "run_rolled_back")
		if failed := runLogEntry(t, log, "step_failed"); failed.ErrorCode != "database_migration_failed" {
			t.Fatalf("step_failed %+v", failed)
		}
		if runLogEntry(t, log, "database_restored").Bytes != runLogEntry(t, log, "database_backed_up").Bytes {
			t.Fatalf("restore must name the backup it used: %+v", log.Entries)
		}
	})
	t.Run("restore failure is logged", func(t *testing.T) {
		fixture, database := newMigratingFixture(t, nil)
		database.failAt, database.failRestore = 5, true
		if _, err := fixture.runner.Run(t.Context(), fixture.bundle); err == nil {
			t.Fatal("restore failure must fail the run")
		}
		log := nativeRunLog(t, fixture, "migration-restore-failed")
		assertRunLogEvents(t, log, "step_failed:database_migrate", "rollback_started", "database_restore_started",
			"step_failed:database_restore", "run_failed")
		if last := log.Entries[len(log.Entries)-1]; last.ErrorCode != "database_restore_failed" || last.Level != "error" {
			t.Fatalf("terminal entry %+v", last)
		}
	})
	t.Run("rewritten migration names the rule", func(t *testing.T) {
		fixture, _ := newMigratingFixture(t, func(files map[string][]byte) {
			files["migrations/002_step_2.up.sql"] = []byte("ALTER TABLE real_data DROP COLUMN required;")
		})
		if _, err := fixture.runner.Run(t.Context(), fixture.bundle); !errors.Is(err, ErrCandidateRejected) {
			t.Fatal(err)
		}
		assertRunLogEvents(t, nativeRunLog(t, fixture, "migration-rejected"), "lineage_rejected/migrations_not_append_only", "run_failed")
	})
}
