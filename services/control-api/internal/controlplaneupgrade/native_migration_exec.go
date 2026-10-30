//go:build !windows

package controlplaneupgrade

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const (
	nativeBackupDirectory = "database-backups"
	nativeBackupRetention = 3
	nativeBackupReserve   = 256 << 20
	nativeBackupLimit     = 1 << 40
)

var nativePlanFileID = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

func (executor *nativeExecutor) backupFile(plan Plan) (string, error) {
	if !nativePlanFileID.MatchString(plan.ID) || executor.backupDir == "" {
		return "", ErrInvalidPlan
	}
	return filepath.Join(executor.backupDir, plan.ID+".dump"), nil
}

func (executor *nativeExecutor) databaseContext(ctx context.Context) (context.Context, context.CancelFunc) {
	// A half-written dump, migration or restore must not be abandoned by the
	// runner's stop signal; recovery bounds each with DatabaseTimeout instead.
	return context.WithTimeout(context.WithoutCancel(ctx), executor.config.DatabaseTimeout)
}

// PendingMigrations re-derives the appended migration set from the two
// verified releases; it is deterministic for a plan.
func (executor *nativeExecutor) PendingMigrations(_ context.Context, plan Plan) ([]string, error) {
	current, err := executor.verifyArtifact(plan.Rollback)
	if err != nil {
		return nil, err
	}
	candidate, err := executor.verifyArtifact(plan.Target)
	if err != nil {
		return nil, err
	}
	applied, ok := nativeAppendedMigrations(current, candidate)
	if !ok {
		return nil, fmt.Errorf("%w: %w", ErrCandidateRejected, ErrTargetMismatch)
	}
	return applied, nil
}

// databasePreflight proves, before Drain, that a migrating candidate can be
// backed up and restored: tools, credentials, ledger head, ownership and
// backup space. Space shortage keeps a distinct, retryable code.
func (executor *nativeExecutor) databasePreflight(ctx context.Context, plan Plan, current, candidate NativeManifest) error {
	applied, ok := nativeAppendedMigrations(current, candidate)
	if !ok {
		return fmt.Errorf("%w: %w", ErrCandidateRejected, ErrTargetMismatch)
	}
	if len(applied) == 0 {
		return nil
	}
	if _, err := executor.backupFile(plan); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, executor.config.StepTimeout)
	defer cancel()
	coded := func(err error) error { return withStepCode("database_preflight_failed", err) }
	if err := executor.ensureBackupDirectory(); err != nil {
		return coded(err)
	}
	dsn, err := executor.databaseURL(ctx)
	if err != nil {
		return coded(err)
	}
	if err := executor.database.Compatible(ctx, dsn); err != nil {
		return coded(err)
	}
	if err := executor.expectLedger(ctx, dsn, nativeMigrationHead(current)); err != nil {
		return coded(err)
	}
	if err := executor.expectOwnership(ctx, dsn); err != nil {
		return coded(err)
	}
	return executor.checkBackupSpace(ctx, dsn)
}

func (executor *nativeExecutor) expectLedger(ctx context.Context, dsn string, head int) error {
	output, err := executor.database.Query(ctx, dsn, "SELECT count(*)::text || ':' || coalesce(max(version), 0)::text FROM schema_migrations")
	if err != nil {
		return err
	}
	if output != fmt.Sprintf("%d:%d", head, head) {
		return fmt.Errorf("%w: database migration ledger %q does not match release head %d", ErrTargetMismatch, output, head)
	}
	return nil
}

func (executor *nativeExecutor) expectOwnership(ctx context.Context, dsn string) error {
	output, err := executor.database.Query(ctx, dsn, nativeOwnershipSQL)
	if err != nil {
		return err
	}
	if output != "0" {
		return fmt.Errorf("%w: %s database objects are not owned by the control role or are extensions", ErrTargetMismatch, output)
	}
	return nil
}

func (executor *nativeExecutor) checkBackupSpace(ctx context.Context, dsn string) error {
	output, err := executor.database.Query(ctx, dsn, "SELECT pg_database_size(current_database())")
	size, convErr := strconv.ParseInt(output, 10, 64)
	if err != nil || convErr != nil || size < 0 {
		return withStepCode("database_preflight_failed", errors.Join(ErrTargetMismatch, err, convErr))
	}
	available, err := executor.freeSpace(executor.backupDir)
	if err != nil {
		return withStepCode("database_preflight_failed", err)
	}
	// A custom-format dump is compressed and rarely exceeds the database size.
	if required := size + nativeBackupReserve; available < required {
		return withStepCode("database_backup_space_insufficient",
			fmt.Errorf("%w: %d bytes free, %d required", ErrBackupSpaceInsufficient, available, required))
	}
	return nil
}

func nativeFreeSpace(directory string) (int64, error) {
	var stat syscall.Statfs_t
	if err := syscall.Statfs(directory, &stat); err != nil {
		return 0, err
	}
	return int64(stat.Bavail) * int64(stat.Bsize), nil
}

func (executor *nativeExecutor) ensureBackupDirectory() error {
	if err := os.Mkdir(executor.backupDir, 0o700); err != nil && !os.IsExist(err) {
		return err
	}
	info, err := os.Lstat(executor.backupDir)
	stat, ok := infoSysStat(info)
	if err != nil || !ok || !info.IsDir() || stat.Uid != executor.owner || info.Mode().Perm() != 0o700 {
		return ErrInvalidConfig
	}
	return nil
}

// StopControl stops only the database client (control-api). The gateway has
// no database connection and keeps edge sessions up during the backup.
func (executor *nativeExecutor) StopControl(ctx context.Context, _ Plan) error {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), executor.config.StepTimeout)
	defer cancel()
	if _, err := executor.commands.Run(ctx, "systemctl", "stop", executor.config.ControlUnit); err != nil {
		return fmt.Errorf("stop %s: %w", executor.config.ControlUnit, err)
	}
	return executor.controlStopped(ctx)
}

func (executor *nativeExecutor) controlStopped(ctx context.Context) error {
	output, err := executor.commands.Run(ctx, "systemctl", "show", "--no-pager", "--property=ActiveState,MainPID", executor.config.ControlUnit)
	if err != nil {
		return ErrTargetMismatch
	}
	properties := make(map[string]string)
	for _, line := range strings.Split(string(output), "\n") {
		if key, value, found := strings.Cut(line, "="); found {
			properties[key] = value
		}
	}
	if (properties["ActiveState"] != "inactive" && properties["ActiveState"] != "failed") || properties["MainPID"] != "0" {
		return fmt.Errorf("%w: %s is still running", ErrTargetMismatch, executor.config.ControlUnit)
	}
	return nil
}

// BackupDatabase writes a verified pg_dump -Fc archive named by plan ID into
// the runner's 0700 state directory. Only a complete, fsynced, re-read dump is
// recorded; a crash before that leaves an ignored temporary file.
func (executor *nativeExecutor) BackupDatabase(ctx context.Context, plan Plan, record *MigrationRecord) error {
	if record == nil || record.BackupPath != "" {
		return ErrCorruptState
	}
	filename, err := executor.backupFile(plan)
	if err != nil {
		return err
	}
	ctx, cancel := executor.databaseContext(ctx)
	defer cancel()
	started := time.Now()
	if err := executor.ensureBackupDirectory(); err != nil {
		return err
	}
	if err := executor.controlStopped(ctx); err != nil {
		return err
	}
	dsn, err := executor.databaseURL(ctx)
	if err != nil {
		return err
	}
	if err := executor.expectLedger(ctx, dsn, nativeMigrationVersion(record.Applied[0])-1); err != nil {
		return err
	}
	executor.pruneBackups(filepath.Base(filename))
	if err := executor.checkBackupSpace(ctx, dsn); err != nil {
		return err
	}
	file, err := os.CreateTemp(executor.backupDir, ".dump-*.tmp")
	if err != nil {
		return err
	}
	temporary := file.Name()
	defer os.Remove(temporary)
	if err := file.Close(); err != nil {
		return err
	}
	if err := executor.database.Dump(ctx, dsn, temporary); err != nil {
		return err
	}
	if err := nativeSyncFile(temporary); err != nil {
		return err
	}
	if err := executor.database.Verify(ctx, temporary); err != nil {
		return err
	}
	digest, size, err := digestRegularFile(temporary, nativeBackupLimit)
	if err != nil {
		return err
	}
	if err := os.Rename(temporary, filename); err != nil {
		return err
	}
	if err := syncDirectory(executor.backupDir); err != nil {
		return err
	}
	record.BackupPath, record.BackupBytes, record.BackupSHA256 = filename, size, digest
	record.BackupMillis = time.Since(started).Milliseconds()
	return nil
}

// MigrateDatabase runs the candidate's own `control-api migrate up` with the
// control service's DATABASE_URL, then proves the ledger reached its head.
// Re-running it after a crash is a no-op for already applied migrations.
func (executor *nativeExecutor) MigrateDatabase(ctx context.Context, plan Plan, record *MigrationRecord) error {
	if record == nil || record.BackupPath == "" || record.Restored {
		return ErrCorruptState
	}
	ctx, cancel := executor.databaseContext(ctx)
	defer cancel()
	started := time.Now()
	if _, err := executor.verifyArtifact(plan.Target); err != nil {
		return err
	}
	if err := executor.controlStopped(ctx); err != nil {
		return err
	}
	dsn, err := executor.databaseURL(ctx)
	if err != nil {
		return err
	}
	if err := executor.database.EnsureRoles(ctx, dsn); err != nil {
		record.RolesError = truncateRolesError(err.Error())
	}
	if err := executor.database.Migrate(ctx, dsn, filepath.Join(executor.release(plan.Target), "bin/control-api")); err != nil {
		return err
	}
	if err := executor.expectLedger(ctx, dsn, nativeMigrationVersion(record.Applied[len(record.Applied)-1])); err != nil {
		return err
	}
	record.Migrated, record.MigrateMillis = true, time.Since(started).Milliseconds()
	return nil
}

func truncateRolesError(message string) string {
	if len(message) > 512 {
		return message[:512]
	}
	return message
}

// RestoreDatabase returns the database to the plan's backup. Restore over
// pg_dump/pg_restore is preferred to running down scripts: it does not depend
// on rarely exercised, possibly lossy down SQL, and also undoes partial
// migrations and any rows the candidate wrote before its health failed.
func (executor *nativeExecutor) RestoreDatabase(ctx context.Context, plan Plan, record *MigrationRecord) error {
	filename, err := executor.backupFile(plan)
	if err != nil || record == nil || record.BackupPath != filename {
		return ErrCorruptState
	}
	ctx, cancel := executor.databaseContext(ctx)
	defer cancel()
	started := time.Now()
	info, err := os.Lstat(filename)
	stat, ok := infoSysStat(info)
	if err != nil || !ok || stat.Uid != executor.owner {
		return fmt.Errorf("%w: database backup is missing or not runner-owned", ErrTargetMismatch)
	}
	digest, size, err := digestRegularFile(filename, nativeBackupLimit)
	if err != nil || digest != record.BackupSHA256 || size != record.BackupBytes {
		return fmt.Errorf("%w: database backup changed after it was recorded", ErrTargetMismatch)
	}
	if err := executor.controlStopped(ctx); err != nil {
		return err
	}
	dsn, err := executor.databaseURL(ctx)
	if err != nil {
		return err
	}
	if err := executor.expectOwnership(ctx, dsn); err != nil {
		return err
	}
	if err := executor.database.Restore(ctx, dsn, filename); err != nil {
		return err
	}
	if err := executor.expectLedger(ctx, dsn, nativeMigrationVersion(record.Applied[0])-1); err != nil {
		return err
	}
	record.RestoreMillis = time.Since(started).Milliseconds()
	return nil
}

func nativeSyncFile(filename string) error {
	file, err := os.OpenFile(filename, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	defer file.Close()
	return file.Sync()
}

// pruneBackups removes interrupted temporaries and keeps the newest
// nativeBackupRetention completed dumps besides the current plan's.
func (executor *nativeExecutor) pruneBackups(keep string) {
	entries, err := os.ReadDir(executor.backupDir)
	if err != nil {
		return
	}
	type dump struct {
		name string
		at   time.Time
	}
	var dumps []dump
	for _, entry := range entries {
		name := entry.Name()
		info, err := entry.Info()
		if err != nil || !info.Mode().IsRegular() {
			continue
		}
		if strings.HasPrefix(name, ".dump-") && strings.HasSuffix(name, ".tmp") {
			_ = os.Remove(filepath.Join(executor.backupDir, name))
			continue
		}
		if name != keep && strings.HasSuffix(name, ".dump") && nativePlanFileID.MatchString(strings.TrimSuffix(name, ".dump")) {
			dumps = append(dumps, dump{name, info.ModTime()})
		}
	}
	sort.Slice(dumps, func(i, j int) bool { return dumps[i].at.After(dumps[j].at) })
	for index := nativeBackupRetention; index < len(dumps); index++ {
		_ = os.Remove(filepath.Join(executor.backupDir, dumps[index].name))
	}
}

func (executor *nativeExecutor) databaseURL(ctx context.Context) (string, error) {
	if executor.controlDSN != nil {
		return executor.controlDSN(ctx)
	}
	return executor.unitDatabaseURL(ctx)
}

// unitDatabaseURL reads DATABASE_URL exactly as systemd hands it to the
// control unit: its EnvironmentFiles in order, last assignment wins. No
// second copy of the credential is provisioned for the runner.
func (executor *nativeExecutor) unitDatabaseURL(ctx context.Context) (string, error) {
	missing := errors.New("control unit has no readable DATABASE_URL")
	output, err := executor.commands.Run(ctx, "systemctl", "show", "--no-pager", "--property=Environment,EnvironmentFiles", executor.config.ControlUnit)
	if err != nil {
		return "", missing
	}
	value := ""
	for _, line := range strings.Split(string(output), "\n") {
		key, rest, _ := strings.Cut(line, "=")
		switch key {
		case "Environment":
			for _, assignment := range strings.Fields(rest) {
				if name, found := strings.CutPrefix(assignment, "DATABASE_URL="); found {
					if strings.ContainsAny(name, `"'\`) {
						return "", missing
					}
					value = name
				}
			}
		}
	}
	// EnvironmentFile= assignments override Environment= ones in systemd.
	for _, line := range strings.Split(string(output), "\n") {
		rest, found := strings.CutPrefix(line, "EnvironmentFiles=")
		if !found || rest == "" {
			continue
		}
		filename, options, _ := strings.Cut(rest, " ")
		fileValue, present, err := readNativeEnvironmentValue(filename, executor.owner, "DATABASE_URL")
		if err != nil {
			if os.IsNotExist(err) && strings.Contains(options, "ignore_errors=yes") {
				continue
			}
			return "", missing
		}
		if present {
			value = fileValue
		}
	}
	if value == "" {
		return "", missing
	}
	if _, err := parseNativeDSN(value); err != nil {
		return "", err
	}
	return value, nil
}

func readNativeEnvironmentValue(filename string, owner uint32, name string) (string, bool, error) {
	if !filepath.IsAbs(filename) || filepath.Clean(filename) != filename {
		return "", false, ErrInvalidConfig
	}
	if _, err := os.Lstat(filename); err != nil {
		return "", false, err
	}
	encoded, err := nativeReadRegular(filename, owner, 1<<20)
	if err != nil {
		return "", false, err
	}
	value, present := "", false
	for _, line := range strings.Split(string(encoded), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		key, raw, found := strings.Cut(strings.TrimPrefix(line, "export "), "=")
		if !found || strings.TrimSpace(key) != name {
			continue
		}
		raw = strings.TrimSpace(raw)
		if len(raw) >= 2 && (raw[0] == '"' || raw[0] == '\'') && raw[len(raw)-1] == raw[0] {
			raw = raw[1 : len(raw)-1]
		}
		if strings.ContainsAny(raw, "\"'\\ \t") {
			return "", false, ErrInvalidConfig
		}
		value, present = raw, true
	}
	return value, present, nil
}
