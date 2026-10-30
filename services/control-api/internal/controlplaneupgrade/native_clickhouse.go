//go:build !windows

package controlplaneupgrade

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
)

// A native release carries its ClickHouse migrations and the helper that
// applies them. The helper keeps a schema_migrations ledger (version, name,
// SHA-256) in the analytics database and applies only what is missing, so the
// same call serves first install, upgrade and retry.
const (
	nativeClickHouseScript     = "clickhouse/configure-clickhouse.py"
	nativeClickHouseMigrations = "clickhouse/migrations/"
)

var nativeClickHouseMigration = regexp.MustCompile(`^clickhouse/migrations/(([0-9]{3})_[a-z0-9]+(?:_[a-z0-9]+)*)\.up\.sql$`)

// nativeClickHouseInventory returns the release's CH migrations in version
// order, or false when they are not exactly 001..N with the helper present.
func nativeClickHouseInventory(manifest NativeManifest) ([]NativeFile, bool) {
	script, migrations := false, []NativeFile(nil)
	for _, file := range manifest.Files {
		switch {
		case file.Path == nativeClickHouseScript:
			script = file.Mode == 0o644 && file.Bytes > 0
		case strings.HasPrefix(file.Path, "clickhouse/"):
			match := nativeClickHouseMigration.FindStringSubmatch(file.Path)
			if match == nil || len(match[1]) > 96 || file.Mode != 0o644 || file.Bytes < 1 || match[2] != fmt.Sprintf("%03d", len(migrations)+1) {
				return nil, false
			}
			migrations = append(migrations, file)
		}
	}
	return migrations, script || len(migrations) == 0
}

// nativeAppendedClickHouseMigrations accepts only append-only CH migration
// changes: every current migration stays byte-identical at its version and the
// candidate adds contiguous versions after it. A release that carried the
// helper must keep carrying it. It returns the appended identifiers.
func nativeAppendedClickHouseMigrations(current, candidate NativeManifest) ([]string, bool) {
	old, oldOK := nativeClickHouseInventory(current)
	next, nextOK := nativeClickHouseInventory(candidate)
	if !oldOK || !nextOK || len(next) < len(old) ||
		(nativeFile(current, nativeClickHouseScript) != NativeFile{} && nativeFile(candidate, nativeClickHouseScript) == NativeFile{}) {
		return nil, false
	}
	for index, file := range old {
		if next[index] != file {
			return nil, false
		}
	}
	var added []string
	for _, file := range next[len(old):] {
		added = append(added, nativeClickHouseMigration.FindStringSubmatch(file.Path)[1])
	}
	return added, true
}

type nativeClickHouseResult struct {
	Status  string   `json:"status"`
	Reason  string   `json:"reason"`
	Pending []string `json:"pending"`
	Applied []string `json:"applied"`
}

// Ledger states that no retry of this candidate can fix.
var nativeClickHouseTerminal = map[string]bool{"checksum_mismatch": true, "ledger_ahead": true}

var nativeClickHouseReasons = map[string]bool{"checksum_mismatch": true, "ledger_ahead": true, "ledger_gap": true,
	"ledger_missing": true, "unledgered_schema": true, "clickhouse_error": true, "invalid_input": true}

// clickhouseMigrate runs the candidate's own helper against its own migration
// directory: with check, a read-only ledger verification (Preflight); without,
// applying what is missing (Activate, before control-api restarts).
func (executor *nativeExecutor) clickhouseMigrate(ctx context.Context, plan Plan, candidate NativeManifest, check bool) error {
	if nativeFile(candidate, nativeClickHouseScript) == (NativeFile{}) {
		return nil
	}
	release := executor.release(plan.Target)
	arguments := []string{"-I", "-B", filepath.Join(release, nativeClickHouseScript), "migrate",
		"--migrations", filepath.Join(release, nativeClickHouseMigrations)}
	event, failed, code, status := "clickhouse_migrated", "clickhouse_migration_failed", "clickhouse_migration_failed", "migrations_applied"
	var cancel context.CancelFunc
	if check {
		arguments = append(arguments, "--check")
		event, failed, code, status = "clickhouse_migrations_checked", "clickhouse_check_failed", "clickhouse_preflight_failed", "migrations_checked"
		ctx, cancel = context.WithTimeout(ctx, executor.config.StepTimeout)
	} else {
		// Like a PostgreSQL migration, a half-applied one is never abandoned on stop.
		ctx, cancel = executor.databaseContext(ctx)
	}
	defer cancel()
	output, err := executor.commands.Run(ctx, "python3", arguments...)
	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	var result nativeClickHouseResult
	decodeErr := json.Unmarshal([]byte(lines[len(lines)-1]), &result)
	if err != nil || decodeErr != nil || result.Status != status {
		reason := "unexpected"
		switch {
		case errors.Is(ctx.Err(), context.DeadlineExceeded):
			reason = "timeout"
		case nativeClickHouseReasons[result.Reason]:
			reason = result.Reason
		}
		logRun(ctx, RunLogEntry{Level: "error", Event: failed, Reason: reason, Version: plan.Target.Version})
		failure := fmt.Errorf("%w: ClickHouse migration %s", ErrTargetMismatch, reason)
		if nativeClickHouseTerminal[reason] {
			failure = fmt.Errorf("%w: %w", ErrCandidateRejected, failure)
		}
		return withStepCode(code, failure)
	}
	names := result.Applied
	if check {
		names = result.Pending
	}
	var migrations []string
	for _, name := range names {
		identifier := strings.TrimSuffix(name, ".up.sql")
		if migrationIdentifier.MatchString(identifier) && len(identifier) <= 96 && len(migrations) < maxMigrationsPerPlan {
			migrations = append(migrations, identifier)
		}
	}
	logRun(ctx, RunLogEntry{Level: "info", Event: event, Count: len(names), Migrations: migrations, Version: plan.Target.Version})
	return nil
}
