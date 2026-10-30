package database

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"io/fs"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/cdnca/cdnca/services/control-api/migrations"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	migrationLockID        int64 = 726491175848209
	migrationUnlockTimeout       = 5 * time.Second
)

var migrationFilenamePattern = regexp.MustCompile(`^([0-9]{3})_([a-z0-9]+(?:_[a-z0-9]+)*)\.(up|down)\.sql$`)

type migration struct {
	version    int64
	identifier string
	upName     string
	downName   string
	upSQL      []byte
	downSQL    []byte
	upSHA256   string
	downSHA256 string
}

func Migrate(ctx context.Context, pool *pgxpool.Pool, direction string) error {
	return migrateFS(ctx, pool, direction, migrations.FS)
}

func migrateFS(ctx context.Context, pool *pgxpool.Pool, direction string, source fs.FS) (resultErr error) {
	if direction != "up" && direction != "down" {
		return fmt.Errorf("migration direction must be up or down")
	}
	all, err := loadMigrationsFrom(source)
	if err != nil {
		return err
	}

	conn, err := pool.Acquire(ctx)
	if err != nil {
		return fmt.Errorf("acquire migration connection: %w", err)
	}
	releaseConnection := true
	defer func() {
		if releaseConnection {
			conn.Release()
		}
	}()

	if _, err := conn.Exec(ctx, "SELECT pg_advisory_lock($1)", migrationLockID); err != nil {
		releaseConnection = false
		closeErr := destroyMigrationConnection(conn)
		return fmt.Errorf("lock migrations: %w; connection destroyed because lock ownership is uncertain: %v", err, closeErr)
	}
	defer func() {
		unlockCtx, cancel := context.WithTimeout(context.Background(), migrationUnlockTimeout)
		defer cancel()
		var unlocked bool
		unlockErr := conn.QueryRow(unlockCtx, "SELECT pg_advisory_unlock($1)", migrationLockID).Scan(&unlocked)
		if unlockErr == nil && unlocked {
			return
		}

		releaseConnection = false
		closeErr := destroyMigrationConnection(conn)
		if resultErr == nil {
			resultErr = fmt.Errorf(
				"unlock migrations could not be confirmed (unlocked=%t, unlock_error=%v); connection destroyed: %v",
				unlocked, unlockErr, closeErr,
			)
		}
	}()

	if err := ensureMigrationLedger(ctx, conn); err != nil {
		return err
	}
	if err := validateAppliedMigrations(ctx, conn, all); err != nil {
		return err
	}

	switch direction {
	case "up":
		return migrateUp(ctx, conn, all)
	case "down":
		return migrateDown(ctx, conn, all)
	}
	return nil
}

func migrateUp(ctx context.Context, conn *pgxpool.Conn, all []migration) error {
	for _, item := range all {
		var applied bool
		if err := conn.QueryRow(ctx,
			"SELECT EXISTS (SELECT 1 FROM schema_migrations WHERE version = $1)",
			item.version,
		).Scan(&applied); err != nil {
			return fmt.Errorf("read migration %d state: %w", item.version, err)
		}
		if applied {
			continue
		}
		if err := pgx.BeginFunc(ctx, conn, func(tx pgx.Tx) error {
			if _, err := tx.Exec(ctx, string(item.upSQL)); err != nil {
				return err
			}
			_, err := tx.Exec(ctx, `
				INSERT INTO schema_migrations (
					version, migration_id, checksum_sha256, down_checksum_sha256,
					integrity_state, metadata_recorded_at
				) VALUES ($1, $2, $3, $4, 'verified', now())`,
				item.version, item.identifier, item.upSHA256, item.downSHA256)
			return err
		}); err != nil {
			return fmt.Errorf("apply migration %d: %w", item.version, err)
		}
	}
	return nil
}

func migrateDown(ctx context.Context, conn *pgxpool.Conn, all []migration) error {
	var current int64
	var integrity string
	err := conn.QueryRow(ctx, `
		SELECT version, integrity_state
		FROM schema_migrations
		ORDER BY version DESC
		LIMIT 1`).Scan(&current, &integrity)
	if err == pgx.ErrNoRows {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read current migration: %w", err)
	}
	if integrity != "verified" {
		return fmt.Errorf(
			"rollback migration %d blocked: integrity state %q does not prove the historical down script; "+
				"restore the exact archived migration artifacts and follow the manual review/recovery procedure in "+
				"docs/runbooks/control-migrations.md; no override is available",
			current, integrity,
		)
	}

	for _, item := range all {
		if item.version != current {
			continue
		}
		if err := pgx.BeginFunc(ctx, conn, func(tx pgx.Tx) error {
			if _, err := tx.Exec(ctx, string(item.downSQL)); err != nil {
				return err
			}
			_, err := tx.Exec(ctx, "DELETE FROM schema_migrations WHERE version = $1", item.version)
			return err
		}); err != nil {
			return fmt.Errorf("rollback migration %d: %w", item.version, err)
		}
		return nil
	}
	return fmt.Errorf("rollback script for migration %d is missing", current)
}

func loadMigrations() ([]migration, error) {
	return loadMigrationsFrom(migrations.FS)
}

func loadMigrationsFrom(source fs.FS) ([]migration, error) {
	entries, err := fs.ReadDir(source, ".")
	if err != nil {
		return nil, fmt.Errorf("read embedded migrations: %w", err)
	}
	byVersion := make(map[int64]*migration)
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".sql") {
			continue
		}
		matches := migrationFilenamePattern.FindStringSubmatch(entry.Name())
		if matches == nil {
			return nil, fmt.Errorf("invalid migration filename %q", entry.Name())
		}
		version, err := strconv.ParseInt(matches[1], 10, 64)
		if err != nil || version == 0 {
			return nil, fmt.Errorf("invalid migration filename %q", entry.Name())
		}
		identifier := matches[1] + "_" + matches[2]
		script, err := fs.ReadFile(source, entry.Name())
		if err != nil {
			return nil, fmt.Errorf("read migration file %q: %w", entry.Name(), err)
		}
		if command := topLevelTransactionControl(script); command != "" {
			return nil, fmt.Errorf("migration file %q contains transaction control %s", entry.Name(), command)
		}
		item := byVersion[version]
		if item == nil {
			item = &migration{version: version, identifier: identifier}
			byVersion[version] = item
		} else if item.identifier != identifier {
			return nil, fmt.Errorf(
				"duplicate migration version %d: up/down names do not match (%q and %q)",
				version, item.identifier, identifier,
			)
		}
		if matches[3] == "up" {
			if item.upName != "" {
				return nil, fmt.Errorf("duplicate migration version %d up script", version)
			}
			item.upName = entry.Name()
			item.upSQL = script
			item.upSHA256 = sha256Hex(script)
		} else {
			if item.downName != "" {
				return nil, fmt.Errorf("duplicate migration version %d down script", version)
			}
			item.downName = entry.Name()
			item.downSQL = script
			item.downSHA256 = sha256Hex(script)
		}
	}
	if len(byVersion) == 0 {
		return nil, fmt.Errorf("no migration files found")
	}
	result := make([]migration, 0, len(byVersion))
	for _, item := range byVersion {
		if item.upName == "" || item.downName == "" {
			return nil, fmt.Errorf("migration %d requires both up and down scripts", item.version)
		}
		result = append(result, *item)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].version < result[j].version })
	for i, item := range result {
		expected := int64(i + 1)
		if item.version != expected {
			return nil, fmt.Errorf("migration version gap: expected %d, found %d", expected, item.version)
		}
	}
	return result, nil
}

func ensureMigrationLedger(ctx context.Context, conn *pgxpool.Conn) error {
	if _, err := conn.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS schema_migrations (
			version bigint PRIMARY KEY,
				migration_id text,
				checksum_sha256 text,
				down_checksum_sha256 text,
				integrity_state text,
			metadata_recorded_at timestamptz,
			applied_at timestamptz NOT NULL DEFAULT now()
		);
		ALTER TABLE schema_migrations ADD COLUMN IF NOT EXISTS migration_id text;
		ALTER TABLE schema_migrations ADD COLUMN IF NOT EXISTS checksum_sha256 text;
		ALTER TABLE schema_migrations ADD COLUMN IF NOT EXISTS down_checksum_sha256 text;
		ALTER TABLE schema_migrations ADD COLUMN IF NOT EXISTS integrity_state text;
		ALTER TABLE schema_migrations ADD COLUMN IF NOT EXISTS metadata_recorded_at timestamptz`); err != nil {
		return fmt.Errorf("create or upgrade migration ledger: %w", err)
	}
	return nil
}

type appliedMigration struct {
	Version      int64
	Identifier   string
	UpChecksum   string
	DownChecksum string
	Integrity    string
	MetadataTime bool
}

type legacyMetadataUpdate struct {
	Version      int64
	Identifier   string
	UpChecksum   string
	DownChecksum string
}

func validateAppliedMigrations(ctx context.Context, conn *pgxpool.Conn, all []migration) error {
	rows, err := conn.Query(ctx, `
		SELECT version,
			COALESCE(migration_id, ''),
			COALESCE(checksum_sha256, ''),
			COALESCE(down_checksum_sha256, ''),
			COALESCE(integrity_state, ''),
			metadata_recorded_at IS NOT NULL
		FROM schema_migrations
		ORDER BY version`)
	if err != nil {
		return fmt.Errorf("read migration ledger: %w", err)
	}
	applied, err := pgx.CollectRows(rows, pgx.RowToStructByPos[appliedMigration])
	if err != nil {
		return fmt.Errorf("read migration ledger: %w", err)
	}

	byVersion := make(map[int64]migration, len(all))
	for _, item := range all {
		byVersion[item.version] = item
	}
	for i, record := range applied {
		expected := int64(i + 1)
		if record.Version != expected {
			return fmt.Errorf("applied migration gap: expected version %d, found %d; refusing low-version backfill", expected, record.Version)
		}
		if _, ok := byVersion[record.Version]; !ok {
			return fmt.Errorf("applied migration %d has no matching embedded migration", record.Version)
		}
	}

	updates := make([]legacyMetadataUpdate, 0)
	for _, record := range applied {
		item := byVersion[record.Version]
		if record.Identifier == "" && record.UpChecksum == "" && record.DownChecksum == "" && record.Integrity == "" && !record.MetadataTime {
			updates = append(updates, legacyMetadataUpdate{
				Version: item.version, Identifier: item.identifier,
				UpChecksum: item.upSHA256, DownChecksum: item.downSHA256,
			})
			continue
		}
		if record.Identifier == "" || record.UpChecksum == "" || record.Integrity == "" || !record.MetadataTime {
			return fmt.Errorf("migration %d ledger metadata is incomplete", record.Version)
		}
		if record.Identifier != item.identifier {
			return fmt.Errorf("migration %d identifier mismatch: ledger=%q embedded=%q", item.version, record.Identifier, item.identifier)
		}
		if record.UpChecksum != item.upSHA256 {
			return fmt.Errorf("migration %d up checksum mismatch: applied SQL differs from %s", item.version, item.upName)
		}
		switch record.Integrity {
		case "verified":
		case "legacy_unverified":
		default:
			return fmt.Errorf("migration %d has invalid integrity state %q", item.version, record.Integrity)
		}
		if record.DownChecksum == "" {
			updates = append(updates, legacyMetadataUpdate{
				Version: item.version, Identifier: item.identifier,
				UpChecksum: item.upSHA256, DownChecksum: item.downSHA256,
			})
			continue
		}
		if record.DownChecksum != item.downSHA256 {
			return fmt.Errorf("migration %d down checksum mismatch: rollback SQL differs from %s", item.version, item.downName)
		}
	}
	if len(updates) == 0 {
		return nil
	}
	return pgx.BeginFunc(ctx, conn, func(tx pgx.Tx) error {
		for _, update := range updates {
			tag, err := tx.Exec(ctx, `
				UPDATE schema_migrations
				SET migration_id=$2,
					checksum_sha256=$3,
					down_checksum_sha256=$4,
					integrity_state='legacy_unverified',
					metadata_recorded_at=now()
				WHERE version=$1`,
				update.Version, update.Identifier, update.UpChecksum, update.DownChecksum,
			)
			if err != nil {
				return fmt.Errorf("record legacy migration %d metadata: %w", update.Version, err)
			}
			if tag.RowsAffected() != 1 {
				return fmt.Errorf("record legacy migration %d metadata: updated %d rows, want 1", update.Version, tag.RowsAffected())
			}
		}
		return nil
	})
}

func sha256Hex(script []byte) string {
	return fmt.Sprintf("%x", sha256.Sum256(script))
}

// This scanner only inspects statement-leading tokens and skips SQL bodies,
// strings, identifiers, and comments where transaction words are data.
func topLevelTransactionControl(script []byte) string {
	atStatementStart := true
	firstToken := ""
	for i := 0; i < len(script); {
		switch {
		case script[i] == '-' && i+1 < len(script) && script[i+1] == '-':
			i += 2
			for i < len(script) && script[i] != '\n' {
				i++
			}
		case script[i] == '/' && i+1 < len(script) && script[i+1] == '*':
			i = skipBlockComment(script, i+2)
		case script[i] == '\'' || script[i] == '"':
			i = skipQuotedSQL(script, i+1, script[i])
		case script[i] == '$':
			if next, ok := skipDollarQuotedSQL(script, i); ok {
				i = next
			} else {
				i++
			}
		case script[i] == ';':
			atStatementStart = true
			firstToken = ""
			i++
		case isSQLIdentifierStart(script[i]):
			start := i
			i++
			for i < len(script) && isSQLIdentifierPart(script[i]) {
				i++
			}
			token := strings.ToUpper(string(script[start:i]))
			if atStatementStart {
				firstToken = token
				atStatementStart = false
				switch token {
				case "BEGIN", "COMMIT", "ROLLBACK":
					return token
				}
			} else if firstToken == "START" && token == "TRANSACTION" {
				return "START TRANSACTION"
			}
		default:
			i++
		}
	}
	return ""
}

func skipQuotedSQL(script []byte, i int, quote byte) int {
	for i < len(script) {
		if script[i] != quote {
			i++
			continue
		}
		if i+1 < len(script) && script[i+1] == quote {
			i += 2
			continue
		}
		return i + 1
	}
	return i
}

func skipDollarQuotedSQL(script []byte, start int) (int, bool) {
	i := start + 1
	if i < len(script) && script[i] != '$' && !isSQLIdentifierStart(script[i]) {
		return start, false
	}
	for i < len(script) && isDollarTagPart(script[i]) {
		i++
	}
	if i >= len(script) || script[i] != '$' {
		return start, false
	}
	delimiter := script[start : i+1]
	closing := bytes.Index(script[i+1:], delimiter)
	if closing < 0 {
		return len(script), true
	}
	return i + 1 + closing + len(delimiter), true
}

func skipBlockComment(script []byte, i int) int {
	depth := 1
	for i < len(script) && depth > 0 {
		switch {
		case script[i] == '/' && i+1 < len(script) && script[i+1] == '*':
			depth++
			i += 2
		case script[i] == '*' && i+1 < len(script) && script[i+1] == '/':
			depth--
			i += 2
		default:
			i++
		}
	}
	return i
}

func isSQLIdentifierStart(char byte) bool {
	return char == '_' || char >= 'A' && char <= 'Z' || char >= 'a' && char <= 'z'
}

func isSQLIdentifierPart(char byte) bool {
	return isSQLIdentifierStart(char) || char >= '0' && char <= '9' || char == '$'
}

func isDollarTagPart(char byte) bool {
	return isSQLIdentifierStart(char) || char >= '0' && char <= '9'
}

func destroyMigrationConnection(conn *pgxpool.Conn) error {
	raw := conn.Hijack()
	ctx, cancel := context.WithTimeout(context.Background(), migrationUnlockTimeout)
	defer cancel()
	return raw.Close(ctx)
}
