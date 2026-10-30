// Package databasetest lets integration tests exercise the round trip of an
// early migration without rolling back from the release head. Migration 268's
// down script is a deliberate one-way gate (P2682), so a test that needs to
// roll back past it must only load migrations 1..target, the same way the
// migrations package's version-isolated tests do.
package databasetest

import (
	"context"
	"fmt"
	"io/fs"
	"testing/fstest"
	_ "unsafe" // go:linkname

	// Linking the migrator package keeps the go:linkname target present even when
	// the calling test package does not import database itself.
	_ "github.com/cdnca/cdnca/services/control-api/internal/database"
	controlmigrations "github.com/cdnca/cdnca/services/control-api/migrations"
	"github.com/jackc/pgx/v5/pgxpool"
)

//go:linkname migrateFS github.com/cdnca/cdnca/services/control-api/internal/database.migrateFS
func migrateFS(context.Context, *pgxpool.Pool, string, fs.FS) error

// MigrateThrough runs one direction of the migrator against migrations
// 1..target only. "up" applies every missing migration up to target; "down"
// rolls back the current head, which must be <= target.
func MigrateThrough(ctx context.Context, pool *pgxpool.Pool, direction string, target int64) error {
	source, err := MigrationsThrough(target)
	if err != nil {
		return err
	}
	return migrateFS(ctx, pool, direction, source)
}

// MigrationsThrough returns the embedded up/down pairs for versions 1..target.
func MigrationsThrough(target int64) (fs.FS, error) {
	if target <= 0 {
		return nil, fmt.Errorf("migration target must be positive: %d", target)
	}
	files := make(fstest.MapFS, int(target)*2)
	for version := int64(1); version <= target; version++ {
		for _, direction := range []string{"up", "down"} {
			matches, err := fs.Glob(controlmigrations.FS, fmt.Sprintf("%03d_*.%s.sql", version, direction))
			if err != nil || len(matches) != 1 {
				return nil, fmt.Errorf("resolve migration %03d %s: matches=%v err=%v", version, direction, matches, err)
			}
			content, err := fs.ReadFile(controlmigrations.FS, matches[0])
			if err != nil {
				return nil, fmt.Errorf("read migration %q: %w", matches[0], err)
			}
			files[matches[0]] = &fstest.MapFile{Data: content}
		}
	}
	return files, nil
}
