//go:build integration

package migrations_test

import (
	"context"
	"fmt"
	"io/fs"
	"testing/fstest"
	_ "unsafe"

	controlmigrations "github.com/cdnca/cdnca/services/control-api/migrations"
	"github.com/jackc/pgx/v5/pgxpool"
)

//go:linkname migrateVersionIsolatedFS github.com/cdnca/cdnca/services/control-api/internal/database.migrateFS
func migrateVersionIsolatedFS(context.Context, *pgxpool.Pool, string, fs.FS) error

func migrateVersionIsolated(
	ctx context.Context,
	pool *pgxpool.Pool,
	direction string,
	target int64,
) error {
	source, err := versionIsolatedMigrationFS(target)
	if err != nil {
		return err
	}
	return migrateVersionIsolatedFS(ctx, pool, direction, source)
}

func versionIsolatedMigrationFS(target int64) (fs.FS, error) {
	if target <= 0 {
		return nil, fmt.Errorf("migration target must be positive: %d", target)
	}
	files := make(fstest.MapFS, int(target)*2)
	for version := int64(1); version <= target; version++ {
		for _, direction := range []string{"up", "down"} {
			pattern := fmt.Sprintf("%03d_*.%s.sql", version, direction)
			matches, err := fs.Glob(controlmigrations.FS, pattern)
			if err != nil || len(matches) != 1 {
				return nil, fmt.Errorf("resolve migration %03d %s: matches=%v err=%v",
					version, direction, matches, err)
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
