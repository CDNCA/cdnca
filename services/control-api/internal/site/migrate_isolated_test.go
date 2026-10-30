package site

import (
	"context"
	"fmt"
	"io/fs"
	"testing/fstest"
	_ "unsafe"

	controlmigrations "github.com/cdnca/cdnca/services/control-api/migrations"
	"github.com/jackc/pgx/v5/pgxpool"
)

//go:linkname migrateIsolatedFS github.com/cdnca/cdnca/services/control-api/internal/database.migrateFS
func migrateIsolatedFS(context.Context, *pgxpool.Pool, string, fs.FS) error

// migrateDownTo rolls the newest migrations back down to (and including)
// target, one at a time, so a test can reach an older migration's down guard
// after later migrations were added.
func migrateDownTo(ctx context.Context, pool *pgxpool.Pool, target int64) error {
	var head int64
	if err := pool.QueryRow(ctx, `SELECT max(version) FROM schema_migrations`).Scan(&head); err != nil {
		return err
	}
	for version := head; version >= target; version-- {
		files := fstest.MapFS{}
		for v := int64(1); v <= version; v++ {
			for _, direction := range []string{"up", "down"} {
				matches, err := fs.Glob(controlmigrations.FS, fmt.Sprintf("%03d_*.%s.sql", v, direction))
				if err != nil || len(matches) != 1 {
					return fmt.Errorf("migration %d %s: %v %v", v, direction, matches, err)
				}
				raw, err := fs.ReadFile(controlmigrations.FS, matches[0])
				if err != nil {
					return err
				}
				files[matches[0]] = &fstest.MapFile{Data: raw}
			}
		}
		if err := migrateIsolatedFS(ctx, pool, "down", files); err != nil {
			return err
		}
	}
	return nil
}
