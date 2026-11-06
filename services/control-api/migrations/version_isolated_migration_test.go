//go:build integration

package migrations_test

import (
	"context"
	"fmt"
	"io/fs"
	"strings"
	"sync"
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

// versionIsolatedMigrationFS used to glob all embedded files once per version
// and direction, so one call cost target x files and a test stepping a
// template clone down one migration at a time spent most of its time there
// (CPU-bound, not PostgreSQL). The directory is now indexed once per process
// under the same "%03d_*.<direction>.sql" rule.
func versionIsolatedMigrationFS(target int64) (fs.FS, error) {
	if target <= 0 {
		return nil, fmt.Errorf("migration target must be positive: %d", target)
	}
	index, err := embeddedMigrationIndex()
	if err != nil {
		return nil, err
	}
	files := make(fstest.MapFS, int(target)*2)
	for version := int64(1); version <= target; version++ {
		for _, direction := range []string{"up", "down"} {
			matches := index[fmt.Sprintf("%03d.%s", version, direction)]
			if len(matches) != 1 {
				return nil, fmt.Errorf("resolve migration %03d %s: matches=%v err=%v",
					version, direction, migrationNames(matches), nil)
			}
			files[matches[0].name] = &fstest.MapFile{Data: matches[0].data}
		}
	}
	return files, nil
}

type embeddedMigration struct {
	name string
	data []byte
}

// embeddedMigrationIndex maps "<prefix before the first _>.<up|down>" to the
// embedded files with that prefix and suffix, in name order (what fs.Glob of
// "%03d_*.<direction>.sql" returned).
var embeddedMigrationIndex = sync.OnceValues(func() (map[string][]embeddedMigration, error) {
	names, err := fs.Glob(controlmigrations.FS, "*_*.sql")
	if err != nil {
		return nil, err
	}
	index := make(map[string][]embeddedMigration, len(names))
	for _, name := range names {
		prefix, _, _ := strings.Cut(name, "_")
		for _, direction := range []string{"up", "down"} {
			if !strings.HasSuffix(name, "."+direction+".sql") {
				continue
			}
			data, err := fs.ReadFile(controlmigrations.FS, name)
			if err != nil {
				return nil, fmt.Errorf("read migration %q: %w", name, err)
			}
			key := prefix + "." + direction
			index[key] = append(index[key], embeddedMigration{name: name, data: data})
		}
	}
	return index, nil
})

func migrationNames(items []embeddedMigration) []string {
	names := make([]string, len(items))
	for i, item := range items {
		names[i] = item.name
	}
	return names
}
