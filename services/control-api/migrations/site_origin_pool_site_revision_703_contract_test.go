package migrations

import (
	"strings"
	"testing"
)

// Migration 703: on the verified 702 head, the origin
// pool gets its own version, the site revision its last change wrote (nullable, not backfilled: a backfill would
// advance every scope's edge configuration revision through the pool triggers). Down drops the column.
func TestSiteOriginPoolSiteRevision703Contract(t *testing.T) {
	read := func(name string) string {
		body, err := FS.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		return string(body)
	}
	up := read("703_site_origin_pool_site_revision.up.sql")
	down := read("703_site_origin_pool_site_revision.down.sql")
	for _, fragment := range []string{
		"LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE",
		"(SELECT count(*) FROM schema_migrations) <> 702", "(SELECT max(version) FROM schema_migrations) <> 702",
		"WHERE version=702 AND", "migration_id='702_edge_publication_serving_nodes'", "ERRCODE='P7030'",
		"ALTER TABLE site_origin_pools ADD COLUMN site_revision bigint",
		"CHECK (site_revision IS NULL OR site_revision >= 1)",
	} {
		if !strings.Contains(up, fragment) {
			t.Errorf("703 up missing %q", fragment)
		}
	}
	if strings.Contains(up, "UPDATE site_origin_pools") {
		t.Error("703 up must not backfill site_origin_pools (its triggers advance edge configuration revisions)")
	}
	for _, fragment := range []string{
		"(SELECT count(*) FROM schema_migrations) <> 703",
		"migration_id='703_site_origin_pool_site_revision'", "ERRCODE='P7030'",
		"ALTER TABLE site_origin_pools DROP COLUMN site_revision;",
	} {
		if !strings.Contains(down, fragment) {
			t.Errorf("703 down missing %q", fragment)
		}
	}
}
