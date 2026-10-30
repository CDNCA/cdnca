package migrations_test

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"

	controlmigrations "github.com/cdnca/cdnca/services/control-api/migrations"
)

const (
	siteDomains147UpSHA256   = "353df42d5169317c797469af9341f827d16f51ba7312b2f4185326bc4934cab0"
	siteDomains147DownSHA256 = "e536c664a82d23e7b61d89380c69f22476770e5eaa0a5c3bd69de6bad3c02ede"
)

func TestSITE02SiteDomains148Contract(t *testing.T) {
	upBytes, err := controlmigrations.FS.ReadFile("148_site_domains.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	downBytes, err := controlmigrations.FS.ReadFile("148_site_domains.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	up, down := string(upBytes), string(downBytes)

	for _, required := range []string{
		"migration 148 requires the exact verified 147 release head",
		"version = 147 AND migration_id = '147_site_capture_policy'",
		siteDomains147UpSHA256,
		siteDomains147DownSHA256,
		"CREATE TABLE site_domain_facts",
		"global_sequence bigint",
		"pg_advisory_xact_lock",
		"site domain wildcard overlap",
		"CREATE TABLE site_domain_export_snapshots",
		"CREATE TABLE site_domain_export_rows",
		"actor_user_id",
		"actor_scope_id",
		"target_scope_id",
		"filter_sha256",
		"site domain facts are append-only",
		"site domain export snapshots are immutable",
		"site domain export rows are immutable",
		"REVOKE ALL ON site_domain_facts",
		"sites.export",
	} {
		if !strings.Contains(up, required) {
			t.Errorf("148 up missing %q", required)
		}
	}
	if guard, mutation := strings.Index(up, "migration 148 requires the exact verified 147 release head"), strings.Index(up, "CREATE TABLE site_domain_facts"); guard < 0 || mutation < 0 || guard > mutation {
		t.Fatal("148 predecessor guard must run before the first mutation")
	}

	upSHA := fmt.Sprintf("%x", sha256.Sum256(upBytes))
	for _, required := range []string{
		"migration 148 rollback requires the exact verified 148 head",
		"version = 148 AND migration_id = '148_site_domains'",
		upSHA,
		"migration 148 rollback would discard historical site domain facts",
		"migration 148 rollback would discard immutable export snapshots",
		"DROP TABLE site_domain_export_rows",
		"DROP TABLE site_domain_export_snapshots",
		"DROP TABLE site_domain_facts",
		"version = 147 AND migration_id = '147_site_capture_policy'",
		siteDomains147UpSHA256,
		siteDomains147DownSHA256,
	} {
		if !strings.Contains(down, required) {
			t.Errorf("148 down missing %q", required)
		}
	}
	if guard, mutation := strings.Index(down, "migration 148 rollback requires the exact verified 148 head"), strings.Index(down, "DROP TABLE"); guard < 0 || mutation < 0 || guard > mutation {
		t.Fatal("148 rollback guard must run before the first mutation")
	}
	for _, forbidden := range []string{"DELETE FROM schema_migrations", "CASCADE", "__UP_SHA256__", "__DOWN_SHA256__"} {
		if strings.Contains(up+down, forbidden) {
			t.Errorf("148 migration contains forbidden marker %q", forbidden)
		}
	}
}
