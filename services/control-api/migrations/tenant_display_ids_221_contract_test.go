package migrations

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

const (
	migration220UpSHA221   = "340dc49da585b3f9e2f85da9ffeb42ba7a5e184a48c8b157a88ad27fd26cf713"
	migration220DownSHA221 = "4567747996feb94eb56bf01f31ac1875b141485c381b6c2e6fe90b7c08d78493"
	migration221UpSHA      = "f15a1d7c1f22e2dd5e42032d386399791c000d3b7fed63bfcc2359e111d7b51a"
	migration221DownSHA    = "40c91bbd390cf9d19ccba4dc3c948ea83ca4cc7a2551b67ebf49e7cf76966fc3"
)

func TestTenantDisplayIDs221Contract(t *testing.T) {
	predecessorUp := readTenantDisplayIDMigration(t, "220_error_page_scope_overrides.up.sql")
	predecessorDown := readTenantDisplayIDMigration(t, "220_error_page_scope_overrides.down.sql")
	up := readTenantDisplayIDMigration(t, "221_tenant_display_ids.up.sql")
	down := readTenantDisplayIDMigration(t, "221_tenant_display_ids.down.sql")

	if got := migrationSHA221(predecessorUp); got != migration220UpSHA221 {
		t.Fatalf("migration 220 up checksum = %s, want frozen %s", got, migration220UpSHA221)
	}
	if got := migrationSHA221(predecessorDown); got != migration220DownSHA221 {
		t.Fatalf("migration 220 down checksum = %s, want frozen %s", got, migration220DownSHA221)
	}
	if got := migrationSHA221(up); got != migration221UpSHA {
		t.Fatalf("migration 221 up checksum = %s, want down-fenced %s", got, migration221UpSHA)
	}
	if got := migrationSHA221(down); got != migration221DownSHA {
		t.Fatalf("migration 221 down checksum = %s, want frozen %s", got, migration221DownSHA)
	}

	for _, required := range []string{
		"LOCK TABLE schema_migrations, tenants IN ACCESS EXCLUSIVE MODE",
		"(SELECT count(*) FROM schema_migrations) <> 220",
		"(SELECT min(version) FROM schema_migrations) <> 1",
		"(SELECT max(version) FROM schema_migrations) <> 220",
		"integrity_state IS DISTINCT FROM 'verified'",
		"version = 220 AND migration_id = '220_error_page_scope_overrides'",
		"checksum_sha256 = '" + migration220UpSHA221 + "'",
		"down_checksum_sha256 = '" + migration220DownSHA221 + "'",
		"CREATE SEQUENCE tenants_display_id_seq AS bigint MINVALUE 1 NO MAXVALUE NO CYCLE",
		"ADD COLUMN display_id bigint",
		"row_number() OVER (ORDER BY created_at, id)",
		"COALESCE((SELECT max(display_id) FROM tenants), 0) + 1",
		"false\n);",
		"ALTER COLUMN display_id SET DEFAULT nextval('tenants_display_id_seq')",
		"ALTER COLUMN display_id SET NOT NULL",
		"CHECK (display_id > 0)",
		"UNIQUE (display_id)",
		"ALTER SEQUENCE tenants_display_id_seq OWNED BY tenants.display_id",
		"BEFORE UPDATE OF display_id ON tenants",
		"tenant display ID is immutable",
		"GRANT USAGE, SELECT ON SEQUENCE tenants_display_id_seq TO cdnca_control_app",
	} {
		if !strings.Contains(string(up), required) {
			t.Errorf("up migration missing %q", required)
		}
	}
	for _, required := range []string{
		"LOCK TABLE schema_migrations, tenants IN ACCESS EXCLUSIVE MODE",
		"(SELECT count(*) FROM schema_migrations) <> 221",
		"(SELECT min(version) FROM schema_migrations) <> 1",
		"(SELECT max(version) FROM schema_migrations) <> 221",
		"integrity_state IS DISTINCT FROM 'verified'",
		"version = 221 AND migration_id = '221_tenant_display_ids'",
		"checksum_sha256 = '" + migration221UpSHA + "'",
		"version = 220 AND migration_id = '220_error_page_scope_overrides'",
		"checksum_sha256 = '" + migration220UpSHA221 + "'",
		"down_checksum_sha256 = '" + migration220DownSHA221 + "'",
		"REVOKE USAGE, SELECT ON SEQUENCE tenants_display_id_seq FROM cdnca_control_app",
		"DROP TRIGGER tenants_display_id_immutable_221 ON tenants",
		"DROP FUNCTION protect_tenant_display_id_221()",
		"ALTER SEQUENCE tenants_display_id_seq OWNED BY NONE",
		"DROP CONSTRAINT tenants_display_id_unique",
		"DROP CONSTRAINT tenants_display_id_positive",
		"DROP COLUMN display_id",
		"DROP SEQUENCE tenants_display_id_seq",
	} {
		if !strings.Contains(string(down), required) {
			t.Errorf("down migration missing %q", required)
		}
	}

	if guard, mutation := strings.Index(string(up), "migration 221 requires the exact verified 220 release head"),
		strings.Index(string(up), "CREATE SEQUENCE tenants_display_id_seq"); guard < 0 || mutation < 0 || guard > mutation {
		t.Fatal("migration 221 predecessor guard must precede the first schema mutation")
	}
	if guard, mutation := strings.Index(string(down), "migration 221 rollback requires the exact verified 221 release head"),
		strings.Index(string(down), "REVOKE USAGE, SELECT ON SEQUENCE tenants_display_id_seq"); guard < 0 || mutation < 0 || guard > mutation {
		t.Fatal("migration 221 rollback guard must precede the first rollback mutation")
	}

	combined := strings.ToUpper(string(up) + string(down))
	for _, forbidden := range []string{" CASCADE", "TRUNCATE", "DROP SCHEMA", "DELETE FROM SCHEMA_MIGRATIONS", "__UP_SHA256__", "__DOWN_SHA256__"} {
		if strings.Contains(combined, forbidden) {
			t.Errorf("migration contains forbidden token %q", forbidden)
		}
	}
}

func readTenantDisplayIDMigration(t *testing.T, name string) []byte {
	t.Helper()
	payload, err := FS.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	return payload
}

func migrationSHA221(payload []byte) string {
	digest := sha256.Sum256(payload)
	return hex.EncodeToString(digest[:])
}
