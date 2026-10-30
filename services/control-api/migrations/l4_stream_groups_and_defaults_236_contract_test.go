package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

const (
	l4StreamGroupsAndDefaults236UpSHA      = "cd3ae7c94469bcc37595e8169ff431ef7e46580ee3369bc127ee2305f751f65f"
	l4StreamGroupsAndDefaults236DownSHA    = "2cf881d6a733b8a48bc05ed5df2c5340741981c841f1a6da8c1e4b84f8c767fb"
	l4StreamGroupsAndDefaults236ParentUp   = regionCatalogManagement235UpSHA
	l4StreamGroupsAndDefaults236ParentDown = regionCatalogManagement235DownSHA
)

func TestL4StreamGroupsAndDefaults236Contract(t *testing.T) {
	files := map[string]struct{ name, sha string }{
		"up":   {"236_l4_stream_groups_and_defaults.up.sql", l4StreamGroupsAndDefaults236UpSHA},
		"down": {"236_l4_stream_groups_and_defaults.down.sql", l4StreamGroupsAndDefaults236DownSHA},
	}
	contents := make(map[string]string, len(files))
	for label, file := range files {
		payload, err := FS.ReadFile(file.name)
		if err != nil {
			t.Fatalf("read migration 236 %s: %v", label, err)
		}
		if got := fmt.Sprintf("%x", sha256.Sum256(payload)); got != file.sha {
			t.Fatalf("migration 236 %s checksum = %s, want %s", label, got, file.sha)
		}
		contents[label] = string(payload)
	}

	up := contents["up"]
	for _, required := range []string{
		"(SELECT count(*) FROM schema_migrations) <> 235",
		"version = 235 AND migration_id = '235_region_catalog_management'",
		l4StreamGroupsAndDefaults236ParentUp,
		l4StreamGroupsAndDefaults236ParentDown,
		"ADD COLUMN balance_way text NOT NULL DEFAULT 'rr'",
		"l4_forwards_balance_way_236_check CHECK (balance_way IN ('rr', 'ip_hash'))",
		"CREATE TABLE l4_stream_groups",
		"CREATE TABLE l4_stream_group_members",
		"CREATE TABLE l4_stream_user_defaults",
		"CREATE TABLE l4_stream_group_default_write_requests",
		"CREATE TABLE l4_stream_group_display_id_sequences",
		"setting_name IN ('proxy_protocol', 'listen_protocol', 'balance_way')",
		"scope_name IN ('global', 'group')",
		"l4_stream_user_defaults_global_236_idx",
		"l4_stream_user_defaults_group_236_idx",
		"CREATE FUNCTION allocate_l4_stream_group_display_id_236()",
		"CREATE FUNCTION protect_l4_stream_group_236()",
		"CREATE FUNCTION protect_l4_stream_group_write_request_236()",
		"UNIQUE (actor_user_id, operation, idempotency_key)",
		"BEFORE TRUNCATE ON l4_stream_groups",
		"GRANT SELECT, INSERT, UPDATE, DELETE ON l4_stream_groups TO cdnca_control_app",
	} {
		if !strings.Contains(up, required) {
			t.Errorf("migration 236 up is missing %q", required)
		}
	}

	down := contents["down"]
	for _, required := range []string{
		"(SELECT count(*) FROM schema_migrations) <> 236",
		"version = 236 AND migration_id = '236_l4_stream_groups_and_defaults'",
		l4StreamGroupsAndDefaults236UpSHA,
		"rollback requires the exact verified 236 release head",
		"rollback cannot discard stream groups, defaults, or idempotency receipts",
		"USING ERRCODE = 'P2363'",
		"DROP TABLE l4_stream_group_default_write_requests",
		"DROP TABLE l4_stream_user_defaults",
		"DROP TABLE l4_stream_group_members",
		"DROP TABLE l4_stream_groups",
		"DROP FUNCTION protect_l4_stream_group_236()",
		"DROP COLUMN balance_way",
	} {
		if !strings.Contains(down, required) {
			t.Errorf("migration 236 down is missing %q", required)
		}
	}

	combined := strings.ToUpper(up + down)
	for _, forbidden := range []string{" CASCADE", "DELETE FROM SCHEMA_MIGRATIONS", "DROP SCHEMA", "__UP_SHA256__", "__DOWN_SHA256__"} {
		if strings.Contains(combined, forbidden) {
			t.Errorf("migration 236 contains forbidden token %q", forbidden)
		}
	}
	if guard, mutation := strings.Index(down, "migration 236 rollback requires the exact verified 236 release head"),
		strings.Index(down, "REVOKE SELECT, INSERT, UPDATE ON l4_stream_group_display_id_sequences"); guard < 0 || mutation < 0 || guard > mutation {
		t.Fatal("migration 236 rollback guards must run before the first rollback mutation")
	}
}
