package migrations

import (
	"strings"
	"testing"
)

func TestOrderDisplayIDs212Contract(t *testing.T) {
	upBytes, err := FS.ReadFile("212_order_display_ids.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	downBytes, err := FS.ReadFile("212_order_display_ids.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	up, down := string(upBytes), string(downBytes)
	for _, required := range []string{
		"version=211 AND migration_id='211_node_display_ids'",
		"checksum_sha256='11a619efabf41fadb21c6684087dfbe91059397c3b317d2a68a9739bd71216c9'",
		"down_checksum_sha256='87dfe8d5e9bdfece27ac09b79512278722b768bfc09c0b264b536592574590a5'",
		"account_order_display_id_sequences", "package_order_display_id_sequences",
		"recharge_order_display_id_sequences", "ALTER TABLE account_order_records ADD COLUMN display_id bigint",
		"ALTER TABLE package_orders ADD COLUMN display_id bigint",
		"ALTER TABLE recharge_orders_v1 ADD COLUMN display_id bigint",
		"PARTITION BY tenant_scope_id ORDER BY created_at,id",
		"account_order_records_scope_display_id_unique UNIQUE(tenant_scope_id,display_id)",
		"package_orders_scope_display_id_unique UNIQUE(tenant_scope_id,display_id)",
		"recharge_orders_scope_display_id_unique UNIQUE(tenant_scope_id,display_id)",
		"allocate_account_order_display_id_212", "allocate_package_order_display_id_212",
		"allocate_recharge_order_display_id_212", "OLD.display_id<>NEW.display_id",
	} {
		if !strings.Contains(up, required) {
			t.Errorf("up migration missing %q", required)
		}
	}
	for _, required := range []string{
		"version=212 AND migration_id='212_order_display_ids'",
		"DROP COLUMN display_id", "DROP TABLE account_order_display_id_sequences",
		"DROP TABLE package_order_display_id_sequences", "DROP TABLE recharge_order_display_id_sequences",
	} {
		if !strings.Contains(down, required) {
			t.Errorf("down migration missing %q", required)
		}
	}
	combined := strings.ToUpper(up + down)
	for _, forbidden := range []string{" CASCADE", "TRUNCATE", "DROP SCHEMA", "DELETE FROM SCHEMA_MIGRATIONS", "__UP_SHA256__", "__DOWN_SHA256__"} {
		if strings.Contains(combined, forbidden) {
			t.Errorf("migration contains forbidden token %q", forbidden)
		}
	}
}
