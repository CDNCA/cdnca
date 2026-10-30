//go:build integration

package migrations_test

import "testing"

// TestSiteProtocolBatchDrop521Migration rolls 521 up, down and up: the eight
// 136 tables and their functions disappear and come back empty, and the
// site_protocols permissions (with their system role grants) go with up and
// come back with down (merge-p9). 待出包前全量跑.
func TestSiteProtocolBatchDrop521Migration(t *testing.T) {
	const version = 521
	pool := migrationPoolAt(t, version-1)
	state := func() (tables, functions, permissions int) {
		t.Helper()
		if err := pool.QueryRow(t.Context(), `SELECT
			(SELECT count(*) FROM unnest(ARRAY['site_protocol_batches','site_protocol_states','site_protocol_batch_items',
				'site_protocol_jobs','site_protocol_node_results','site_protocol_write_requests','site_protocol_outbox',
				'site_protocol_audit_events']) name WHERE to_regclass(name) IS NOT NULL),
			(SELECT count(*) FROM pg_proc WHERE proname IN ('validate_site_protocol_scope_136','guard_site_protocol_batch_136',
				'guard_site_protocol_state_136','guard_site_protocol_item_136','guard_site_protocol_node_result_136',
				'guard_site_protocol_outbox_136','guard_site_protocol_receipt_136','guard_site_protocol_append_only_136')),
			(SELECT count(*) FROM permissions WHERE name IN ('site_protocols.read','site_protocols.manage')) +
			(SELECT count(*) FROM custom_rbac_permission_catalog WHERE permission_name IN ('site_protocols.read','site_protocols.manage')) +
			(SELECT count(*) FROM pg_proc WHERE proname='grant_site_protocol_permissions_136')`).Scan(
			&tables, &functions, &permissions); err != nil {
			t.Fatal(err)
		}
		return tables, functions, permissions
	}
	for _, step := range []string{"up", "down", "up"} {
		if err := migrateVersionIsolated(t.Context(), pool, step, version); err != nil {
			t.Fatalf("%s %d: %v", step, version, err)
		}
		tables, functions, permissions := state()
		want, wantPermissions := 0, 0
		if step == "down" {
			want, wantPermissions = 8, 5 // 2 permissions + 2 catalog rows + the grant function
		}
		if tables != want || functions != want || permissions != wantPermissions {
			t.Fatalf("after %s tables=%d functions=%d permissions=%d", step, tables, functions, permissions)
		}
	}
}
