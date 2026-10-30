package migrations

import (
	"strings"
	"testing"
)

func TestErrorPageSlots218Contract(t *testing.T) {
	up, err := FS.ReadFile("218_error_page_slots.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	down, err := FS.ReadFile("218_error_page_slots.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{
		"CREATE TABLE error_page_slots",
		"CREATE TABLE error_page_slot_revisions",
		"'blacklist', 'http_400', 'http_403', 'waf_block', 'http_502', 'http_504'",
		"'traffic_exceeded', 'package_expired', 'site_locked', 'domain_unconfigured'",
		"'node_ip_access', 'connection_limit'",
		"error_page.slot.bind", "error_page.slot.unbind",
		"error_pages.manage", "asset_status <> 'ready'", "asset_object_state <> 'final'",
		"error_page_assets_bound_slot_guard_218", "cdnca_control_app",
	} {
		if !strings.Contains(string(up), required) {
			t.Errorf("up migration missing %q", required)
		}
	}
	for _, required := range []string{
		"DROP TRIGGER error_page_assets_bound_slot_guard_218",
		"DROP TABLE error_page_slot_revisions",
		"DROP TABLE error_page_slots",
		"DROP CONSTRAINT error_page_write_requests_operation_check",
	} {
		if !strings.Contains(string(down), required) {
			t.Errorf("down migration missing %q", required)
		}
	}
}
