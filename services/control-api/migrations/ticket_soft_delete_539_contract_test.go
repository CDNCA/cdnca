package migrations

import (
	"strings"
	"testing"
)

// Migration 539 (fix-ticketops): staff soft-delete tickets; messages and
// bound attachments stay (314). The 538 predecessor is pinned at merge.
func TestTicketSoftDelete539Contract(t *testing.T) {
	for _, script := range []struct {
		name     string
		required []string
	}{
		{"539_ticket_soft_delete.up.sql", []string{
			"(SELECT count(*) FROM schema_migrations) <> 538", "(SELECT max(version) FROM schema_migrations) <> 538",
			"ERRCODE='P5390'", "ERRCODE='P5393'",
			"ALTER TABLE tickets ADD COLUMN deleted_at timestamptz",
			"ALTER TABLE tickets ADD COLUMN deleted_by_user_id uuid REFERENCES users(id)",
			"CHECK ((deleted_at IS NULL) = (deleted_by_user_id IS NULL))",
			"CREATE TRIGGER tickets_deleted_guard_539",
		}},
		{"539_ticket_soft_delete.down.sql", []string{
			"(SELECT count(*) FROM schema_migrations) <> 539", "migration_id='539_ticket_soft_delete'",
			"ERRCODE='P5391'", "ERRCODE='P5392'",
			"DROP FUNCTION tickets_deleted_guard_539();",
			"ALTER TABLE tickets DROP COLUMN deleted_at;",
		}},
	} {
		raw, err := FS.ReadFile(script.name)
		if err != nil {
			t.Fatal(err)
		}
		for _, required := range script.required {
			if !strings.Contains(string(raw), required) {
				t.Errorf("%s missing %q", script.name, required)
			}
		}
	}
	// 软删除：539 不得授予 DELETE，也不得动 314 的附件删除守卫。
	raw, _ := FS.ReadFile("539_ticket_soft_delete.up.sql")
	if strings.Contains(string(raw), "GRANT DELETE") || strings.Contains(string(raw), "ticket_attachments_delete_guard_314") {
		t.Fatal("539 must stay a soft delete and keep bound attachments")
	}
}
