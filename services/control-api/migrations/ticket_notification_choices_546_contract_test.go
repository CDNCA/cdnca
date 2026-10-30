package migrations

import (
	"strings"
	"testing"
)

// Migration 546: per-member in-app choice for
// ticket notifications, the staff overdue reminder event and its dedup
// column. The 545 predecessor is pinned by checksum.
func TestTicketNotificationChoices546Contract(t *testing.T) {
	for _, script := range []struct {
		name     string
		required []string
	}{
		{"546_ticket_notification_choices.up.sql", []string{
			"(SELECT count(*) FROM schema_migrations) <> 545", "(SELECT max(version) FROM schema_migrations) <> 545",
			"migration_id='545_security_ban_networks'",
			"checksum_sha256='7bd280330a3f7f50dea9beb05aafaa64e42ff961f27a41ef5e189c7fb42bc0ba'",
			"down_checksum_sha256='1f4eb68b60c5af8ebc55ae024feae11e0e55145d845db46b895d4f914055da03'",
			"ERRCODE='P5460'",
			"ALTER TABLE notification_subscriptions ADD COLUMN inbox_enabled boolean NOT NULL DEFAULT true",
			"ALTER TABLE tickets ADD COLUMN sla_reminded_at timestamptz",
			"'ticket.staff.overdue'", "('ticket_staff_overdue', 1, 'email'", "('ticket_staff_overdue', 1, 'sms'",
		}},
		{"546_ticket_notification_choices.down.sql", []string{
			"(SELECT count(*) FROM schema_migrations) <> 546", "migration_id='546_ticket_notification_choices'",
			"ERRCODE='P5461'", "ERRCODE='P5462'", "DROP COLUMN inbox_enabled", "DROP COLUMN sla_reminded_at",
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
}
