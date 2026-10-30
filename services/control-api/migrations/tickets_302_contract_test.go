package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// 工单. Every number the merge renumbering touches is here: the
// version, the previous head it guards on, and the script checksums.
const (
	ticketsVersion         = 302
	ticketsID              = "302_tickets"
	ticketsPreviousID      = "301_line_group_publication_sync_hold"
	ticketsPreviousUpSHA   = "18f6165f855411e1de1799454ec7e8c22245cdf292ddcc40b13d921ff11092f8"
	ticketsPreviousDownSHA = "17463b2c338ce34c72c1e096c0ef5ac92eda769d7d4020ca343f1d76f8443248"
	ticketsUpSHA           = "dacca1529d3d10f48f75125ec29d82ae33e99a72ab9fc28927d8123de988d2ef"
	ticketsDownSHA         = "91b6b40573cd5c636810e94d61b0673dffd3034184fda3a8a2fe6d11e35c2e4a"
)

func TestTickets302Contract(t *testing.T) {
	previous := ticketsVersion - 1
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{ticketsID + ".up.sql", ticketsUpSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", previous),
			fmt.Sprintf("(SELECT max(version) FROM schema_migrations) <> %d", previous),
			"migration_id='" + ticketsPreviousID + "'",
			"checksum_sha256='" + ticketsPreviousUpSHA + "'",
			"down_checksum_sha256='" + ticketsPreviousDownSHA + "'",
			fmt.Sprintf("ERRCODE='P%d0'", ticketsVersion),
			"('tickets.read', ", "('tickets.manage', ",
			"FOREIGN KEY (tenant_scope_id, user_id) REFERENCES memberships(scope_id, user_id)",
			"CHECK (NOT internal OR author_kind = 'staff')",
			"CHECK ((status = 'resolved') = (resolved_at IS NOT NULL))",
			"object_key text NOT NULL UNIQUE",
			"('ticket.created', true, true, true, 1, 24, true, now())",
			"GRANT SELECT, INSERT ON ticket_messages, ticket_write_requests TO cdnca_control_app, cdnca_control_runtime",
		}},
		{ticketsID + ".down.sql", ticketsDownSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", ticketsVersion),
			"migration_id='" + ticketsID + "'",
			fmt.Sprintf("ERRCODE='P%d1'", ticketsVersion),
			"EXISTS (SELECT 1 FROM tickets)",
			"ALTER TABLE notification_templates DISABLE TRIGGER notification_templates_immutable",
			"DROP TABLE tickets",
		}},
	} {
		raw, err := FS.ReadFile(script.name)
		if err != nil {
			t.Fatal(err)
		}
		if got := fmt.Sprintf("%x", sha256.Sum256(raw)); got != script.sha {
			t.Fatalf("%s checksum drift: %s", script.name, got)
		}
		for _, required := range script.required {
			if !strings.Contains(string(raw), required) {
				t.Errorf("%s missing %q", script.name, required)
			}
		}
	}
}
