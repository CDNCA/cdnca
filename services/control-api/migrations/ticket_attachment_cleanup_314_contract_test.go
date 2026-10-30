package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// 未提交附件清理. Every number the merge renumbering touches is
// here: the version, the previous head it guards on, and the script checksums.
const (
	ticketCleanupVersion         = 314
	ticketCleanupID              = "314_ticket_attachment_cleanup"
	ticketCleanupPreviousID      = "313_waf_rule_subscriptions"
	ticketCleanupPreviousUpSHA   = "8e1b9f23e46e67bcaab4ea91655cde81a18c3f0395ea1906b1d9e19f76cce4b3"
	ticketCleanupPreviousDownSHA = "07bde19bbb5ad2a98f80df7ae103f24129cfbbff02ac539117e1e7e15f84fcb6"
	ticketCleanupUpSHA           = "e5b4dc29d293a7fbbf64a089f26f443f49e3d703021e32fdc64a48a7aadd7ffa"
	ticketCleanupDownSHA         = "62230c4fca3eabef097e6b338508fef63bed34642af0a69109345733b81d1c3d"
)

func TestTicketAttachmentCleanup314Contract(t *testing.T) {
	previous := ticketCleanupVersion - 1
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{ticketCleanupID + ".up.sql", ticketCleanupUpSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", previous),
			fmt.Sprintf("(SELECT max(version) FROM schema_migrations) <> %d", previous),
			"migration_id='" + ticketCleanupPreviousID + "'",
			"checksum_sha256='" + ticketCleanupPreviousUpSHA + "'",
			"down_checksum_sha256='" + ticketCleanupPreviousDownSHA + "'",
			fmt.Sprintf("ERRCODE='P%d0'", ticketCleanupVersion),
			"IF OLD.message_id IS NOT NULL THEN",
			"GRANT DELETE ON ticket_attachments TO cdnca_control_app, cdnca_control_runtime",
		}},
		{ticketCleanupID + ".down.sql", ticketCleanupDownSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", ticketCleanupVersion),
			"migration_id='" + ticketCleanupID + "'",
			fmt.Sprintf("ERRCODE='P%d1'", ticketCleanupVersion),
			"REVOKE DELETE ON ticket_attachments",
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
