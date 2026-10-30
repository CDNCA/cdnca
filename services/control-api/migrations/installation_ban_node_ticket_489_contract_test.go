package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// Migration 489 (PF09): each node's held ServiceTicket
// times on installation_ban_node_state. Number 489 is the dispatched one; the
// guard pins the integration head 484 for now — renumber/repin at merge
// (shift-migrations.py + cascade-all.sh). Everything that changes is here.
const (
	migration489Version         = 489
	migration489PreviousVersion = 488
	migration489ID              = "489_installation_ban_node_ticket"
	migration489PreviousID      = "488_market_renewal_stop_notices"
	migration489PreviousUpSHA   = "9065189ac08869cc500223bfaf1458c6c9c994e21bf5ed1c3f8f129dfdb43692"
	migration489PreviousDownSHA = "81a076a6a4843d9b7caaee976d631f24da10240587948cacb9d21cc50b863a7e"
	migration489UpSHA           = "355e03eb8e87828a78801d2c4cbc17abcc654aeba92f78f62e147ba5177947da"
	migration489DownSHA         = "a35456bba9f7bd3429b7c4872dfa006725cd3464505a6b5d474e12197aed8200"
)

func TestInstallationBanNodeTicket489Contract(t *testing.T) {
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{migration489ID + ".up.sql", migration489UpSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration489PreviousVersion),
			fmt.Sprintf("(SELECT max(version) FROM schema_migrations) <> %d", migration489PreviousVersion),
			"migration_id='" + migration489PreviousID + "'", migration489PreviousUpSHA, migration489PreviousDownSHA,
			"ERRCODE='P4890'", "ADD COLUMN ticket_issued_at timestamptz", "ADD COLUMN ticket_not_after timestamptz",
			"(ticket_issued_at IS NULL) = (ticket_not_after IS NULL)",
		}},
		{migration489ID + ".down.sql", migration489DownSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration489Version),
			"migration_id='" + migration489ID + "'", "ERRCODE='P4891'", "DROP COLUMN ticket_issued_at",
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
