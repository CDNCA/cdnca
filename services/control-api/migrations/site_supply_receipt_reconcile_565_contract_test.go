package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// Migration 565 (fix-cfgflow2 §2: market subscription receipt reconciliation)
// is a placeholder number; the merge renumbers it after the head it lands on.
// Everything that changes with the renumbering is here.
const (
	migration565Version         = 565
	migration565PreviousVersion = 564
	migration565PreviousID      = "564_deployment_status_error_codes"
	migration565PreviousUpSHA   = "a83d5a322db203f7ba87f45c9220b9604370dd9478cdd1e109f9dddc53d60eb4"
	migration565PreviousDownSHA = "28c2e6f74650c037c95cdb007b76246dede2570e60181835c588374f88c58cf8"
	migration565ID              = "565_site_supply_receipt_reconcile"
)

func TestSiteSupplyReceiptReconcile565Contract(t *testing.T) {
	for _, script := range []struct {
		name     string
		required []string
	}{
		{migration565ID + ".up.sql", []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration565PreviousVersion),
			fmt.Sprintf("(SELECT max(version) FROM schema_migrations) <> %d", migration565PreviousVersion),
			fmt.Sprintf("WHERE version=%d AND", migration565PreviousVersion),
			"migration_id='" + migration565PreviousID + "'",
			"checksum_sha256='" + migration565PreviousUpSHA + "'",
			"down_checksum_sha256='" + migration565PreviousDownSHA + "'",
			"ERRCODE='P5650'", "'pending', 'committing', 'applied', 'failed', 'inconsistent'",
			"ADD COLUMN pending_revision", "ADD COLUMN next_reconcile_at",
			"('market.supply.receipt_unconfirmed', true",
			"('market.supply.receipt_unconfirmed.zh-cn', 1, 'sms'", "('market.supply.receipt_unconfirmed.zh-cn', 1, 'email'",
			"ARRAY['domain','supply','revision','reason']",
		}},
		{migration565ID + ".down.sql", []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration565Version),
			"migration_id='" + migration565ID + "'", "ERRCODE='P5651'", "ERRCODE='P5652'", "ERRCODE='P5653'",
			"DELETE FROM notification_event_policies", "DELETE FROM admin_inbox_messages",
			"state IN ('pending', 'applied', 'failed', 'inconsistent')",
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
	for suffix, want := range map[string]string{".up.sql": migration565PreviousUpSHA, ".down.sql": migration565PreviousDownSHA} {
		raw, err := FS.ReadFile(migration565PreviousID + suffix)
		if err != nil {
			t.Fatal(err)
		}
		if got := fmt.Sprintf("%x", sha256.Sum256(raw)); got != want {
			t.Errorf("%s%s checksum %s, guard pins %s", migration565PreviousID, suffix, got, want)
		}
	}
}
