package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// Migration 368 (PA-20: generic transactional domain event outbox) is a
// placeholder number: the merge renumbers it after the head it lands on.
// Everything that changes with the renumbering is here.
const (
	migration368Version         = 368
	migration368ID              = "368_domain_event_outbox"
	migration368PreviousID      = "367_ip_intel_updates"
	migration368PreviousUpSHA   = "955b1067c671e95b8936a8104fca76c2f8915fbcba4c461392a097e1047fe515"
	migration368PreviousDownSHA = "7996a514fc7658985bb94fbec64b504b5a24b3192ab5f9c07743d22e0fa9f8b5"
	migration368UpSHA           = "e9f9ae32d271771a2e33eb6c05421003ac74af60606e6c82a322e32f310edae7"
	migration368DownSHA         = "9358a26e2b893f9ad3d62b30fbbd29a51bd2a35a97202957d588f854ea7f2168"
)

func TestDomainEventOutbox368Contract(t *testing.T) {
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{migration368ID + ".up.sql", migration368UpSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration368Version-1),
			fmt.Sprintf("(SELECT max(version) FROM schema_migrations) <> %d", migration368Version-1),
			"migration_id='" + migration368PreviousID + "'", migration368PreviousUpSHA, migration368PreviousDownSHA,
			"ERRCODE='P3680'",
			// Same-transaction append with per-subject commit-ordered sequence.
			"CREATE FUNCTION domain_event_append_368(", "FOR UPDATE;", "ON CONFLICT ON CONSTRAINT domain_event_subject_heads_368_pkey DO NOTHING",
			// Closed per-event payload contract, checked in SQL as well as Go.
			"CREATE FUNCTION domain_event_payload_valid_368(", "NOT domain_event_payload_valid_368(NEW.event_type, NEW.payload)",
			// Deliveries re-check the bound installation's permission (replays too).
			"CREATE TRIGGER plugin_webhook_deliveries_domain_scope_368", "installation.status='enabled' AND required_scope = ANY(installation.approved_scopes)",
			// Reserved events are not subscribable; the first batch is active.
			"WHERE contract.status = 'active') <> cardinality(NEW.event_types)",
			"UPDATE plugin_webhook_event_contracts_122 SET status='active'",
			"DROP TABLE deployment_domain_event_source_outbox;", "DROP TABLE deployment_domain_event_fanout_receipts;",
			// site.updated is produced for every committed site revision.
			"CREATE CONSTRAINT TRIGGER sites_emit_site_updated_event_368", "DEFERRABLE INITIALLY DEFERRED",
		}},
		{migration368ID + ".down.sql", migration368DownSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration368Version),
			"migration_id='" + migration368ID + "'", "ERRCODE='P3689'", "would discard domain event history",
			"ENABLE TRIGGER plugin_webhook_event_contracts_protect_122",
			"CREATE TABLE deployment_domain_event_source_outbox", "CREATE TABLE deployment_domain_event_fanout_receipts",
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
		// No DROP ... CASCADE; ON DELETE CASCADE restores the 284 node purge
		// foreign keys in down.
		if strings.Contains(strings.ReplaceAll(string(raw), "ON DELETE CASCADE", ""), "CASCADE") {
			t.Errorf("%s uses CASCADE", script.name)
		}
	}
}
