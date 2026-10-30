package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// Migrations 369 (PA-24: certificate/node/usage/security producers) and
// 370 (PA-24: subscription site filter) are placeholder numbers: the merge
// renumbers them after the head they land on. Everything that changes with
// the renumbering is here.
const (
	migration369ID      = "369_domain_event_producers"
	migration369UpSHA   = "aee6a30a6111fd2bbdb0ed68bf42f8b398c3868bbab1b57be259784c132911a9"
	migration369DownSHA = "683e9da03180b13aa62a64099ee190b29e58cf03bd5d14321896bf48029b30f7"
	migration370ID      = "370_plugin_webhook_site_filter"
	migration370UpSHA   = "3798ab70a98f87506e28f20a2bcfaaa285f4719d9f317da49c1bd61445114346"
	migration370DownSHA = "82f5c6601402f57afbc5bc45be513108fe306e22ea9839547a3b39123ca1ff09"
)

func TestDomainEventProducers369And370Contract(t *testing.T) {
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{migration369ID + ".up.sql", migration369UpSHA, []string{
			"(SELECT count(*) FROM schema_migrations) <> 368", "migration_id='" + migration368ID + "'",
			migration368UpSHA, migration368DownSHA, "ERRCODE='P3690'",
			// Each producer is a trigger on the table that records the business fact.
			"CREATE TRIGGER certificate_orders_emit_status_event_369", "CREATE TRIGGER node_presence_emit_status_event_369",
			"CREATE TRIGGER nodes_emit_admin_event_369", "CREATE TRIGGER package_monitor_transition_facts_emit_usage_event_369",
			"CREATE TRIGGER package_cycle_enforcement_emit_usage_event_369", "CREATE TRIGGER cc_auto_switch_windows_emit_incident_event_369",
			// Node events fan out to the tenants a node serves, never to platform scope.
			"JOIN access_scopes scope ON scope.id=carried.scope_id AND scope.kind='tenant'",
			"UPDATE plugin_webhook_event_contracts_122 SET status='active'",
		}},
		{migration369ID + ".down.sql", migration369DownSHA, []string{
			"(SELECT count(*) FROM schema_migrations) <> 369", "migration_id='" + migration369ID + "'",
			"ERRCODE='P3699'", "would discard domain event history", "ENABLE TRIGGER domain_event_types_protect_368",
		}},
		{migration370ID + ".up.sql", migration370UpSHA, []string{
			"(SELECT count(*) FROM schema_migrations) <> 369", "migration_id='" + migration369ID + "'",
			migration369UpSHA, migration369DownSHA, "ERRCODE='P3700'",
			"ADD COLUMN site_ids uuid[]", "plugin webhook site filter is immutable",
			"site.scope_id=NEW.tenant_scope_id AND site.deleted_at IS NULL",
			"CREATE TRIGGER plugin_webhook_deliveries_site_filter_370",
		}},
		{migration370ID + ".down.sql", migration370DownSHA, []string{
			"(SELECT count(*) FROM schema_migrations) <> 370", "migration_id='" + migration370ID + "'",
			"ERRCODE='P3709'", "would widen site-filtered subscriptions",
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
		if strings.Contains(string(raw), "CASCADE") {
			t.Errorf("%s uses CASCADE", script.name)
		}
	}
}
