package migrations_test

import (
	"strings"
	"testing"

	controlmigrations "github.com/cdnca/cdnca/services/control-api/migrations"
)

func TestL4LineSwitches139PinsExactPredecessorAndStateMachine(t *testing.T) {
	up := readL4LineSwitch139(t, "139_l4_line_switches.up.sql")
	for _, required := range []string{
		"migration 139 requires the exact verified 138 release head",
		"version = 138 AND migration_id = '138_challenge_publication_facts'",
		"checksum_sha256 = '14399e504508dbe31dd78711d22ef2c2f4e5a20aad0fc299ee355553e3a3ae9e'",
		"down_checksum_sha256 = '063b1504731a6b630aed43fe46a60247ef9bc86893d4330755209a6720a04218'",
		"CREATE TABLE l4_line_switches",
		"CREATE TABLE l4_line_switch_workload_grants",
		"workload_id = 'control-api.l4-line-switch-reconciler'",
		"UNIQUE (configuration_scope_id, idempotency_key)",
		"state_document_identity_139",
		"must begin at preparing revision 1",
		"NEW.state_revision <> OLD.state_revision + 1",
		"invalid L4 line switch state transition",
		"OLD.state = 'health_gate' AND NEW.state IN ('draining_old','compensating_old','completed','rolled_back')",
		"CREATE UNIQUE INDEX l4_line_switches_one_active_139",
		"L4 line switch state is durable",
		"CREATE TABLE l4_line_target_heads",
		"CREATE TABLE l4_line_target_events",
		"CREATE TABLE l4_node_drain_counters",
		"CREATE TABLE l4_line_switch_drain_plans",
		"UNIQUE (configuration_scope_id, switch_id, operation)",
		"UNIQUE (configuration_scope_id, node_id, plan_revision)",
		"plan_sha256 = sha256(convert_to(canonical_plan::text, 'UTF8'))",
		"L4 line target head must advance monotonically",
		"L4 line target events are append-only",
		"L4 node drain revision must advance monotonically",
		"L4 line switch drain plans are append-only",
		"L4 line switch workload grants are append-only",
	} {
		if !strings.Contains(up, required) {
			t.Errorf("139 up missing %q", required)
		}
	}
	if guard, mutation := strings.Index(up, "migration 139 requires the exact verified 138 release head"),
		strings.Index(up, "CREATE TABLE l4_line_switches"); guard < 0 || mutation < 0 || guard > mutation {
		t.Fatal("139 predecessor guard must run before the first schema mutation")
	}
	if identity, trigger := strings.Index(up, "CREATE FUNCTION state_document_identity_139"),
		strings.Index(up, "CREATE FUNCTION protect_l4_line_switch_139"); identity < 0 || trigger < 0 || identity > trigger {
		t.Fatal("139 state document identity function must exist before the protecting trigger function")
	}
}

func TestL4LineSwitches139RollbackFailsClosed(t *testing.T) {
	down := readL4LineSwitch139(t, "139_l4_line_switches.down.sql")
	for _, required := range []string{
		"migration 139 rollback requires the exact verified 139 head",
		"version = 139 AND migration_id = '139_l4_line_switches'",
		"checksum_sha256 = '2ad9c5bdb52acc550197197113b581ea36e123826275121f68c48e687cdbc680'",
		"version = 138 AND migration_id = '138_challenge_publication_facts'",
		"checksum_sha256 = '14399e504508dbe31dd78711d22ef2c2f4e5a20aad0fc299ee355553e3a3ae9e'",
		"down_checksum_sha256 = '063b1504731a6b630aed43fe46a60247ef9bc86893d4330755209a6720a04218'",
		"migration 139 rollback would discard durable L4 line switch state",
		"EXISTS (SELECT 1 FROM l4_line_target_heads)",
		"EXISTS (SELECT 1 FROM l4_line_target_events)",
		"EXISTS (SELECT 1 FROM l4_node_drain_counters)",
		"EXISTS (SELECT 1 FROM l4_line_switch_drain_plans)",
		"EXISTS (SELECT 1 FROM l4_line_switch_workload_grants)",
		"DROP TABLE l4_line_switch_drain_plans",
		"DROP TABLE l4_node_drain_counters",
		"DROP TABLE l4_line_target_events",
		"DROP TABLE l4_line_target_heads",
		"DROP TABLE l4_line_switches",
		"DROP TABLE l4_line_switch_workload_grants",
	} {
		if !strings.Contains(down, required) {
			t.Errorf("139 down missing %q", required)
		}
	}
	if strings.Contains(down, "DELETE FROM schema_migrations") {
		t.Fatal("139 down must leave migration metadata ownership to the runner")
	}
}

func readL4LineSwitch139(t *testing.T, name string) string {
	t.Helper()
	content, err := controlmigrations.FS.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	return string(content)
}
