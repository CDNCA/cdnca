package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// Migration 616: 287's nine RESTRICT node keys go back to
// 284's CASCADE, the 321/343 node keys and the 348/477 deployment fact keys
// cascade too, and the 348/477 guards let only a node purge cascade delete.
// The 615 predecessor is pinned by checksum.
const (
	migration616ID      = "616_node_purge_fk_restore"
	migration615UpSHA   = "bc37a458ac1a6c9c3370123ba4aa350b085273439951956aa50877dd4c0f44b9"
	migration615DownSHA = "dd6b5d142e5e7791913dc06dd580fc9bede95a3c5f508bf9b06bea2896344244"
)

var migration616NodeTables = []string{
	"cache_operation_nodes", "security_policy_publication_targets", "acme_http01_overlay_targets",
	"firewall_command_outbox", "cc_coordination_setting_targets", "cc_coordination_facts",
	"l4_node_drain_counters", "l4_line_switch_drain_plans", "ja4_block_edge_receipt_queue_158",
}

func TestNodePurgeFKRestore616Contract(t *testing.T) {
	read := func(name string) string {
		t.Helper()
		raw, err := FS.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		return string(raw)
	}
	prevUp, prevDown := read("615_billing_adjustment_mfa_waiver.up.sql"), read("615_billing_adjustment_mfa_waiver.down.sql")
	if got := fmt.Sprintf("%x", sha256.Sum256([]byte(prevUp))); got != migration615UpSHA {
		t.Fatalf("615 up checksum drift: %s", got)
	}
	if got := fmt.Sprintf("%x", sha256.Sum256([]byte(prevDown))); got != migration615DownSHA {
		t.Fatalf("615 down checksum drift: %s", got)
	}
	up, down := read(migration616ID+".up.sql"), read(migration616ID+".down.sql")
	for _, required := range []string{
		"(SELECT count(*) FROM schema_migrations) <> 615", "(SELECT max(version) FROM schema_migrations) <> 615",
		"migration_id='615_billing_adjustment_mfa_waiver'", "checksum_sha256='" + migration615UpSHA + "'",
		"down_checksum_sha256='" + migration615DownSHA + "'", "ERRCODE='P6160'", "ERRCODE='P6162'",
		"REFERENCES nodes(id) ON DELETE CASCADE",
		"node_availability_alert_states_node_id_fkey FOREIGN KEY (node_id) REFERENCES nodes(id) ON DELETE CASCADE",
		"edge_challenge_redeliveries_node_id_fkey FOREIGN KEY (node_id) REFERENCES nodes(id) ON DELETE CASCADE",
		"WHEN (NOT node_purge_in_progress()) EXECUTE FUNCTION guard_node_deployment_timeout_348()",
		"WHEN (NOT node_purge_in_progress()) EXECUTE FUNCTION guard_node_deployment_status_refusal_477()",
	} {
		if !strings.Contains(up, required) {
			t.Errorf("616 up missing %q", required)
		}
	}
	for _, table := range migration616NodeTables {
		if !strings.Contains(up, "('"+table+"')") || !strings.Contains(down, "('"+table+"')") {
			t.Errorf("616 does not rebind %s both ways", table)
		}
	}
	var downSQL strings.Builder
	for _, line := range strings.Split(down, "\n") {
		if !strings.HasPrefix(strings.TrimSpace(line), "--") {
			downSQL.WriteString(line + "\n")
		}
	}
	if strings.Count(downSQL.String(), "ON DELETE RESTRICT") != 5 || strings.Contains(downSQL.String(), "ON DELETE CASCADE") {
		t.Error("616 down must restore RESTRICT on every key it changed")
	}
	for _, required := range []string{
		"(SELECT count(*) FROM schema_migrations) <> 616", "migration_id='" + migration616ID + "'", "ERRCODE='P6163'",
		"BEFORE INSERT OR UPDATE OR DELETE ON node_deployment_timeouts",
		"BEFORE INSERT OR UPDATE OR DELETE ON node_deployment_status_refusals",
	} {
		if !strings.Contains(down, required) {
			t.Errorf("616 down missing %q", required)
		}
	}
}
