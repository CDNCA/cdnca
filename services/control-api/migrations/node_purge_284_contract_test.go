package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

func TestNodePurge284Contract(t *testing.T) {
	for _, script := range []struct {
		name, sha string
		required  []string
		forbidden []string
	}{
		{"284_node_purge.up.sql", "0a0aff51ef85661bcaaa563a4618929fb76daab884515e33160163b1fb6057be", []string{
			"(SELECT count(*) FROM schema_migrations) <> 283", "283_security_custom_rule_report_state",
			"fcd817b0bdf2157651205b47d94aa83027a1d3c5bd6dd158067d60d700f0a079",
			"4163b07aacb95be5707172b137e23998aec5c2676a5557b85ab52997e34d8280",
			"ERRCODE='P2840'", "pg_trigger_depth() > 0", "current_setting('cdnca.node_purge', true)",
			"NOT EXISTS (SELECT 1 FROM nodes WHERE id = target)", "CREATE TABLE node_purged_ids",
			"node_line_endpoints_purge_guard_284", "ERRCODE='P2841'", "ERRCODE='P2842'",
			"WHEN (NOT node_purge_permits(OLD.node_id))", "WHEN (NOT node_purge_in_progress())",
		}, []string{
			// The L2 membership business reference stays RESTRICT.
			"DROP CONSTRAINT l2_topology_nodes_tenant_scope_id_node_id_fkey",
			// Guards are gated, never disabled.
			"DISABLE TRIGGER", "session_replication_role",
		}},
		{"284_node_purge.down.sql", "fe2bf9efbbc6713af9c792c2c40d828c8caacd13ed9e5062e3d82548463ca872", []string{
			"(SELECT count(*) FROM schema_migrations) <> 284", "284_node_purge",
			"DROP TABLE node_purged_ids", "DROP FUNCTION node_purge_permits(uuid)",
		}, []string{"ON DELETE CASCADE"}},
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
		for _, forbidden := range script.forbidden {
			if strings.Contains(string(raw), forbidden) {
				t.Errorf("%s must not contain %q", script.name, forbidden)
			}
		}
	}
	// Every FK switched to CASCADE in up is restored without it in down.
	up, _ := FS.ReadFile("284_node_purge.up.sql")
	down, _ := FS.ReadFile("284_node_purge.down.sql")
	count := func(script []byte, action string) (constraints, matching int) {
		for _, line := range strings.Split(string(script), "\n") {
			if strings.Contains(line, "ADD CONSTRAINT") {
				constraints++
				if strings.Contains(line, action) {
					matching++
				}
			}
		}
		return constraints, matching
	}
	upTotal, cascades := count(up, "ON DELETE CASCADE")
	downTotal, restores := count(down, "ON DELETE RESTRICT")
	// 101 node foreign keys (99 RESTRICT + 2 NO ACTION before 284); L2 is untouched.
	if upTotal != 101 || cascades != 101 || downTotal != 101 || restores != 99 {
		t.Fatalf("up %d/%d cascade, down %d/%d restrict", cascades, upTotal, restores, downTotal)
	}
}
