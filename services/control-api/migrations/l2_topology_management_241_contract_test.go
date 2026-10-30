package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

const (
	l2TopologyManagement241UpSHA   = "da19054e99340bce06c1bf8b64b99bb986ed05ef951085e8c8936b871308ee63"
	l2TopologyManagement241DownSHA = "227520f20eb7bdbd9e0a939d101cd4d43511a3d4a4839e0aceee6d9ef2fa053d"
)

func TestL2TopologyManagement241Contract(t *testing.T) {
	files := map[string]struct {
		name string
		sha  string
	}{
		"up":   {"241_l2_topology_management.up.sql", l2TopologyManagement241UpSHA},
		"down": {"241_l2_topology_management.down.sql", l2TopologyManagement241DownSHA},
	}
	contents := make(map[string]string, len(files))
	for label, file := range files {
		payload, err := FS.ReadFile(file.name)
		if err != nil {
			t.Fatalf("read migration 241 %s: %v", label, err)
		}
		if got := fmt.Sprintf("%x", sha256.Sum256(payload)); got != file.sha {
			t.Fatalf("migration 241 %s checksum = %s, want %s", label, got, file.sha)
		}
		contents[label] = string(payload)
	}

	for _, required := range []string{
		"(SELECT count(*) FROM schema_migrations) <> 240",
		"240_node_monitoring_compatibility_fields",
		"b5a841e06c3d75024dfa9ca8c05b2bc08324b0990b7d1a4a53c8dd6564e61390",
		"40aab73c4220c2bdb5296ac6ae81443d46fcaf67075720e09ac5b75f4fb898ca",
		"CREATE TABLE l2_topology_configs",
		"CREATE TABLE l2_topology_conditions",
		"CREATE TABLE l2_topology_nodes",
		"CREATE TABLE l2_topology_write_requests",
		"FOREIGN KEY (tenant_scope_id, node_id)",
		"l2_topology_nodes_scope_node_active_241_idx",
		"protect_l2_topology_write_request_241",
		"node_scheduling.l2_config.create",
		"node_scheduling.l2_node.delete",
		"GRANT USAGE, SELECT ON SEQUENCE",
	} {
		if !strings.Contains(contents["up"], required) {
			t.Errorf("migration 241 up is missing %q", required)
		}
	}

	for _, required := range []string{
		"(SELECT count(*) FROM schema_migrations) <> 241",
		"migration 241 rollback cannot discard L2 topology data or idempotency receipts",
		l2TopologyManagement241UpSHA,
		"DROP TABLE l2_topology_write_requests",
		"DROP TABLE l2_topology_nodes",
		"DROP TABLE l2_topology_conditions",
		"DROP TABLE l2_topology_configs",
		"ALTER TABLE nodes DROP CONSTRAINT nodes_scope_id_241_unique",
	} {
		if !strings.Contains(contents["down"], required) {
			t.Errorf("migration 241 down is missing %q", required)
		}
	}

	combined := strings.ToUpper(contents["up"] + contents["down"])
	for _, forbidden := range []string{" CASCADE", "DELETE FROM SCHEMA_MIGRATIONS", "DROP SCHEMA", "__UP_SHA256__", "__DOWN_SHA256__"} {
		if strings.Contains(combined, forbidden) {
			t.Errorf("migration 241 contains forbidden token %q", forbidden)
		}
	}
}
