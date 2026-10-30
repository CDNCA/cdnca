package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

const (
	nodeManagementSettings239UpSHA   = "2889178f6f06f46209c9ffa6e49166a152447cd4b171325620e9779034fa5324"
	nodeManagementSettings239DownSHA = "c9672a6d6e71ad8f21ab93af8c017eabdb98317bd1efbb2fabbd1d9162e241e7"
)

func TestNodeManagementSettings239Contract(t *testing.T) {
	files := map[string]struct{ name, sha string }{
		"up":   {"239_node_management_settings.up.sql", nodeManagementSettings239UpSHA},
		"down": {"239_node_management_settings.down.sql", nodeManagementSettings239DownSHA},
	}
	contents := make(map[string]string, len(files))
	for label, file := range files {
		payload, err := FS.ReadFile(file.name)
		if err != nil {
			t.Fatalf("read migration 239 %s: %v", label, err)
		}
		if got := fmt.Sprintf("%x", sha256.Sum256(payload)); got != file.sha {
			t.Fatalf("migration 239 %s checksum = %s, want %s", label, got, file.sha)
		}
		contents[label] = string(payload)
	}

	for _, required := range []string{
		"(SELECT count(*) FROM schema_migrations) <> 238",
		"version = 238 AND migration_id = '238_l4_stream_sequence_delete_grants'",
		"1408c479408d540459eb5d78d7ae98c75c6382b6a40c330170a4c0976f5a28f7",
		"3b8bf691cfa55800344620895fb587c82dce74de5cf97ef6a2f6a26d389010a9",
		"ADD COLUMN management_settings jsonb NOT NULL",
		"nodes_management_settings_239_check",
		"'schema_version', 1",
		"'sort', 100",
		"'node_type', 'L1'",
		"'traffic_total_gb', 500",
		"'secondary_ips', '[]'::jsonb",
	} {
		if !strings.Contains(contents["up"], required) {
			t.Fatalf("migration 239 up is missing %q", required)
		}
	}
	for _, required := range []string{
		"version = 239 AND migration_id = '239_node_management_settings'",
		nodeManagementSettings239UpSHA,
		"migration 239 rollback cannot discard node management settings",
		"DROP COLUMN management_settings",
	} {
		if !strings.Contains(contents["down"], required) {
			t.Fatalf("migration 239 down is missing %q", required)
		}
	}
}
