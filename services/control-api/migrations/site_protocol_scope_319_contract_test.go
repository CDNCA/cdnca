package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// 136 defect fix. Every number the merge renumbering touches is here.
const (
	protocolScopeVersion        = 319
	protocolScopeID             = "319_site_protocol_scope_fields"
	protocolScopePreviousID     = "318_edge_publication_compile_inputs"
	protocolScopePreviousUpSHA  = "9b31c6f7d9f9247e3fd02d9e9b85955f672b46b8b6cbae96c614d63f0ae58e1b"
	protocolScopePreviousDownSH = "cd2ae2c483ec22bd32f36c146b7087a3464e9e05025f71833ebc1fbc333e57c8"
	protocolScopeUpSHA          = "5ec4f621fa457dc60cd348f6995170a45f5d0cc6719d8084b580d9085a6f3379"
	protocolScopeDownSHA        = "cbfcb9acfe69c76524efb4c612d5a13c850247b5d8cbbb8a74ade1cb8201d1f1"
)

func TestSiteProtocolScope319Contract(t *testing.T) {
	previous := protocolScopeVersion - 1
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{protocolScopeID + ".up.sql", protocolScopeUpSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", previous),
			fmt.Sprintf("(SELECT max(version) FROM schema_migrations) <> %d", previous),
			"migration_id='" + protocolScopePreviousID + "'",
			"checksum_sha256='" + protocolScopePreviousUpSHA + "'",
			"down_checksum_sha256='" + protocolScopePreviousDownSH + "'",
			fmt.Sprintf("ERRCODE='P%d0'", protocolScopeVersion),
			"ELSIF TG_TABLE_NAME='site_protocol_node_results' THEN",
		}},
		{protocolScopeID + ".down.sql", protocolScopeDownSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", protocolScopeVersion),
			"migration_id='" + protocolScopeID + "'",
			fmt.Sprintf("ERRCODE='P%d1'", protocolScopeVersion),
			"IF TG_TABLE_NAME IN ('site_protocol_states','site_protocol_batch_items') AND",
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
