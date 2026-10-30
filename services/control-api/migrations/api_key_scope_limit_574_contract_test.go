package migrations

import (
	"strings"
	"testing"
)

// Migration 574 (fix-apikeysimple): api_keys.scopes up to 128 so the simple
// API key switch can issue an all-permissions key. Predecessor 552 is pinned
// by checksum (re-pinned by the merge task if another 574 lands first).
func TestAPIKeyScopeLimit574Contract(t *testing.T) {
	for _, script := range []struct {
		name     string
		required []string
	}{
		{"574_api_key_scope_limit.up.sql", []string{
			"(SELECT count(*) FROM schema_migrations) <> 573", "(SELECT max(version) FROM schema_migrations) <> 573",
			"migration_id='573_node_gateway_address_changes'",
			"checksum_sha256='b8cc8181cbf0a625d7b922abeeb3d32e322c547dd286e84ea902172da86fe18c'",
			"down_checksum_sha256='087de3f98d24ad34f991c6930d9159179062590d08d34959d03badfa36d4e50e'",
			"ERRCODE='P5740'", "DROP CONSTRAINT api_keys_scopes_check",
			"CHECK (cardinality(scopes) BETWEEN 1 AND 128)",
		}},
		{"574_api_key_scope_limit.down.sql", []string{
			"(SELECT count(*) FROM schema_migrations) <> 574", "migration_id='574_api_key_scope_limit'",
			"ERRCODE='P5741'", "cardinality(scopes) > 32", "ERRCODE='P5742'",
			"CHECK (cardinality(scopes) BETWEEN 1 AND 32)",
		}},
	} {
		body, err := FS.ReadFile(script.name)
		if err != nil {
			t.Fatal(err)
		}
		for _, fragment := range script.required {
			if !strings.Contains(string(body), fragment) {
				t.Errorf("%s missing %q", script.name, fragment)
			}
		}
	}
}
