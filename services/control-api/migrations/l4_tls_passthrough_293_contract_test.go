package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

func TestL4TLSPassthrough293Contract(t *testing.T) {
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{"293_l4_tls_passthrough.up.sql", "e9cf0e5df8011f95991400d9f777b577b9c02916880cf2f46fb214926e7cdfd4", []string{
			"(SELECT count(*) FROM schema_migrations) <> 292", "292_node_scope_conflict_audit_index",
			"a76b9d72641858fb17f30b14b261083c6bfeb1350ab844ccc845835dc6eeab0b", "ERRCODE='P2930'",
			"l4_forwards_protocol_port_active_293_idx", "WHERE deleted_at IS NULL AND NOT tls_passthrough",
			"l4_forward_listeners_socket_293_idx", "WHERE reserved AND NOT tls_passthrough",
			"l4_forward_server_names_port_293_idx ON l4_forward_server_names(port, server_name)",
			"validate_l4_runtime_spec_293", "check_l4_passthrough_facts_293", "ERRCODE='P2931'",
		}},
		{"293_l4_tls_passthrough.down.sql", "fda860fd118b23e521776fca729882ebf959b4fb6b5b825a2288b91ad34b271c", []string{
			"(SELECT count(*) FROM schema_migrations) <> 293", "293_l4_tls_passthrough", "ERRCODE='P2932'",
			"ERRCODE='P2933'", "l4_forwards_protocol_port_active_idx", "l4_forward_listeners_socket_248_idx",
			"l4_publish_intents_runtime_spec_248",
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
