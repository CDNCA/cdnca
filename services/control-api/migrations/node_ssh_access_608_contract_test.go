package migrations

import (
	"strings"
	"testing"
)

// Migration 608: nodes.ssh (platform administrators only,
// no role grant), remembered terminal credentials, the install job's
// restrict_ssh flag and the node's "controller-only SSH" state. The
// predecessor is pinned by checksum.
func TestNodeSSHAccess608Contract(t *testing.T) {
	for _, script := range []struct {
		name      string
		required  []string
		forbidden []string
	}{
		{"608_node_ssh_access.up.sql", []string{
			"(SELECT count(*) FROM schema_migrations) <> 607", "(SELECT max(version) FROM schema_migrations) <> 607",
			"migration_id='607_firewall_action_default_receipt'",
			"checksum_sha256='a40fdc5eb96f3ca70f1c064ab35d78d4d4bf0b4c071a8f64a3428c7b2997ce16'",
			"down_checksum_sha256='ee42b0545cde05d061a1513a3de343167d7f8cbd2619853996dcc7c5886c00cd'",
			"ERRCODE='P6080'", "('nodes.ssh',", "CREATE TABLE node_ssh_credentials",
			"credential_ciphertext bytea NOT NULL", "host_key_sha256 text NOT NULL CHECK",
			"ADD COLUMN restrict_ssh boolean NOT NULL DEFAULT false", "CREATE TABLE node_ssh_access",
			"CHECK (NOT enabled OR cardinality(controller_cidrs) >= 1)",
			"published_operation text NOT NULL DEFAULT '' CHECK (published_operation IN ('', 'apply', 'confirm'))",
			"CHECK (published_revision <= revision)", "REVOKE ALL ON node_ssh_credentials, node_ssh_access FROM PUBLIC",
		}, []string{"INSERT INTO role_permissions", "custom_rbac_permission_catalog"}},
		{"608_node_ssh_access.down.sql", []string{
			"(SELECT count(*) FROM schema_migrations) <> 608", "migration_id='608_node_ssh_access'",
			"ERRCODE='P6081'", "ERRCODE='P6082'", "DROP TABLE node_ssh_access", "DROP COLUMN restrict_ssh",
			"DROP TABLE node_ssh_credentials", "DELETE FROM permissions WHERE name = 'nodes.ssh'",
		}, nil},
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
		for _, fragment := range script.forbidden {
			if strings.Contains(string(body), fragment) {
				t.Errorf("%s must not contain %q", script.name, fragment)
			}
		}
	}
}
