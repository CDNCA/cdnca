package migrations

import (
	"strings"
	"testing"
)

// Migration 617: node_ssh_install_jobs.restrict_ssh_allow_cidrs,
// the "also allow" addresses of an SSH install with controller-only SSH.
// Older rows stay '{}'. The predecessor is pinned by checksum.
const (
	nodeSSHInstallAllow617PreviousID   = "616_node_purge_fk_restore"
	nodeSSHInstallAllow617PreviousUp   = "6a59064a53c49344c14bd137f9c4b21599d70c42c997192fdae5cbdc6b43c46f"
	nodeSSHInstallAllow617PreviousDown = "b33468073011b084431f8a45475c0a1cd4a92e5c03770d416d95f044b5fb8f40"
)

func TestNodeSSHInstallAllowCIDRs617Contract(t *testing.T) {
	for _, script := range []struct {
		name      string
		required  []string
		forbidden []string
	}{
		{"617_node_ssh_install_allow_cidrs.up.sql", []string{
			"(SELECT count(*) FROM schema_migrations) <> 616", "(SELECT max(version) FROM schema_migrations) <> 616",
			"migration_id='" + nodeSSHInstallAllow617PreviousID + "'",
			"checksum_sha256='" + nodeSSHInstallAllow617PreviousUp + "'",
			"down_checksum_sha256='" + nodeSSHInstallAllow617PreviousDown + "'",
			"ERRCODE='P6170'", "ADD COLUMN restrict_ssh_allow_cidrs text[] NOT NULL DEFAULT '{}'",
			"CHECK (cardinality(restrict_ssh_allow_cidrs) <= 64)",
		}, []string{"UPDATE node_ssh_install_jobs", "DROP "}},
		{"617_node_ssh_install_allow_cidrs.down.sql", []string{
			"(SELECT count(*) FROM schema_migrations) <> 617", "migration_id='617_node_ssh_install_allow_cidrs'",
			"ERRCODE='P6171'", "ALTER TABLE node_ssh_install_jobs DROP COLUMN restrict_ssh_allow_cidrs",
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
