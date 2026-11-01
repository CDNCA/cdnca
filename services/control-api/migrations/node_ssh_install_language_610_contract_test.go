package migrations

import (
	"strings"
	"testing"
)

// Migration 610: node_ssh_install_jobs.language, the
// operator's UI language the SSH install command carries as --lang. Older
// rows stay ” (no --lang). The predecessor is pinned by checksum.
const (
	nodeSSHInstallLanguage610PreviousID   = "609_smart_schedule"
	nodeSSHInstallLanguage610PreviousUp   = "084932cdb4c795fc264bc7945353073e78ad51457dd4204f6bbca5b9cf66bc5f"
	nodeSSHInstallLanguage610PreviousDown = "e17b463e2ebcfe8f6a6ca39836c8d4f51bf26dbbe5cad1e9b4fa2096effc95e7"
)

func TestNodeSSHInstallLanguage610Contract(t *testing.T) {
	for _, script := range []struct {
		name      string
		required  []string
		forbidden []string
	}{
		{"610_node_ssh_install_language.up.sql", []string{
			"(SELECT count(*) FROM schema_migrations) <> 609", "(SELECT max(version) FROM schema_migrations) <> 609",
			"migration_id='" + nodeSSHInstallLanguage610PreviousID + "'",
			"checksum_sha256='" + nodeSSHInstallLanguage610PreviousUp + "'",
			"down_checksum_sha256='" + nodeSSHInstallLanguage610PreviousDown + "'",
			"ERRCODE='P6100'", "ADD COLUMN language text NOT NULL DEFAULT ''",
			"CHECK (language IN ('', 'zh', 'en'))",
		}, []string{"UPDATE node_ssh_install_jobs", "DROP "}},
		{"610_node_ssh_install_language.down.sql", []string{
			"(SELECT count(*) FROM schema_migrations) <> 610", "migration_id='610_node_ssh_install_language'",
			"ERRCODE='P6101'", "ALTER TABLE node_ssh_install_jobs DROP COLUMN language",
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
