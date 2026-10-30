package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// Migration 575 (fix-btenv5: node install trust check failure alerts) is
// a placeholder number; the merge renumbers it after the head it lands on.
// Everything that changes with the renumbering is here.
const (
	migration575Version         = 575
	migration575PreviousVersion = 574
	migration575PreviousID      = "574_api_key_scope_limit"
	migration575PreviousUpSHA   = "45a11368fcfbac3b1337e4463cf6bdd138d0a84b29aa8789c3bcbeb15c6be69e"
	migration575PreviousDownSHA = "795df77e6316dc62b4fc987ca771482148c180822ee61f85a98f4fd4a97d3712"
	migration575ID              = "575_node_install_trust_alerts"
)

func TestNodeInstallTrustAlerts575Contract(t *testing.T) {
	for _, script := range []struct {
		name     string
		required []string
	}{
		{migration575ID + ".up.sql", []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration575PreviousVersion),
			fmt.Sprintf("(SELECT max(version) FROM schema_migrations) <> %d", migration575PreviousVersion),
			fmt.Sprintf("WHERE version=%d AND", migration575PreviousVersion),
			"migration_id='" + migration575PreviousID + "'",
			"checksum_sha256='" + migration575PreviousUpSHA + "'",
			"down_checksum_sha256='" + migration575PreviousDownSHA + "'",
			"ERRCODE='P5750'", "('node.install_trust.failed', true",
			"('node.install_trust.failed.zh-cn', 1, 'sms'", "('node.install_trust.failed.zh-cn', 1, 'email'",
			"ARRAY['download','failures']", "ARRAY['download','failures','reason','since','occurred_at']",
		}},
		{migration575ID + ".down.sql", []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration575Version),
			"migration_id='" + migration575ID + "'", "ERRCODE='P5751'", "ERRCODE='P5752'",
			"DELETE FROM notification_event_policies", "DELETE FROM admin_inbox_messages",
		}},
	} {
		raw, err := FS.ReadFile(script.name)
		if err != nil {
			t.Fatal(err)
		}
		for _, required := range script.required {
			if !strings.Contains(string(raw), required) {
				t.Errorf("%s missing %q", script.name, required)
			}
		}
	}
	// The guard must pin the predecessor's actual checksums.
	for suffix, want := range map[string]string{".up.sql": migration575PreviousUpSHA, ".down.sql": migration575PreviousDownSHA} {
		raw, err := FS.ReadFile(migration575PreviousID + suffix)
		if err != nil {
			t.Fatal(err)
		}
		if got := fmt.Sprintf("%x", sha256.Sum256(raw)); got != want {
			t.Errorf("%s%s checksum %s, guard pins %s", migration575PreviousID, suffix, got, want)
		}
	}
}
