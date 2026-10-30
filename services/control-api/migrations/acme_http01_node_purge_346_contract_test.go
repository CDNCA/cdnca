package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// Migration 346 (ADR 0006 node purge for the ADR-0003
// HTTP-01 facts) is a placeholder number: the merge renumbers it after the
// head it lands on. Everything that changes with the renumbering is here.
const (
	migration346Version         = 346
	migration346ID              = "346_acme_http01_node_purge"
	migration346PreviousID      = "345_challenge_wildcard_site_binding"
	migration346PreviousUpSHA   = "4d88859e1cd695ea20c29d6466aa346aaf6f0164771d3741d7ccc6a0ec9dd69c"
	migration346PreviousDownSHA = "af50113884d47396c6daa1dd369624b9038ca5bde76d07b5f1799e3b4eb582b2"
	migration346UpSHA           = "7fda0b7754abf4a43e4d7ff9e3760a2cb125b1a88a98c676c827d4bf56f57972"
	migration346DownSHA         = "a5b4033a06efbf85a9b5f23364621201f27d31198ab346d6b24ca75d8d174831"
)

func TestACMEHTTP01NodePurge346Contract(t *testing.T) {
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{migration346ID + ".up.sql", migration346UpSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration346Version-1),
			fmt.Sprintf("(SELECT max(version) FROM schema_migrations) <> %d", migration346Version-1),
			"migration_id='" + migration346PreviousID + "'", migration346PreviousUpSHA, migration346PreviousDownSHA,
			"ERRCODE='P3460'", "CREATE TABLE acme_http01_site_overlay_epoch_purged_members",
			"CREATE FUNCTION %1$I.acme_http01_purge_node_346", "SECURITY DEFINER",
			"hashtextextended('acme-http01-overlay', 0)", "current_setting('cdnca.node_purge', true)",
			"CREATE OR REPLACE FUNCTION validate_acme_http01_site_overlay_epoch_342",
			"GRANT EXECUTE ON FUNCTION acme_http01_purge_node_346(uuid) TO cdnca_control_app",
		}},
		{migration346ID + ".down.sql", migration346DownSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration346Version),
			"migration_id='" + migration346ID + "'", "ERRCODE='P3469'", "ERRCODE='P0001'",
			"DROP TABLE acme_http01_site_overlay_epoch_purged_members",
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
