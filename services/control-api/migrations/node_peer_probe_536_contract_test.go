package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// Migration 536 (node peer probe availability log). Its
// predecessor is 535 (acme_certificate_owner), pinned by checksum;
// checksums in the guard.
const (
	migration536ID      = "536_node_peer_probe_log"
	migration536UpSHA   = "152e7d6a488e17b06487cc1ec9910c1e8d1b8b0566747c5ca4241e447307a23a"
	migration536DownSHA = "a64a8b01e9a896f753c78e9627f144b223371c9e931e82938f1ed5b34fdd453e"
)

func TestNodePeerProbe536Contract(t *testing.T) {
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{migration536ID + ".up.sql", migration536UpSHA, []string{
			"(SELECT count(*) FROM schema_migrations) <> 535", "(SELECT max(version) FROM schema_migrations) <> 535",
			"migration_id='535_acme_certificate_owner'", "ERRCODE='P5360'", "CREATE TABLE node_peer_probe_results", "controller_ok boolean",
		}},
		{migration536ID + ".down.sql", migration536DownSHA, []string{
			"(SELECT count(*) FROM schema_migrations) <> 536", "migration_id='" + migration536ID + "'",
			"ERRCODE='P5361'", "DROP TABLE node_peer_probe_results",
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
