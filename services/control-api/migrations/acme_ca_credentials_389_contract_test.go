package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// Migration 389 (ACME EAB credentials) is a placeholder number
// after 388: the merge renumbers 387-389 together.
const (
	migration389Version = 389
	migration389ID      = "389_acme_ca_credentials"
	migration389UpSHA   = "7ed8cf7fc6ce984a50f5316ab13456c7bc23f89a6c6403351602723a36dcc044"
	migration389DownSHA = "0696ea87dff35b604c11a9c2325b52d057bd8f33e21ace16154421d6b1bbe226"
)

func TestACMECACredentials389Contract(t *testing.T) {
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{migration389ID + ".up.sql", migration389UpSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration389Version-1),
			"migration_id='" + migration388ID + "'", migration388UpSHA, migration388DownSHA, "ERRCODE='P3890'",
			"CREATE TABLE acme_ca_credentials", "'zerossl','google_trust'", "'zerossl','lets_encrypt','google_trust'",
		}},
		{migration389ID + ".down.sql", migration389DownSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration389Version),
			"migration_id='" + migration389ID + "'", "ERRCODE='P3892'", "ERRCODE='P3893'", "DROP TABLE acme_ca_credentials",
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
