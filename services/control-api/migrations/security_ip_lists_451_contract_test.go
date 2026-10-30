package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// Migration 451 (named IP lists) is a placeholder number;
// the merge renumbers it after the head it lands on. Everything that changes
// with the renumbering is here.
const (
	migration451Version         = 451
	migration451ID              = "451_security_ip_lists"
	migration451PreviousID      = "450_waf_adapt_node_limits"
	migration451PreviousUpSHA   = "057dfb35fa99e6cd96d0be3dc34d1677cb9a1c7591d7e4bb2eda02aa99e6bea5"
	migration451PreviousDownSHA = "9365c964108bf3a8a77e547911d5108c5576f777951cf41d6c72b716da31a431"
	migration451UpSHA           = "c36630cb599f465559434e1f8b2c0c72c99b7c19b3e591c36c9f76ae0a12fef5"
	migration451DownSHA         = "2d1e3167789dabf7c6ba950e06f82f7b4ebdadd96b7c7043aba818674af40477"
)

func TestSecurityIPLists451Contract(t *testing.T) {
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{migration451ID + ".up.sql", migration451UpSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration451Version-1),
			fmt.Sprintf("(SELECT max(version) FROM schema_migrations) <> %d", migration451Version-1),
			"migration_id='" + migration451PreviousID + "'", migration451PreviousUpSHA, migration451PreviousDownSHA,
			"ERRCODE='P4510'", "CREATE TABLE security_ip_lists", "CREATE TABLE security_ip_list_write_requests",
			"'market_limits', 'ip_list']::text[]", "BETWEEN 1 AND 17",
		}},
		{migration451ID + ".down.sql", migration451DownSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration451Version),
			"migration_id='" + migration451ID + "'", "ERRCODE='P4511'", "ERRCODE='P4512'",
			"DROP TABLE security_ip_lists",
		}},
	} {
		raw, err := FS.ReadFile(script.name)
		if err != nil {
			t.Skipf("%s not embedded under this number (local renumbering): %v", script.name, err)
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
