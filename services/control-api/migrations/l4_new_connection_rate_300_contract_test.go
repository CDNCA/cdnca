package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// Every number the merge renumbering touches is here: the
// version, the previous head it guards on, and the script checksums.
const (
	l4NewConnRateVersion        = 300
	l4NewConnRateID             = "300_l4_new_connection_rate"
	l4NewConnRatePreviousID     = "299_package_traffic_enforcement"
	l4NewConnRatePreviousUpSHA  = "61b0f33fbdade032abffa52015271acb3b4fb117be787c889663ee27d75b9824"
	l4NewConnRatePreviousDownSH = "8b1fcea6bf466652afc1e876f80556aa30a61898dd1abcc34ee31a52c30be091"
	l4NewConnRateUpSHA          = "57c497adfbc4c2bc9d1cf87c872332bc6d919614dc33132868fe8a00cdbef250"
	l4NewConnRateDownSHA        = "fb2987d6d82d8db1c8e19607d71fbbdfc872e88d7575a0fbdcc9a2604d9a279a"
)

func TestL4NewConnectionRate300Contract(t *testing.T) {
	previous := l4NewConnRateVersion - 1
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{l4NewConnRateID + ".up.sql", l4NewConnRateUpSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", previous),
			fmt.Sprintf("(SELECT max(version) FROM schema_migrations) <> %d", previous),
			"migration_id='" + l4NewConnRatePreviousID + "'",
			"checksum_sha256='" + l4NewConnRatePreviousUpSHA + "'",
			"down_checksum_sha256='" + l4NewConnRatePreviousDownSH + "'",
			fmt.Sprintf("ERRCODE='P%d0'", l4NewConnRateVersion),
			"max_new_connections_per_client_per_second BETWEEN 0 AND 100000",
			"new_connection_burst BETWEEN 0 AND 100000", "new_connection_ban_seconds BETWEEN 0 AND 86400",
			"validate_l4_runtime_spec_293(target_stream_id,target_scope_id,target_site_id,runtime_spec-'new_conn_rate')",
			"ARRAY['ban_seconds','burst','rate_per_second']", "l4_publish_intents_runtime_spec_300",
		}},
		{l4NewConnRateID + ".down.sql", l4NewConnRateDownSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", l4NewConnRateVersion),
			"migration_id='" + l4NewConnRateID + "'",
			fmt.Sprintf("ERRCODE='P%d1'", l4NewConnRateVersion), fmt.Sprintf("ERRCODE='P%d2'", l4NewConnRateVersion),
			"l4_publish_intents_runtime_spec_293",
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
