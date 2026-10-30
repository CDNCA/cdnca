package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// Migration 447 (GW-06/GW-08: Agent Gateway registry, binding
// tokens and Gateway certificates), a placeholder number on top of 433.
// Everything that changes with a renumbering is here.
const (
	migration447Version         = 447
	migration447ID              = "447_agent_gateways"
	migration447PreviousID      = "446_migrate_import"
	migration447PreviousUpSHA   = "86a1e1d2c969e966fe9585564bbf0b8a230e0b6980a877c35be9c05002ca7725"
	migration447PreviousDownSHA = "43bfa7f0ddedd8969fd66278d46c31941fcb406b5fcef584217d33cba0dcbbb1"
	migration447UpSHA           = "3441bdb3855cf1b57c07bb959eac937497c6737711925ccd60a31cf792ab2607"
	migration447DownSHA         = "ef73ed3669c888610b958b794265b40744e53114bff66a6c7df2b1c6b30ebe4b"
)

func TestAgentGateways447Contract(t *testing.T) {
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{migration447ID + ".up.sql", migration447UpSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration447Version-1),
			fmt.Sprintf("(SELECT max(version) FROM schema_migrations) <> %d", migration447Version-1),
			"migration_id='" + migration447PreviousID + "'", migration447PreviousUpSHA, migration447PreviousDownSHA,
			"ERRCODE='P4470'", "secret_sha256 bytea NOT NULL", "'system.gateway.manage'",
		}},
		{migration447ID + ".down.sql", migration447DownSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration447Version),
			"migration_id='" + migration447ID + "'", "ERRCODE='P4471'", "ERRCODE='P4472'",
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
