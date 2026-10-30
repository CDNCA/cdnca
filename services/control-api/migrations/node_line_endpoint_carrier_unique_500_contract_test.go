package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// Migration 500 (NET-02): line group endpoints are unique per
// (carrier, address, port), so one IP can sit on several carrier lines.
// The merge renumbered 497→500 (predecessor 499).
const (
	migration500Version         = 500
	migration500PreviousVersion = 499
	migration500ID              = "500_node_line_endpoint_carrier_unique"
	migration500PreviousID      = "499_l4_forward_line_cname"
	migration500UpSHA           = "78742033724ff34b37c46cddd0eeb1382d582ba4e19d68cbd647a52190e6ffd9"
	migration500DownSHA         = "98e26164798934be3f67f6466e0bd24de6bc3055c2709f3d7b90341fa1a04de1"
)

func TestNodeLineEndpointCarrierUnique500Contract(t *testing.T) {
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{migration500ID + ".up.sql", migration500UpSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration500PreviousVersion),
			fmt.Sprintf("(SELECT max(version) FROM schema_migrations) <> %d", migration500PreviousVersion),
			"migration_id='" + migration500PreviousID + "'", migration499UpSHA, migration499DownSHA,
			"ERRCODE='P5000'", "ERRCODE='P5001'",
			"UNIQUE (tenant_scope_id, line_group_id, config_revision, carrier, address, port)",
		}},
		{migration500ID + ".down.sql", migration500DownSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration500Version),
			"migration_id='" + migration500ID + "'", "ERRCODE='P5002'", "ERRCODE='P5003'",
			"ADD UNIQUE (tenant_scope_id, line_group_id, config_revision, address, port)",
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
