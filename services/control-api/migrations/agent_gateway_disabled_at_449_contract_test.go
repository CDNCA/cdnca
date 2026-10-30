package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// Migration 449 (agent_gateways.disabled_at for the disabled
// Gateway drain grace, ADR 0013 §5.2), split out of 448 in merge-batch12.
// Everything that changes with a renumbering is here.
const (
	migration449Version         = 449
	migration449ID              = "449_agent_gateway_disabled_at"
	migration449PreviousID      = "448_agent_gateway_settings"
	migration449PreviousUpSHA   = "c474df5e04ff73f9b95d1c6545aaa1019750ff934f0f61d6fba5d9085222fcef"
	migration449PreviousDownSHA = "904abf00f6c180f56e633ca66f208a5ebbaa7bb02c49450e33b777d5206830ab"
	migration449UpSHA           = "ee29f2f7729d456bd7194e9730e13ebc235b8d8e5e934895f847bebffebd8afa"
	migration449DownSHA         = "dd63d5ce247fa273fae90b965776a165aca3cbde6a9e617fc26c6104a7654fda"
)

func TestAgentGatewayDisabledAt449Contract(t *testing.T) {
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{migration449ID + ".up.sql", migration449UpSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration449Version-1),
			fmt.Sprintf("(SELECT max(version) FROM schema_migrations) <> %d", migration449Version-1),
			"migration_id='" + migration449PreviousID + "'", migration449PreviousUpSHA, migration449PreviousDownSHA,
			"ERRCODE='P4490'", "ADD COLUMN disabled_at timestamptz",
		}},
		{migration449ID + ".down.sql", migration449DownSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration449Version),
			"migration_id='" + migration449ID + "'", "ERRCODE='P4491'", "DROP COLUMN disabled_at",
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
