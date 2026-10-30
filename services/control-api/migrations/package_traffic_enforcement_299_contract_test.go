package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// Migration 299 (G9c-① package traffic enforcement) sits on the exact verified
// 298 head. Renumbering on merge only touches this block and the two scripts.
const (
	packageTrafficEnforcementVersion        = 299
	packageTrafficEnforcementPreviousID     = "298_payment_channels"
	packageTrafficEnforcementPreviousUpSHA  = "cb59bdfe8ad4b3e4f24c83f7ae98d3f443e2f77475c5518695a61e64c0fab155"
	packageTrafficEnforcementPreviousDownSH = "f34e609b85ce1fd697586b4645c8fe17189af972a758b490fac9827bffe68513"
	packageTrafficEnforcementUpSHA          = "61b0f33fbdade032abffa52015271acb3b4fb117be787c889663ee27d75b9824"
	packageTrafficEnforcementDownSHA        = "8b1fcea6bf466652afc1e876f80556aa30a61898dd1abcc34ee31a52c30be091"
)

func TestPackageTrafficEnforcement299Contract(t *testing.T) {
	previous := packageTrafficEnforcementVersion - 1
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{"299_package_traffic_enforcement.up.sql", packageTrafficEnforcementUpSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", previous),
			fmt.Sprintf("(SELECT max(version) FROM schema_migrations) <> %d", previous),
			packageTrafficEnforcementPreviousID, packageTrafficEnforcementPreviousUpSHA,
			packageTrafficEnforcementPreviousDownSH, "ERRCODE='P2990'",
			"CREATE TABLE package_traffic_site_suspensions", "CREATE TABLE package_traffic_enforcement_schedule",
			"ON package_traffic_site_suspensions (site_id) WHERE recovered_at IS NULL",
			"'package.traffic.suspended.zh-cn'", "'package.traffic.recovered.zh-cn'",
		}},
		{"299_package_traffic_enforcement.down.sql", packageTrafficEnforcementDownSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", packageTrafficEnforcementVersion),
			"299_package_traffic_enforcement", "ERRCODE='P2992'", "WHERE recovered_at IS NULL",
			"DISABLE TRIGGER notification_templates_immutable", "ENABLE TRIGGER notification_templates_immutable",
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
