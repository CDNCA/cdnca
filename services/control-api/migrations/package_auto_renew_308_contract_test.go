package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// Migration 308 (G6-c 套餐自动续费) is a placeholder on the exact verified 307
// head; the coordinator renumbers it on merge. Number, previous head and
// checksums are kept together here.
const (
	packageAutoRenewVersion      = "308"
	packageAutoRenewPrevious     = "307_site_origin_keepalive"
	packageAutoRenewPreviousUp   = "64af8a7720f0d553a0e63c6101c19729c6433a5df4996c67b1b3cbe95e9299b1"
	packageAutoRenewPreviousDown = "fe0466749f4fb83f1d655a053c65f86dda4aa33d38c51fd512ac84ca711e456a"
	packageAutoRenewUpSHA        = "cf00f85140ed657e76bcff2cbb0db8c5a5f284d82dbd459a2e0fbf2e2ef3a5df"
	packageAutoRenewDownSHA      = "3dd8a5febfb33f7676245c9b6f41f44d3d2ad6846456b0d3fe760aa6530d4b4b"
)

func TestPackageAutoRenew308Contract(t *testing.T) {
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{packageAutoRenewVersion + "_package_auto_renew.up.sql", packageAutoRenewUpSHA, []string{
			"(SELECT count(*) FROM schema_migrations) <> 307", "(SELECT max(version) FROM schema_migrations) <> 307",
			packageAutoRenewPrevious, packageAutoRenewPreviousUp, packageAutoRenewPreviousDown,
			"ERRCODE='P3080'", "CREATE TABLE package_subscription_auto_renew_settings",
			"CREATE TABLE package_auto_renew_attempts", "UNIQUE (subscription_id, ends_at, attempt_no)",
			"lead_hours integer NOT NULL CHECK (lead_hours BETWEEN 1 AND 720)",
			"'package.auto_renew.succeeded'", "'package.auto_renew.failed'",
			"('package.auto_renew.succeeded.zh-cn', 1, 'sms'", "('package.auto_renew.failed.zh-cn', 1, 'email'",
		}},
		{packageAutoRenewVersion + "_package_auto_renew.down.sql", packageAutoRenewDownSHA, []string{
			"(SELECT count(*) FROM schema_migrations) <> 308", "308_package_auto_renew",
			"ERRCODE='P3081'", "ERRCODE='P3082'", "DROP TABLE package_auto_renew_attempts",
			"DROP TABLE package_subscription_auto_renew_settings",
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
