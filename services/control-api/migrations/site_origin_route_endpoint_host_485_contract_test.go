package migrations_test

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"

	controlmigrations "github.com/cdnca/cdnca/services/control-api/migrations"
)

// (A15/ORIGIN-DB-01): 485 follows
// 484_escalate_reseller_policies (pinned by checksum); BATCH reserves 488,
// renumbering moves the P485x codes with the version.
const (
	originRouteHostVersion  = 485
	originRouteHostID       = "485_site_origin_route_endpoint_host"
	originRouteHostPinned   = "484_escalate_reseller_policies"
	originRouteHostPinUpSHA = "447d48e465ee270bfe13ff03fda8fe38012fbab255c2d2891f8d8ab92070717f"
	originRouteHostPinDnSHA = "c5e0b5c384938132bd631a96aa050d68bb9935e6f07aa8b68337670de68ec6c7"
	originRouteHostUpSHA    = "c64d5358608d5c625f6a1cd56ca5e23b9165389f73f3e0ebd9b9e20cabd8ebec"
	originRouteHostDownSHA  = "c6809a2fd482ecc8dd2c36c4b6cb937f226aee59c78a442181b7ca555321bbed"
	originRouteHostFunction = "site_origin_route_host_valid_485"
)

func TestSiteOriginRouteEndpointHost485Contract(t *testing.T) {
	for _, script := range []struct {
		name, sha string
		required  []string
		mutation  string
	}{
		{originRouteHostID + ".up.sql", originRouteHostUpSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", originRouteHostVersion-1),
			"migration_id='" + originRouteHostPinned + "'",
			"checksum_sha256='" + originRouteHostPinUpSHA + "'",
			"down_checksum_sha256='" + originRouteHostPinDnSHA + "'",
			"ALTER COLUMN host TYPE text USING host(host)",
			"CHECK (" + originRouteHostFunction + "(host))",
			"'169.254.0.0/16'", "'fe80::/10'", "'255.255.255.255'", "'0.0.0.0'", "'::'",
			"ERRCODE='P4850'",
		}, "CREATE FUNCTION"},
		{originRouteHostID + ".down.sql", originRouteHostDownSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", originRouteHostVersion),
			"migration_id='" + originRouteHostID + "'",
			"ERRCODE='P4851'", "ERRCODE='P4852'",
			"ALTER COLUMN host TYPE inet USING host::inet",
			"DROP FUNCTION " + originRouteHostFunction + "(text)",
		}, "ALTER TABLE"},
	} {
		raw, err := controlmigrations.FS.ReadFile(script.name)
		if err != nil {
			t.Fatal(err)
		}
		if got := fmt.Sprintf("%x", sha256.Sum256(raw)); got != script.sha {
			t.Fatalf("%s checksum drift: %s", script.name, got)
		}
		text := string(raw)
		for _, required := range script.required {
			if !strings.Contains(text, required) {
				t.Errorf("%s missing %q", script.name, required)
			}
		}
		if guard, mutation := strings.Index(text, "RAISE EXCEPTION"), strings.Index(text, script.mutation); guard < 0 || mutation < guard {
			t.Errorf("%s mutates before its guard", script.name)
		}
	}
}
