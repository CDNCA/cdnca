package migrations_test

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"

	controlmigrations "github.com/cdnca/cdnca/services/control-api/migrations"
)

// (ADR 0018 RS-01): 480 follows 479_cname_cancelled_intent_fails_site
// (pinned by checksum); renumbering moves the P48xx codes with the version.
const (
	resellerCoreVersion       = 480
	resellerCoreID            = "480_reseller_core"
	resellerCorePinnedID      = "479_cname_cancelled_intent_fails_site"
	resellerCorePinnedUpSHA   = "c75ffc514f776a7ec0161b29738bb1a6e15eaa896e5335954ee498d837bf6050"
	resellerCorePinnedDownSHA = "3479adb4c3b7feec74a7a88a4ab677e4d3e1abc871993be868b797c2020b9a9b"
	resellerCoreUpSHA         = "feaf0c58cb8f33bd5fc0ec9a0c475adc00a0d62b23dc9a97c4880931e6603852"
	resellerCoreDownSHA       = "8a78b5ca212b82ab5f1ca38696e40b3f6b4d6e1aa4c5274374af2a97a7b00410"
)

func TestResellerCore480Contract(t *testing.T) {
	previous := resellerCoreVersion - 1
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{resellerCoreID + ".up.sql", resellerCoreUpSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", previous),
			fmt.Sprintf("(SELECT max(version) FROM schema_migrations) <> %d", previous),
			"migration_id='" + resellerCorePinnedID + "'",
			"checksum_sha256='" + resellerCorePinnedUpSHA + "'",
			"down_checksum_sha256='" + resellerCorePinnedDownSHA + "'",
			fmt.Sprintf("ERRCODE='P%d0'", resellerCoreVersion),
			"CREATE TABLE reseller_profiles",
			"ALTER TABLE tenants ADD COLUMN parent_scope_id uuid REFERENCES access_scopes(id)",
			"wholesale_price_list text NOT NULL DEFAULT 'standard'",
			"prepaid_account_id uuid REFERENCES billing_accounts(id)",
			"low_balance_minor bigint NOT NULL DEFAULT 0",
			"'reseller.packages.manage'", "'reseller.customers.manage'", "'reseller.customers.read'",
			"BEFORE INSERT ON node_line_group_grants",
			"CREATE FUNCTION reseller_products_using_line_group_480(reseller uuid, group_owner uuid, group_id uuid)",
			"ERRCODE='P4801'", "ERRCODE='P4802'", "ERRCODE='P4803'", "ERRCODE='P4804'", "ERRCODE='P4805'",
			"ERRCODE='P4806'", "ERRCODE='P4807'", "ERRCODE='P4808'", "ERRCODE='P4809'",
		}},
		{resellerCoreID + ".down.sql", resellerCoreDownSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", resellerCoreVersion),
			"migration_id='" + resellerCoreID + "'",
			fmt.Sprintf("ERRCODE='P%d10'", resellerCoreVersion/10),
			fmt.Sprintf("ERRCODE='P%d11'", resellerCoreVersion/10),
			"DROP TABLE reseller_profiles",
			"ALTER TABLE tenants DROP COLUMN parent_scope_id",
		}},
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
		guard, mutation := strings.Index(text, "RAISE EXCEPTION"), strings.Index(text, "CREATE TABLE")
		if mutation < 0 {
			mutation = strings.Index(text, "DROP ")
		}
		if guard < 0 || mutation < guard {
			t.Errorf("%s guard must precede the first mutation", script.name)
		}
	}
}
