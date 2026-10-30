package migrations_test

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"

	controlmigrations "github.com/cdnca/cdnca/services/control-api/migrations"
)

// (ADR 0018 RS-03): 483 follows 482_reseller_impersonation
// (pinned by checksum); renumbering moves the P483x codes with the version.
const (
	resellerBillingVersion  = 483
	resellerBillingID       = "483_reseller_billing"
	resellerBillingPinned   = "482_reseller_impersonation"
	resellerBillingPinUpSHA = "0dac3d102451e85c7a0c18be2f067d1efc3d57a9250d0e688383de2c3a93609f"
	resellerBillingPinDnSHA = "59951ed53896a1e8a6646738ffcf7ac960b60bba75c222b9d011ac978b288d48"
	resellerBillingUpSHA    = "062c1b0db7110049aef458683e9d3214c2d74dba683005e7d66642b367294d6f"
	resellerBillingDownSHA  = "1c03ce007118f84f1bbc03df23cb38b5fe7cf9c2f5daad5da4e290e2178a096c"
)

func TestResellerBilling483Contract(t *testing.T) {
	pinned, err := controlmigrations.FS.ReadFile(resellerBillingPinned + ".up.sql")
	if err != nil {
		t.Fatal(err)
	}
	if got := fmt.Sprintf("%x", sha256.Sum256(pinned)); got != resellerBillingPinUpSHA {
		t.Fatalf("482 checksum drift: %s", got)
	}
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{resellerBillingID + ".up.sql", resellerBillingUpSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", resellerBillingVersion-1),
			"migration_id='" + resellerBillingPinned + "'",
			"checksum_sha256='" + resellerBillingPinUpSHA + "'",
			"down_checksum_sha256='" + resellerBillingPinDnSHA + "'",
			"ALTER TABLE package_orders ADD COLUMN seller_scope_id uuid",
			"ALTER TABLE package_orders ADD COLUMN wholesale_minor bigint",
			"CHECK (funding_source IN ('balance', 'provider', 'reseller'))",
			"'migrate_import_credit','reseller_sale','reseller_wholesale'",
			"CREATE FUNCTION reseller_wholesale_minor_483(reseller uuid, product_spec jsonb, sale_period text)",
			"CREATE OR REPLACE FUNCTION assert_package_commercial_transaction()",
			"CHECK (prepaid_account_id = scope_id)",
			"'reseller.prepaid.low_balance'",
			"ERRCODE='P4830'", "ERRCODE='P4831'", "ERRCODE='P4832'", "ERRCODE='P4833'", "ERRCODE='P4834'", "ERRCODE='P4835'",
		}},
		{resellerBillingID + ".down.sql", resellerBillingDownSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", resellerBillingVersion),
			"migration_id='" + resellerBillingID + "'",
			"ERRCODE='P4836'", "ERRCODE='P4837'",
			"ALTER TABLE package_orders DROP COLUMN seller_scope_id",
			"CHECK (funding_source IN ('balance', 'provider'))",
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
		if guard, mutation := strings.Index(text, "RAISE EXCEPTION"), strings.Index(text, "ALTER TABLE"); guard < 0 ||
			mutation < guard {
			t.Errorf("%s guard must precede the first mutation", script.name)
		}
	}
	// Down restores the 446 commerce guard and shape check byte for byte.
	down, _ := controlmigrations.FS.ReadFile(resellerBillingID + ".down.sql")
	source, _ := controlmigrations.FS.ReadFile("446_migrate_import.up.sql")
	text := string(source)
	constraints := text[strings.Index(text, "ALTER TABLE billing_transactions DROP CONSTRAINT billing_transactions_operation_check;"):strings.Index(text, "CREATE OR REPLACE FUNCTION assert_package_commercial_transaction()")]
	functionStart := strings.Index(text, "CREATE OR REPLACE FUNCTION assert_package_commercial_transaction()")
	function := text[functionStart : strings.Index(text[functionStart:], "\n$$;")+functionStart+len("\n$$;")]
	for _, part := range []string{strings.TrimSpace(constraints), function} {
		if !strings.Contains(string(down), part) {
			t.Errorf("483 down does not restore %.60q from 446", part)
		}
	}
}
