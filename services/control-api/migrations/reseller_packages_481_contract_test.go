package migrations_test

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"

	controlmigrations "github.com/cdnca/cdnca/services/control-api/migrations"
)

// (ADR 0018 RS-02): 481 follows 480_reseller_core (pinned by
// checksum); renumbering moves the P48xx codes with the version.
const (
	resellerPackagesVersion = 481
	resellerPackagesID      = "481_reseller_packages"
	resellerPackagesPinned  = "480_reseller_core"
	resellerPackagesUpSHA   = "0090f42d63231589ad8eff70f4d230da7b38bd9cb2a1080eae5cd8507c68b2b7"
	resellerPackagesDownSHA = "d23d1fa3bb822e9f2163be035e1406d4e4adc43723eec0453476467d9879e7ac"
)

func TestResellerPackages481Contract(t *testing.T) {
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{resellerPackagesID + ".up.sql", resellerPackagesUpSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", resellerPackagesVersion-1),
			"migration_id='" + resellerPackagesPinned + "'",
			"checksum_sha256='" + resellerCoreUpSHA + "'",
			"down_checksum_sha256='" + resellerCoreDownSHA + "'",
			"ALTER TABLE package_groups ADD COLUMN owner_scope_id uuid REFERENCES access_scopes(id)",
			"ALTER TABLE package_products ADD COLUMN owner_scope_id uuid REFERENCES access_scopes(id)",
			"ON package_groups (owner_scope_id, lower(name)) WHERE deleted_at IS NULL",
			"ON package_products (owner_scope_id, lower(name)) WHERE deleted_at IS NULL",
			"CREATE TABLE reseller_wholesale_prices",
			"CREATE OR REPLACE FUNCTION bind_package_catalog_audit_090()",
			"CREATE OR REPLACE FUNCTION protect_package_catalog_state_090()",
			"CREATE OR REPLACE FUNCTION validate_package_offer_publication_event_090()",
			"CREATE OR REPLACE FUNCTION reseller_products_using_line_group_480(reseller uuid, group_owner uuid, group_id uuid)",
			"product.spec->>'node_group_id' = group_id::text OR product.spec->>'backup_node_group_id' = group_id::text",
			"package_catalog_current_backend_owns_xid_130(source.xmin)",
			"ERRCODE='P4812'", "ERRCODE='P4813'", "ERRCODE='P4814'", "ERRCODE='P4815'", "ERRCODE='P4816'",
		}},
		{resellerPackagesID + ".down.sql", resellerPackagesDownSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", resellerPackagesVersion),
			"migration_id='" + resellerPackagesID + "'",
			"ERRCODE='P4817'", "ERRCODE='P4818'",
			"CREATE UNIQUE INDEX package_products_name_active_unique",
			"ALTER TABLE package_products DROP COLUMN owner_scope_id",
			"DROP TABLE reseller_wholesale_prices",
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
		guard, mutation := strings.Index(text, "RAISE EXCEPTION"), strings.Index(text, "ALTER TABLE")
		if mutation < 0 || strings.Index(text, "CREATE OR REPLACE") < mutation {
			mutation = strings.Index(text, "CREATE OR REPLACE")
		}
		if guard < 0 || mutation < guard {
			t.Errorf("%s guard must precede the first mutation", script.name)
		}
	}
	// The down script restores the exact 090/130/480 function bodies.
	down, _ := controlmigrations.FS.ReadFile(resellerPackagesID + ".down.sql")
	for _, original := range []struct{ file, start string }{
		{"090_package_offer_publication.up.sql", "CREATE FUNCTION bind_package_catalog_audit_090()"},
		{"090_package_offer_publication.up.sql", "CREATE FUNCTION validate_package_offer_publication_event_090()"},
		{"130_package_catalog_subtransaction_xid_guard.up.sql", "CREATE OR REPLACE FUNCTION protect_package_catalog_state_090()"},
		{"480_reseller_core.up.sql", "CREATE FUNCTION reseller_products_using_line_group_480("},
	} {
		raw, err := controlmigrations.FS.ReadFile(original.file)
		if err != nil {
			t.Fatal(err)
		}
		text := string(raw)
		start := strings.Index(text, original.start)
		end := strings.Index(text[start:], "\n$$;") + start + len("\n$$;")
		body := strings.Replace(text[start:end], "CREATE FUNCTION", "CREATE OR REPLACE FUNCTION", 1)
		if start < 0 || !strings.Contains(string(down), body) {
			t.Errorf("481 down does not restore %s from %s", original.start, original.file)
		}
	}
}
