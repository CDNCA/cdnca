package migrations_test

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"

	controlmigrations "github.com/cdnca/cdnca/services/control-api/migrations"
)

// (ADR 0018 RS-04): 484 follows 483_reseller_billing
// (pinned by checksum); renumbering moves the P484x codes with the version.
const (
	escalateResellerVersion   = 484
	escalateResellerID        = "484_escalate_reseller_policies"
	escalateResellerPinned    = "483_reseller_billing"
	escalateResellerPinUpSHA  = "062c1b0db7110049aef458683e9d3214c2d74dba683005e7d66642b367294d6f"
	escalateResellerPinDnSHA  = "1c03ce007118f84f1bbc03df23cb38b5fe7cf9c2f5daad5da4e290e2178a096c"
	escalateResellerUpSHA     = "447d48e465ee270bfe13ff03fda8fe38012fbab255c2d2891f8d8ab92070717f"
	escalateResellerDownSHA   = "c5e0b5c384938132bd631a96aa050d68bb9935e6f07aa8b68337670de68ec6c7"
	escalateResellerOwnerCode = "P4842"
)

func TestEscalateResellerPolicies484Contract(t *testing.T) {
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{escalateResellerID + ".up.sql", escalateResellerUpSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", escalateResellerVersion-1),
			"migration_id='" + escalateResellerPinned + "'",
			"checksum_sha256='" + escalateResellerPinUpSHA + "'",
			"down_checksum_sha256='" + escalateResellerPinDnSHA + "'",
			"product.owner_scope_id = NEW.owner_scope_id",
			"BEFORE INSERT OR UPDATE ON escalate_package_policies",
			"ERRCODE='P4840'", "ERRCODE='P4841'", "ERRCODE='" + escalateResellerOwnerCode + "'",
		}},
		{escalateResellerID + ".down.sql", escalateResellerDownSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", escalateResellerVersion),
			"migration_id='" + escalateResellerID + "'",
			"ERRCODE='P4843'",
			"DROP TRIGGER escalate_package_policies_owner_484 ON escalate_package_policies",
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
		guard := strings.Index(text, "RAISE EXCEPTION")
		mutation := strings.Index(text, "CREATE FUNCTION")
		if mutation < 0 {
			mutation = strings.Index(text, "DROP TRIGGER")
		}
		if guard < 0 || mutation < guard {
			t.Errorf("%s guard must precede the first mutation", script.name)
		}
	}
	// The pinned predecessor is the file in this tree.
	for _, file := range []struct{ name, sha string }{
		{escalateResellerPinned + ".up.sql", escalateResellerPinUpSHA},
		{escalateResellerPinned + ".down.sql", escalateResellerPinDnSHA},
	} {
		raw, err := controlmigrations.FS.ReadFile(file.name)
		if err != nil {
			t.Fatal(err)
		}
		if got := fmt.Sprintf("%x", sha256.Sum256(raw)); got != file.sha {
			t.Errorf("%s pinned %s, file is %s", file.name, file.sha, got)
		}
	}
}
