package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// Migration 317 (FX57 逾期停服) placeholder number: on merge the coordinator
// renumbers it after the integration head. Every value that moves with the
// renumber is kept in this block.
const (
	secondaryVerificationHolds317Version         = "317"
	secondaryVerificationHolds317PreviousCount   = "316"
	secondaryVerificationHolds317PreviousID      = "316_l4_toa"
	secondaryVerificationHolds317PreviousUpSHA   = "18e4b00b627ff5367dfcfbcff59af5b8dae21dbcd26820eaa53c94c103bc87e3"
	secondaryVerificationHolds317PreviousDownSHA = "3afc4e8e5fdee2bc7953d7659e1df6526adfcb4e1645184dc691600298123ec0"
	secondaryVerificationHolds317UpSHA           = "64ca2e1ae3498152b5b0d9d28f494f031de87d2ecd8c8416e7163c3ddd510cac"
	secondaryVerificationHolds317DownSHA         = "926397567843234f34420ae3ba06c9d298044b59ff903d1cfca1adf64f9e1cbb"
)

func TestIdentitySecondaryVerificationSiteHolds317Contract(t *testing.T) {
	name := secondaryVerificationHolds317Version + "_identity_secondary_verification_site_holds"
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{name + ".up.sql", secondaryVerificationHolds317UpSHA, []string{
			"(SELECT count(*) FROM schema_migrations) <> " + secondaryVerificationHolds317PreviousCount,
			"(SELECT max(version) FROM schema_migrations) <> " + secondaryVerificationHolds317PreviousCount,
			secondaryVerificationHolds317PreviousID, secondaryVerificationHolds317PreviousUpSHA, secondaryVerificationHolds317PreviousDownSHA,
			"ERRCODE='P3170'", "CREATE TABLE identity_secondary_verification_site_holds",
			"CHECK (disabled_site OR locked_site)", "WHERE released_at IS NULL",
			"GRANT SELECT, INSERT, UPDATE ON identity_secondary_verification_site_holds TO cdnca_control_app, cdnca_control_runtime",
		}},
		{name + ".down.sql", secondaryVerificationHolds317DownSHA, []string{
			"(SELECT count(*) FROM schema_migrations) <> " + secondaryVerificationHolds317Version, name, "ERRCODE='P3171'",
			"EXISTS (SELECT 1 FROM identity_secondary_verification_site_holds)", "DROP TABLE identity_secondary_verification_site_holds",
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
	for name, sha := range map[string]string{
		secondaryVerificationHolds317PreviousID + ".up.sql":   secondaryVerificationHolds317PreviousUpSHA,
		secondaryVerificationHolds317PreviousID + ".down.sql": secondaryVerificationHolds317PreviousDownSHA,
	} {
		raw, err := FS.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		if got := fmt.Sprintf("%x", sha256.Sum256(raw)); got != sha {
			t.Fatalf("predecessor %s is not the pinned head: %s", name, got)
		}
	}
}
