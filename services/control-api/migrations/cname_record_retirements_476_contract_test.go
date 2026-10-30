package migrations_test

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"

	controlmigrations "github.com/cdnca/cdnca/services/control-api/migrations"
)

// (assigned 478, renumbered 476 at merge; the guard pins 474 by checksum and
// expects the head 475). Every number the merge renumbering touches is here.
const (
	cnameRetirementsVersion        = 476
	cnameRetirementsID             = "476_cname_record_retirements"
	cnameRetirementsPinnedID       = "474_site_claim_guard_runtime_observation"
	cnameRetirementsPinnedUpSHA    = "2ea02118cbf180d14424e57b201a8c76dc16c5908bc8f498874056cda402fb5c"
	cnameRetirementsPinnedDownSHA  = "a9c1f44b863a6358876eca432fb44c8f4fd2f5cefea559124cd4a7b8b4c13058"
	cnameRetirementsUpSHA          = "174073e52e00432cf8e82224cfd962c1ff59e887212baab3199378910fc0bd5c"
	cnameRetirementsDownSHA        = "5e03007fa6e62255714591002896bed68dca0a4b8fbf03e569fee856d10231ce"
	cnameRetirementsRotationRefuse = "generated CNAME regeneration must rotate its HMAC key"
)

func TestCNAMERecordRetirements476Contract(t *testing.T) {
	previous := cnameRetirementsVersion - 1
	for _, script := range []struct {
		name, sha string
		required  []string
		forbidden []string
	}{
		{cnameRetirementsID + ".up.sql", cnameRetirementsUpSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", previous),
			fmt.Sprintf("(SELECT max(version) FROM schema_migrations) <> %d", previous),
			"migration_id='" + cnameRetirementsPinnedID + "'",
			"checksum_sha256='" + cnameRetirementsPinnedUpSHA + "'",
			"down_checksum_sha256='" + cnameRetirementsPinnedDownSHA + "'",
			fmt.Sprintf("ERRCODE='P%d0'", cnameRetirementsVersion),
			"CREATE TABLE cname_record_retirements (",
			"claim_id uuid NOT NULL UNIQUE",
			"reason IN ('site_deleted','generation_rotated')",
			"BEFORE INSERT OR UPDATE OR DELETE ON cname_record_retirements",
			"BEFORE TRUNCATE ON cname_record_retirements",
			"CREATE FUNCTION cname_claim_released_476(retired_claim_id uuid)",
			"CREATE OR REPLACE FUNCTION assert_cname_allocation_consistency_113()",
		}, []string{cnameRetirementsRotationRefuse}},
		{cnameRetirementsID + ".down.sql", cnameRetirementsDownSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", cnameRetirementsVersion),
			"migration_id='" + cnameRetirementsID + "'",
			fmt.Sprintf("ERRCODE='P%d1'", cnameRetirementsVersion),
			cnameRetirementsRotationRefuse,
			"DROP TABLE cname_record_retirements;",
		}, nil},
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
		for _, forbidden := range script.forbidden {
			if strings.Contains(text, forbidden) {
				t.Errorf("%s still contains %q", script.name, forbidden)
			}
		}
		if guard, mutation := strings.Index(text, "RAISE EXCEPTION"), strings.Index(text, "CREATE "); guard < 0 || mutation < guard {
			t.Errorf("%s guard must precede the first mutation", script.name)
		}
	}
}
