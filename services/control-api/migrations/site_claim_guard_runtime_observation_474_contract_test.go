package migrations_test

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"

	controlmigrations "github.com/cdnca/cdnca/services/control-api/migrations"
)

// (assigned 476; local placeholder 474 guarding the integration head
// 473). Every number the merge renumbering touches is here.
const (
	siteClaimGuardObservationVersion         = 474
	siteClaimGuardObservationID              = "474_site_claim_guard_runtime_observation"
	siteClaimGuardObservationPreviousID      = "473_dns_zone_provider_apex"
	siteClaimGuardObservationPreviousUpSHA   = "f8ba83c2aa3d8a7ba315e9d3b6724ef30eff5251999b1e210150af969d1b3ba3"
	siteClaimGuardObservationPreviousDownSHA = "b12755c42899557bb44072b6d486f981aaf3120e0c6ba77386f51fd08a7415f1"
	siteClaimGuardObservationUpSHA           = "2ea02118cbf180d14424e57b201a8c76dc16c5908bc8f498874056cda402fb5c"
	siteClaimGuardObservationDownSHA         = "a9c1f44b863a6358876eca432fb44c8f4fd2f5cefea559124cd4a7b8b4c13058"
)

func TestSiteClaimGuardRuntimeObservation474Contract(t *testing.T) {
	previous := siteClaimGuardObservationVersion - 1
	observation := "ARRAY['ipv6_runtime_state','ipv6_runtime_source_revision','updated_at']"
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{siteClaimGuardObservationID + ".up.sql", siteClaimGuardObservationUpSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", previous),
			fmt.Sprintf("(SELECT max(version) FROM schema_migrations) <> %d", previous),
			"migration_id='" + siteClaimGuardObservationPreviousID + "'",
			"checksum_sha256='" + siteClaimGuardObservationPreviousUpSHA + "'",
			"down_checksum_sha256='" + siteClaimGuardObservationPreviousDownSHA + "'",
			fmt.Sprintf("ERRCODE='P%d0'", siteClaimGuardObservationVersion),
			"to_jsonb(NEW) - " + observation + " IS DISTINCT FROM",
			"to_jsonb(OLD) - " + observation + ") AND EXISTS (",
			"claim.state IN ('claimed','uncertain')",
			"USING ERRCODE = 'P8903'",
			"DROP TRIGGER sites_provider_mutation_claim_guard_089 ON sites;",
			"BEFORE UPDATE OR DELETE ON sites",
			"EXECUTE FUNCTION block_dns_site_claimed_authority_mutation_474()",
		}},
		{siteClaimGuardObservationID + ".down.sql", siteClaimGuardObservationDownSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", siteClaimGuardObservationVersion),
			"migration_id='" + siteClaimGuardObservationID + "'",
			fmt.Sprintf("ERRCODE='P%d1'", siteClaimGuardObservationVersion),
			"EXECUTE FUNCTION block_dns_site_claimed_authority_mutation_089()",
			"DROP FUNCTION block_dns_site_claimed_authority_mutation_474();",
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
		if guard, mutation := strings.Index(text, "RAISE EXCEPTION"), strings.Index(text, "DROP TRIGGER"); guard < 0 || mutation < guard {
			t.Errorf("%s guard must precede the first mutation", script.name)
		}
	}
}
