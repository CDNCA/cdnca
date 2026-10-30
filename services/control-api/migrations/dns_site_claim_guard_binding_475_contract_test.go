package migrations_test

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"

	controlmigrations "github.com/cdnca/cdnca/services/control-api/migrations"
)

// (475; guards the integration head 474 site claim guard runtime observation).
// Every number the merge renumbering touches is here.
const (
	dnsSiteClaimGuardVersion         = 475
	dnsSiteClaimGuardID              = "475_dns_site_claim_guard_binding"
	dnsSiteClaimGuardPreviousID      = "474_site_claim_guard_runtime_observation"
	dnsSiteClaimGuardPreviousUpSHA   = "2ea02118cbf180d14424e57b201a8c76dc16c5908bc8f498874056cda402fb5c"
	dnsSiteClaimGuardPreviousDownSHA = "a9c1f44b863a6358876eca432fb44c8f4fd2f5cefea559124cd4a7b8b4c13058"
	dnsSiteClaimGuardUpSHA           = "8838b71afdb4b12630cdc9ff74c2e40a78decc46152eccdbe5fe7a8351c26256"
	dnsSiteClaimGuardDownSHA         = "fba7ba32b9b31622724917139cbd201e5b41b80ef853c546187e985a50eeebe8"
)

func TestDNSSiteClaimGuardBinding475Contract(t *testing.T) {
	previous := dnsSiteClaimGuardVersion - 1
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{dnsSiteClaimGuardID + ".up.sql", dnsSiteClaimGuardUpSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", previous),
			fmt.Sprintf("(SELECT max(version) FROM schema_migrations) <> %d", previous),
			"migration_id='" + dnsSiteClaimGuardPreviousID + "'",
			"checksum_sha256='" + dnsSiteClaimGuardPreviousUpSHA + "'",
			"down_checksum_sha256='" + dnsSiteClaimGuardPreviousDownSHA + "'",
			fmt.Sprintf("ERRCODE='P%d0'", dnsSiteClaimGuardVersion),
			"NEW.revision IS DISTINCT FROM OLD.revision",
			"dns_reconcile_site_config_digest_089(NEW) IS DISTINCT FROM dns_reconcile_site_config_digest_089(OLD)",
			"claim.state IN ('claimed','uncertain')",
			"USING ERRCODE = 'P8903'",
			"DROP TRIGGER sites_provider_mutation_claim_guard_089 ON sites;",
			"tgfoid='block_dns_site_claimed_authority_mutation_474()'::regprocedure",
			"EXECUTE FUNCTION block_dns_site_claimed_authority_mutation_475();",
		}},
		{dnsSiteClaimGuardID + ".down.sql", dnsSiteClaimGuardDownSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", dnsSiteClaimGuardVersion),
			"migration_id='" + dnsSiteClaimGuardID + "'",
			fmt.Sprintf("ERRCODE='P%d1'", dnsSiteClaimGuardVersion),
			"DROP TRIGGER sites_provider_mutation_claim_guard_089 ON sites;",
			"EXECUTE FUNCTION block_dns_site_claimed_authority_mutation_474();",
			"DROP FUNCTION block_dns_site_claimed_authority_mutation_475();",
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
