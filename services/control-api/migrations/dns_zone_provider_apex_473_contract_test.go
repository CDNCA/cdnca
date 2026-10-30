package migrations_test

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"

	controlmigrations "github.com/cdnca/cdnca/services/control-api/migrations"
)

// (473, BATCH 82; guards the integration head 472 site cache
// status header). Every number the merge renumbering touches is here.
const (
	dnsZoneProviderApexVersion         = 473
	dnsZoneProviderApexID              = "473_dns_zone_provider_apex"
	dnsZoneProviderApexPreviousID      = "472_site_cache_status_header"
	dnsZoneProviderApexPreviousUpSHA   = "bfa4893110282f6df2a541a7f15f92ec631db93e5ec27c8e246ef3e897a0a0e2"
	dnsZoneProviderApexPreviousDownSHA = "ff250fffa7d109a2cfa61a74c0141669fea2587c97c987bac387204879b8ea6f"
	dnsZoneProviderApexUpSHA           = "f8ba83c2aa3d8a7ba315e9d3b6724ef30eff5251999b1e210150af969d1b3ba3"
	dnsZoneProviderApexDownSHA         = "b12755c42899557bb44072b6d486f981aaf3120e0c6ba77386f51fd08a7415f1"
)

func TestDNSZoneProviderApex473Contract(t *testing.T) {
	previous := dnsZoneProviderApexVersion - 1
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{dnsZoneProviderApexID + ".up.sql", dnsZoneProviderApexUpSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", previous),
			fmt.Sprintf("(SELECT max(version) FROM schema_migrations) <> %d", previous),
			"migration_id='" + dnsZoneProviderApexPreviousID + "'",
			"checksum_sha256='" + dnsZoneProviderApexPreviousUpSHA + "'",
			"down_checksum_sha256='" + dnsZoneProviderApexPreviousDownSHA + "'",
			fmt.Sprintf("ERRCODE='P%d0'", dnsZoneProviderApexVersion),
			"ADD COLUMN provider_zone_apex text CHECK (",
			"provider_zone_apex IS NULL OR (",
			"(name = provider_zone_apex OR right(name, char_length(provider_zone_apex) + 1) = '.' || provider_zone_apex)",
		}},
		{dnsZoneProviderApexID + ".down.sql", dnsZoneProviderApexDownSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", dnsZoneProviderApexVersion),
			"migration_id='" + dnsZoneProviderApexID + "'",
			fmt.Sprintf("ERRCODE='P%d1'", dnsZoneProviderApexVersion),
			"DROP COLUMN provider_zone_apex",
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
		if guard, mutation := strings.Index(text, "RAISE EXCEPTION"), strings.Index(text, "ALTER TABLE"); guard < 0 || mutation < guard {
			t.Errorf("%s guard must precede the first mutation", script.name)
		}
	}
}
