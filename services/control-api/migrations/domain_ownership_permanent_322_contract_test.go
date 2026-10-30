package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// Migration 322 (G6 ownership proofs stay valid; placeholder number) sits on
// the exact verified 321 head. The numbers live together for renumbering.
const (
	domainOwnershipPermanentVersion  = "322"
	domainOwnershipPermanentPrevious = "321_node_availability_alert_states"
	domainOwnershipPermanentPrevUp   = "acd73fe79225092cea6a792821943581292c8c5a566aee452749c0b111546117"
	domainOwnershipPermanentPrevDown = "52135be11ac5e4570e63da1ec438295b29e528df73842915be486982e412f99c"
	domainOwnershipPermanentUpSHA    = "0a36f436bacd8c9121c8eb0351f95cd13dbbf2bddcecf229d3f21b5954f23bcd"
	domainOwnershipPermanentDownSHA  = "09c30b909370ec31691e6fc968902cf70793390838279dacca58dbe5dddcaca3"
)

func TestDomainOwnershipPermanent322Contract(t *testing.T) {
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{domainOwnershipPermanentVersion + "_domain_ownership_permanent.up.sql", domainOwnershipPermanentUpSHA, []string{
			"(SELECT count(*) FROM schema_migrations) <> 321", domainOwnershipPermanentPrevious,
			domainOwnershipPermanentPrevUp, domainOwnershipPermanentPrevDown, "ERRCODE='P3220'",
			"DROP COLUMN next_check_at, DROP COLUMN consecutive_failures",
		}},
		{domainOwnershipPermanentVersion + "_domain_ownership_permanent.down.sql", domainOwnershipPermanentDownSHA, []string{
			"(SELECT count(*) FROM schema_migrations) <> 322", "322_domain_ownership_permanent", "ERRCODE='P3221'",
			"CREATE INDEX domain_ownerships_due_299_idx",
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
}
