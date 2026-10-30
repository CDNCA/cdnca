package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// Migration 343 (JS challenge policies are
// redelivered to nodes that joined or recovered, and a confirmed delivery
// republishes the scope with trigger challenge_delivery) is a placeholder
// number: the merge renumbers it after the head it lands on. Everything that
// changes with the renumbering is in this block.
const (
	migration343Version         = 343
	migration343ID              = "343_challenge_policy_redelivery"
	migration343PreviousID      = "342_acme_http01_cleanup_debt"
	migration343PreviousUpSHA   = "7d99900ceb9f9955c3fef1589c16a0f0d427db3c40e2af207229d9b0a12d9520"
	migration343PreviousDownSHA = "36dae24e16005edbcf884290fe51558bb1ad99cc26f1c8aca3a02153fde4145b"
	migration343UpSHA           = "718012174b2f86e4e56d01da55b111ff6a44f153c9e3d35bcd765c82996602ef"
	migration343DownSHA         = "d2bccbb4a57b9079a58d2fba8d77c734245268998d42d1af0e46bab37a0ede31"
)

func TestChallengePolicyRedelivery343Contract(t *testing.T) {
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{migration343ID + ".up.sql", migration343UpSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration343Version-1),
			fmt.Sprintf("(SELECT max(version) FROM schema_migrations) <> %d", migration343Version-1),
			"migration_id='" + migration343PreviousID + "'", migration343PreviousUpSHA, migration343PreviousDownSHA,
			"ERRCODE='P3430'", "CREATE TABLE edge_challenge_redeliveries (",
			"'rule_catalog', 'challenge_delivery']::text[]", "cardinality(triggers) BETWEEN 1 AND 8",
			"'secondary_verification', 'rule_catalog', 'challenge_delivery'));",
			"'node.challenge_delivered')),", "'challenge_delivered')),",
			"(source_kind = 'challenge_delivery' AND permission_name = 'sites.manage' AND reason = 'challenge_delivered' AND\n" +
				"         operation = 'node.challenge_delivered' AND source_resource_id IS NOT NULL)",
			"attempt integer NOT NULL CHECK (attempt BETWEEN 0 AND 8)",
		}},
		{migration343ID + ".down.sql", migration343DownSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration343Version),
			"migration_id='" + migration343ID + "'", "ERRCODE='P3431'",
			"EXISTS (SELECT 1 FROM edge_challenge_redeliveries)", "WHERE source_kind = 'challenge_delivery'",
			"cardinality(triggers) BETWEEN 1 AND 7", "DROP TABLE edge_challenge_redeliveries;",
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
