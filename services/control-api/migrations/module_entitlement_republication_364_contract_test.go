package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// Migration 364 (a revoked module leaves scopes
// pending republication; granting it again republishes them with trigger
// module_entitlement) is a placeholder number: the merge renumbers it after
// the head it lands on. Everything that changes with the renumbering is here.
const (
	migration364Version         = 364
	migration364ID              = "364_module_entitlement_republication"
	migration364PreviousID      = "363_rule_pack_protection"
	migration364PreviousUpSHA   = "bcd1e0d6d738e783d8ed0690f8ffd9adb4f07674d888e56e06047cb1ba4482fd"
	migration364PreviousDownSHA = "b0491dacc3291c7dbc954dadbfdd366ab30a213133c5f6a7b5fe51290d74db3e"
	migration364UpSHA           = "53e3b8f018f9f4702dac9a3802a2c5cd68e556f00940cc3d9c75a71bdd7b5398"
	migration364DownSHA         = "f7e9d1e030cf9e790622b63ce553ab4a822988c57ed4b6ef94342189fefc95c8"
)

func TestModuleEntitlementRepublication364Contract(t *testing.T) {
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{migration364ID + ".up.sql", migration364UpSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration364Version-1),
			fmt.Sprintf("(SELECT max(version) FROM schema_migrations) <> %d", migration364Version-1),
			"migration_id='" + migration364PreviousID + "'", migration364PreviousUpSHA, migration364PreviousDownSHA,
			"ERRCODE='P3640'", "CREATE TABLE edge_module_publication_holds (", "CREATE TABLE edge_module_grant_marks (",
			"'challenge_delivery', 'module_entitlement']::text[]", "cardinality(triggers) BETWEEN 1 AND 9",
			"'entitlement.modules_granted')),", "'entitlement_changed')),",
			"(source_kind = 'module_entitlement' AND permission_name = 'sites.manage' AND reason = 'entitlement_changed' AND\n" +
				"         operation = 'entitlement.modules_granted' AND source_resource_id IS NOT NULL)",
		}},
		{migration364ID + ".down.sql", migration364DownSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration364Version),
			"migration_id='" + migration364ID + "'", "ERRCODE='P3641'",
			"EXISTS (SELECT 1 FROM edge_module_publication_holds)", "WHERE source_kind = 'module_entitlement'",
			"cardinality(triggers) BETWEEN 1 AND 8", "DROP TABLE edge_module_publication_holds;",
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
