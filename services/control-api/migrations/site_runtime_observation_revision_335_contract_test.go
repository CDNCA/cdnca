package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// Migration 335 (site IPv6 observation no longer advances the scope's
// source_revision) is a placeholder number: the merge renumbers it after the
// head it lands on. Everything that changes with the renumbering is in this
// block.
const (
	migration335Version         = 335
	migration335ID              = "335_site_runtime_observation_revision"
	migration335PreviousID      = "334_l4_port_range"
	migration335PreviousUpSHA   = "8797397e3bb1dfcaebf69422f8ac5dbce8a8e86ccfcabc27f937096c8c5dcbaa"
	migration335PreviousDownSHA = "a9ff06178c9f888ccd237f73769851bd68bc1ba0e97d1cc1c107216df2965303"
	migration335UpSHA           = "8efc7dc791cd6b1b104e43c4034fb33cca34586fa753db97c1a2f76d2476e431"
	migration335DownSHA         = "fba9c2b6ff80501081631bdce6b08ff284734bdfe1f1fa38fe7aa16d803394f4"
)

func TestSiteRuntimeObservationRevision335Contract(t *testing.T) {
	// The observation columns the trigger ignores: exactly these three, so any
	// other sites column (configuration) still advances source_revision.
	const exempt = "ARRAY['ipv6_runtime_state','ipv6_runtime_source_revision','updated_at']"
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{migration335ID + ".up.sql", migration335UpSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration335Version-1),
			fmt.Sprintf("(SELECT max(version) FROM schema_migrations) <> %d", migration335Version-1),
			"migration_id='" + migration335PreviousID + "'", migration335PreviousUpSHA, migration335PreviousDownSHA,
			"ERRCODE='P3350'", "tgfoid='bump_edge_configuration_scope_revision()'::regprocedure",
			"CREATE FUNCTION bump_edge_configuration_site_revision_335()",
			"to_jsonb(NEW) - " + exempt, "to_jsonb(OLD) - " + exempt,
			"DROP TRIGGER sites_bump_edge_configuration_revision ON sites;",
			"FOR EACH ROW EXECUTE FUNCTION bump_edge_configuration_site_revision_335();",
		}},
		{migration335ID + ".down.sql", migration335DownSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration335Version),
			"migration_id='" + migration335ID + "'", "ERRCODE='P3351'",
			"FOR EACH ROW EXECUTE FUNCTION bump_edge_configuration_scope_revision();",
			"DROP FUNCTION bump_edge_configuration_site_revision_335();",
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
	// 021's shared function (l4_forwards still uses it) is not replaced.
	raw, err := FS.ReadFile(migration335ID + ".up.sql")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "REPLACE FUNCTION bump_edge_configuration_scope_revision") ||
		strings.Contains(string(raw), "l4_forwards") {
		t.Fatal("335 must only re-point the sites trigger")
	}
}
