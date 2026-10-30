package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// Placeholder number; renumbered on merge with the const block.
const (
	migration329Version         = 329
	migration329ID              = "329_ip_intel_node_distribution"
	migration329PreviousID      = "328_l4_session_log"
	migration329PreviousUpSHA   = "88f45b5711dba3c53c8c1c0a0fdf75cde7f1fc036e3bdc4a38456854df9e9fb1"
	migration329PreviousDownSHA = "0a68e90db060befb2cc03aef8765a3bff4f95a8027352a4ee87b649eb7ec1589"
	migration329UpSHA           = "478749ae18f6af81b650f2c2f50845cc7ea7e2f201a70aeb3d1189622c715187"
	migration329DownSHA         = "65b1265253a15eccf0d664ac868cf7161a49b38be38d499cf5559d6781b92d07"
)

func TestIPIntelNodeDistribution329Contract(t *testing.T) {
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{migration329ID + ".up.sql", migration329UpSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration329Version-1),
			"migration_id='" + migration329PreviousID + "'", migration329PreviousUpSHA, migration329PreviousDownSHA,
			"ERRCODE='P3290'", "CREATE TABLE ip_intel_node_distributions", "configuration_artifacts_node_artifact_329",
		}},
		{migration329ID + ".down.sql", migration329DownSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration329Version),
			"migration_id='" + migration329ID + "'", "ERRCODE='P3291'",
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
	for name, want := range map[string]string{migration329PreviousID + ".up.sql": migration329PreviousUpSHA,
		migration329PreviousID + ".down.sql": migration329PreviousDownSHA} {
		raw, err := FS.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		if got := fmt.Sprintf("%x", sha256.Sum256(raw)); got != want {
			t.Fatalf("%s checksum %s, guard expects %s", name, got, want)
		}
	}
}
