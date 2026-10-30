package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// Site objects (site runtime v8). Every number the merge
// renumbering touches is here.
const (
	edgeSiteObjectsVersion         = 354
	edgeSiteObjectsID              = "354_edge_site_objects"
	edgeSiteObjectsPreviousID      = "353_artifact_sync"
	edgeSiteObjectsPreviousUpSHA   = "25291860ab06be9a3dc35d7b54d0333d017be463a710f8040dd2ad860f28538e"
	edgeSiteObjectsPreviousDownSHA = "a01337f726ef3b0c570cf220d1de45e907c85f381a3061262f47c8e7cc184d05"
	edgeSiteObjectsUpSHA           = "06b5e447a616e274de5bbe543c912dbe19d59b95ce029e6aba73cab40ae42ff4"
	edgeSiteObjectsDownSHA         = "d4c3c472ce1bd27ecd9e8c20c3ce7c946a080898e004c64326dc0521e7e1c4c1"
)

func TestEdgeSiteObjects354Contract(t *testing.T) {
	previous := edgeSiteObjectsVersion - 1
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{edgeSiteObjectsID + ".up.sql", edgeSiteObjectsUpSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", previous),
			fmt.Sprintf("(SELECT max(version) FROM schema_migrations) <> %d", previous),
			"migration_id='" + edgeSiteObjectsPreviousID + "'",
			"checksum_sha256='" + edgeSiteObjectsPreviousUpSHA + "'",
			"down_checksum_sha256='" + edgeSiteObjectsPreviousDownSHA + "'",
			fmt.Sprintf("ERRCODE='P%d0'", edgeSiteObjectsVersion),
			"CREATE TABLE edge_site_object_keys", "CREATE TABLE edge_site_objects",
			"CREATE TABLE edge_site_object_publications", "BETWEEN 1 AND 268435456",
			"member_sha256", "CREATE OR REPLACE FUNCTION validate_security_policy_activation_node_artifact_333()",
			"application/vnd.cdnca.edge-site-root+json;version=1",
			"edge_publication_compile_inputs_v2_size_354", "<= 16777216",
		}},
		{edgeSiteObjectsID + ".down.sql", edgeSiteObjectsDownSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", edgeSiteObjectsVersion),
			"migration_id='" + edgeSiteObjectsID + "'",
			fmt.Sprintf("ERRCODE='P%d3'", edgeSiteObjectsVersion), fmt.Sprintf("ERRCODE='P%d4'", edgeSiteObjectsVersion),
			"BETWEEN 1 AND 4194304", "artifact.sha256=NEW.artifact_sha256 AND artifact.sha256=sha256(artifact.wire_bytes)",
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
