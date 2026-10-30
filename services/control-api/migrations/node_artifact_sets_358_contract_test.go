package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// Placeholder number (PA-01); renumbered on merge with the const block.
const (
	migration358Version         = 358
	migration358ID              = "358_node_artifact_sets"
	migration358PreviousID      = "357_recharge_payment_legacy_reconcile_drop"
	migration358PreviousUpSHA   = "5e8101deee14f96bb09769b33831facd4215a539df5ec169040f761ca2d97cb7"
	migration358PreviousDownSHA = "8dbecc582284d023d24e3aee071497db192c4bfcc8c6ae6f612af9d94b5131c1"
	migration358UpSHA           = "67cd69e1463ce32abf89a6dc2182185806cb260f283a31797bb8997d78831d5b"
	migration358DownSHA         = "6f3c098dc885ef7709d05361c8c73046e4077274f3110aebe6920b6d523de94b"
)

func TestNodeArtifactSets358Contract(t *testing.T) {
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{migration358ID + ".up.sql", migration358UpSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration358Version-1),
			"migration_id='" + migration358PreviousID + "'", migration358PreviousUpSHA, migration358PreviousDownSHA,
			"ERRCODE='P3580'", "CREATE TABLE node_artifact_sets", "CREATE TABLE node_artifact_applied_items",
			"configuration_artifacts_node_artifact_358", "DROP FUNCTION bind_node_artifact_media_type_329()",
			"application/vnd.cdnca.edge.artifact-set+json;version=1", "application/vnd.cdnca.edge.artifact-segment;version=1",
		}},
		{migration358ID + ".down.sql", migration358DownSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration358Version),
			"migration_id='" + migration358ID + "'", "ERRCODE='P3581'", "CREATE FUNCTION bind_node_artifact_media_type_329()",
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
	for name, want := range map[string]string{migration358PreviousID + ".up.sql": migration358PreviousUpSHA,
		migration358PreviousID + ".down.sql": migration358PreviousDownSHA} {
		raw, err := FS.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		if got := fmt.Sprintf("%x", sha256.Sum256(raw)); got != want {
			t.Fatalf("%s checksum %s, guard expects %s", name, got, want)
		}
	}
}

// The media type literals in the trigger must stay those of
// libs/edgeconfig/artifactset (checked without importing it here: the
// migrations package has no edgeconfig dependency).
func TestNodeArtifactSets358MediaTypesMatchTheFormat(t *testing.T) {
	raw, err := FS.ReadFile(migration358ID + ".up.sql")
	if err != nil {
		t.Fatal(err)
	}
	for _, mediaType := range []string{"application/vnd.cdnca.edge.artifact-set+json;version=1",
		"application/vnd.cdnca.edge.artifact-segment;version=1"} {
		if strings.Count(string(raw), "'"+mediaType+"'") < 2 {
			t.Errorf("trigger does not name %s in both branches", mediaType)
		}
	}
}
