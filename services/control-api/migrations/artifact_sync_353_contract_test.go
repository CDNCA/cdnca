package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// Migration 353 (PA-02 artifactsync) is a placeholder number: the merge
// renumbers it after the head it lands on. Everything that changes with the
// renumbering is here.
const (
	migration353Version         = 353
	migration353ID              = "353_artifact_sync"
	migration353PreviousID      = "352_capability_hold_published"
	migration353PreviousUpSHA   = "0da091ad25a8dbca26a0dc3f5b865704d6b8357ea1da686c4c757aaea15ff64e"
	migration353PreviousDownSHA = "fa4edbb55f03cb0c2bc93f4e30b1703d2dd0c92db817e1db5641e5a373cb600d"
	migration353UpSHA           = "25291860ab06be9a3dc35d7b54d0333d017be463a710f8040dd2ad860f28538e"
	migration353DownSHA         = "a01337f726ef3b0c570cf220d1de45e907c85f381a3061262f47c8e7cc184d05"
)

func TestArtifactSync353Contract(t *testing.T) {
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{migration353ID + ".up.sql", migration353UpSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration353Version-1),
			fmt.Sprintf("(SELECT max(version) FROM schema_migrations) <> %d", migration353Version-1),
			"migration_id='" + migration353PreviousID + "'", migration353PreviousUpSHA, migration353PreviousDownSHA,
			"ERRCODE='P3530'", "DROP TABLE security_rule_catalog_consumer_state", "DROP TABLE ip_intel_library",
			"CREATE TABLE artifact_catalog_entries", "CREATE TABLE artifact_objects", "CREATE TABLE local_artifacts",
			"CREATE TABLE artifact_enablement_overrides", "local artifact revisions only move forward",
		}},
		{migration353ID + ".down.sql", migration353DownSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration353Version),
			"migration_id='" + migration353ID + "'", "ERRCODE='P3531'",
			"DROP TABLE local_artifacts", "CREATE TABLE security_rule_catalog_consumer_state", "CREATE TABLE ip_intel_library",
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
