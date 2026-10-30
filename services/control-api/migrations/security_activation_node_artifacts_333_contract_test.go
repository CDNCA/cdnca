package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// Migration 333 (security activation on site runtime v2) is a
// placeholder number: the merge renumbers it after the head it lands on.
// Everything that changes with the renumbering is in this block.
const (
	migration333Version         = 333
	migration333ID              = "333_security_activation_node_artifacts"
	migration333PreviousID      = "332_node_traffic_history_retention"
	migration333PreviousUpSHA   = "978cd44a59362d5622eddfbe0753475169ef9c9d8730217284ff42d830035b93"
	migration333PreviousDownSHA = "029c9d24d1fa9fce2c1fbb998230c3e3d9cbfb184e2c5fc00eebfcb97ab840cf"
	migration333UpSHA           = "5e9e7605e6cabc43ff1af6cd38cf0f22849dc07f664d18daeb199cf551b97d36"
	migration333DownSHA         = "f5c379562defa2787322ccea73abf03dc44fbca6e181e1f8cac655c21bc08cef"
)

func TestSecurityActivationNodeArtifacts333Contract(t *testing.T) {
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{migration333ID + ".up.sql", migration333UpSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration333Version-1),
			fmt.Sprintf("(SELECT max(version) FROM schema_migrations) <> %d", migration333Version-1),
			"migration_id='" + migration333PreviousID + "'", migration333PreviousUpSHA, migration333PreviousDownSHA,
			"ERRCODE='P3330'", "CREATE TABLE security_policy_activation_node_artifacts_333",
			"CREATE FUNCTION security_policy_activation_node_artifact_sha256_333(",
			"'validate_security_policy_activation_rollout_088()'",
			"'security_policy_activation_phase_healthy_088(uuid,text)'",
			"'validate_security_policy_activation_recovery_rollout_088()'",
			"IF occurrences <> 1", "ADD COLUMN site_runtime_schema",
		}},
		{migration333ID + ".down.sql", migration333DownSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration333Version),
			"migration_id='" + migration333ID + "'", "ERRCODE='P3331'",
			"DROP TABLE security_policy_activation_node_artifacts_333", "DROP COLUMN site_runtime_schema",
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
