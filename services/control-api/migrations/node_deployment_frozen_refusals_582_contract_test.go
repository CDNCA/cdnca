package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// Migration 582 (fix-stoppolicy2, placeholder number): an APPLY a frozen node
// refused is marked "waiting for redelivery" instead of counting as a failure,
// and marked redelivered once when the node unfreezes. The 581 predecessor is
// pinned by checksum.
const (
	migration582Version         = 582
	migration582PreviousVersion = 581
	migration582PreviousID      = "581_plugin_installation_resume"
	migration582PreviousUpSHA   = "4efdce42b601f8c8918c0aa28d2ef8d9925466bac2bfbfab5e994b58ae8386e1"
	migration582PreviousDownSHA = "8343058a9922b5cad7b570a9aef60889100285ce2ba2bbadb1a6b7989d4b551c"
	migration582ID              = "582_node_deployment_frozen_refusals"
)

func TestNodeDeploymentFrozenRefusals582Contract(t *testing.T) {
	for _, script := range []struct {
		name     string
		required []string
	}{
		{migration582ID + ".up.sql", []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration582PreviousVersion),
			fmt.Sprintf("(SELECT max(version) FROM schema_migrations) <> %d", migration582PreviousVersion),
			fmt.Sprintf("WHERE version=%d AND", migration582PreviousVersion),
			"migration_id='" + migration582PreviousID + "'",
			"checksum_sha256='" + migration582PreviousUpSHA + "'",
			"down_checksum_sha256='" + migration582PreviousDownSHA + "'",
			"ERRCODE='P5820'", "CREATE TABLE node_deployment_frozen_refusals",
			"REFERENCES node_deployments (id, attempt) ON DELETE CASCADE",
			"deployment.action = 'apply' AND deployment.state = 'failed'",
			"ERRCODE='P5821'", "OLD.redelivered_at IS NOT NULL OR NEW.redelivered_at IS NULL", "ERRCODE='P5822'",
			"BEFORE INSERT OR UPDATE ON node_deployment_frozen_refusals",
			"GRANT SELECT, INSERT, UPDATE ON node_deployment_frozen_refusals TO cdnca_control_app, cdnca_control_runtime",
		}},
		{migration582ID + ".down.sql", []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration582Version),
			"migration_id='" + migration582ID + "'", "ERRCODE='P5823'",
			"DROP TABLE node_deployment_frozen_refusals", "DROP FUNCTION guard_node_deployment_frozen_refusal_582()",
		}},
	} {
		raw, err := FS.ReadFile(script.name)
		if err != nil {
			t.Fatal(err)
		}
		for _, required := range script.required {
			if !strings.Contains(string(raw), required) {
				t.Errorf("%s missing %q", script.name, required)
			}
		}
	}
	for suffix, want := range map[string]string{".up.sql": migration582PreviousUpSHA, ".down.sql": migration582PreviousDownSHA} {
		raw, err := FS.ReadFile(migration582PreviousID + suffix)
		if err != nil {
			t.Fatal(err)
		}
		if got := fmt.Sprintf("%x", sha256.Sum256(raw)); got != want {
			t.Errorf("%s%s checksum %s, guard pins %s", migration582PreviousID, suffix, got, want)
		}
	}
}
