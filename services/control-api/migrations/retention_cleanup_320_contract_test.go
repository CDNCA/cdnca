package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// Every number the merge renumbering touches is here.
const (
	retentionCleanupVersion        = 320
	retentionCleanupID             = "320_retention_cleanup"
	retentionCleanupPreviousID     = "319_site_protocol_scope_fields"
	retentionCleanupPreviousUpSHA  = "5ec4f621fa457dc60cd348f6995170a45f5d0cc6719d8084b580d9085a6f3379"
	retentionCleanupPreviousDownSH = "cbfcb9acfe69c76524efb4c612d5a13c850247b5d8cbbb8a74ade1cb8201d1f1"
	retentionCleanupUpSHA          = "95a73b22348a55322f13fa7c0605004c71d102abb5f1977beae57317e5909eb5"
	retentionCleanupDownSHA        = "d1c616198a0041b502f01b7ad5f8da0d4c9c09aa0e9b8efa0b971eed00c6231b"
)

func TestRetentionCleanup320Contract(t *testing.T) {
	previous := retentionCleanupVersion - 1
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{retentionCleanupID + ".up.sql", retentionCleanupUpSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", previous),
			fmt.Sprintf("(SELECT max(version) FROM schema_migrations) <> %d", previous),
			"migration_id='" + retentionCleanupPreviousID + "'",
			"checksum_sha256='" + retentionCleanupPreviousUpSHA + "'",
			"down_checksum_sha256='" + retentionCleanupPreviousDownSH + "'",
			fmt.Sprintf("ERRCODE='P%d0'", retentionCleanupVersion),
			"current_user <> 'cdnca_retention_cleanup'",
			"GRANT SELECT, DELETE ON node_metric_samples TO cdnca_retention_cleanup",
		}},
		{retentionCleanupID + ".down.sql", retentionCleanupDownSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", retentionCleanupVersion),
			"migration_id='" + retentionCleanupID + "'",
			"WHEN (NOT node_purge_in_progress()) EXECUTE FUNCTION protect_node_metric_sample_150()",
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
