package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// Node traffic history. Every number the merge renumbering touches is here.
const (
	nodeTrafficRetentionVersion        = 332
	nodeTrafficRetentionID             = "332_node_traffic_history_retention"
	nodeTrafficRetentionPreviousID     = "331_audit_event_archive"
	nodeTrafficRetentionPreviousUpSHA  = "1af7fdf12733a8ddb1d322033c71e756d9ec13e18ff35acb10b7c3fe65715831"
	nodeTrafficRetentionPreviousDownSH = "5d9b52ec22684e388f4faff0defa55e6cc10f2796a2ec77c5eae5fe8b32c18df"
	nodeTrafficRetentionUpSHA          = "978cd44a59362d5622eddfbe0753475169ef9c9d8730217284ff42d830035b93"
	nodeTrafficRetentionDownSHA        = "029c9d24d1fa9fce2c1fbb998230c3e3d9cbfb184e2c5fc00eebfcb97ab840cf"
)

func TestNodeTrafficHistoryRetention332Contract(t *testing.T) {
	previous := nodeTrafficRetentionVersion - 1
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{nodeTrafficRetentionID + ".up.sql", nodeTrafficRetentionUpSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", previous),
			fmt.Sprintf("(SELECT max(version) FROM schema_migrations) <> %d", previous),
			"migration_id='" + nodeTrafficRetentionPreviousID + "'",
			"checksum_sha256='" + nodeTrafficRetentionPreviousUpSHA + "'",
			"down_checksum_sha256='" + nodeTrafficRetentionPreviousDownSH + "'",
			fmt.Sprintf("ERRCODE='P%d0'", nodeTrafficRetentionVersion),
			"retention_cleanup_cutoff_331('node_traffic_history_days')",
			"EXISTS (SELECT 1 FROM node_traffic_sync_tasks task WHERE task.evaluation_id = OLD.id)",
		}},
		{nodeTrafficRetentionID + ".down.sql", nodeTrafficRetentionDownSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", nodeTrafficRetentionVersion),
			"migration_id='" + nodeTrafficRetentionID + "'",
			"WHEN (NOT node_purge_permits(OLD.node_id)) EXECUTE FUNCTION reject_node_traffic_evidence_mutation_181()",
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
