package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// fix-cfl-a2 清缓存、解锁 IP 历史按 cleanup_cache_days 清理。
// 占位号与前驱都集中在这里，合入改号时一并改。
const (
	cacheBanRetentionVersion       = 566
	cacheBanRetentionID            = "566_cache_ban_history_retention"
	cacheBanRetentionPreviousCount = 565
	cacheBanRetentionPreviousID    = "565_site_supply_receipt_reconcile"
	cacheBanRetentionPreviousUp    = "7f0725a8f86a752f6103160adc6e90f001d88e5f7055fcc1c08582a2dfc66bd2"
	cacheBanRetentionPreviousDown  = "b687c6b4787cc347bb28c238ddfc27f1cc91136c363bccde8f69c56535fe886c"
)

func TestCacheBanHistoryRetention566Contract(t *testing.T) {
	previousUp, _ := FS.ReadFile(cacheBanRetentionPreviousID + ".up.sql")
	previousDown, _ := FS.ReadFile(cacheBanRetentionPreviousID + ".down.sql")
	if fmt.Sprintf("%x", sha256.Sum256(previousUp)) != cacheBanRetentionPreviousUp ||
		fmt.Sprintf("%x", sha256.Sum256(previousDown)) != cacheBanRetentionPreviousDown {
		t.Fatal("predecessor checksums drifted")
	}
	for _, script := range []struct {
		name     string
		required []string
	}{
		{cacheBanRetentionID + ".up.sql", []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", cacheBanRetentionPreviousCount),
			fmt.Sprintf("(SELECT max(version) FROM schema_migrations) <> %d", cacheBanRetentionPreviousCount),
			"migration_id='" + cacheBanRetentionPreviousID + "'",
			"checksum_sha256='" + cacheBanRetentionPreviousUp + "'",
			"down_checksum_sha256='" + cacheBanRetentionPreviousDown + "'",
			fmt.Sprintf("ERRCODE='P%d0'", cacheBanRetentionVersion),
			"IF setting <> 'cleanup_cache_days' THEN", "days := COALESCE(days, 30);",
			"operation.state IN ('succeeded', 'partial_failed', 'failed', 'cancelled')",
			"command.completed_at IS NULL",
			"CREATE TRIGGER cache_operations_protected BEFORE UPDATE ON cache_operations",
			"WHEN (current_user <> 'cdnca_retention_cleanup') EXECUTE FUNCTION protect_cache_operation_transition()",
			"WHEN (current_user <> 'cdnca_retention_cleanup' AND NOT node_purge_permits(OLD.node_id))",
			"'cache_operation_cancel_deliveries'] LOOP",
			"OLD.released_at < least(cutoff, transaction_timestamp() - interval '7 days')",
			"ELSE OLD.banned_until < cutoff END",
			"WHEN (current_user = 'cdnca_retention_cleanup') EXECUTE FUNCTION guard_retention_delete_security_ban_566()",
		}},
		{cacheBanRetentionID + ".down.sql", []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", cacheBanRetentionVersion),
			"migration_id='" + cacheBanRetentionID + "'",
			fmt.Sprintf("ERRCODE='P%d1'", cacheBanRetentionVersion),
			"CREATE TRIGGER cache_operations_protected BEFORE UPDATE OR DELETE ON cache_operations",
			"CREATE TRIGGER cache_operation_commands_protected BEFORE INSERT OR UPDATE OR DELETE ON cache_operation_commands",
			"CREATE TRIGGER cache_operation_targets_append_only BEFORE UPDATE OR DELETE ON cache_operation_targets",
			"DROP FUNCTION retention_cleanup_cutoff_566(text);",
		}},
	} {
		body, err := FS.ReadFile(script.name)
		if err != nil {
			t.Fatal(err)
		}
		for _, fragment := range script.required {
			if !strings.Contains(string(body), fragment) {
				t.Errorf("%s missing %q", script.name, fragment)
			}
		}
	}
}
