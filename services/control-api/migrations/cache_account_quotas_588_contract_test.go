package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// Migration 588 (fix-cachequota, placeholder number): cache purge/prewarm
// daily quotas count per account (tenant scope). An account's own limits
// override the system setting defaults; a NULL column follows the default.
// The 587 predecessor is pinned by checksum.
const (
	migration588Version         = 588
	migration588PreviousVersion = 587
	migration588PreviousID      = "587_plugin_promo_charge_notice"
	migration588PreviousUpSHA   = "74a2e8867020908f3b0300d3e8c99d14b1a42c375dae5bb390d1ef2e7506a40a"
	migration588PreviousDownSHA = "3e0af927e2169681ab11334b803d5b9231df36ec201770334c36a59677ae6b13"
	migration588ID              = "588_cache_account_quotas"
)

func TestCacheAccountQuotas588Contract(t *testing.T) {
	for _, script := range []struct {
		name     string
		required []string
	}{
		{migration588ID + ".up.sql", []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration588PreviousVersion),
			fmt.Sprintf("(SELECT max(version) FROM schema_migrations) <> %d", migration588PreviousVersion),
			fmt.Sprintf("WHERE version=%d AND", migration588PreviousVersion),
			"migration_id='" + migration588PreviousID + "'",
			"checksum_sha256='" + migration588PreviousUpSHA + "'",
			"down_checksum_sha256='" + migration588PreviousDownSHA + "'",
			"ERRCODE='P5880'", "ERRCODE='P5881'", "ERRCODE='P5882'",
			"CREATE TABLE cache_operation_account_quotas",
			"url_purge_limit integer CHECK (url_purge_limit BETWEEN 0 AND 10000000)",
			"directory_purge_limit integer CHECK (directory_purge_limit BETWEEN 0 AND 1000000)",
			"prewarm_limit integer CHECK (prewarm_limit BETWEEN 0 AND 10000000)",
			"CREATE INDEX cache_operations_account_daily_588_idx",
			"GRANT SELECT, INSERT, UPDATE ON cache_operation_account_quotas TO cdnca_control_app, cdnca_control_runtime",
		}},
		{migration588ID + ".down.sql", []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration588Version),
			"migration_id='" + migration588ID + "'",
			"ERRCODE='P5883'",
			"DROP INDEX cache_operations_account_daily_588_idx",
			"DROP TABLE cache_operation_account_quotas",
			"DROP FUNCTION protect_cache_operation_account_quota_588()",
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
	for suffix, want := range map[string]string{".up.sql": migration588PreviousUpSHA, ".down.sql": migration588PreviousDownSHA} {
		raw, err := FS.ReadFile(migration588PreviousID + suffix)
		if err != nil {
			t.Fatal(err)
		}
		if got := fmt.Sprintf("%x", sha256.Sum256(raw)); got != want {
			t.Errorf("%s%s checksum %s, guard pins %s", migration588PreviousID, suffix, got, want)
		}
	}
}
