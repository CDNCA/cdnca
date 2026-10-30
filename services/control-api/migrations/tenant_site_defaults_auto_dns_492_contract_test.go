package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// Migration 492: dns_providers.remark, site_user_defaults (the
// tenant's 网站列表 > 默认设置) and site_auto_dns_tasks (建站「DNS API（自动
// 添加记录）」). Placeholder 490 renumbered to 492 at merge (after
// 491_audit_user_agent). Everything that changes is in this block.
const (
	migration492Version         = 492
	migration492PreviousVersion = 491
	migration492ID              = "492_tenant_site_defaults_auto_dns"
	migration492PreviousID      = "491_audit_user_agent"
	migration492PreviousUpSHA   = "910509fe143010d111092d82e708e54f306c6eb8ac16f496005999d1623a5ff2"
	migration492PreviousDownSHA = "86252f1ad503ed9ca383de7ef96d23d97361463daf94bfc1a8de2192271b908c"
	migration492UpSHA           = "53389281060ad1dd6b5616b3f8b2b137ff568674459b57fedcde97b4995cf3c5"
	migration492DownSHA         = "4378935fb9b80acc14a6390888f4545adb07bc467f175b8f33d07b8a581171d6"
)

func TestTenantSiteDefaultsAutoDNS492Contract(t *testing.T) {
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{migration492ID + ".up.sql", migration492UpSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration492PreviousVersion),
			fmt.Sprintf("(SELECT max(version) FROM schema_migrations) <> %d", migration492PreviousVersion),
			"migration_id='" + migration492PreviousID + "'", migration492PreviousUpSHA, migration492PreviousDownSHA,
			"ERRCODE='P4920'", "ADD COLUMN remark text NOT NULL DEFAULT ''",
			"CREATE TABLE site_user_defaults", "CREATE TABLE site_auto_dns_tasks",
			"'site_default.create', 'site_default.update', 'site_default.delete'", "generation bigint NOT NULL DEFAULT 1",
		}},
		{migration492ID + ".down.sql", migration492DownSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration492Version),
			"migration_id='" + migration492ID + "'", "ERRCODE='P4921'",
			"DROP TABLE site_auto_dns_tasks", "DROP TABLE site_user_defaults", "DROP COLUMN remark",
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
