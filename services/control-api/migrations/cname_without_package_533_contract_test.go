package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// Migration 533 (fix-nopkg): platform default line group and CNAME intents /
// frozen targets without a package. The 532 predecessor is pinned at merge.
const (
	migration533ID      = "533_cname_without_package"
	migration533UpSHA   = "a7eb4f050b1ca20f34eac14c7f3aaaea42bb0e30a0c129ac88fe6094070af526"
	migration533DownSHA = "0cef91130d0e2740112d3b12ef8cc076cba8f1680e4faec437ea9caaf6749a4c"
)

func TestCNAMEWithoutPackage533Contract(t *testing.T) {
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{migration533ID + ".up.sql", migration533UpSHA, []string{
			"(SELECT count(*) FROM schema_migrations) <> 532", "(SELECT max(version) FROM schema_migrations) <> 532",
			"ERRCODE='P5330'", "ERRCODE='P5332'",
			"ADD COLUMN is_platform_default boolean NOT NULL DEFAULT false",
			"CREATE UNIQUE INDEX node_line_groups_platform_default_533_key ON node_line_groups ((is_platform_default))",
			"WHERE is_platform_default;",
			"ALTER TABLE cname_allocation_targets ALTER COLUMN package_subscription_id DROP NOT NULL;",
			"ALTER TABLE cname_allocation_intents ALTER COLUMN package_subscription_id DROP NOT NULL",
			"CHECK (package_subscription_id IS NOT NULL OR mode='site')",
			"intent.package_subscription_id IS NOT DISTINCT FROM NEW.package_subscription_id",
			"to_jsonb(NEW) - 'is_platform_default' = to_jsonb(OLD) - 'is_platform_default'",
		}},
		{migration533ID + ".down.sql", migration533DownSHA, []string{
			"(SELECT count(*) FROM schema_migrations) <> 533", "migration_id='" + migration533ID + "'",
			"ERRCODE='P5331'", "ERRCODE='P5333'",
			"ALTER COLUMN package_subscription_id SET NOT NULL",
			"intent.package_subscription_id=NEW.package_subscription_id",
			"ALTER TABLE node_line_groups DROP COLUMN is_platform_default;",
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
