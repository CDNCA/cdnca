package migrations

import (
	"strings"
	"testing"
)

// Migration 544: official free system rule packs
// are on by default. The 543 predecessor is pinned at merge.
func TestOfficialRulePacksEnabled544Contract(t *testing.T) {
	for _, script := range []struct {
		name     string
		required []string
	}{
		{"544_official_rule_packs_enabled.up.sql", []string{
			"(SELECT count(*) FROM schema_migrations) <> 543", "(SELECT max(version) FROM schema_migrations) <> 543",
			"ERRCODE='P5440'",
			// Only the control plane's own platform rows of system packs; an administrator's row stays.
			"pack.layer='system' AND enablement.level='platform'", "enablement.updated_by_user_id IS NULL AND enablement.state='inherit'",
			// Sites that already published are recomputed on the next sync.
			"SET materialized_sha256=NULL", "entry.kind='rule_pack' AND entry.requires_feature=''",
		}},
		{"544_official_rule_packs_enabled.down.sql", []string{
			"(SELECT count(*) FROM schema_migrations) <> 544", "migration_id='544_official_rule_packs_enabled'",
			"ERRCODE='P5441'", "updated_by_user_id IS NULL AND state='enabled'", "pack_id <> 'system/waf-php-vpatch'",
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
}
