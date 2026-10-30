package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// Migration 460 (攻击自动升级) is allotted 460 on the 459 head;
// everything that changes with a renumbering is here.
const (
	migration460Version         = 460
	migration460ID              = "460_attack_escalation"
	migration460PreviousID      = "459_tenant_system_role_grants"
	migration460PreviousUpSHA   = "c4772c854d5294193c6d91b858b5a3b76e4ca809baf8a20f8fbc2e5c966c20af"
	migration460PreviousDownSHA = "aa0701eeab00c053ac7f597ec7e54912917143dc87924a033367b167ac607547"
	migration460UpSHA           = "1df7430b58c0d00752bac88118cfb40c49171b93f323d3d5ca6b57e3debda662"
	migration460DownSHA         = "5476994323e7aaeae25b23915c6b6e72e01762072f3df6173c91c8e0b71668f5"
)

func TestAttackEscalation460Contract(t *testing.T) {
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{migration460ID + ".up.sql", migration460UpSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration460Version-1),
			fmt.Sprintf("(SELECT max(version) FROM schema_migrations) <> %d", migration460Version-1),
			"migration_id='" + migration460PreviousID + "'", migration460PreviousUpSHA, migration460PreviousDownSHA,
			"ERRCODE='P4600'", "CREATE TABLE node_line_group_tiers", "CREATE TABLE node_line_group_grants",
			"CREATE TABLE escalate_package_policies", "CREATE TABLE escalate_sites", "CREATE TABLE escalate_site_states", "CREATE TABLE escalate_events", "ERRCODE='P4603'",
			"ERRCODE='P4604'", "ERRCODE='P4605'", "CREATE TABLE escalate_site_routes",
			"CREATE TABLE escalate_site_drop_node_states", "dns_cname_retargets_ttl_460_check", "'attack_escalate'",
			"'attack_escalation']::text[]", "CREATE OR REPLACE FUNCTION tenant_carries_node_287",
			"CREATE OR REPLACE FUNCTION acme_http01_site_candidate_nodes", "'security.escalate.blackhole'",
		}},
		{migration460ID + ".down.sql", migration460DownSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration460Version),
			"migration_id='" + migration460ID + "'", "ERRCODE='P4601'", "DROP TABLE node_line_group_tiers",
		}},
	} {
		raw, err := FS.ReadFile(script.name)
		if err != nil {
			t.Skipf("%s not embedded under this number (local renumbering): %v", script.name, err)
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
