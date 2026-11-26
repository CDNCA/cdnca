package migrations

import (
	"strings"
	"testing"
)

// Migration 705: on the verified 704 head, tenant scopes with sites or streams and no automatic publication policy
// get a community_default automatic one, and a site bound to no package and no line group is served by the platform
// default line group (618 / 663) and belongs in the publication (692). Down restores the 701 and 692 definitions.
func TestCommunityDefaultPublication705Contract(t *testing.T) {
	read := func(name string) string {
		body, err := FS.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		return string(body)
	}
	up := read("705_community_default_publication.up.sql")
	down := read("705_community_default_publication.down.sql")
	for _, fragment := range []string{
		"LOCK TABLE schema_migrations, edge_automatic_publication_policy_facts IN ACCESS EXCLUSIVE MODE",
		"(SELECT count(*) FROM schema_migrations) <> 704", "(SELECT max(version) FROM schema_migrations) <> 704",
		"WHERE version=704 AND", "migration_id='704_notification_templates_en'", "ERRCODE='P7050'",
		"'community_default'", "60000,30000,3,3,1800",
		"NOT EXISTS (SELECT 1 FROM edge_automatic_publication_policy_facts policy WHERE policy.target_scope_id=scope.id)",
		"CREATE OR REPLACE FUNCTION site_publication_expected_692",
		"CREATE OR REPLACE FUNCTION site_publication_outcome_618",
		"CREATE OR REPLACE FUNCTION site_sync_status_batch_663",
	} {
		if !strings.Contains(up, fragment) {
			t.Errorf("705 up missing %q", fragment)
		}
	}
	// Both serving CTEs (618 and 663) name the platform default for a site without a package or line group.
	if got := strings.Count(up, "platform_default.is_platform_default"); got != 2 {
		t.Errorf("705 up names the platform default line group %d times, want 2 (618 and 663)", got)
	}
	if got := strings.Count(up, "site.package_subscription_id IS NULL OR"); got != 2 {
		t.Errorf("705 up lets a site without a package belong in the publication %d times, want 2 (692 and 663)", got)
	}
	head := up[:strings.Index(up, "CREATE OR REPLACE FUNCTION")]
	if strings.Contains(head, "edge_automatic_publication_requests") || strings.Contains(head, "edge_system_republication_heads") {
		t.Error("705 up must not enqueue publications itself")
	}
	for _, fragment := range []string{
		"(SELECT count(*) FROM schema_migrations) <> 705",
		"migration_id='705_community_default_publication'", "ERRCODE='P7051'",
		"CREATE OR REPLACE FUNCTION site_publication_expected_692",
		"CREATE OR REPLACE FUNCTION site_publication_outcome_618",
		"CREATE OR REPLACE FUNCTION site_sync_status_batch_663",
	} {
		if !strings.Contains(down, fragment) {
			t.Errorf("705 down missing %q", fragment)
		}
	}
	if strings.Contains(down, "platform_default") || strings.Contains(down, "DELETE FROM edge_automatic_publication_policy_facts") {
		t.Error("705 down must restore the 701/692 definitions and keep the policies")
	}
}
