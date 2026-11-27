package migrations

import (
	"strings"
	"testing"
)

// Migration 706: on the verified 705 head, the L2 branches of 618 and 663 take the platform default line group
// for a site bound to no package and no line group (l2_mode package); down restores the 705 definitions.
func TestCommunityL2PlatformDefault706Contract(t *testing.T) {
	read := func(name string) string {
		body, err := FS.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		return string(body)
	}
	up := read("706_community_l2_platform_default.up.sql")
	down := read("706_community_l2_platform_default.down.sql")
	for _, fragment := range []string{
		"LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE",
		"(SELECT count(*) FROM schema_migrations) <> 705", "(SELECT max(version) FROM schema_migrations) <> 705",
		"WHERE version=705 AND", "migration_id='705_community_default_publication'", "ERRCODE='P7060'",
		"CREATE OR REPLACE FUNCTION site_publication_outcome_618",
		"CREATE OR REPLACE FUNCTION site_sync_status_batch_663",
	} {
		if !strings.Contains(up, fragment) {
			t.Errorf("706 up missing %q", fragment)
		}
	}
	// 705's line group branches plus the two L2 branches name the platform default.
	if got := strings.Count(up, "platform_default.is_platform_default"); got != 4 {
		t.Errorf("706 up names the platform default line group %d times, want 4 (618 and 663, line group and L2)", got)
	}
	for _, fragment := range []string{
		"(SELECT count(*) FROM schema_migrations) <> 706",
		"migration_id='706_community_l2_platform_default'", "ERRCODE='P7061'",
		"CREATE OR REPLACE FUNCTION site_publication_outcome_618",
		"CREATE OR REPLACE FUNCTION site_sync_status_batch_663",
	} {
		if !strings.Contains(down, fragment) {
			t.Errorf("706 down missing %q", fragment)
		}
	}
	if got := strings.Count(down, "platform_default.is_platform_default"); got != 2 {
		t.Errorf("706 down names the platform default line group %d times, want the 705 line group branches only", got)
	}
	if strings.Contains(up, "FUNCTION site_publication_expected_692") || strings.Contains(down, "FUNCTION site_publication_expected_692") {
		t.Error("706 must leave 692 as 705 defined it")
	}
}
