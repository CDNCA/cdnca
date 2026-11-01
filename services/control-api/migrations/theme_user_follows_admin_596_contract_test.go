package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// Migration 596 (fix-themefollow: the user console follows the admin console
// live). Everything that changes if a merge renumbers it is here.
const (
	migration596Version         = 596
	migration596PreviousVersion = 595
	migration596PreviousID      = "595_entitlement_customer_display"
	migration596PreviousUpSHA   = "8535da99c67bb01647bb0e481037dd7151c6ea82f0f6c7c17500a43869327a3a"
	migration596PreviousDownSHA = "01ebe57d761db0c7bc7ef7c3c44c0b72eaa2e23b62d6f8ad7e3384fc70406201"
	migration596ID              = "596_theme_user_follows_admin"
)

func TestThemeUserFollowsAdmin596Contract(t *testing.T) {
	for _, script := range []struct {
		name     string
		required []string
	}{
		{migration596ID + ".up.sql", []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration596PreviousVersion),
			fmt.Sprintf("(SELECT max(version) FROM schema_migrations) <> %d", migration596PreviousVersion),
			fmt.Sprintf("WHERE version=%d AND", migration596PreviousVersion),
			"migration_id='" + migration596PreviousID + "'",
			"checksum_sha256='" + migration596PreviousUpSHA + "'",
			"down_checksum_sha256='" + migration596PreviousDownSHA + "'",
			"ERRCODE='P5960'", "ALTER COLUMN package_sha256 DROP NOT NULL",
			"CHECK (package_sha256 IS NOT NULL OR slot = 'user')",
			"CREATE OR REPLACE FUNCTION validate_theme_activation_360()",
			"CREATE OR REPLACE FUNCTION protect_theme_facts_360()", "'migration-596'",
		}},
		{migration596ID + ".down.sql", []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration596Version),
			"migration_id='" + migration596ID + "'", "ERRCODE='P5961'", "ERRCODE='P5962'",
			"DROP CONSTRAINT theme_activations_user_follows_596", "ALTER COLUMN package_sha256 SET NOT NULL",
			"DISABLE TRIGGER theme_activations_protected_360", "ENABLE TRIGGER theme_activations_protected_360",
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
	for suffix, want := range map[string]string{".up.sql": migration596PreviousUpSHA, ".down.sql": migration596PreviousDownSHA} {
		raw, err := FS.ReadFile(migration596PreviousID + suffix)
		if err != nil {
			t.Fatal(err)
		}
		if got := fmt.Sprintf("%x", sha256.Sum256(raw)); got != want {
			t.Errorf("%s%s checksum %s, guard pins %s", migration596PreviousID, suffix, got, want)
		}
	}
	// The down restores 360's function bodies exactly.
	original, err := FS.ReadFile("360_theme_packages.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	down, err := FS.ReadFile(migration596ID + ".down.sql")
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"validate_theme_activation_360()", "protect_theme_facts_360()"} {
		body := functionBody(t, string(original), "CREATE FUNCTION "+name)
		if !strings.Contains(string(down), "CREATE OR REPLACE FUNCTION "+name+body) {
			t.Errorf("down does not restore %s as 360 defined it", name)
		}
	}
}

func functionBody(t *testing.T, script, header string) string {
	t.Helper()
	start := strings.Index(script, header)
	if start < 0 {
		t.Fatalf("%q not found", header)
	}
	rest := script[start+len(header):]
	end := strings.Index(rest, "$$;")
	if end < 0 {
		t.Fatalf("%q has no body end", header)
	}
	return rest[:end+3]
}
