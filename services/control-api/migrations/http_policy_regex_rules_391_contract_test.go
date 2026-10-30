package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// Migration 391 (HTTP policy regex rules and preserve_path,
// site access settings, forced HTTPS status and excluded domains)
// is a placeholder number: the merge renumbers it after the head it lands on.
// Everything that changes with the renumbering is in this block.
const (
	migrationHTTPRegex391Version         = 391
	migrationHTTPRegex391ID              = "391_http_policy_regex_rules"
	migrationHTTPRegex391PreviousID      = "390_site_schedule302"
	migrationHTTPRegex391PreviousUpSHA   = "f805e5191361bd348ad96744b0df05ad42c329d6c1b9f64c0db5c31b46a66ac8"
	migrationHTTPRegex391PreviousDownSHA = "74363990e8e80de3c076aa9a20c057a7143bf0143a5e3673ba173351e4fae76b"
	migrationHTTPRegex391UpSHA           = "3394a5f15823e3f7fc28fd65d176a4afd2e4f0bd586232dfc94a572b6d1bbc66"
	migrationHTTPRegex391DownSHA         = "ff8424ee96e74fc490a9c0222728fdbba4ce679d4d7c26499da132bfb8442dd0"
)

func TestHTTPPolicyRegexRules391Contract(t *testing.T) {
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{migrationHTTPRegex391ID + ".up.sql", migrationHTTPRegex391UpSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migrationHTTPRegex391Version-1),
			fmt.Sprintf("(SELECT max(version) FROM schema_migrations) <> %d", migrationHTTPRegex391Version-1),
			"migration_id='" + migrationHTTPRegex391PreviousID + "'", migrationHTTPRegex391PreviousUpSHA, migrationHTTPRegex391PreviousDownSHA,
			"ERRCODE='P3910'",
			"CREATE FUNCTION http_policy_regex_valid_391", "CREATE FUNCTION http_policy_regex_target_valid_391",
			"CREATE OR REPLACE FUNCTION http_policy_redirects_valid_056", "'preserve_path'",
			"CREATE OR REPLACE FUNCTION http_policy_rewrites_valid_056",
			"CREATE OR REPLACE FUNCTION http_policy_rewrite_chain_valid_056",
			"CREATE OR REPLACE FUNCTION http_policy_rule_conflicts_valid_056",
			"CREATE TABLE site_access_settings", "CREATE TABLE site_access_write_requests",
			"sites_https_redirect_status_391", "sites_https_redirect_exclude_hosts_391",
			"CREATE OR REPLACE FUNCTION system_configuration_v2_default_other",
			"error_page_rule_revisions_category_391", "theme_error_pages_status_391",
		}},
		{migrationHTTPRegex391ID + ".down.sql", migrationHTTPRegex391DownSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migrationHTTPRegex391Version),
			"migration_id='" + migrationHTTPRegex391ID + "'", "ERRCODE='P3911'",
			"DROP FUNCTION http_policy_regex_valid_391(text)",
			"DROP TABLE site_access_settings", "DROP COLUMN https_redirect_status",
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
