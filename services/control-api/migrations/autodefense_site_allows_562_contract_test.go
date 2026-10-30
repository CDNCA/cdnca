package migrations

import (
	"strings"
	"testing"
)

// Migration 562 (fix-adwhitelist, placeholder number): the "解除并加白"
// entries of the auto defense allow list. The predecessor is pinned to the
// integration head 554 by checksum (renumbered and re-pinned at merge).
func TestAutoDefenseSiteAllows562Contract(t *testing.T) {
	for _, script := range []struct {
		name     string
		required []string
	}{
		{"562_autodefense_site_allows.up.sql", []string{
			"(SELECT count(*) FROM schema_migrations) <> 561", "(SELECT max(version) FROM schema_migrations) <> 561",
			"migration_id='561_fallback_chain'",
			"checksum_sha256='dde5d9feddd7570881033c218f65ad5ced0f75e54c147915edc85c7fcb81e281'",
			"down_checksum_sha256='ca1a7585ffc3bfedd2e42498fe74f5392dcc02d262742220ff208fdbf6425a11'",
			"ERRCODE='P5620'", "CREATE TABLE autodefense_site_allows",
			// fix-adwhitelist3: a network or a JA4, permanent or until its expiry
			"kind text NOT NULL CHECK (kind IN ('cidr', 'ja4'))", "PRIMARY KEY (tenant_scope_id, site_id, kind, target)",
			"expires_at timestamptz CHECK (expires_at IS NULL OR (isfinite(expires_at) AND expires_at > created_at))",
			"CREATE INDEX autodefense_site_allows_expires_at ON autodefense_site_allows (expires_at) WHERE expires_at IS NOT NULL",
			"REFERENCES sites(scope_id, id) ON DELETE CASCADE", "CHECK (source = 'release')",
			"REVOKE ALL ON autodefense_site_allows FROM PUBLIC",
			"GRANT SELECT, INSERT, UPDATE, DELETE ON autodefense_site_allows TO cdnca_control_app, cdnca_control_runtime",
			// fix-adwhitelist2: single releases delivered to the nodes (Site.Releases)
			"to_regclass('autodefense_site_releases') IS NOT NULL", "CREATE TABLE autodefense_site_releases",
			"CHECK (kind IN ('ip', 'cidr', 'ja4'))", "PRIMARY KEY (tenant_scope_id, site_id, kind, target)",
			"REVOKE ALL ON autodefense_site_releases FROM PUBLIC",
			"GRANT SELECT, INSERT, UPDATE, DELETE ON autodefense_site_releases TO cdnca_control_app, cdnca_control_runtime",
			// fix-adwhitelist3: a person's retry and the per target node answers
			"retry integer NOT NULL DEFAULT 0 CHECK (retry BETWEEN 0 AND 100)",
			"to_regclass('autodefense_site_release_acks') IS NOT NULL", "CREATE TABLE autodefense_site_release_acks",
			"PRIMARY KEY (tenant_scope_id, site_id, kind, target, node_id)", "CHECK (applied = (error_code IS NULL))",
			"REFERENCES autodefense_site_releases(tenant_scope_id, site_id, kind, target) ON DELETE CASCADE",
			"GRANT SELECT, INSERT, UPDATE, DELETE ON autodefense_site_release_acks TO cdnca_control_app, cdnca_control_runtime",
			// merge-p20b: the release_acks report kind is a receipt kind
			"'drift', 'waf_evidence',\n                    'release_acks'))",
		}},
		{"562_autodefense_site_allows.down.sql", []string{
			"(SELECT count(*) FROM schema_migrations) <> 562", "migration_id='562_autodefense_site_allows'",
			"ERRCODE='P5621'", "DELETE FROM autodefense_report_receipts WHERE kind='release_acks'",
			"CHECK (kind IN ('minute', 'state', 'candidate', 'verdicts', 'adjust', 'node_event', 'drift', 'waf_evidence'));",
			"DROP TABLE autodefense_site_release_acks;\nDROP TABLE autodefense_site_releases;\nDROP TABLE autodefense_site_allows",
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
