package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// Migration 303 (G6 domain trust, placeholder) sits on the exact verified 302 head. The
// numbers live together so the coordinator can renumber on merge.
const (
	domainTrustVersion           = "303"
	domainTrustPrevious          = "302_tickets"
	domainTrustPreviousUpSHA     = "dacca1529d3d10f48f75125ec29d82ae33e99a72ab9fc28927d8123de988d2ef"
	domainTrustPreviousDownSHA   = "91b6b40573cd5c636810e94d61b0673dffd3034184fda3a8a2fe6d11e35c2e4a"
	domainTrustUpSHA             = "ab0677edaf2c2db45e8b7f7d764a6ff5d766911f9de519209777363ccb876153"
	domainTrustDownSHA           = "7c851de89b64a91c45efe4acd9e4e89387774a69ac1daf67bd6a87bf1a522b9a"
	domainTrustPreviousHeadCount = "(SELECT count(*) FROM schema_migrations) <> 302"
)

func TestDomainTrust303Contract(t *testing.T) {
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{domainTrustVersion + "_domain_trust.up.sql", domainTrustUpSHA, []string{
			domainTrustPreviousHeadCount, domainTrustPrevious, domainTrustPreviousUpSHA, domainTrustPreviousDownSHA,
			"ERRCODE='P3030'",
			"CREATE OR REPLACE FUNCTION guard_site_domain_fact_148()",
			"USING ERRCODE = '23505', CONSTRAINT = 'site_domain_facts_overlap_148'",
			"PERFORM lock_site_domains_299(ARRAY[NEW.canonical_domain])",
			"CREATE UNIQUE INDEX domain_ownerships_verified_apex_299_idx ON domain_ownerships(apex) WHERE status = 'verified'",
			"DEFERRABLE INITIALLY DEFERRED",
			"ON CONFLICT (template_id, version, channel) DO NOTHING",
		}},
		{domainTrustVersion + "_domain_trust.down.sql", domainTrustDownSHA, []string{
			"(SELECT count(*) FROM schema_migrations) <> 303", "303_domain_trust", "ERRCODE='P3031'",
			"PERFORM pg_advisory_xact_lock(148, 1);",
			"DROP TABLE site_domain_active;",
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
