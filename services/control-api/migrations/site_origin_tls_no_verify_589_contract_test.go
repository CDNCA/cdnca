package migrations

import (
	"strings"
	"testing"
)

// Migration 589: site_origin_pools.tls_trust gains 'none'
// (回源 HTTPS 不校验源站证书). Predecessor 588 is pinned by checksum.
func TestSiteOriginTLSNoVerify589Contract(t *testing.T) {
	for _, script := range []struct {
		name     string
		required []string
	}{
		{"589_site_origin_tls_no_verify.up.sql", []string{
			"(SELECT count(*) FROM schema_migrations) <> 588", "(SELECT max(version) FROM schema_migrations) <> 588",
			"migration_id='588_cache_account_quotas'",
			"checksum_sha256='c63c8624454b69bdaceddd9b17d810bcc04e80fed2ea5511f8e7c56168a4e257'",
			"down_checksum_sha256='b54815eb77c437e27e5ac937c591ffd185a7e060dc8775ddad77ce222cbd2f78'",
			"ERRCODE='P5890'", "DROP CONSTRAINT site_origin_pools_tls_trust_check",
			"CHECK (tls_trust IN ('system', 'custom', 'none'))",
		}},
		{"589_site_origin_tls_no_verify.down.sql", []string{
			"(SELECT count(*) FROM schema_migrations) <> 589", "migration_id='589_site_origin_tls_no_verify'",
			"ERRCODE='P5891'", "tls_trust = 'none'", "ERRCODE='P5892'",
			"CHECK (tls_trust IN ('system', 'custom'))",
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
