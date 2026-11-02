package migrations

import (
	"strings"
	"testing"
)

// Migration 621 : orders whose issuance outbox already
// failed with a code the dispatcher never retries are failed like
// acmeruntime.settleFailure would; already-failed orders are left alone and
// down changes no data.
func TestCertificateOrderOutboxFailure621Contract(t *testing.T) {
	for _, script := range []struct {
		name      string
		required  []string
		forbidden []string
	}{
		{"621_certificate_order_outbox_failure.up.sql", []string{
			"(SELECT count(*) FROM schema_migrations) <> 620", "(SELECT max(version) FROM schema_migrations) <> 620",
			"migration_id='620_http_policy_orphan_cleanup'", "column_name = 'failure_reason'", "ERRCODE='P6210'",
			"WHERE certificate_order.status IN ('pending', 'validating', 'issuing')",
			"AND latest.status = 'failed'",
			"'acme_dns_zone_unavailable', 'acme_dns_provider_platform_managed', 'acme_renewal_skipped_auto_renew_off',",
			// dnsacme.dnsZoneUnavailableReasonFormat
			"format('所选 DNS API 下没有托管 %s 的解析域，无法用 DNS 验证；请添加该域名所在 DNS 服务商的 API，或改用 HTTP 验证'",
			"revision = certificate_order.revision + 1",
			"updated_at = greatest(certificate_order.updated_at, statement_timestamp())",
		}, []string{"UPDATE dns_acme_outbox", "DELETE FROM", "INSERT INTO audit_events", "DROP "}},
		{"621_certificate_order_outbox_failure.down.sql", []string{
			"(SELECT count(*) FROM schema_migrations) <> 621", "migration_id='621_certificate_order_outbox_failure'",
			"ERRCODE='P6211'",
		}, []string{"UPDATE ", "DELETE FROM", "DROP "}},
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
		for _, fragment := range script.forbidden {
			if strings.Contains(string(body), fragment) {
				t.Errorf("%s must not contain %q", script.name, fragment)
			}
		}
	}
}
