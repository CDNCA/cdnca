package migrations

import (
	"strings"
	"testing"
)

// Migration 570: a renewed version
// is delivered to the nodes by the system, then switched in through the
// system republication channel (trigger certificate_renewal). The 569
// predecessor is pinned by checksum.
func TestCertificateRenewalDelivery570Contract(t *testing.T) {
	for _, script := range []struct {
		name     string
		required []string
	}{
		{"570_certificate_renewal_delivery.up.sql", []string{
			"(SELECT count(*) FROM schema_migrations) <> 569", "(SELECT max(version) FROM schema_migrations) <> 569",
			"migration_id='569_dns_provider_managed_by'",
			"checksum_sha256='26b098221e9b5fba4f8f4be3e8c99e22c74dc07fcca7c8465969c6e426e52a38'",
			"down_checksum_sha256='c920a0d83e918ccf6325b72fb1d77db57a96673b22ecfbd5ff0d5a30592438fa'",
			"ERRCODE='P5700'", "cardinality(triggers) BETWEEN 1 AND 22", "'package_suspension', 'certificate_renewal']::text[]",
			"'package_expiry', 'node_storage',\n        'package_suspension', 'certificate_renewal'))",
			"CREATE TABLE certificate_renewal_deliveries",
		}},
		{"570_certificate_renewal_delivery.down.sql", []string{
			"(SELECT count(*) FROM schema_migrations) <> 570", "migration_id='570_certificate_renewal_delivery'",
			"ERRCODE='P5701'", "ERRCODE='P5702'", "DROP TABLE certificate_renewal_deliveries",
			"cardinality(triggers) BETWEEN 1 AND 21",
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
