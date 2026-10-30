//go:build integration

package migrations_test

import (
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestSystemConfigurationTLSProtocols226UpDownUp(t *testing.T) {
	pool := packageCommerceRBAC079Pool(t, 225)
	assertSystemConfigurationTLSProtocols226(t, pool, `["SSLv2"]`, false)
	assertSystemConfigurationTLSProtocols226(t, pool, `["SSLv3"]`, false)
	assertSystemConfigurationTLSProtocols226(t, pool, `["TLSv1","TLSv1.1","TLSv1.2","TLSv1.3"]`, true)

	if err := migrateVersionIsolated(t.Context(), pool, "up", 226); err != nil {
		t.Fatalf("225 -> 226: %v", err)
	}
	assertPackageCommerceRBAC079Ledger(t, pool, 226)
	for _, protocols := range []string{
		`["SSLv2"]`,
		`["SSLv3"]`,
		`["SSLv2","SSLv3","TLSv1","TLSv1.1","TLSv1.2","TLSv1.3"]`,
	} {
		assertSystemConfigurationTLSProtocols226(t, pool, protocols, true)
	}
	for _, protocols := range []string{
		`[]`,
		`["SSLv2","SSLv2"]`,
		`["TLSv1.4"]`,
	} {
		assertSystemConfigurationTLSProtocols226(t, pool, protocols, false)
	}
	assertSystemConfigurationDefaultSSL226(t, pool,
		`{"mode":"recommended","protocols":["TLSv1.2","TLSv1.3"],"cipher_suites":"ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305","prefer_server_ciphers":false}`,
		true,
	)
	assertSystemConfigurationDefaultSSL226(t, pool,
		`{"mode":"recommended","protocols":["SSLv2","TLSv1.2","TLSv1.3"],"cipher_suites":"ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305","prefer_server_ciphers":false}`,
		false,
	)
	assertSystemConfigurationDefaultSSL226(t, pool,
		`{"mode":"custom","protocols":["SSLv2","SSLv3"],"cipher_suites":"DEFAULT:@SECLEVEL=0","prefer_server_ciphers":true}`,
		true,
	)

	if err := migrateVersionIsolated(t.Context(), pool, "down", 226); err != nil {
		t.Fatalf("226 -> 225: %v", err)
	}
	assertPackageCommerceRBAC079Ledger(t, pool, 225)
	assertSystemConfigurationTLSProtocols226(t, pool, `["SSLv2"]`, false)
	assertSystemConfigurationTLSProtocols226(t, pool, `["TLSv1","TLSv1.1","TLSv1.2","TLSv1.3"]`, true)

	if err := migrateVersionIsolated(t.Context(), pool, "up", 226); err != nil {
		t.Fatalf("225 -> 226 reapply: %v", err)
	}
	assertPackageCommerceRBAC079Ledger(t, pool, 226)
	assertSystemConfigurationTLSProtocols226(t, pool, `["SSLv2","SSLv3"]`, true)
}

func assertSystemConfigurationTLSProtocols226(
	t *testing.T, pool *pgxpool.Pool, protocols string, want bool,
) {
	t.Helper()
	var got bool
	if err := pool.QueryRow(t.Context(),
		`SELECT system_configuration_v2_tls_protocols($1::jsonb)`, protocols).Scan(&got); err != nil {
		t.Fatalf("validate TLS protocols %s: %v", protocols, err)
	}
	if got != want {
		t.Fatalf("TLS protocols %s valid=%v, want %v", protocols, got, want)
	}
}

func assertSystemConfigurationDefaultSSL226(
	t *testing.T, pool *pgxpool.Pool, ssl string, want bool,
) {
	t.Helper()
	var got bool
	if err := pool.QueryRow(t.Context(),
		`SELECT system_configuration_v2_default_ssl($1::jsonb)`, ssl).Scan(&got); err != nil {
		t.Fatalf("validate default SSL %s: %v", ssl, err)
	}
	if got != want {
		t.Fatalf("default SSL %s valid=%v, want %v", ssl, got, want)
	}
}
