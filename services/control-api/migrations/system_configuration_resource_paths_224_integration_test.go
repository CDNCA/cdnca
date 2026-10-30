//go:build integration

package migrations_test

import (
	"encoding/json"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestSystemConfigurationResourcePaths224UpDownUp(t *testing.T) {
	pool := packageCommerceRBAC079Pool(t, 223)

	if err := migrateVersionIsolated(t.Context(), pool, "up", 224); err != nil {
		t.Fatalf("223 -> 224: %v", err)
	}
	assertPackageCommerceRBAC079Ledger(t, pool, 224)
	assertSystemConfigurationResourcePath224(t, pool, true, "/data/download-temp")
	assertSystemConfigurationResourcePath224(t, pool, true, "/data/download-temp/")
	assertSystemConfigurationResourcePath224(t, pool, true, "/data/download-temp/export")
	assertSystemConfigurationResourcePath224(t, pool, true, "/data/download-temp/export/")
	assertSystemConfigurationResourcePath224(t, pool, true, "/var/lib/cdnca")
	assertSystemConfigurationResourcePath224(t, pool, true, "/var/lib/cdnca/")
	assertSystemConfigurationResourcePath224(t, pool, true, "/var/lib/cdnca/export")
	for _, path := range []string{
		"/data/download-temperature",
		"/data/download-temp//export",
		"/data/download-temp/../escape",
		"/data/download-temp/./export",
		`/data/download-temp\export`,
		"/data/download-temp/\nexport",
		"/var/lib/cdnca-sibling",
	} {
		assertSystemConfigurationResourcePath224(t, pool, false, path)
	}

	observed := systemConfigurationResourceSite224("/data/download-temp/", 200)
	assertSystemConfigurationResourceSite224(t, pool, observed, true)
	assertSystemConfigurationResourceSite224(
		t, pool, systemConfigurationResourceSite224("/data/download-temp/", 1001), false,
	)

	if err := migrateVersionIsolated(t.Context(), pool, "down", 224); err != nil {
		t.Fatalf("224 -> 223: %v", err)
	}
	assertPackageCommerceRBAC079Ledger(t, pool, 223)
	assertSystemConfigurationResourceSite224(t, pool, observed, false)
	assertSystemConfigurationResourceSite224(
		t, pool, systemConfigurationResourceSite224("/var/lib/cdnca", 100), true,
	)

	if err := migrateVersionIsolated(t.Context(), pool, "up", 224); err != nil {
		t.Fatalf("223 -> 224 reapply: %v", err)
	}
	assertPackageCommerceRBAC079Ledger(t, pool, 224)
	assertSystemConfigurationResourcePath224(t, pool, true, "/data/download-temp/")
	assertSystemConfigurationResourceSite224(t, pool, observed, true)
}

func assertSystemConfigurationResourcePath224(t *testing.T, pool *pgxpool.Pool, want bool, path string) {
	t.Helper()
	var got bool
	if err := pool.QueryRow(
		t.Context(),
		`SELECT system_configuration_v2_resource_access_log_path_224(to_jsonb($1::text))`,
		path,
	).Scan(&got); err != nil {
		t.Fatalf("validate resource path %q: %v", path, err)
	}
	if got != want {
		t.Fatalf("resource path %q valid = %t, want %t", path, got, want)
	}
}

func assertSystemConfigurationResourceSite224(t *testing.T, pool *pgxpool.Pool, site []byte, want bool) {
	t.Helper()
	var got bool
	if err := pool.QueryRow(
		t.Context(), `SELECT system_configuration_v2_resource_site($1::jsonb)`, string(site),
	).Scan(&got); err != nil {
		t.Fatalf("validate resource site: %v", err)
	}
	if got != want {
		t.Fatalf("resource site valid = %t, want %t: %s", got, want, site)
	}
}

func systemConfigurationResourceSite224(path string, multiplier int) []byte {
	value := map[string]any{
		"related_config_min_limit":        1000,
		"related_config_max_times_limit":  multiplier,
		"black_ip_limit":                  50,
		"white_ip_limit":                  50,
		"daily_clean_url_limit":           2000,
		"daily_clean_dir_limit":           500,
		"daily_pre_cache_url_limit":       2000,
		"daily_ip_unlock_limit":           1000,
		"ip_unlock_per_request_limit":     50,
		"cc_rule_max_limit":               5,
		"max_domains_per_site":            100,
		"listen_default_http_80":          true,
		"daily_access_log_download_limit": 10,
		"access_log_tmp_dir":              path,
		"access_log_retain_hours":         12,
	}
	payload, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}
	return payload
}
