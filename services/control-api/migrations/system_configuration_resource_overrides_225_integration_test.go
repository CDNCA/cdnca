//go:build integration

package migrations_test

import (
	"encoding/json"
	"strconv"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

const migration225Resources = `{
	"site": {
		"black_ip_limit": 10000,
		"white_ip_limit": 10000,
		"cc_rule_max_limit": 1000,
		"access_log_tmp_dir": "/var/lib/cdnca/access-logs",
		"max_domains_per_site": 10,
		"daily_clean_dir_limit": 1000,
		"daily_clean_url_limit": 1000,
		"daily_ip_unlock_limit": 1000,
		"daily_pre_cache_url_limit": 1000,
		"access_log_retain_hours": 24,
		"listen_default_http_80": true,
		"related_config_min_limit": 1,
		"ip_unlock_per_request_limit": 1,
		"daily_access_log_download_limit": 10,
		"related_config_max_times_limit": 1
	},
	"stream": {
		"acl_max_limit": 1000,
		"custom_port_not_allow": [],
		"related_config_min_limit": 1,
		"related_config_max_times_limit": 1
	},
	"site_stream": {
		"custom_port_allow": [],
		"custom_port_not_allow": []
	},
	"overrides": []
}`

func TestSystemConfigurationResourceOverrides225UpDownUp(t *testing.T) {
	pool := packageCommerceRBAC079Pool(t, 224)
	differentSettings := `[
		{"id":"resource01","scope":"region","scope_id":"east","values":{"site":{"black_ip_limit":20000}}},
		{"id":"resource02","scope":"region","scope_id":"east","values":{"site":{"white_ip_limit":30000}}}
	]`
	duplicateSetting := `[
		{"id":"resource01","scope":"region","scope_id":"east","values":{"site":{"black_ip_limit":20000}}},
		{"id":"resource02","scope":"region","scope_id":"east","values":{"site":{"black_ip_limit":30000}}}
	]`
	multipleSettings := `[
		{"id":"resource03","scope":"region","scope_id":"east","values":{"site":{"black_ip_limit":20000,"white_ip_limit":30000}}}
	]`

	assertSystemConfigurationResourceOverrides225(t, pool, differentSettings, false)
	assertSystemConfigurationResourceOverrides225(t, pool, multipleSettings, true)

	if err := migrateVersionIsolated(t.Context(), pool, "up", 225); err != nil {
		t.Fatalf("224 -> 225: %v", err)
	}
	assertPackageCommerceRBAC079Ledger(t, pool, 225)
	assertSystemConfigurationResourceOverrides225(t, pool, differentSettings, true)
	assertSystemConfigurationResourceOverrides225(t, pool, duplicateSetting, false)
	assertSystemConfigurationResourceOverrides225(t, pool, multipleSettings, false)

	if err := migrateVersionIsolated(t.Context(), pool, "down", 225); err != nil {
		t.Fatalf("225 -> 224: %v", err)
	}
	assertPackageCommerceRBAC079Ledger(t, pool, 224)
	assertSystemConfigurationResourceOverrides225(t, pool, differentSettings, false)
	assertSystemConfigurationResourceOverrides225(t, pool, multipleSettings, true)

	if err := migrateVersionIsolated(t.Context(), pool, "up", 225); err != nil {
		t.Fatalf("224 -> 225 reapply: %v", err)
	}
	assertPackageCommerceRBAC079Ledger(t, pool, 225)
	assertSystemConfigurationResourceOverrides225(t, pool, differentSettings, true)
}

func TestSystemConfigurationResourcePortRanges225UpDownUp(t *testing.T) {
	pool := packageCommerceRBAC079Pool(t, 224)
	assertSystemConfigurationPortRanges225(t, pool, 129, false)

	if err := migrateVersionIsolated(t.Context(), pool, "up", 225); err != nil {
		t.Fatalf("224 -> 225: %v", err)
	}
	for _, test := range []struct {
		count int
		want  bool
	}{{129, true}, {256, true}, {257, false}} {
		t.Run(strconv.Itoa(test.count), func(t *testing.T) {
			assertSystemConfigurationPortRanges225(t, pool, test.count, test.want)
		})
	}

	if err := migrateVersionIsolated(t.Context(), pool, "down", 225); err != nil {
		t.Fatalf("225 -> 224: %v", err)
	}
	assertSystemConfigurationPortRanges225(t, pool, 129, false)

	if err := migrateVersionIsolated(t.Context(), pool, "up", 225); err != nil {
		t.Fatalf("224 -> 225 reapply: %v", err)
	}
	assertSystemConfigurationPortRanges225(t, pool, 256, true)
}

func assertSystemConfigurationResourceOverrides225(
	t *testing.T, pool *pgxpool.Pool, overrides string, want bool,
) {
	t.Helper()
	var got bool
	if err := pool.QueryRow(t.Context(), `SELECT system_configuration_v2_resources_is_valid(
		jsonb_set($1::jsonb, '{overrides}', $2::jsonb)
	)`, migration225Resources, overrides).Scan(&got); err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("resource overrides valid=%v, want %v: %s", got, want, overrides)
	}
}

func assertSystemConfigurationPortRanges225(
	t *testing.T, pool *pgxpool.Pool, count int, want bool,
) {
	t.Helper()
	ranges := make([]map[string]int, count)
	for index := range ranges {
		ranges[index] = map[string]int{"from": index + 1, "to": index + 1}
	}
	candidate, err := json.Marshal(ranges)
	if err != nil {
		t.Fatal(err)
	}
	var got bool
	if err := pool.QueryRow(t.Context(),
		`SELECT system_configuration_v2_port_ranges($1::jsonb)`, string(candidate)).Scan(&got); err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("%d ranges valid=%v, want %v", count, got, want)
	}
}
