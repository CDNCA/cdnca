package migrations

import (
	"strings"
	"testing"
)

func TestSystemConfigurationCanonicalV221Contract(t *testing.T) {
	up, err := FS.ReadFile("219_system_configuration_canonical_v2.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	down, err := FS.ReadFile("219_system_configuration_canonical_v2.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	upSQL, downSQL := string(up), string(down)
	for _, required := range []string{
		"requires an empty revision stream",
		"cdnca.system-configuration/v2",
		"system_configuration_render_canonical_snapshot_v1_035",
		"system_configuration_snapshot_is_valid_v1_035",
		"CREATE FUNCTION system_configuration_v2_nginx_is_valid",
		"CREATE FUNCTION system_configuration_v2_defaults_is_valid",
		"CREATE FUNCTION system_configuration_v2_resources_is_valid",
		"'recommended','legacy_tls12','legacy_full','custom'",
		"'range','content','enabled','no_cache'",
		"'ignore_vary','ttl_seconds','ignore_query'",
		"ARRAY['string','variable']",
		"'scheme','http_port','https_port','http_version','ssl_protocols'",
		"'keepalive_enabled','post_body_limit_bytes','connect_timeout_seconds'",
		"ARRAY['http','stream','worker','overrides']",
		"ARRAY['stream','website','overrides','certificate']",
		"ARRAY['site','stream','overrides','site_stream']",
		"raw <> document::text",
		"ARRAY['node_monitoring']",
	} {
		if !strings.Contains(upSQL, required) {
			t.Errorf("up migration missing %q", required)
		}
	}
	for _, forbidden := range []string{
		"'max_sites_per_tenant'",
		"'max_origins_per_site'",
		"'max_certificates_per_tenant'",
		"'minimum_related_config_limit'",
	} {
		if strings.Contains(upSQL, forbidden) {
			t.Errorf("up migration retained v1 canonical field %q", forbidden)
		}
	}
	for _, required := range []string{
		"canonical v2 revisions cannot be losslessly downgraded",
		"cdnca.system-configuration/v1",
		"RENAME TO system_configuration_render_canonical_snapshot",
		"RENAME TO system_configuration_snapshot_is_valid",
		"DROP FUNCTION system_configuration_v2_nginx_is_valid",
		"DROP FUNCTION system_configuration_v2_defaults_is_valid",
		"DROP FUNCTION system_configuration_v2_resources_is_valid",
	} {
		if !strings.Contains(downSQL, required) {
			t.Errorf("down migration missing %q", required)
		}
	}
}

func TestSystemConfigurationCanonicalV221ResourceOverrideBaselineContract(t *testing.T) {
	up, err := FS.ReadFile("219_system_configuration_canonical_v2.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	upSQL := string(up)
	start := strings.Index(upSQL, "CREATE FUNCTION system_configuration_v2_resources_override")
	end := strings.Index(upSQL, "CREATE FUNCTION system_configuration_v2_error_pages_is_valid")
	if start < 0 || end <= start {
		t.Fatal("resource validation function block is missing")
	}
	resourceSQL := upSQL[start:end]
	for _, required := range []string{"seen_scopes", "item->>'scope_id' = ANY(seen_scopes)"} {
		if !strings.Contains(resourceSQL, required) {
			t.Errorf("resource validation contract missing %q", required)
		}
	}
	for _, deferred := range []string{"num_nonnulls(", "seen_scope_settings", "chr(31)"} {
		if strings.Contains(resourceSQL, deferred) {
			t.Fatalf("migration 219 contains post-release resource override logic %q", deferred)
		}
	}
}

func TestSystemConfigurationCanonicalV221PortRangeBaselineContract(t *testing.T) {
	up, err := FS.ReadFile("219_system_configuration_canonical_v2.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	upSQL := string(up)
	start := strings.Index(upSQL, "CREATE FUNCTION system_configuration_v2_port_ranges")
	end := strings.Index(upSQL, "CREATE FUNCTION system_configuration_v2_nginx_worker")
	if start < 0 || end <= start {
		t.Fatal("port range validation function block is missing")
	}
	portRangeSQL := upSQL[start:end]
	if !strings.Contains(portRangeSQL, "jsonb_array_length(candidate) > 128") {
		t.Fatal("migration 219 port range baseline is not 128")
	}
	if strings.Contains(portRangeSQL, "jsonb_array_length(candidate) > 256") {
		t.Fatal("migration 219 was rewritten with the post-release 256 limit")
	}
}
