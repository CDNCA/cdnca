LOCK TABLE system_configuration_revisions IN ACCESS EXCLUSIVE MODE;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM system_configuration_revisions) THEN
        RAISE EXCEPTION
            'system configuration migration 219 down refused: canonical v2 revisions cannot be losslessly downgraded';
    END IF;
END;
$$;

ALTER TABLE system_configuration_revisions
    DROP CONSTRAINT system_configuration_revisions_canonical_schema_check;
ALTER TABLE system_configuration_revisions
    ADD CONSTRAINT system_configuration_revisions_canonical_schema_check
    CHECK (canonical_schema = 'cdnca.system-configuration/v1');

DROP FUNCTION system_configuration_snapshot_is_valid(bytea);
DROP FUNCTION system_configuration_render_canonical_snapshot(jsonb);

ALTER FUNCTION system_configuration_render_canonical_snapshot_v1_035(jsonb)
    RENAME TO system_configuration_render_canonical_snapshot;
ALTER FUNCTION system_configuration_snapshot_is_valid_v1_035(bytea)
    RENAME TO system_configuration_snapshot_is_valid;

DROP FUNCTION system_configuration_v2_node_monitoring_is_valid(jsonb);
DROP FUNCTION system_configuration_v2_secrets_is_valid(jsonb);
DROP FUNCTION system_configuration_v2_error_pages_is_valid(jsonb);
DROP FUNCTION system_configuration_v2_resources_is_valid(jsonb);
DROP FUNCTION system_configuration_v2_resources_override(jsonb);
DROP FUNCTION system_configuration_v2_resource_site_stream(jsonb);
DROP FUNCTION system_configuration_v2_resource_stream(jsonb);
DROP FUNCTION system_configuration_v2_resource_site(jsonb);
DROP FUNCTION system_configuration_v2_defaults_is_valid(jsonb);
DROP FUNCTION system_configuration_v2_defaults_override(jsonb, jsonb);
DROP FUNCTION system_configuration_v2_default_website(jsonb);
DROP FUNCTION system_configuration_v2_default_origin(jsonb);
DROP FUNCTION system_configuration_v2_default_other(jsonb);
DROP FUNCTION system_configuration_v2_waf_modules(jsonb);
DROP FUNCTION system_configuration_v2_origin_headers(jsonb);
DROP FUNCTION system_configuration_v2_cache_rules(jsonb);
DROP FUNCTION system_configuration_v2_default_ssl(jsonb);
DROP FUNCTION system_configuration_v2_tls_protocols(jsonb);
DROP FUNCTION system_configuration_v2_nginx_is_valid(jsonb);
DROP FUNCTION system_configuration_v2_nginx_override(jsonb, jsonb);
DROP FUNCTION system_configuration_v2_nginx_stream(jsonb);
DROP FUNCTION system_configuration_v2_nginx_http(jsonb);
DROP FUNCTION system_configuration_v2_nginx_worker(jsonb);
DROP FUNCTION system_configuration_v2_port_ranges(jsonb);
DROP FUNCTION system_configuration_v2_port_list(jsonb);
DROP FUNCTION system_configuration_v2_string_set(jsonb, text[], integer, integer);
DROP FUNCTION system_configuration_v2_safe_label(jsonb);
DROP FUNCTION system_configuration_v2_short_id(jsonb);
DROP FUNCTION system_configuration_v2_json_keys_exact(jsonb, text[], text[]);
