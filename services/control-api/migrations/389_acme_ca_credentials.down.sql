LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;

DO $migration_389_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 389 OR
       (SELECT max(version) FROM schema_migrations) <> 389 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=389 AND
        migration_id='389_acme_ca_credentials' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 389 down requires the exact verified migration head' USING ERRCODE='P3892';
    END IF;
    IF EXISTS (SELECT 1 FROM system_configuration_revisions
               WHERE convert_from(canonical_snapshot,'UTF8') ~ '"issuer": *"google_trust"') THEN
        RAISE EXCEPTION 'migration 389 down refuses: a system configuration uses Google Trust Services' USING ERRCODE='P3893';
    END IF;
END;
$migration_389_down$;

CREATE OR REPLACE FUNCTION system_configuration_v2_defaults_override(candidate jsonb, defaults_document jsonb)
RETURNS boolean
LANGUAGE plpgsql
IMMUTABLE
AS $$
DECLARE
    website jsonb := candidate->'website';
    stream jsonb := candidate->'stream';
    certificate jsonb := candidate->'certificate';
BEGIN
    IF NOT system_configuration_v2_json_keys_exact(
           candidate, ARRAY[]::text[], ARRAY['stream','website','certificate']
       ) OR candidate = '{}'::jsonb THEN
        RETURN false;
    END IF;
    IF website IS NOT NULL THEN
        IF NOT system_configuration_v2_json_keys_exact(website, ARRAY[]::text[], ARRAY[
               'ssl','other','origin','waf_enabled','cache_rules','force_https','hsts_enabled',
               'http2_enabled','http3_enabled','waf_modules','http_listen_ports',
               'https_listen_ports','default_cc_policy_id','ocsp_stapling_enabled',
               'origin_request_headers'
           ]) OR website = '{}'::jsonb OR
           (website ? 'http_listen_ports' AND NOT system_configuration_v2_port_list(website->'http_listen_ports')) OR
           (website ? 'https_listen_ports' AND NOT system_configuration_v2_port_list(website->'https_listen_ports')) OR
           (website ? 'hsts_enabled' AND jsonb_typeof(website->'hsts_enabled') <> 'boolean') OR
           (website ? 'http2_enabled' AND jsonb_typeof(website->'http2_enabled') <> 'boolean') OR
           (website ? 'http3_enabled' AND jsonb_typeof(website->'http3_enabled') <> 'boolean') OR
           (website ? 'force_https' AND jsonb_typeof(website->'force_https') <> 'boolean') OR
           (website ? 'ssl' AND NOT system_configuration_v2_default_ssl(website->'ssl')) OR
           (website ? 'ocsp_stapling_enabled' AND
            jsonb_typeof(website->'ocsp_stapling_enabled') <> 'boolean') OR
           (website ? 'origin' AND (
               NOT system_configuration_v2_json_keys_exact(
                   website->'origin', ARRAY[]::text[], ARRAY[
                       'scheme','http_port','https_port','http_version','ssl_protocols',
                       'keepalive_enabled','post_body_limit_bytes','connect_timeout_seconds',
                       'response_timeout_seconds'
                   ]
               ) OR website->'origin' = '{}'::jsonb OR
               NOT system_configuration_v2_default_origin(
                   defaults_document->'website'->'origin' || website->'origin'
               )
           )) OR
           (website ? 'cache_rules' AND NOT system_configuration_v2_cache_rules(website->'cache_rules')) OR
           (website ? 'origin_request_headers' AND
            NOT system_configuration_v2_origin_headers(website->'origin_request_headers')) OR
           (website ? 'default_cc_policy_id' AND
            jsonb_typeof(website->'default_cc_policy_id') NOT IN ('string','null')) OR
           (website ? 'default_cc_policy_id' AND
            jsonb_typeof(website->'default_cc_policy_id') = 'string' AND
            NOT system_configuration_v2_safe_label(website->'default_cc_policy_id')) OR
           (website ? 'waf_enabled' AND jsonb_typeof(website->'waf_enabled') <> 'boolean') OR
           (website ? 'waf_modules' AND NOT system_configuration_v2_waf_modules(website->'waf_modules')) OR
           (website ? 'other' AND NOT system_configuration_v2_default_other(website->'other')) THEN
            RETURN false;
        END IF;
    END IF;
    IF stream IS NOT NULL AND (
       NOT system_configuration_v2_json_keys_exact(
           stream, ARRAY[]::text[], ARRAY['protocol','load_balancing','proxy_protocol_enabled']
       ) OR stream = '{}'::jsonb OR
       (stream ? 'protocol' AND stream->>'protocol' NOT IN ('tcp','udp')) OR
       (stream ? 'load_balancing' AND stream->>'load_balancing' NOT IN ('round_robin','ip_hash')) OR
       (stream ? 'proxy_protocol_enabled' AND jsonb_typeof(stream->'proxy_protocol_enabled') <> 'boolean')
    ) THEN RETURN false; END IF;
    IF certificate IS NOT NULL AND (
       NOT system_configuration_v2_json_keys_exact(certificate, ARRAY[]::text[], ARRAY['issuer']) OR
       certificate = '{}'::jsonb OR certificate->>'issuer' NOT IN ('zerossl','lets_encrypt')
    ) THEN RETURN false; END IF;
    RETURN true;
EXCEPTION WHEN OTHERS THEN
    RETURN false;
END;
$$;

CREATE OR REPLACE FUNCTION system_configuration_v2_defaults_is_valid(candidate jsonb)
RETURNS boolean
LANGUAGE plpgsql
IMMUTABLE
AS $$
DECLARE
    stream jsonb := candidate->'stream';
    certificate jsonb := candidate->'certificate';
    item jsonb;
    seen_ids text[] := ARRAY[]::text[];
    seen_scopes text[] := ARRAY[]::text[];
BEGIN
    IF NOT system_configuration_v2_json_keys_exact(
           candidate, ARRAY['stream','website','overrides','certificate']
       ) OR NOT system_configuration_v2_default_website(candidate->'website') OR
       NOT system_configuration_v2_json_keys_exact(
           stream, ARRAY['protocol','load_balancing','proxy_protocol_enabled']
       ) OR stream->>'protocol' NOT IN ('tcp','udp') OR
       stream->>'load_balancing' NOT IN ('round_robin','ip_hash') OR
       jsonb_typeof(stream->'proxy_protocol_enabled') <> 'boolean' OR
       NOT system_configuration_v2_json_keys_exact(certificate, ARRAY['issuer']) OR
       certificate->>'issuer' NOT IN ('zerossl','lets_encrypt') OR
       jsonb_typeof(candidate->'overrides') <> 'array' THEN
        RETURN false;
    END IF;
    FOR item IN SELECT value FROM jsonb_array_elements(candidate->'overrides') LOOP
        IF NOT system_configuration_v2_json_keys_exact(item, ARRAY['id','scope','values','scope_id']) OR
           NOT system_configuration_v2_short_id(item->'id') OR item->>'scope' <> 'region' OR
           NOT system_configuration_v2_safe_label(item->'scope_id') OR
           NOT system_configuration_v2_defaults_override(item->'values', candidate) OR
           item->>'id' = ANY(seen_ids) OR item->>'scope_id' = ANY(seen_scopes) THEN
            RETURN false;
        END IF;
        seen_ids := array_append(seen_ids, item->>'id');
        seen_scopes := array_append(seen_scopes, item->>'scope_id');
    END LOOP;
    RETURN true;
EXCEPTION WHEN OTHERS THEN
    RETURN false;
END;
$$;

DROP TABLE acme_ca_credentials;
DROP FUNCTION validate_acme_ca_credentials_scope_389();
