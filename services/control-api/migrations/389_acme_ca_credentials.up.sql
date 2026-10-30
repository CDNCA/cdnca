LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;

DO $migration_389_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 388 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 388 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=388 AND
        migration_id='388_certificate_notices' AND
        checksum_sha256='6b3de6c8bf5d45920e60b609b090c0ea921ef94ac54fc3ec3c34e951541f38db' AND
        down_checksum_sha256='e10a84ecab7253cb5f21927776297985626537490b0423894afba8183fb46c4c' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR to_regclass(current_schema() || '.acme_ca_credentials') IS NOT NULL THEN
        RAISE EXCEPTION 'migration 389 requires the exact verified 388 release head' USING ERRCODE='P3890';
    END IF;
END;
$migration_389_up$;

-- r136 ge-tls (GoEdge 对照缺失 5): ACME External Account Binding for CAs
-- that require it (ZeroSSL, Google Trust Services). One row per CA for the
-- installation: its directory and the EAB key ID with the HMAC key sealed by
-- the DNS credential keyring (dnsacme.AESGCMCredentialCipher, the same KEK
-- and rotation as DNS API credentials). The HMAC key is never returned by an
-- API; responses show only whether it is set and a short digest.
-- 系统设置 > 网站默认 > 证书 > 签发机构 (defaults.certificate.issuer) picks the
-- CA new orders use; google_trust is new.
CREATE TABLE acme_ca_credentials (
    platform_scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE RESTRICT,
    ca text NOT NULL CHECK (ca IN ('zerossl','google_trust')),
    directory_url text NOT NULL CHECK (
        directory_url LIKE 'https://%' AND octet_length(directory_url) <= 2048 AND directory_url !~ '[[:cntrl:][:space:]]'
    ),
    eab_key_id text NOT NULL CHECK (octet_length(eab_key_id) BETWEEN 1 AND 256 AND eab_key_id !~ '[[:cntrl:][:space:]]'),
    eab_hmac_key_id text NOT NULL CHECK (octet_length(eab_hmac_key_id) BETWEEN 1 AND 255),
    eab_hmac_ciphertext bytea NOT NULL CHECK (octet_length(eab_hmac_ciphertext) BETWEEN 16 AND 4096),
    eab_hmac_sha256_prefix text NOT NULL CHECK (eab_hmac_sha256_prefix ~ '^[0-9a-f]{8}$'),
    revision bigint NOT NULL CHECK (revision > 0),
    updated_by_user_id uuid NOT NULL,
    updated_at timestamptz NOT NULL,
    PRIMARY KEY (platform_scope_id, ca),
    FOREIGN KEY (platform_scope_id, updated_by_user_id) REFERENCES memberships(scope_id, user_id) ON DELETE RESTRICT
);

CREATE FUNCTION validate_acme_ca_credentials_scope_389() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM access_scopes WHERE id=NEW.platform_scope_id AND kind='platform' AND tenant_id IS NULL) THEN
        RAISE EXCEPTION 'ACME CA credentials require the platform scope' USING ERRCODE='P3891';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER acme_ca_credentials_scope_389 BEFORE INSERT OR UPDATE ON acme_ca_credentials
FOR EACH ROW EXECUTE FUNCTION validate_acme_ca_credentials_scope_389();

REVOKE ALL ON acme_ca_credentials FROM PUBLIC;
REVOKE ALL ON FUNCTION validate_acme_ca_credentials_scope_389() FROM PUBLIC;
DO $grant_389$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname='cdnca_control_app') THEN
        GRANT SELECT, INSERT, UPDATE, DELETE ON acme_ca_credentials TO cdnca_control_app;
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname='cdnca_control_runtime') THEN
        GRANT SELECT ON acme_ca_credentials TO cdnca_control_runtime;
    END IF;
END;
$grant_389$;

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
       certificate = '{}'::jsonb OR certificate->>'issuer' NOT IN ('zerossl','lets_encrypt','google_trust')
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
       certificate->>'issuer' NOT IN ('zerossl','lets_encrypt','google_trust') OR
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
