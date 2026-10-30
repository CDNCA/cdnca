INSERT INTO permissions (name, description) VALUES
    ('system_configuration.read', 'Read platform system configuration revisions'),
    ('system_configuration.manage', 'Create, validate, activate, and roll back platform system configuration revisions');

INSERT INTO role_permissions (role_id, permission_name)
SELECT roles.id, permissions.name
FROM roles
CROSS JOIN permissions
WHERE roles.system_role
  AND roles.name = 'platform_owner'
  AND permissions.name IN ('system_configuration.read', 'system_configuration.manage')
ON CONFLICT DO NOTHING;

CREATE TABLE system_configuration_streams (
    platform_scope_id uuid PRIMARY KEY REFERENCES access_scopes(id) ON DELETE RESTRICT,
    head_revision bigint NOT NULL DEFAULT 0 CHECK (head_revision >= 0 AND head_revision < 9223372036854775807),
    active_revision bigint,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    CHECK (active_revision IS NULL OR (active_revision > 0 AND active_revision <= head_revision)),
    CHECK (created_at >= timestamptz '0001-01-01 00:00:00+00' AND
           updated_at < timestamptz '10000-01-01 00:00:00+00' AND
           updated_at >= created_at)
);

CREATE TABLE system_configuration_revisions (
    platform_scope_id uuid NOT NULL REFERENCES system_configuration_streams(platform_scope_id) ON DELETE RESTRICT,
    revision bigint NOT NULL CHECK (revision > 0 AND revision < 9223372036854775807),
    status text NOT NULL CHECK (status IN ('draft', 'validated', 'active', 'superseded', 'rejected')),
    canonical_schema text NOT NULL CHECK (canonical_schema = 'cdnca.system-configuration/v1'),
    canonical_snapshot bytea NOT NULL CHECK (octet_length(canonical_snapshot) BETWEEN 1 AND 1048576),
    snapshot_sha256 bytea NOT NULL CHECK (octet_length(snapshot_sha256) = 32),
    source_revision bigint,
    created_by_user_id uuid NOT NULL,
    created_by_scope_id uuid NOT NULL,
    created_at timestamptz NOT NULL,
    state_changed_at timestamptz NOT NULL,
    PRIMARY KEY (platform_scope_id, revision),
    FOREIGN KEY (created_by_scope_id, created_by_user_id)
        REFERENCES memberships(scope_id, user_id) ON DELETE RESTRICT,
    FOREIGN KEY (platform_scope_id, source_revision)
        REFERENCES system_configuration_revisions(platform_scope_id, revision) ON DELETE RESTRICT,
    CHECK (created_by_scope_id = platform_scope_id),
    CHECK (source_revision IS NULL OR source_revision < revision),
    CHECK (created_at >= timestamptz '0001-01-01 00:00:00+00' AND
           state_changed_at < timestamptz '10000-01-01 00:00:00+00' AND
           state_changed_at >= created_at)
);

ALTER TABLE system_configuration_streams
    ADD CONSTRAINT system_configuration_streams_active_revision_fk
    FOREIGN KEY (platform_scope_id, active_revision)
    REFERENCES system_configuration_revisions(platform_scope_id, revision)
    ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED;

CREATE UNIQUE INDEX system_configuration_one_active_revision_idx
    ON system_configuration_revisions (platform_scope_id) WHERE status = 'active';
CREATE INDEX system_configuration_revisions_created_idx
    ON system_configuration_revisions (platform_scope_id, created_at DESC, revision DESC);

CREATE TABLE system_configuration_preflights (
    platform_scope_id uuid NOT NULL,
    revision bigint NOT NULL,
    preflight_sequence bigint NOT NULL CHECK (preflight_sequence > 0 AND preflight_sequence < 9223372036854775807),
    snapshot_sha256 bytea NOT NULL CHECK (octet_length(snapshot_sha256) = 32),
    passed boolean NOT NULL,
    checks json NOT NULL CHECK (
        json_typeof(checks) = 'array'
        AND json_array_length(checks) = 5
        AND octet_length(checks::text) <= 8192
    ),
    performed_by_user_id uuid NOT NULL,
    performed_by_scope_id uuid NOT NULL,
    performed_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    PRIMARY KEY (platform_scope_id, revision, preflight_sequence),
    FOREIGN KEY (platform_scope_id, revision)
        REFERENCES system_configuration_revisions(platform_scope_id, revision) ON DELETE RESTRICT,
    FOREIGN KEY (performed_by_scope_id, performed_by_user_id)
        REFERENCES memberships(scope_id, user_id) ON DELETE RESTRICT,
    CHECK (performed_by_scope_id = platform_scope_id),
    CHECK (performed_at >= timestamptz '0001-01-01 00:00:00+00' AND
           expires_at < timestamptz '10000-01-01 00:00:00+00' AND
           expires_at > performed_at)
);

CREATE TABLE system_configuration_write_requests (
    id uuid PRIMARY KEY,
    actor_user_id uuid NOT NULL,
    actor_scope_id uuid NOT NULL,
    target_scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE RESTRICT,
    operation text NOT NULL CHECK (operation IN (
        'system_configuration.create_draft',
        'system_configuration.preflight',
        'system_configuration.activate',
        'system_configuration.rollback'
    )),
    idempotency_key text NOT NULL CHECK (
        octet_length(idempotency_key) BETWEEN 1 AND 128
        AND idempotency_key ~ '^[A-Za-z0-9][A-Za-z0-9._:-]*$'
    ),
    request_digest bytea NOT NULL CHECK (octet_length(request_digest) = 32),
    response_body jsonb CHECK (response_body IS NULL OR jsonb_typeof(response_body) = 'object'),
    created_at timestamptz NOT NULL,
    completed_at timestamptz,
    UNIQUE (actor_user_id, operation, idempotency_key),
    FOREIGN KEY (actor_scope_id, actor_user_id)
        REFERENCES memberships(scope_id, user_id) ON DELETE RESTRICT,
    CHECK (actor_scope_id = target_scope_id),
    CHECK (created_at >= timestamptz '0001-01-01 00:00:00+00' AND
           created_at < timestamptz '10000-01-01 00:00:00+00'),
    CHECK ((completed_at IS NULL AND response_body IS NULL) OR
           (completed_at IS NOT NULL AND response_body IS NOT NULL AND completed_at >= created_at AND
            completed_at < timestamptz '10000-01-01 00:00:00+00'))
);

CREATE INDEX system_configuration_write_requests_scope_created_idx
    ON system_configuration_write_requests (target_scope_id, created_at DESC);

CREATE FUNCTION validate_system_configuration_platform_scope()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM access_scopes
        WHERE id = NEW.platform_scope_id AND kind = 'platform' AND tenant_id IS NULL
    ) THEN
        RAISE EXCEPTION 'system configuration requires a platform scope';
    END IF;
    IF TG_OP = 'INSERT' AND (NEW.head_revision <> 0 OR NEW.active_revision IS NOT NULL OR
       NEW.updated_at <> NEW.created_at) THEN
        RAISE EXCEPTION 'invalid initial system configuration stream';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER system_configuration_streams_platform_scope
BEFORE INSERT OR UPDATE ON system_configuration_streams
FOR EACH ROW EXECUTE FUNCTION validate_system_configuration_platform_scope();

CREATE FUNCTION system_configuration_json_keys_exact(candidate jsonb, expected text[])
RETURNS boolean
LANGUAGE sql
IMMUTABLE
AS $$
    SELECT candidate IS NOT NULL AND jsonb_typeof(candidate) = 'object' AND
           COALESCE((SELECT array_agg(key ORDER BY key) FROM jsonb_object_keys(candidate) key),
                    ARRAY[]::text[]) = expected;
$$;

CREATE FUNCTION system_configuration_json_integer(candidate jsonb, minimum numeric, maximum numeric)
RETURNS boolean
LANGUAGE plpgsql
IMMUTABLE
AS $$
DECLARE
    raw text;
    parsed numeric;
BEGIN
    IF candidate IS NULL OR jsonb_typeof(candidate) <> 'number' THEN
        RETURN false;
    END IF;
    raw := candidate #>> '{}';
    IF raw !~ '^-?(0|[1-9][0-9]*)$' THEN
        RETURN false;
    END IF;
    parsed := raw::numeric;
    RETURN parsed BETWEEN minimum AND maximum;
EXCEPTION WHEN OTHERS THEN
    RETURN false;
END;
$$;

CREATE FUNCTION system_configuration_render_canonical_snapshot(document jsonb)
RETURNS bytea
LANGUAGE plpgsql
IMMUTABLE
STRICT
AS $$
DECLARE
    nginx jsonb := document->'configuration'->'nginx';
    defaults_document jsonb := document->'configuration'->'defaults';
    resources jsonb := document->'configuration'->'resources';
    error_pages jsonb := document->'configuration'->'error_pages';
    secrets jsonb := document->'configuration'->'secrets';
    reference jsonb;
    resolver_values text;
    method_values text;
    error_page_values text;
    result text;
BEGIN
    SELECT COALESCE(string_agg(value::text,',' ORDER BY ordinality),'')
      INTO resolver_values
    FROM jsonb_array_elements(nginx->'resolver_addresses') WITH ORDINALITY item(value,ordinality);
    SELECT COALESCE(string_agg(value::text,',' ORDER BY ordinality),'')
      INTO method_values
    FROM jsonb_array_elements(nginx->'proxy_cache_methods') WITH ORDINALITY item(value,ordinality);
    SELECT COALESCE(string_agg(
        '{"status_code":' || (value->'status_code')::text ||
        ',"mime_type":' || (value->'mime_type')::text ||
        ',"size_bytes":' || (value->'size_bytes')::text ||
        ',"sha256":' || (value->'sha256')::text ||
        ',"storage_object_key":' || (value->'storage_object_key')::text || '}',
        ',' ORDER BY ordinality),'') INTO error_page_values
    FROM jsonb_array_elements(error_pages) WITH ORDINALITY item(value,ordinality);

    result := '{"schema":' || (document->'schema')::text || ',"configuration":{' ||
        '"nginx":{' ||
        '"worker_processes":' || (nginx->'worker_processes')::text ||
        ',"worker_rlimit_nofile":' || (nginx->'worker_rlimit_nofile')::text ||
        ',"worker_shutdown_timeout_ms":' || (nginx->'worker_shutdown_timeout_ms')::text ||
        ',"worker_connections":' || (nginx->'worker_connections')::text ||
        ',"resolver_addresses":[' || resolver_values || ']' ||
        ',"resolver_timeout_ms":' || (nginx->'resolver_timeout_ms')::text ||
        ',"gzip_level":' || (nginx->'gzip_level')::text ||
        ',"gzip_minimum_bytes":' || (nginx->'gzip_minimum_bytes')::text ||
        ',"gzip_vary":' || (nginx->'gzip_vary')::text ||
        ',"proxy_buffering":' || (nginx->'proxy_buffering')::text ||
        ',"proxy_cache_methods":[' || method_values || ']' ||
        ',"proxy_cache_max_bytes":' || (nginx->'proxy_cache_max_bytes')::text ||
        ',"proxy_cache_zone_bytes":' || (nginx->'proxy_cache_zone_bytes')::text ||
        ',"proxy_max_temp_file_bytes":' || (nginx->'proxy_max_temp_file_bytes')::text ||
        ',"proxy_connect_timeout_ms":' || (nginx->'proxy_connect_timeout_ms')::text ||
        ',"proxy_send_timeout_ms":' || (nginx->'proxy_send_timeout_ms')::text ||
        ',"proxy_read_timeout_ms":' || (nginx->'proxy_read_timeout_ms')::text ||
        ',"stream_proxy_timeout_ms":' || (nginx->'stream_proxy_timeout_ms')::text ||
        ',"server_header":' || (nginx->'server_header')::text ||
        ',"client_max_body_bytes":' || (nginx->'client_max_body_bytes')::text ||
        ',"default_mime_type":' || (nginx->'default_mime_type')::text ||
        ',"keepalive_requests":' || (nginx->'keepalive_requests')::text ||
        ',"keepalive_timeout_ms":' || (nginx->'keepalive_timeout_ms')::text ||
        ',"log_not_found":' || (nginx->'log_not_found')::text ||
        ',"server_names_hash_max_size":' || (nginx->'server_names_hash_max_size')::text ||
        ',"server_tokens":' || (nginx->'server_tokens')::text || '},"defaults":{';
    IF defaults_document ? 'site_template' THEN
        reference := defaults_document->'site_template';
        result := result || '"site_template":{"id":' || (reference->'id')::text ||
            ',"revision":' || (reference->'revision')::text || '},';
    END IF;
    IF defaults_document ? 'cache_policy' THEN
        reference := defaults_document->'cache_policy';
        result := result || '"cache_policy":{"id":' || (reference->'id')::text ||
            ',"revision":' || (reference->'revision')::text || '},';
    END IF;
    IF defaults_document ? 'waf_policy' THEN
        reference := defaults_document->'waf_policy';
        result := result || '"waf_policy":{"id":' || (reference->'id')::text ||
            ',"revision":' || (reference->'revision')::text || '},';
    END IF;
    IF defaults_document ? 'cc_policy' THEN
        reference := defaults_document->'cc_policy';
        result := result || '"cc_policy":{"id":' || (reference->'id')::text ||
            ',"revision":' || (reference->'revision')::text || '},';
    END IF;
    IF defaults_document ? 'acl_policy' THEN
        reference := defaults_document->'acl_policy';
        result := result || '"acl_policy":{"id":' || (reference->'id')::text ||
            ',"revision":' || (reference->'revision')::text || '},';
    END IF;
    result := result ||
        '"listen_port":' || (defaults_document->'listen_port')::text ||
        ',"origin_scheme":' || (defaults_document->'origin_scheme')::text ||
        ',"origin_port":' || (defaults_document->'origin_port')::text ||
        ',"https_port":' || (defaults_document->'https_port')::text || '},"resources":{' ||
        '"max_sites_per_tenant":' || (resources->'max_sites_per_tenant')::text ||
        ',"max_origins_per_site":' || (resources->'max_origins_per_site')::text ||
        ',"max_domains_per_site":' || (resources->'max_domains_per_site')::text ||
        ',"max_certificates_per_tenant":' || (resources->'max_certificates_per_tenant')::text ||
        ',"max_blacklist_ips_per_site":' || (resources->'max_blacklist_ips_per_site')::text ||
        ',"max_whitelist_ips_per_site":' || (resources->'max_whitelist_ips_per_site')::text ||
        ',"daily_url_purge_limit":' || (resources->'daily_url_purge_limit')::text ||
        ',"daily_directory_purge_limit":' || (resources->'daily_directory_purge_limit')::text ||
        ',"daily_prewarm_limit":' || (resources->'daily_prewarm_limit')::text ||
        ',"max_acl_rules_per_policy":' || (resources->'max_acl_rules_per_policy')::text ||
        ',"max_cc_rules_per_policy":' || (resources->'max_cc_rules_per_policy')::text ||
        ',"max_custom_error_page_bytes":' || (resources->'max_custom_error_page_bytes')::text ||
        ',"minimum_related_config_limit":' || (resources->'minimum_related_config_limit')::text ||
        ',"related_config_max_multiplier":' || (resources->'related_config_max_multiplier')::text ||
        '},"error_pages":[' || error_page_values || '],"secrets":{';
    IF secrets ? 'error_page_storage' THEN
        reference := secrets->'error_page_storage';
        result := result || '"error_page_storage":{' ||
            '"provider":' || (reference->'provider')::text ||
            ',"reference":' || (reference->'reference')::text ||
            ',"key_id":' || (reference->'key_id')::text ||
            ',"algorithm":' || (reference->'algorithm')::text ||
            ',"ciphertext_sha256":' || (reference->'ciphertext_sha256')::text || '}';
    END IF;
    result := result || '}}}';
    RETURN convert_to(result, 'UTF8');
END;
$$;

CREATE FUNCTION system_configuration_actor_has_permission(
    requested_scope_id uuid, requested_user_id uuid, requested_permission text
)
RETURNS boolean
LANGUAGE sql
STABLE
AS $$
    SELECT EXISTS (
        SELECT 1
        FROM access_scopes scope
        JOIN memberships membership
          ON membership.scope_id = scope.id AND membership.user_id = requested_user_id
         AND membership.status = 'active'
        JOIN users account ON account.id = membership.user_id AND account.status = 'active'
        JOIN role_assignments assignment
          ON assignment.scope_id = scope.id AND assignment.user_id = membership.user_id
        JOIN roles role ON role.id = assignment.role_id AND role.scope_id = scope.id
        JOIN role_permissions permission ON permission.role_id = role.id
        WHERE scope.id = requested_scope_id AND scope.kind = 'platform' AND scope.tenant_id IS NULL
          AND permission.permission_name = requested_permission
    );
$$;

CREATE FUNCTION system_configuration_snapshot_is_valid(candidate bytea)
RETURNS boolean
LANGUAGE plpgsql
IMMUTABLE
AS $$
DECLARE
    raw text;
    document jsonb;
    configuration jsonb;
    nginx jsonb;
    defaults_document jsonb;
    resources jsonb;
    error_pages jsonb;
    secrets jsonb;
    item jsonb;
    reference jsonb;
    reference_name text;
    resolver text;
    object_key text;
BEGIN
    raw := convert_from(candidate, 'UTF8');
    IF raw <> btrim(raw) THEN RETURN false; END IF;
    document := raw::jsonb;
    IF NOT system_configuration_json_keys_exact(document, ARRAY['configuration','schema']) OR
       document->>'schema' IS DISTINCT FROM 'cdnca.system-configuration/v1' OR
       jsonb_typeof(document->'schema') <> 'string' OR
       NOT system_configuration_json_keys_exact(document->'configuration',
           ARRAY['defaults','error_pages','nginx','resources','secrets']) THEN
        RETURN false;
    END IF;
    configuration := document->'configuration';
    nginx := configuration->'nginx';
    defaults_document := configuration->'defaults';
    resources := configuration->'resources';
    error_pages := configuration->'error_pages';
    secrets := configuration->'secrets';

    IF NOT system_configuration_json_keys_exact(nginx, ARRAY[
        'client_max_body_bytes','default_mime_type','gzip_level','gzip_minimum_bytes','gzip_vary',
        'keepalive_requests','keepalive_timeout_ms','log_not_found','proxy_buffering',
        'proxy_cache_max_bytes','proxy_cache_methods','proxy_cache_zone_bytes',
        'proxy_connect_timeout_ms','proxy_max_temp_file_bytes','proxy_read_timeout_ms',
        'proxy_send_timeout_ms','resolver_addresses','resolver_timeout_ms','server_header',
        'server_names_hash_max_size','server_tokens','stream_proxy_timeout_ms','worker_connections',
        'worker_processes','worker_rlimit_nofile','worker_shutdown_timeout_ms']) OR
       NOT system_configuration_json_integer(nginx->'worker_processes', 0, 256) OR
       NOT system_configuration_json_integer(nginx->'worker_rlimit_nofile', 1024, 1048576) OR
       NOT system_configuration_json_integer(nginx->'worker_shutdown_timeout_ms', 1000, 300000) OR
       NOT system_configuration_json_integer(nginx->'worker_connections', 128, 1048576) OR
       (nginx->>'worker_connections')::bigint > (nginx->>'worker_rlimit_nofile')::bigint OR
       NOT system_configuration_json_integer(nginx->'resolver_timeout_ms', 100, 30000) OR
       NOT system_configuration_json_integer(nginx->'gzip_level', 1, 9) OR
       NOT system_configuration_json_integer(nginx->'gzip_minimum_bytes', 0, 1073741824) OR
       NOT system_configuration_json_integer(nginx->'proxy_cache_max_bytes', 0, 1125899906842624) OR
       NOT system_configuration_json_integer(nginx->'proxy_cache_zone_bytes', 1048576, 17179869184) OR
       NOT system_configuration_json_integer(nginx->'proxy_max_temp_file_bytes', 0, 1099511627776) OR
       NOT system_configuration_json_integer(nginx->'proxy_connect_timeout_ms', 100, 75000) OR
       NOT system_configuration_json_integer(nginx->'proxy_send_timeout_ms', 100, 3600000) OR
       NOT system_configuration_json_integer(nginx->'proxy_read_timeout_ms', 100, 3600000) OR
       NOT system_configuration_json_integer(nginx->'stream_proxy_timeout_ms', 100, 86400000) OR
       NOT system_configuration_json_integer(nginx->'client_max_body_bytes', 1024, 10737418240) OR
       NOT system_configuration_json_integer(nginx->'keepalive_requests', 1, 1000000) OR
       NOT system_configuration_json_integer(nginx->'keepalive_timeout_ms', 100, 3600000) OR
       NOT system_configuration_json_integer(nginx->'server_names_hash_max_size', 512, 65536) OR
       ((nginx->>'server_names_hash_max_size')::bigint &
        ((nginx->>'server_names_hash_max_size')::bigint - 1)) <> 0 OR
       jsonb_typeof(nginx->'gzip_vary') <> 'boolean' OR
       jsonb_typeof(nginx->'proxy_buffering') <> 'boolean' OR
       jsonb_typeof(nginx->'log_not_found') <> 'boolean' OR
       jsonb_typeof(nginx->'server_tokens') <> 'boolean' OR
       jsonb_typeof(nginx->'server_header') <> 'string' OR
       (nginx->>'server_header' <> '' AND nginx->>'server_header' !~ '^[A-Za-z0-9][A-Za-z0-9 ._-]{0,63}$') OR
       nginx->>'server_header' ~ '[[:cntrl:]]' OR
       jsonb_typeof(nginx->'default_mime_type') <> 'string' OR
       nginx->>'default_mime_type' NOT IN ('application/json','text/html','text/plain') OR
       jsonb_typeof(nginx->'resolver_addresses') <> 'array' OR
       jsonb_array_length(nginx->'resolver_addresses') NOT BETWEEN 1 AND 4 OR
       jsonb_typeof(nginx->'proxy_cache_methods') <> 'array' OR
       jsonb_array_length(nginx->'proxy_cache_methods') NOT BETWEEN 1 AND 2 THEN
        RETURN false;
    END IF;
    IF (SELECT count(*) FROM jsonb_array_elements(nginx->'resolver_addresses')) <>
       (SELECT count(DISTINCT value #>> '{}') FROM jsonb_array_elements(nginx->'resolver_addresses') value) OR
       (SELECT count(*) FROM jsonb_array_elements(nginx->'proxy_cache_methods')) <>
       (SELECT count(DISTINCT value #>> '{}') FROM jsonb_array_elements(nginx->'proxy_cache_methods') value) OR
       (SELECT array_agg(value #>> '{}' ORDER BY ordinality)
          FROM jsonb_array_elements(nginx->'resolver_addresses') WITH ORDINALITY item(value,ordinality))
       IS DISTINCT FROM
       (SELECT array_agg(value #>> '{}' ORDER BY (value #>> '{}') COLLATE "C")
          FROM jsonb_array_elements(nginx->'resolver_addresses') item(value)) OR
       (SELECT array_agg(value #>> '{}' ORDER BY ordinality)
          FROM jsonb_array_elements(nginx->'proxy_cache_methods') WITH ORDINALITY item(value,ordinality))
       IS DISTINCT FROM
       (SELECT array_agg(value #>> '{}' ORDER BY (value #>> '{}') COLLATE "C")
          FROM jsonb_array_elements(nginx->'proxy_cache_methods') item(value)) THEN
        RETURN false;
    END IF;
    FOR item IN SELECT value FROM jsonb_array_elements(nginx->'resolver_addresses') LOOP
        IF jsonb_typeof(item) <> 'string' THEN RETURN false; END IF;
        resolver := item #>> '{}';
        IF resolver <> btrim(resolver) OR resolver ~ '[[:cntrl:]]' OR position('/' IN resolver) > 0 THEN
            RETURN false;
        END IF;
        IF resolver IS DISTINCT FROM host(resolver::inet) THEN RETURN false; END IF;
    END LOOP;
    FOR item IN SELECT value FROM jsonb_array_elements(nginx->'proxy_cache_methods') LOOP
        IF jsonb_typeof(item) <> 'string' OR item #>> '{}' NOT IN ('GET','HEAD') THEN RETURN false; END IF;
    END LOOP;

    IF jsonb_typeof(defaults_document) <> 'object' OR
       NOT system_configuration_json_keys_exact(
           defaults_document - 'site_template' - 'cache_policy' - 'waf_policy' - 'cc_policy' - 'acl_policy',
           ARRAY['https_port','listen_port','origin_port','origin_scheme']) OR
       NOT system_configuration_json_integer(defaults_document->'listen_port', 1, 65535) OR
       NOT system_configuration_json_integer(defaults_document->'origin_port', 1, 65535) OR
       NOT system_configuration_json_integer(defaults_document->'https_port', 1, 65535) OR
       jsonb_typeof(defaults_document->'origin_scheme') <> 'string' OR
       defaults_document->>'origin_scheme' NOT IN ('http','https') THEN
        RETURN false;
    END IF;
    FOREACH reference_name IN ARRAY ARRAY['site_template','cache_policy','waf_policy','cc_policy','acl_policy'] LOOP
        IF defaults_document ? reference_name THEN
            reference := defaults_document->reference_name;
            IF NOT system_configuration_json_keys_exact(reference, ARRAY['id','revision']) OR
               jsonb_typeof(reference->'id') <> 'string' OR
               reference->>'id' !~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' OR
               reference->>'id' = '00000000-0000-0000-0000-000000000000' OR
               NOT system_configuration_json_integer(reference->'revision', 1, 9223372036854775806) THEN
                RETURN false;
            END IF;
            PERFORM (reference->>'id')::uuid;
        END IF;
    END LOOP;

    IF NOT system_configuration_json_keys_exact(resources, ARRAY[
        'daily_directory_purge_limit','daily_prewarm_limit','daily_url_purge_limit',
        'max_acl_rules_per_policy','max_blacklist_ips_per_site','max_cc_rules_per_policy',
        'max_certificates_per_tenant','max_custom_error_page_bytes','max_domains_per_site',
        'max_origins_per_site','max_sites_per_tenant','max_whitelist_ips_per_site',
        'minimum_related_config_limit','related_config_max_multiplier']) OR
       NOT system_configuration_json_integer(resources->'max_sites_per_tenant', 1, 1000000) OR
       NOT system_configuration_json_integer(resources->'max_origins_per_site', 1, 64) OR
       NOT system_configuration_json_integer(resources->'max_domains_per_site', 1, 100) OR
       NOT system_configuration_json_integer(resources->'max_certificates_per_tenant', 1, 100000) OR
       NOT system_configuration_json_integer(resources->'max_blacklist_ips_per_site', 1, 1000000) OR
       NOT system_configuration_json_integer(resources->'max_whitelist_ips_per_site', 1, 1000000) OR
       NOT system_configuration_json_integer(resources->'daily_url_purge_limit', 1, 10000000) OR
       NOT system_configuration_json_integer(resources->'daily_directory_purge_limit', 1, 1000000) OR
       NOT system_configuration_json_integer(resources->'daily_prewarm_limit', 1, 10000000) OR
       NOT system_configuration_json_integer(resources->'max_acl_rules_per_policy', 1, 100000) OR
       NOT system_configuration_json_integer(resources->'max_cc_rules_per_policy', 1, 100000) OR
       NOT system_configuration_json_integer(resources->'max_custom_error_page_bytes', 1, 1048576) OR
       NOT system_configuration_json_integer(resources->'minimum_related_config_limit', 1, 100000) OR
       NOT system_configuration_json_integer(resources->'related_config_max_multiplier', 1, 100) THEN
        RETURN false;
    END IF;

    IF jsonb_typeof(error_pages) <> 'array' OR jsonb_array_length(error_pages) > 13 OR
       (SELECT count(*) FROM jsonb_array_elements(error_pages)) <>
       (SELECT count(DISTINCT value->>'status_code') FROM jsonb_array_elements(error_pages) value) OR
       (SELECT array_agg((value->>'status_code')::integer ORDER BY ordinality)
          FROM jsonb_array_elements(error_pages) WITH ORDINALITY item(value,ordinality))
       IS DISTINCT FROM
       (SELECT array_agg((value->>'status_code')::integer ORDER BY (value->>'status_code')::integer)
          FROM jsonb_array_elements(error_pages) item(value)) THEN
        RETURN false;
    END IF;
    FOR item IN SELECT value FROM jsonb_array_elements(error_pages) LOOP
        IF NOT system_configuration_json_keys_exact(item,
               ARRAY['mime_type','sha256','size_bytes','status_code','storage_object_key']) OR
           NOT system_configuration_json_integer(item->'status_code', 400, 504) OR
           (item->>'status_code')::integer NOT IN (400,401,403,404,405,408,413,429,500,501,502,503,504) OR
           NOT system_configuration_json_integer(item->'size_bytes', 1,
               (resources->>'max_custom_error_page_bytes')::numeric) OR
           jsonb_typeof(item->'mime_type') <> 'string' OR
           item->>'mime_type' NOT IN ('application/json','text/html','text/plain') OR
           jsonb_typeof(item->'sha256') <> 'string' OR item->>'sha256' !~ '^[0-9a-f]{64}$' OR
           jsonb_typeof(item->'storage_object_key') <> 'string' THEN
            RETURN false;
        END IF;
        object_key := item->>'storage_object_key';
        IF object_key <> btrim(object_key) OR object_key ~ '[[:cntrl:]]' OR
           octet_length(object_key) > 512 OR object_key !~ '^[A-Za-z0-9][A-Za-z0-9._/-]*$' OR
           object_key ~ '(^|/)\.\.?(/|$)' OR position('//' IN object_key) > 0 OR
           position(E'\\' IN object_key) > 0 OR left(object_key, 1) = '/' THEN
            RETURN false;
        END IF;
    END LOOP;

    IF jsonb_typeof(secrets) <> 'object' OR
       NOT (system_configuration_json_keys_exact(secrets, ARRAY[]::text[]) OR
            system_configuration_json_keys_exact(secrets, ARRAY['error_page_storage'])) THEN
        RETURN false;
    END IF;
    IF secrets ? 'error_page_storage' THEN
        item := secrets->'error_page_storage';
        IF NOT system_configuration_json_keys_exact(item,
               ARRAY['algorithm','ciphertext_sha256','key_id','provider','reference']) OR
           item->>'provider' NOT IN ('vault','kms-envelope') OR
           item->>'algorithm' NOT IN ('aes-256-gcm','chacha20-poly1305','kms-managed') OR
           item->>'ciphertext_sha256' !~ '^[0-9a-f]{64}$' OR
           item->>'reference' !~ '^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,255}$' OR
           item->>'key_id' !~ '^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,255}$' OR
           item->>'reference' ~ '[[:cntrl:]]' OR item->>'key_id' ~ '[[:cntrl:]]' OR
           position('..' IN item->>'reference') > 0 OR position('//' IN item->>'reference') > 0 OR
           position('..' IN item->>'key_id') > 0 OR position('//' IN item->>'key_id') > 0 THEN
            RETURN false;
        END IF;
    END IF;
    RETURN system_configuration_render_canonical_snapshot(document) = candidate;
EXCEPTION WHEN OTHERS THEN
    RETURN false;
END;
$$;

CREATE FUNCTION validate_system_configuration_revision_insert()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    stream_head bigint;
BEGIN
    PERFORM pg_advisory_xact_lock(hashtextextended(
        'system-configuration-stream:' || NEW.platform_scope_id::text, 0));
    SELECT head_revision INTO stream_head FROM system_configuration_streams
    WHERE platform_scope_id = NEW.platform_scope_id FOR UPDATE;
    IF stream_head IS NULL OR stream_head >= 9223372036854775806 OR
       NEW.revision <> stream_head + 1 OR NEW.status <> 'draft' OR
       NEW.state_changed_at <> NEW.created_at OR
       NEW.snapshot_sha256 IS DISTINCT FROM sha256(NEW.canonical_snapshot) OR
       NOT system_configuration_snapshot_is_valid(NEW.canonical_snapshot) OR
       NOT system_configuration_actor_has_permission(
           NEW.created_by_scope_id, NEW.created_by_user_id, 'system_configuration.manage') OR
       (NEW.source_revision IS NOT NULL AND NOT EXISTS (
           SELECT 1 FROM system_configuration_revisions source
           WHERE source.platform_scope_id = NEW.platform_scope_id
             AND source.revision = NEW.source_revision
             AND source.status IN ('active','superseded')
             AND source.canonical_snapshot = NEW.canonical_snapshot
             AND source.snapshot_sha256 = NEW.snapshot_sha256
       )) THEN
        RAISE EXCEPTION 'invalid system configuration revision insert';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER system_configuration_revisions_validate_insert
BEFORE INSERT ON system_configuration_revisions
FOR EACH ROW EXECUTE FUNCTION validate_system_configuration_revision_insert();

CREATE FUNCTION protect_system_configuration_stream()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'DELETE' OR NEW.platform_scope_id <> OLD.platform_scope_id OR
       NEW.created_at <> OLD.created_at OR NEW.head_revision < OLD.head_revision OR
       (NEW.head_revision <> OLD.head_revision AND
        (OLD.head_revision >= 9223372036854775806 OR NEW.head_revision <> OLD.head_revision + 1)) OR
       NEW.updated_at < OLD.updated_at THEN
        RAISE EXCEPTION 'invalid system configuration stream transition';
    END IF;
    IF NEW.head_revision = OLD.head_revision + 1 AND NOT EXISTS (
        SELECT 1 FROM system_configuration_revisions revision
        WHERE revision.platform_scope_id = NEW.platform_scope_id
          AND revision.revision = NEW.head_revision AND revision.status = 'draft'
    ) THEN
        RAISE EXCEPTION 'system configuration head must reference a new draft';
    END IF;
    IF NEW.active_revision IS DISTINCT FROM OLD.active_revision AND (
        NEW.active_revision IS NULL OR NOT EXISTS (
            SELECT 1 FROM system_configuration_revisions revision
            WHERE revision.platform_scope_id = NEW.platform_scope_id
              AND revision.revision = NEW.active_revision AND revision.status = 'active'
        ) OR (OLD.active_revision IS NOT NULL AND NOT EXISTS (
            SELECT 1 FROM system_configuration_revisions revision
            WHERE revision.platform_scope_id = OLD.platform_scope_id
              AND revision.revision = OLD.active_revision AND revision.status = 'superseded'
        ))
    ) THEN
        RAISE EXCEPTION 'system configuration active revision transition is inconsistent';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER system_configuration_streams_protected
BEFORE UPDATE OR DELETE ON system_configuration_streams
FOR EACH ROW EXECUTE FUNCTION protect_system_configuration_stream();

CREATE FUNCTION protect_system_configuration_revision()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'system configuration revisions cannot be deleted';
    END IF;
    IF ROW(NEW.platform_scope_id, NEW.revision, NEW.canonical_schema,
           NEW.canonical_snapshot, NEW.snapshot_sha256, NEW.source_revision,
           NEW.created_by_user_id, NEW.created_by_scope_id, NEW.created_at)
       IS DISTINCT FROM
       ROW(OLD.platform_scope_id, OLD.revision, OLD.canonical_schema,
           OLD.canonical_snapshot, OLD.snapshot_sha256, OLD.source_revision,
           OLD.created_by_user_id, OLD.created_by_scope_id, OLD.created_at) OR
       NEW.state_changed_at < OLD.state_changed_at OR NOT (
           (OLD.status = 'draft' AND NEW.status IN ('validated', 'rejected')) OR
           (OLD.status = 'validated' AND NEW.status = 'active') OR
           (OLD.status = 'active' AND NEW.status = 'superseded')
       ) THEN
        RAISE EXCEPTION 'invalid system configuration revision transition';
    END IF;
    IF OLD.status = 'draft' AND NEW.status IN ('validated', 'rejected') AND NOT EXISTS (
        SELECT 1 FROM system_configuration_preflights preflight
        WHERE preflight.platform_scope_id = OLD.platform_scope_id
          AND preflight.revision = OLD.revision
          AND preflight.snapshot_sha256 = OLD.snapshot_sha256
          AND preflight.passed = (NEW.status = 'validated')
    ) THEN
        RAISE EXCEPTION 'system configuration validation requires matching preflight';
    END IF;
    IF OLD.status = 'validated' AND NEW.status = 'active' AND NOT EXISTS (
        SELECT 1 FROM (
            SELECT preflight.snapshot_sha256,preflight.passed,
                   preflight.performed_at,preflight.expires_at
            FROM system_configuration_preflights preflight
            WHERE preflight.platform_scope_id = OLD.platform_scope_id
              AND preflight.revision = OLD.revision
            ORDER BY preflight.preflight_sequence DESC LIMIT 1
        ) latest
        WHERE latest.snapshot_sha256 = OLD.snapshot_sha256 AND latest.passed
          AND latest.performed_at <= NEW.state_changed_at
          AND latest.expires_at > NEW.state_changed_at
    ) THEN
        RAISE EXCEPTION 'system configuration activation requires successful preflight';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER system_configuration_revisions_protected
BEFORE UPDATE OR DELETE ON system_configuration_revisions
FOR EACH ROW EXECUTE FUNCTION protect_system_configuration_revision();

CREATE FUNCTION system_configuration_preflight_checks_are_valid(candidate jsonb, declared_passed boolean)
RETURNS boolean
LANGUAGE plpgsql
IMMUTABLE
AS $$
DECLARE
    item jsonb;
    observed_names text[] := ARRAY[]::text[];
    computed_passed boolean := true;
BEGIN
    IF candidate IS NULL OR jsonb_typeof(candidate) <> 'array' OR
       jsonb_array_length(candidate) <> 5 OR octet_length(candidate::text) > 8192 THEN
        RETURN false;
    END IF;
    FOR item IN SELECT value FROM jsonb_array_elements(candidate) LOOP
        IF jsonb_typeof(item) <> 'object' OR
           NOT system_configuration_json_keys_exact(item - 'code' - 'detail', ARRAY['name','status']) OR
           EXISTS (SELECT 1 FROM jsonb_object_keys(item) key
                   WHERE key NOT IN ('name','status','code','detail')) OR
           jsonb_typeof(item->'name') <> 'string' OR
           item->>'name' NOT IN ('schema','references','capacity','nginx_safety','error_pages') OR
           jsonb_typeof(item->'status') <> 'string' OR
           item->>'status' NOT IN ('pass','fail') OR
           (item ? 'detail' AND (
               jsonb_typeof(item->'detail') <> 'string' OR
               char_length(item->>'detail') > 512 OR item->>'detail' ~ '[[:cntrl:]]'
           )) OR
           (item->>'status' = 'pass' AND item ? 'code') OR
           (item->>'status' = 'fail' AND (
               NOT item ? 'code' OR jsonb_typeof(item->'code') <> 'string' OR
               item->>'code' !~ '^[a-z][a-z0-9._-]{0,63}$'
           )) THEN
            RETURN false;
        END IF;
        observed_names := array_append(observed_names, item->>'name');
        computed_passed := computed_passed AND item->>'status' = 'pass';
    END LOOP;
    RETURN observed_names <@ ARRAY['schema','references','capacity','nginx_safety','error_pages'] AND
           (SELECT count(DISTINCT name) FROM unnest(observed_names) name) = 5 AND
           computed_passed = declared_passed;
EXCEPTION WHEN OTHERS THEN
    RETURN false;
END;
$$;

CREATE FUNCTION validate_system_configuration_preflight_insert()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    revision_status text;
    revision_hash bytea;
    revision_changed_at timestamptz;
    last_sequence bigint;
    last_performed_at timestamptz;
BEGIN
    PERFORM pg_advisory_xact_lock(hashtextextended(
        'system-configuration-stream:' || NEW.platform_scope_id::text, 0));
    SELECT status,snapshot_sha256,state_changed_at
      INTO revision_status,revision_hash,revision_changed_at
    FROM system_configuration_revisions
    WHERE platform_scope_id = NEW.platform_scope_id AND revision = NEW.revision
    FOR UPDATE;
    SELECT preflight_sequence,performed_at INTO last_sequence,last_performed_at
    FROM system_configuration_preflights
    WHERE platform_scope_id = NEW.platform_scope_id AND revision = NEW.revision
    ORDER BY preflight_sequence DESC LIMIT 1;
    IF revision_status IS NULL OR revision_status NOT IN ('draft','validated') OR
       (revision_status = 'validated' AND NOT NEW.passed) OR
       NEW.snapshot_sha256 IS DISTINCT FROM revision_hash OR
       NEW.preflight_sequence <> COALESCE(last_sequence,0) + 1 OR
       NEW.performed_at < revision_changed_at OR
       (last_performed_at IS NOT NULL AND NEW.performed_at <= last_performed_at) OR
       NEW.expires_at IS DISTINCT FROM NEW.performed_at + interval '15 minutes' OR
       NOT system_configuration_preflight_checks_are_valid(NEW.checks::jsonb, NEW.passed) OR
       NOT system_configuration_actor_has_permission(
           NEW.performed_by_scope_id, NEW.performed_by_user_id, 'system_configuration.manage') THEN
        RAISE EXCEPTION 'invalid system configuration preflight';
    END IF;
    RETURN NEW;
EXCEPTION WHEN datetime_field_overflow OR numeric_value_out_of_range THEN
    RAISE EXCEPTION 'invalid system configuration preflight';
END;
$$;

CREATE TRIGGER system_configuration_preflights_validate_insert
BEFORE INSERT ON system_configuration_preflights
FOR EACH ROW EXECUTE FUNCTION validate_system_configuration_preflight_insert();

CREATE FUNCTION prevent_system_configuration_preflight_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'system configuration preflights are append-only';
END;
$$;

CREATE TRIGGER system_configuration_preflights_append_only
BEFORE UPDATE OR DELETE ON system_configuration_preflights
FOR EACH ROW EXECUTE FUNCTION prevent_system_configuration_preflight_mutation();

CREATE FUNCTION validate_system_configuration_stream_projection()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    scope_id uuid;
    projected_head bigint;
    projected_active bigint;
    maximum_revision bigint;
    active_count bigint;
    actual_active bigint;
    superseded_count bigint;
    invalid_superseded_count bigint;
BEGIN
    IF TG_OP = 'DELETE' THEN
        scope_id := OLD.platform_scope_id;
    ELSE
        scope_id := NEW.platform_scope_id;
    END IF;
    SELECT head_revision,active_revision INTO projected_head,projected_active
    FROM system_configuration_streams WHERE platform_scope_id = scope_id;
    IF NOT FOUND THEN
        IF EXISTS (SELECT 1 FROM system_configuration_revisions WHERE platform_scope_id = scope_id) THEN
            RAISE EXCEPTION 'inconsistent system configuration stream projection';
        END IF;
        RETURN NULL;
    END IF;
    SELECT max(revision),count(*) FILTER (WHERE status = 'active'),
           max(revision) FILTER (WHERE status = 'active'),
           count(*) FILTER (WHERE status = 'superseded'),
           count(*) FILTER (WHERE status = 'superseded' AND
               (projected_active IS NULL OR revision >= projected_active))
      INTO maximum_revision,active_count,actual_active,superseded_count,invalid_superseded_count
    FROM system_configuration_revisions WHERE platform_scope_id = scope_id;
    IF projected_head <> COALESCE(maximum_revision,0) OR
       (projected_active IS NULL AND (active_count <> 0 OR superseded_count <> 0)) OR
       (projected_active IS NOT NULL AND (
           active_count <> 1 OR actual_active IS DISTINCT FROM projected_active OR
           invalid_superseded_count <> 0
       )) THEN
        RAISE EXCEPTION 'inconsistent system configuration stream projection';
    END IF;
    RETURN NULL;
END;
$$;

CREATE CONSTRAINT TRIGGER system_configuration_streams_projection_consistent
AFTER INSERT OR UPDATE OR DELETE ON system_configuration_streams
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION validate_system_configuration_stream_projection();

CREATE CONSTRAINT TRIGGER system_configuration_revisions_projection_consistent
AFTER INSERT OR UPDATE OR DELETE ON system_configuration_revisions
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION validate_system_configuration_stream_projection();

CREATE FUNCTION protect_system_configuration_write_request()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.completed_at IS NOT NULL OR NEW.response_body IS NOT NULL THEN
            RAISE EXCEPTION 'system configuration write request must start incomplete';
        END IF;
        RETURN NEW;
    END IF;
    IF TG_OP = 'DELETE' OR
       ROW(NEW.id, NEW.actor_user_id, NEW.actor_scope_id, NEW.target_scope_id,
           NEW.operation, NEW.idempotency_key, NEW.request_digest, NEW.created_at)
       IS DISTINCT FROM
       ROW(OLD.id, OLD.actor_user_id, OLD.actor_scope_id, OLD.target_scope_id,
           OLD.operation, OLD.idempotency_key, OLD.request_digest, OLD.created_at) OR
       OLD.completed_at IS NOT NULL OR NEW.completed_at IS NULL OR NEW.response_body IS NULL THEN
        RAISE EXCEPTION 'invalid system configuration write request transition';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER system_configuration_write_requests_protected
BEFORE INSERT OR UPDATE OR DELETE ON system_configuration_write_requests
FOR EACH ROW EXECUTE FUNCTION protect_system_configuration_write_request();

CREATE FUNCTION prevent_system_configuration_truncate()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'system configuration table % cannot be truncated', TG_TABLE_NAME;
END;
$$;

CREATE TRIGGER system_configuration_streams_no_truncate
BEFORE TRUNCATE ON system_configuration_streams
FOR EACH STATEMENT EXECUTE FUNCTION prevent_system_configuration_truncate();

CREATE TRIGGER system_configuration_revisions_no_truncate
BEFORE TRUNCATE ON system_configuration_revisions
FOR EACH STATEMENT EXECUTE FUNCTION prevent_system_configuration_truncate();

CREATE TRIGGER system_configuration_preflights_no_truncate
BEFORE TRUNCATE ON system_configuration_preflights
FOR EACH STATEMENT EXECUTE FUNCTION prevent_system_configuration_truncate();

CREATE TRIGGER system_configuration_write_requests_no_truncate
BEFORE TRUNCATE ON system_configuration_write_requests
FOR EACH STATEMENT EXECUTE FUNCTION prevent_system_configuration_truncate();
