LOCK TABLE schema_migrations, cache_operations, cache_policy_revisions,
    cache_policy_definition_revisions IN ACCESS EXCLUSIVE MODE;

DO $migration_396_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 395 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 395 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=395 AND
        migration_id='395_ddos_tcp_flags' AND
        checksum_sha256='a54c3be15b6174c90bd92234baa891f4f80eb2131eba6b64f20d6daddd55ba13' AND
        down_checksum_sha256='b48d953879faa9b83bf24642ea7981dc318291ec47a3fda4375ab31ba6d21817' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema=current_schema() AND table_name='cache_operations' AND column_name='auto_nodes'
       ) THEN
        RAISE EXCEPTION 'migration 396 requires the exact verified 395 release head' USING ERRCODE='P3960';
    END IF;
END;
$migration_396_up$;

-- r136 ge-cache (GoEdge comparison G5, cache).
--
-- 1. Cache policy extensions of site runtime v2 (stale-if-error, background
--    update, stored object size bounds, slice size), kept beside the
--    revision's other document fields. '{}' is none; the definition and
--    every binding of it carry the same value (binding trigger below).
ALTER TABLE cache_policy_definition_revisions
    ADD COLUMN extensions jsonb NOT NULL DEFAULT '{}'::jsonb
        CHECK (jsonb_typeof(extensions) = 'object' AND
               extensions - ARRAY['stale_if_error','background_update','min_object_bytes',
                                  'max_object_bytes','slice_bytes'] = '{}'::jsonb);
ALTER TABLE cache_policy_revisions
    ADD COLUMN extensions jsonb NOT NULL DEFAULT '{}'::jsonb
        CHECK (jsonb_typeof(extensions) = 'object' AND
               extensions - ARRAY['stale_if_error','background_update','min_object_bytes',
                                  'max_object_bytes','slice_bytes'] = '{}'::jsonb);

CREATE OR REPLACE FUNCTION validate_cache_policy_binding_143()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    definition cache_policy_definition_revisions%ROWTYPE;
BEGIN
    SELECT * INTO definition
    FROM cache_policy_definition_revisions
    WHERE scope_id = NEW.scope_id AND definition_id = NEW.definition_id
      AND revision = NEW.definition_revision
    FOR SHARE;
    IF NOT FOUND OR definition.tenant_id IS DISTINCT FROM NEW.tenant_id OR
       definition.schema_version IS DISTINCT FROM NEW.schema_version OR
       definition.mode IS DISTINCT FROM NEW.mode OR definition.rules IS DISTINCT FROM NEW.rules OR
       definition.query_mode IS DISTINCT FROM NEW.query_mode OR
       definition.query_names IS DISTINCT FROM NEW.query_names OR
       definition.vary_headers IS DISTINCT FROM NEW.vary_headers OR
       definition.disk_quota_bytes IS DISTINCT FROM NEW.disk_quota_bytes OR
       definition.extensions IS DISTINCT FROM NEW.extensions THEN
        RAISE EXCEPTION 'cache policy binding document does not match definition revision'
            USING ERRCODE = 'P1431';
    END IF;
    IF NEW.binding_mode = 'override' AND definition.source_site_id IS DISTINCT FROM NEW.site_id THEN
        RAISE EXCEPTION 'cache policy override definition source does not match site'
            USING ERRCODE = 'P1432';
    END IF;
    RETURN NEW;
END;
$$;

-- 3. A purge/prewarm that names no nodes runs on every node carrying the
--    site (auto_nodes). A node that starts carrying the site within a day of
--    the operation gets its own follow-up operation for the same targets
--    (parent_operation_id, created by cachecontrol.SyncCarryingNodes on the
--    parent actor's behalf); follow-ups do not count toward daily limits.
ALTER TABLE cache_operations
    ADD COLUMN auto_nodes boolean NOT NULL DEFAULT false,
    ADD COLUMN parent_operation_id uuid,
    ADD CONSTRAINT cache_operations_parent_396_fk FOREIGN KEY (scope_id, parent_operation_id)
        REFERENCES cache_operations(scope_id, id) ON DELETE RESTRICT,
    ADD CONSTRAINT cache_operations_parent_396_check
        CHECK (parent_operation_id IS NULL OR (auto_nodes AND parent_operation_id <> id));
CREATE INDEX cache_operations_auto_nodes_396_idx
    ON cache_operations (scope_id, created_at) WHERE auto_nodes AND parent_operation_id IS NULL;
CREATE INDEX cache_operations_parent_396_idx
    ON cache_operations (parent_operation_id) WHERE parent_operation_id IS NOT NULL;

-- 4. System configuration: proxy_cache_dir is removed (the node's cache
--    lives under its state root, <state>/shared/cache, by installation) and
--    proxy_cache_min_free_bytes (nginx min_free, whole MiB, 0 = none) added.
--    Validation applies to new revisions; existing ones are not rewritten
--    (1.0.35 is the first release).
CREATE OR REPLACE FUNCTION system_configuration_v2_nginx_http(candidate jsonb)
RETURNS boolean
LANGUAGE plpgsql
IMMUTABLE
AS $$
DECLARE
    buffers jsonb;
    upstream jsonb;
BEGIN
    IF NOT system_configuration_v2_json_keys_exact(candidate, ARRAY[
        'server','gzip_vary','default_type','log_not_found','proxy_buffering','proxy_cache_min_free_bytes',
        'server_tokens','gzip_comp_level','gzip_http_version','keepalive_requests',
        'proxy_cache_methods','proxy_http_version','server_addr_outgoing',
        'keepalive_timeout_ms','proxy_next_upstream','proxy_read_timeout_ms',
        'proxy_send_timeout_ms','client_max_body_size_bytes','gzip_min_length_bytes',
        'proxy_connect_timeout_ms','proxy_request_buffering','proxy_cache_max_size_bytes',
        'server_names_hash_max_size','large_client_header_buffers','client_body_buffer_size_bytes',
        'proxy_max_temp_file_size_bytes','server_names_hash_bucket_size'
    ]) THEN
        RETURN false;
    END IF;
    buffers := candidate->'large_client_header_buffers';
    upstream := candidate->'proxy_next_upstream';
    IF NOT system_configuration_json_integer(candidate->'gzip_comp_level', 1, 9) OR
       candidate->>'gzip_http_version' NOT IN ('1.0','1.1') OR
       NOT system_configuration_json_integer(candidate->'gzip_min_length_bytes', 0, 1073741824) OR
       jsonb_typeof(candidate->'gzip_vary') <> 'boolean' OR
       jsonb_typeof(candidate->'server_addr_outgoing') <> 'boolean' OR
       jsonb_typeof(candidate->'proxy_request_buffering') <> 'boolean' OR
       jsonb_typeof(candidate->'proxy_buffering') <> 'boolean' OR
       NOT system_configuration_json_integer(candidate->'proxy_cache_min_free_bytes', 0, 17592186044416) OR
       (candidate->>'proxy_cache_min_free_bytes')::bigint % 1048576 <> 0 OR
       NOT system_configuration_json_integer(candidate->'proxy_cache_max_size_bytes', 0, 1125899906842624) OR
       NOT system_configuration_v2_string_set(candidate->'proxy_cache_methods', ARRAY['GET','HEAD'], 1, 2) OR
       candidate->>'proxy_http_version' NOT IN ('1.0','1.1') OR
       NOT system_configuration_json_integer(candidate->'proxy_max_temp_file_size_bytes', 0, 1099511627776) OR
       NOT system_configuration_v2_string_set(upstream, ARRAY[
           'error','timeout','invalid_header','http_500','http_502','http_503','http_504',
           'http_403','http_404','http_429','non_idempotent','off'
       ], 1, 12) OR
       (upstream @> '["off"]'::jsonb AND jsonb_array_length(upstream) <> 1) OR
       NOT system_configuration_json_integer(candidate->'proxy_connect_timeout_ms', 100, 75000) OR
       NOT system_configuration_json_integer(candidate->'proxy_send_timeout_ms', 100, 3600000) OR
       NOT system_configuration_json_integer(candidate->'proxy_read_timeout_ms', 100, 3600000) OR
       NOT system_configuration_json_integer(candidate->'client_body_buffer_size_bytes', 1024, 1073741824) OR
       jsonb_typeof(candidate->'server') <> 'string' OR
       candidate->>'server' !~ '^$|^[A-Za-z0-9][A-Za-z0-9 ._-]{0,63}$' OR
       candidate->>'server' ~ '[[:cntrl:];]' OR
       NOT system_configuration_json_integer(candidate->'client_max_body_size_bytes', 1024, 10737418240) OR
       jsonb_typeof(candidate->'default_type') <> 'string' OR
       candidate->>'default_type' !~ '^[!#$%&''*+.^_\x60|~0-9A-Za-z-]+/[!#$%&''*+.^_\x60|~0-9A-Za-z-]+$' OR
       NOT system_configuration_json_integer(candidate->'keepalive_requests', 1, 1000000) OR
       NOT system_configuration_json_integer(candidate->'keepalive_timeout_ms', 100, 3600000) OR
       jsonb_typeof(candidate->'log_not_found') <> 'boolean' OR
       jsonb_typeof(candidate->'server_tokens') <> 'boolean' OR
       NOT system_configuration_v2_json_keys_exact(buffers, ARRAY['count','size_bytes']) OR
       NOT system_configuration_json_integer(buffers->'count', 1, 32) OR
       NOT system_configuration_json_integer(buffers->'size_bytes', 1024, 1048576) OR
       NOT system_configuration_json_integer(candidate->'server_names_hash_max_size', 512, 65536) OR
       ((candidate->>'server_names_hash_max_size')::bigint &
        ((candidate->>'server_names_hash_max_size')::bigint - 1)) <> 0 OR
       NOT system_configuration_json_integer(candidate->'server_names_hash_bucket_size', 32, 1024) OR
       ((candidate->>'server_names_hash_bucket_size')::bigint &
        ((candidate->>'server_names_hash_bucket_size')::bigint - 1)) <> 0 THEN
        RETURN false;
    END IF;
    RETURN true;
EXCEPTION WHEN OTHERS THEN
    RETURN false;
END;
$$;

CREATE OR REPLACE FUNCTION system_configuration_v2_nginx_override(candidate jsonb, nginx jsonb)
RETURNS boolean
LANGUAGE plpgsql
IMMUTABLE
AS $$
DECLARE
    worker jsonb;
    http jsonb;
    stream jsonb;
BEGIN
    IF NOT system_configuration_v2_json_keys_exact(candidate, ARRAY[]::text[], ARRAY['worker','http','stream']) OR
       candidate = '{}'::jsonb THEN
        RETURN false;
    END IF;
    worker := candidate->'worker';
    IF worker IS NOT NULL AND (
       jsonb_typeof(worker) <> 'object' OR worker = '{}'::jsonb OR
       NOT system_configuration_v2_json_keys_exact(worker, ARRAY[]::text[], ARRAY[
           'logs_dir','worker_connections','worker_processes','worker_rlimit_nofile',
           'worker_shutdown_timeout_ms'
       ]) OR NOT system_configuration_v2_nginx_worker(nginx->'worker' || worker)
    ) THEN RETURN false; END IF;
    http := candidate->'http';
    IF http IS NOT NULL AND (
       jsonb_typeof(http) <> 'object' OR http = '{}'::jsonb OR
       NOT system_configuration_v2_json_keys_exact(http, ARRAY[]::text[], ARRAY[
           'server','gzip_vary','default_type','log_not_found','proxy_buffering','proxy_cache_min_free_bytes',
           'server_tokens','gzip_comp_level','gzip_http_version','keepalive_requests',
           'proxy_cache_methods','proxy_http_version','server_addr_outgoing',
           'keepalive_timeout_ms','proxy_next_upstream','proxy_read_timeout_ms',
           'proxy_send_timeout_ms','client_max_body_size_bytes','gzip_min_length_bytes',
           'proxy_connect_timeout_ms','proxy_request_buffering','proxy_cache_max_size_bytes',
           'server_names_hash_max_size','large_client_header_buffers','client_body_buffer_size_bytes',
           'proxy_max_temp_file_size_bytes','server_names_hash_bucket_size'
       ]) OR NOT system_configuration_v2_nginx_http(nginx->'http' || http)
    ) THEN RETURN false; END IF;
    stream := candidate->'stream';
    IF stream IS NOT NULL AND (
       jsonb_typeof(stream) <> 'object' OR stream = '{}'::jsonb OR
       NOT system_configuration_v2_json_keys_exact(stream, ARRAY[]::text[],
           ARRAY['proxy_timeout_ms','proxy_connect_timeout_ms']) OR
       NOT system_configuration_v2_nginx_stream(nginx->'stream' || stream)
    ) THEN RETURN false; END IF;
    RETURN true;
EXCEPTION WHEN OTHERS THEN
    RETURN false;
END;
$$;
