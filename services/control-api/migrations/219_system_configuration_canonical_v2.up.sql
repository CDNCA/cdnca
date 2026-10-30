LOCK TABLE system_configuration_revisions IN ACCESS EXCLUSIVE MODE;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM system_configuration_revisions) THEN
        RAISE EXCEPTION
            'system configuration migration 219 requires an empty revision stream; v1 facts cannot be rewritten as canonical v2';
    END IF;
END;
$$;

ALTER TABLE system_configuration_revisions
    DROP CONSTRAINT system_configuration_revisions_canonical_schema_check;
ALTER TABLE system_configuration_revisions
    ADD CONSTRAINT system_configuration_revisions_canonical_schema_check
    CHECK (canonical_schema = 'cdnca.system-configuration/v2');

ALTER FUNCTION system_configuration_render_canonical_snapshot(jsonb)
    RENAME TO system_configuration_render_canonical_snapshot_v1_035;
ALTER FUNCTION system_configuration_snapshot_is_valid(bytea)
    RENAME TO system_configuration_snapshot_is_valid_v1_035;

CREATE FUNCTION system_configuration_v2_json_keys_exact(
    candidate jsonb, required_keys text[], optional_keys text[] DEFAULT ARRAY[]::text[]
)
RETURNS boolean
LANGUAGE sql
IMMUTABLE
AS $$
    SELECT candidate IS NOT NULL
       AND jsonb_typeof(candidate) = 'object'
       AND NOT EXISTS (
           SELECT 1 FROM unnest(required_keys) required_key
           WHERE NOT candidate ? required_key
       )
       AND NOT EXISTS (
           SELECT 1 FROM jsonb_object_keys(candidate) actual_key
           WHERE NOT actual_key = ANY(required_keys || optional_keys)
       );
$$;

CREATE FUNCTION system_configuration_v2_short_id(candidate jsonb)
RETURNS boolean
LANGUAGE sql
IMMUTABLE
AS $$
    SELECT jsonb_typeof(candidate) = 'string'
       AND candidate #>> '{}' ~ '^[a-z0-9][a-z0-9_-]{7,31}$';
$$;

CREATE FUNCTION system_configuration_v2_safe_label(candidate jsonb)
RETURNS boolean
LANGUAGE sql
IMMUTABLE
AS $$
    SELECT jsonb_typeof(candidate) = 'string'
       AND candidate #>> '{}' ~ '^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,255}$'
       AND candidate #>> '{}' !~ '[[:cntrl:]]';
$$;

CREATE FUNCTION system_configuration_v2_string_set(
    candidate jsonb, allowed_values text[], minimum_items integer, maximum_items integer
)
RETURNS boolean
LANGUAGE sql
IMMUTABLE
AS $$
    SELECT candidate IS NOT NULL
       AND jsonb_typeof(candidate) = 'array'
       AND jsonb_array_length(candidate) BETWEEN minimum_items AND maximum_items
       AND NOT EXISTS (
           SELECT 1 FROM jsonb_array_elements(candidate) item
           WHERE jsonb_typeof(item) <> 'string' OR item #>> '{}' <> ALL(allowed_values)
       )
       AND (SELECT count(*) FROM jsonb_array_elements(candidate))
           = (SELECT count(DISTINCT item #>> '{}') FROM jsonb_array_elements(candidate) item);
$$;

CREATE FUNCTION system_configuration_v2_port_list(candidate jsonb)
RETURNS boolean
LANGUAGE sql
IMMUTABLE
AS $$
    SELECT candidate IS NOT NULL
       AND jsonb_typeof(candidate) = 'array'
       AND jsonb_array_length(candidate) BETWEEN 1 AND 64
       AND NOT EXISTS (
           SELECT 1 FROM jsonb_array_elements(candidate) item
           WHERE NOT system_configuration_json_integer(item, 1, 65535)
       )
       AND (SELECT count(*) FROM jsonb_array_elements(candidate))
           = (SELECT count(DISTINCT item #>> '{}') FROM jsonb_array_elements(candidate) item);
$$;

CREATE FUNCTION system_configuration_v2_port_ranges(candidate jsonb)
RETURNS boolean
LANGUAGE plpgsql
IMMUTABLE
AS $$
DECLARE
    item jsonb;
    previous_to integer := 0;
BEGIN
    IF candidate IS NULL OR jsonb_typeof(candidate) <> 'array' OR jsonb_array_length(candidate) > 128 THEN
        RETURN false;
    END IF;
    FOR item IN SELECT value FROM jsonb_array_elements(candidate) LOOP
        IF NOT system_configuration_v2_json_keys_exact(item, ARRAY['from','to']) OR
           NOT system_configuration_json_integer(item->'from', 1, 65535) OR
           NOT system_configuration_json_integer(item->'to', 1, 65535) OR
           (item->>'from')::integer > (item->>'to')::integer OR
           (item->>'from')::integer <= previous_to THEN
            RETURN false;
        END IF;
        previous_to := (item->>'to')::integer;
    END LOOP;
    RETURN true;
EXCEPTION WHEN OTHERS THEN
    RETURN false;
END;
$$;

CREATE FUNCTION system_configuration_v2_nginx_worker(candidate jsonb)
RETURNS boolean
LANGUAGE sql
IMMUTABLE
AS $$
    SELECT system_configuration_v2_json_keys_exact(candidate, ARRAY[
               'logs_dir','worker_connections','worker_processes','worker_rlimit_nofile',
               'worker_shutdown_timeout_ms'
           ])
       AND system_configuration_json_integer(candidate->'worker_processes', 0, 256)
       AND system_configuration_json_integer(candidate->'worker_connections', 128, 1048576)
       AND system_configuration_json_integer(candidate->'worker_rlimit_nofile', 1024, 1048576)
       AND (candidate->>'worker_connections')::numeric <= (candidate->>'worker_rlimit_nofile')::numeric
       AND system_configuration_json_integer(candidate->'worker_shutdown_timeout_ms', 1000, 300000)
       AND jsonb_typeof(candidate->'logs_dir') = 'string'
       AND candidate->>'logs_dir' ~ '^/var/log/cdnca(/[^/]+)*$'
       AND candidate->>'logs_dir' !~ '(^|/)\.\.?(/|$)|[[:cntrl:]\\]';
$$;

CREATE FUNCTION system_configuration_v2_nginx_http(candidate jsonb)
RETURNS boolean
LANGUAGE plpgsql
IMMUTABLE
AS $$
DECLARE
    buffers jsonb;
    upstream jsonb;
BEGIN
    IF NOT system_configuration_v2_json_keys_exact(candidate, ARRAY[
        'server','gzip_vary','default_type','log_not_found','proxy_buffering','proxy_cache_dir',
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
       jsonb_typeof(candidate->'proxy_cache_dir') <> 'string' OR
       candidate->>'proxy_cache_dir' !~ '^/var/lib/cdnca(/[^/]+)*$' OR
       candidate->>'proxy_cache_dir' ~ '(^|/)\.\.?(/|$)|[[:cntrl:]\\]' OR
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

CREATE FUNCTION system_configuration_v2_nginx_stream(candidate jsonb)
RETURNS boolean
LANGUAGE sql
IMMUTABLE
AS $$
    SELECT system_configuration_v2_json_keys_exact(candidate,
               ARRAY['proxy_timeout_ms','proxy_connect_timeout_ms'])
       AND system_configuration_json_integer(candidate->'proxy_connect_timeout_ms', 100, 75000)
       AND system_configuration_json_integer(candidate->'proxy_timeout_ms', 100, 86400000);
$$;

CREATE FUNCTION system_configuration_v2_nginx_override(candidate jsonb, nginx jsonb)
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
           'server','gzip_vary','default_type','log_not_found','proxy_buffering','proxy_cache_dir',
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

CREATE FUNCTION system_configuration_v2_nginx_is_valid(candidate jsonb)
RETURNS boolean
LANGUAGE plpgsql
IMMUTABLE
AS $$
DECLARE
    item jsonb;
    seen_ids text[] := ARRAY[]::text[];
    seen_scopes text[] := ARRAY[]::text[];
    scope_key text;
BEGIN
    IF NOT system_configuration_v2_json_keys_exact(candidate, ARRAY['http','stream','worker','overrides']) OR
       NOT system_configuration_v2_nginx_worker(candidate->'worker') OR
       NOT system_configuration_v2_nginx_http(candidate->'http') OR
       NOT system_configuration_v2_nginx_stream(candidate->'stream') OR
       jsonb_typeof(candidate->'overrides') <> 'array' THEN
        RETURN false;
    END IF;
    FOR item IN SELECT value FROM jsonb_array_elements(candidate->'overrides') LOOP
        IF NOT system_configuration_v2_json_keys_exact(item, ARRAY['id','scope','values','scope_id']) OR
           NOT system_configuration_v2_short_id(item->'id') OR
           item->>'scope' NOT IN ('region','node') OR
           NOT system_configuration_v2_safe_label(item->'scope_id') OR
           NOT system_configuration_v2_nginx_override(item->'values', candidate) OR
           item->>'id' = ANY(seen_ids) THEN
            RETURN false;
        END IF;
        scope_key := item->>'scope' || E'\x1f' || item->>'scope_id';
        IF scope_key = ANY(seen_scopes) THEN RETURN false; END IF;
        seen_ids := array_append(seen_ids, item->>'id');
        seen_scopes := array_append(seen_scopes, scope_key);
    END LOOP;
    RETURN true;
EXCEPTION WHEN OTHERS THEN
    RETURN false;
END;
$$;

CREATE FUNCTION system_configuration_v2_tls_protocols(candidate jsonb)
RETURNS boolean
LANGUAGE sql
IMMUTABLE
AS $$
    SELECT system_configuration_v2_string_set(
        candidate, ARRAY['TLSv1','TLSv1.1','TLSv1.2','TLSv1.3'], 1, 4
    );
$$;

CREATE FUNCTION system_configuration_v2_default_ssl(candidate jsonb)
RETURNS boolean
LANGUAGE sql
IMMUTABLE
AS $$
    SELECT system_configuration_v2_json_keys_exact(candidate,
               ARRAY['mode','protocols','cipher_suites','prefer_server_ciphers'])
       AND candidate->>'mode' IN ('recommended','legacy_tls12','legacy_full','custom')
       AND system_configuration_v2_tls_protocols(candidate->'protocols')
       AND jsonb_typeof(candidate->'cipher_suites') = 'string'
       AND char_length(candidate->>'cipher_suites') <= 4096
       AND candidate->>'cipher_suites' !~ '[[:cntrl:]]'
       AND jsonb_typeof(candidate->'prefer_server_ciphers') = 'boolean'
       AND (
           candidate->>'mode' = 'custom'
           OR (
               candidate->>'mode' = 'recommended'
               AND candidate->'protocols' = '["TLSv1.2","TLSv1.3"]'::jsonb
               AND candidate->>'cipher_suites' = 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305'
               AND candidate->'prefer_server_ciphers' = 'false'::jsonb
           )
           OR (
               candidate->>'mode' = 'legacy_tls12'
               AND candidate->'protocols' = '["TLSv1.2","TLSv1.3"]'::jsonb
               AND candidate->>'cipher_suites' = 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES256-SHA:ECDHE-RSA-AES256-SHA:AES128-GCM-SHA256:AES256-GCM-SHA384:AES128-SHA256:AES256-SHA256:AES128-SHA:AES256-SHA'
               AND candidate->'prefer_server_ciphers' = 'true'::jsonb
           )
           OR (
               candidate->>'mode' = 'legacy_full'
               AND candidate->'protocols' = '["TLSv1","TLSv1.1","TLSv1.2","TLSv1.3"]'::jsonb
               AND candidate->>'cipher_suites' = 'DEFAULT:@SECLEVEL=0'
               AND candidate->'prefer_server_ciphers' = 'true'::jsonb
           )
       );
$$;

CREATE FUNCTION system_configuration_v2_cache_rules(candidate jsonb)
RETURNS boolean
LANGUAGE plpgsql
IMMUTABLE
AS $$
DECLARE
    item jsonb;
    seen_ids text[] := ARRAY[]::text[];
    seen_positions integer[] := ARRAY[]::integer[];
    previous_position integer := -1;
    previous_id text := '';
BEGIN
    IF candidate IS NULL OR jsonb_typeof(candidate) <> 'array' OR jsonb_array_length(candidate) > 100 THEN
        RETURN false;
    END IF;
    FOR item IN SELECT value FROM jsonb_array_elements(candidate) LOOP
        IF NOT system_configuration_v2_json_keys_exact(item, ARRAY[
               'id','match','range','content','enabled','no_cache','position','force_cache',
               'ignore_vary','ttl_seconds','ignore_query'
           ]) OR
           NOT system_configuration_v2_short_id(item->'id') OR
           jsonb_typeof(item->'match') <> 'string' OR
           char_length(item->>'match') NOT BETWEEN 1 AND 64 OR item->>'match' ~ '[[:cntrl:]]' OR
           jsonb_typeof(item->'content') NOT IN ('string','null') OR
           (jsonb_typeof(item->'content') = 'string' AND (
               char_length(item->>'content') > 2048 OR item->>'content' ~ '[[:cntrl:]]'
           )) OR
           NOT system_configuration_json_integer(item->'ttl_seconds', 0, 31536000) OR
           jsonb_typeof(item->'ignore_query') <> 'boolean' OR
           jsonb_typeof(item->'force_cache') <> 'boolean' OR
           jsonb_typeof(item->'range') <> 'boolean' OR
           jsonb_typeof(item->'ignore_vary') <> 'boolean' OR
           jsonb_typeof(item->'no_cache') <> 'array' OR
           jsonb_array_length(item->'no_cache') > 100 OR
           EXISTS (
               SELECT 1 FROM jsonb_array_elements(item->'no_cache') condition
               WHERE NOT system_configuration_v2_json_keys_exact(condition, ARRAY['string','variable'])
                  OR jsonb_typeof(condition->'variable') <> 'string'
                  OR char_length(condition->>'variable') NOT BETWEEN 1 AND 256
                  OR condition->>'variable' ~ '[[:cntrl:]]'
                  OR jsonb_typeof(condition->'string') <> 'string'
                  OR char_length(condition->>'string') NOT BETWEEN 1 AND 2048
                  OR condition->>'string' ~ '[[:cntrl:]]'
           ) OR
           jsonb_typeof(item->'enabled') <> 'boolean' OR
           NOT system_configuration_json_integer(item->'position', 0, 99) OR
           item->>'id' = ANY(seen_ids) OR
           (item->>'position')::integer = ANY(seen_positions) OR
           (item->>'position')::integer < previous_position OR
           ((item->>'position')::integer = previous_position AND item->>'id' < previous_id) THEN
            RETURN false;
        END IF;
        seen_ids := array_append(seen_ids, item->>'id');
        seen_positions := array_append(seen_positions, (item->>'position')::integer);
        previous_position := (item->>'position')::integer;
        previous_id := item->>'id';
    END LOOP;
    RETURN true;
EXCEPTION WHEN OTHERS THEN
    RETURN false;
END;
$$;

CREATE FUNCTION system_configuration_v2_origin_headers(candidate jsonb)
RETURNS boolean
LANGUAGE plpgsql
IMMUTABLE
AS $$
DECLARE
    item jsonb;
    seen_ids text[] := ARRAY[]::text[];
    seen_positions integer[] := ARRAY[]::integer[];
    previous_position integer := -1;
    previous_id text := '';
BEGIN
    IF candidate IS NULL OR jsonb_typeof(candidate) <> 'array' OR jsonb_array_length(candidate) > 100 THEN
        RETURN false;
    END IF;
    FOR item IN SELECT value FROM jsonb_array_elements(candidate) LOOP
        IF NOT system_configuration_v2_json_keys_exact(item, ARRAY[
               'id','name','value','action','enabled','position','allow_duplicate'
           ]) OR
           NOT system_configuration_v2_short_id(item->'id') OR
           jsonb_typeof(item->'name') <> 'string' OR
           item->>'name' !~ '^[!#$%&''*+.^_\x60|~0-9A-Za-z-]+$' OR
           item->>'action' NOT IN ('set','append','delete') OR
           (item->>'action' = 'delete' AND jsonb_typeof(item->'value') <> 'null') OR
           (item->>'action' <> 'delete' AND jsonb_typeof(item->'value') <> 'string') OR
           (jsonb_typeof(item->'value') = 'string' AND (
               char_length(item->>'value') > 4096 OR item->>'value' ~ '[[:cntrl:]]'
           )) OR
           jsonb_typeof(item->'allow_duplicate') <> 'boolean' OR
           jsonb_typeof(item->'enabled') <> 'boolean' OR
           NOT system_configuration_json_integer(item->'position', 0, 99) OR
           item->>'id' = ANY(seen_ids) OR
           (item->>'position')::integer = ANY(seen_positions) OR
           (item->>'position')::integer < previous_position OR
           ((item->>'position')::integer = previous_position AND item->>'id' < previous_id) THEN
            RETURN false;
        END IF;
        seen_ids := array_append(seen_ids, item->>'id');
        seen_positions := array_append(seen_positions, (item->>'position')::integer);
        previous_position := (item->>'position')::integer;
        previous_id := item->>'id';
    END LOOP;
    RETURN true;
EXCEPTION WHEN OTHERS THEN
    RETURN false;
END;
$$;

CREATE FUNCTION system_configuration_v2_waf_modules(candidate jsonb)
RETURNS boolean
LANGUAGE sql
IMMUTABLE
AS $$
    SELECT system_configuration_v2_json_keys_exact(candidate, ARRAY[
               'fi','php','ssti','sqli','upload','xss','cmdi','java','jdeser','phpdeser'
           ])
       AND NOT EXISTS (
           SELECT 1 FROM jsonb_each(candidate) entry
           WHERE jsonb_typeof(entry.value) <> 'string'
              OR entry.value #>> '{}' NOT IN ('off','detect','on')
       );
$$;

CREATE FUNCTION system_configuration_v2_default_other(candidate jsonb)
RETURNS boolean
LANGUAGE sql
IMMUTABLE
AS $$
    SELECT system_configuration_v2_json_keys_exact(candidate, ARRAY[
               'gzip_types','gzip_enabled','crawler_policy','load_balancing','websocket_enabled',
               'realtime_send_enabled','block_transparent_proxy','realtime_response_enabled'
           ])
       AND candidate->>'load_balancing' IN ('round_robin','ip_hash','url_hash','least_conn','random')
       AND candidate->>'crawler_policy' IN ('default','allow','deny')
       AND jsonb_typeof(candidate->'gzip_enabled') = 'boolean'
       AND jsonb_typeof(candidate->'gzip_types') = 'array'
       AND jsonb_array_length(candidate->'gzip_types') <= 128
       AND NOT EXISTS (
           SELECT 1 FROM jsonb_array_elements(candidate->'gzip_types') item
           WHERE jsonb_typeof(item) <> 'string'
              OR char_length(item #>> '{}') > 128
              OR item #>> '{}' !~ '^[!#$%&''*+.^_\x60|~0-9A-Za-z-]+/[!#$%&''*+.^_\x60|~0-9A-Za-z-]+$'
       )
       AND (SELECT count(*) FROM jsonb_array_elements(candidate->'gzip_types'))
           = (SELECT count(DISTINCT item #>> '{}') FROM jsonb_array_elements(candidate->'gzip_types') item)
       AND (candidate->'gzip_enabled' = 'false'::jsonb OR jsonb_array_length(candidate->'gzip_types') > 0)
       AND jsonb_typeof(candidate->'websocket_enabled') = 'boolean'
       AND jsonb_typeof(candidate->'block_transparent_proxy') = 'boolean'
       AND jsonb_typeof(candidate->'realtime_response_enabled') = 'boolean'
       AND jsonb_typeof(candidate->'realtime_send_enabled') = 'boolean';
$$;

CREATE FUNCTION system_configuration_v2_default_origin(candidate jsonb)
RETURNS boolean
LANGUAGE sql
IMMUTABLE
AS $$
    SELECT system_configuration_v2_json_keys_exact(candidate, ARRAY[
               'scheme','http_port','https_port','http_version','ssl_protocols',
               'keepalive_enabled','post_body_limit_bytes','connect_timeout_seconds',
               'response_timeout_seconds'
           ])
       AND candidate->>'scheme' IN ('http','https','follow','follow_with_port')
       AND system_configuration_json_integer(candidate->'http_port', 1, 65535)
       AND system_configuration_json_integer(candidate->'https_port', 1, 65535)
       AND system_configuration_json_integer(candidate->'response_timeout_seconds', 1, 3600)
       AND system_configuration_json_integer(candidate->'connect_timeout_seconds', 1, 75)
       AND system_configuration_v2_tls_protocols(candidate->'ssl_protocols')
       AND candidate->>'http_version' IN ('1.0','1.1')
       AND jsonb_typeof(candidate->'keepalive_enabled') = 'boolean'
       AND system_configuration_json_integer(candidate->'post_body_limit_bytes', 1024, 10737418240);
$$;

CREATE FUNCTION system_configuration_v2_default_website(candidate jsonb)
RETURNS boolean
LANGUAGE plpgsql
IMMUTABLE
AS $$
DECLARE
    http jsonb := candidate->'http';
    https jsonb := candidate->'https';
    access_log jsonb := candidate->'access_log';
    security jsonb := candidate->'security';
    auto_block jsonb := security->'waf_auto_block';
BEGIN
    IF NOT system_configuration_v2_json_keys_exact(candidate, ARRAY[
           'http','https','other','origin','security','access_log','cache_rules','origin_request_headers'
       ]) OR
       NOT system_configuration_v2_json_keys_exact(http, ARRAY['listen_ports']) OR
       NOT system_configuration_v2_port_list(http->'listen_ports') OR
       NOT system_configuration_v2_json_keys_exact(https, ARRAY[
           'ssl','force_https','hsts_enabled','http2_enabled','http3_enabled',
           'listen_ports','ocsp_stapling_enabled'
       ]) OR
       NOT system_configuration_v2_port_list(https->'listen_ports') OR
       EXISTS (
           SELECT 1 FROM jsonb_array_elements(http->'listen_ports') left_port
           JOIN jsonb_array_elements(https->'listen_ports') right_port ON left_port = right_port
       ) OR
       jsonb_typeof(https->'hsts_enabled') <> 'boolean' OR
       jsonb_typeof(https->'http2_enabled') <> 'boolean' OR
       jsonb_typeof(https->'http3_enabled') <> 'boolean' OR
       jsonb_typeof(https->'force_https') <> 'boolean' OR
       NOT system_configuration_v2_default_ssl(https->'ssl') OR
       jsonb_typeof(https->'ocsp_stapling_enabled') <> 'boolean' OR
       NOT system_configuration_v2_default_origin(candidate->'origin') OR
       NOT system_configuration_v2_cache_rules(candidate->'cache_rules') OR
       NOT system_configuration_v2_origin_headers(candidate->'origin_request_headers') OR
       NOT system_configuration_v2_json_keys_exact(access_log, ARRAY[
           'capture_request_body','request_body_limit_kb',
           'capture_request_headers','capture_response_headers'
       ]) OR
       jsonb_typeof(access_log->'capture_request_headers') <> 'boolean' OR
       jsonb_typeof(access_log->'capture_response_headers') <> 'boolean' OR
       jsonb_typeof(access_log->'capture_request_body') <> 'boolean' OR
       NOT system_configuration_json_integer(access_log->'request_body_limit_kb', 0, 10240) OR
       (access_log->'capture_request_body' = 'true'::jsonb AND
        (access_log->>'request_body_limit_kb')::integer = 0) OR
       NOT system_configuration_v2_json_keys_exact(security, ARRAY[
           'waf_enabled','waf_modules','waf_auto_block','default_cc_policy_id'
       ]) OR
       jsonb_typeof(security->'default_cc_policy_id') NOT IN ('string','null') OR
       (jsonb_typeof(security->'default_cc_policy_id') = 'string' AND
        NOT system_configuration_v2_safe_label(security->'default_cc_policy_id')) OR
       jsonb_typeof(security->'waf_enabled') <> 'boolean' OR
       NOT system_configuration_v2_json_keys_exact(auto_block,
           ARRAY['enabled','block_seconds','hit_threshold','window_seconds']) OR
       jsonb_typeof(auto_block->'enabled') <> 'boolean' OR
       NOT system_configuration_json_integer(auto_block->'window_seconds', 1, 86400) OR
       NOT system_configuration_json_integer(auto_block->'hit_threshold', 1, 1000000) OR
       NOT system_configuration_json_integer(auto_block->'block_seconds', 1, 604800) OR
       NOT system_configuration_v2_waf_modules(security->'waf_modules') OR
       NOT system_configuration_v2_default_other(candidate->'other') THEN
        RETURN false;
    END IF;
    RETURN true;
EXCEPTION WHEN OTHERS THEN
    RETURN false;
END;
$$;

CREATE FUNCTION system_configuration_v2_defaults_override(candidate jsonb, defaults_document jsonb)
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

CREATE FUNCTION system_configuration_v2_defaults_is_valid(candidate jsonb)
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

CREATE FUNCTION system_configuration_v2_resource_site(candidate jsonb)
RETURNS boolean
LANGUAGE sql
IMMUTABLE
AS $$
    SELECT system_configuration_v2_json_keys_exact(candidate, ARRAY[
               'black_ip_limit','white_ip_limit','cc_rule_max_limit','access_log_tmp_dir',
               'max_domains_per_site','daily_clean_dir_limit','daily_clean_url_limit',
               'daily_ip_unlock_limit','daily_pre_cache_url_limit','access_log_retain_hours',
               'listen_default_http_80','related_config_min_limit','ip_unlock_per_request_limit',
               'daily_access_log_download_limit','related_config_max_times_limit'
           ])
       AND system_configuration_json_integer(candidate->'related_config_min_limit', 1, 100000)
       AND system_configuration_json_integer(candidate->'related_config_max_times_limit', 1, 100)
       AND system_configuration_json_integer(candidate->'black_ip_limit', 1, 1000000)
       AND system_configuration_json_integer(candidate->'white_ip_limit', 1, 1000000)
       AND system_configuration_json_integer(candidate->'daily_clean_url_limit', 1, 10000000)
       AND system_configuration_json_integer(candidate->'daily_clean_dir_limit', 1, 1000000)
       AND system_configuration_json_integer(candidate->'daily_pre_cache_url_limit', 1, 10000000)
       AND system_configuration_json_integer(candidate->'daily_ip_unlock_limit', 1, 10000000)
       AND system_configuration_json_integer(candidate->'ip_unlock_per_request_limit', 1, 100000)
       AND system_configuration_json_integer(candidate->'cc_rule_max_limit', 1, 100000)
       AND system_configuration_json_integer(candidate->'max_domains_per_site', 1, 100)
       AND jsonb_typeof(candidate->'listen_default_http_80') = 'boolean'
       AND system_configuration_json_integer(candidate->'daily_access_log_download_limit', 1, 100000)
       AND jsonb_typeof(candidate->'access_log_tmp_dir') = 'string'
       AND candidate->>'access_log_tmp_dir' ~ '^/var/lib/cdnca(/[^/]+)*$'
       AND candidate->>'access_log_tmp_dir' !~ '(^|/)\.\.?(/|$)|[[:cntrl:]\\]'
       AND system_configuration_json_integer(candidate->'access_log_retain_hours', 1, 720);
$$;

CREATE FUNCTION system_configuration_v2_resource_stream(candidate jsonb)
RETURNS boolean
LANGUAGE sql
IMMUTABLE
AS $$
    SELECT system_configuration_v2_json_keys_exact(candidate, ARRAY[
               'acl_max_limit','custom_port_not_allow','related_config_min_limit',
               'related_config_max_times_limit'
           ])
       AND system_configuration_v2_port_ranges(candidate->'custom_port_not_allow')
       AND system_configuration_json_integer(candidate->'related_config_min_limit', 1, 100000)
       AND system_configuration_json_integer(candidate->'related_config_max_times_limit', 1, 100)
       AND system_configuration_json_integer(candidate->'acl_max_limit', 1, 100000);
$$;

CREATE FUNCTION system_configuration_v2_resource_site_stream(candidate jsonb)
RETURNS boolean
LANGUAGE sql
IMMUTABLE
AS $$
    SELECT system_configuration_v2_json_keys_exact(
               candidate, ARRAY['custom_port_allow','custom_port_not_allow']
           )
       AND system_configuration_v2_port_ranges(candidate->'custom_port_not_allow')
       AND system_configuration_v2_port_ranges(candidate->'custom_port_allow')
       AND NOT EXISTS (
           SELECT 1
           FROM jsonb_array_elements(candidate->'custom_port_not_allow') denied
           CROSS JOIN jsonb_array_elements(candidate->'custom_port_allow') allowed
           WHERE (denied->>'from')::integer <= (allowed->>'to')::integer
             AND (allowed->>'from')::integer <= (denied->>'to')::integer
       );
$$;

CREATE FUNCTION system_configuration_v2_resources_override(candidate jsonb)
RETURNS boolean
LANGUAGE plpgsql
IMMUTABLE
AS $$
DECLARE
    site jsonb := candidate->'site';
    stream jsonb := candidate->'stream';
    site_stream jsonb := candidate->'site_stream';
BEGIN
    IF NOT system_configuration_v2_json_keys_exact(
           candidate, ARRAY[]::text[], ARRAY['site','stream','site_stream']
       ) OR candidate = '{}'::jsonb THEN
        RETURN false;
    END IF;
    IF site IS NOT NULL AND (
       NOT system_configuration_v2_json_keys_exact(site, ARRAY[]::text[],
           ARRAY['black_ip_limit','white_ip_limit','listen_default_http_80']) OR
       site = '{}'::jsonb OR
       (site ? 'black_ip_limit' AND
        NOT system_configuration_json_integer(site->'black_ip_limit', 1, 1000000)) OR
       (site ? 'white_ip_limit' AND
        NOT system_configuration_json_integer(site->'white_ip_limit', 1, 1000000)) OR
       (site ? 'listen_default_http_80' AND
        jsonb_typeof(site->'listen_default_http_80') <> 'boolean')
    ) THEN RETURN false; END IF;
    IF stream IS NOT NULL AND (
       NOT system_configuration_v2_json_keys_exact(stream, ARRAY['custom_port_not_allow']) OR
       NOT system_configuration_v2_port_ranges(stream->'custom_port_not_allow')
    ) THEN RETURN false; END IF;
    IF site_stream IS NOT NULL AND (
       NOT system_configuration_v2_json_keys_exact(
           site_stream, ARRAY[]::text[], ARRAY['custom_port_allow','custom_port_not_allow']
       ) OR site_stream = '{}'::jsonb OR
       (site_stream ? 'custom_port_not_allow' AND
        NOT system_configuration_v2_port_ranges(site_stream->'custom_port_not_allow')) OR
       (site_stream ? 'custom_port_allow' AND
        NOT system_configuration_v2_port_ranges(site_stream->'custom_port_allow')) OR
       (site_stream ? 'custom_port_not_allow' AND site_stream ? 'custom_port_allow' AND EXISTS (
           SELECT 1
           FROM jsonb_array_elements(site_stream->'custom_port_not_allow') denied
           CROSS JOIN jsonb_array_elements(site_stream->'custom_port_allow') allowed
           WHERE (denied->>'from')::integer <= (allowed->>'to')::integer
             AND (allowed->>'from')::integer <= (denied->>'to')::integer
       ))
    ) THEN RETURN false; END IF;
    RETURN true;
EXCEPTION WHEN OTHERS THEN
    RETURN false;
END;
$$;

CREATE FUNCTION system_configuration_v2_resources_is_valid(candidate jsonb)
RETURNS boolean
LANGUAGE plpgsql
IMMUTABLE
AS $$
DECLARE
    item jsonb;
    seen_ids text[] := ARRAY[]::text[];
    seen_scopes text[] := ARRAY[]::text[];
BEGIN
    IF NOT system_configuration_v2_json_keys_exact(
           candidate, ARRAY['site','stream','overrides','site_stream']
       ) OR NOT system_configuration_v2_resource_site(candidate->'site') OR
       NOT system_configuration_v2_resource_stream(candidate->'stream') OR
       NOT system_configuration_v2_resource_site_stream(candidate->'site_stream') OR
       jsonb_typeof(candidate->'overrides') <> 'array' THEN
        RETURN false;
    END IF;
    FOR item IN SELECT value FROM jsonb_array_elements(candidate->'overrides') LOOP
        IF NOT system_configuration_v2_json_keys_exact(item, ARRAY['id','scope','values','scope_id']) OR
           NOT system_configuration_v2_short_id(item->'id') OR item->>'scope' <> 'region' OR
           NOT system_configuration_v2_safe_label(item->'scope_id') OR
           NOT system_configuration_v2_resources_override(item->'values') OR
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

CREATE FUNCTION system_configuration_v2_error_pages_is_valid(candidate jsonb)
RETURNS boolean
LANGUAGE plpgsql
IMMUTABLE
AS $$
DECLARE
    item jsonb;
    previous_status integer := 0;
    object_key text;
BEGIN
    IF candidate IS NULL OR jsonb_typeof(candidate) <> 'array' OR jsonb_array_length(candidate) > 13 THEN
        RETURN false;
    END IF;
    FOR item IN SELECT value FROM jsonb_array_elements(candidate) LOOP
        IF NOT system_configuration_v2_json_keys_exact(item, ARRAY[
               'sha256','mime_type','size_bytes','status_code','storage_object_key'
           ]) OR
           NOT system_configuration_json_integer(item->'status_code', 400, 504) OR
           (item->>'status_code')::integer NOT IN (400,401,403,404,405,408,413,429,500,501,502,503,504) OR
           (item->>'status_code')::integer <= previous_status OR
           jsonb_typeof(item->'mime_type') <> 'string' OR
           item->>'mime_type' NOT IN ('application/json','text/html','text/plain') OR
           NOT system_configuration_json_integer(item->'size_bytes', 1, 1048576) OR
           jsonb_typeof(item->'sha256') <> 'string' OR
           item->>'sha256' !~ '^[0-9a-f]{64}$' OR
           jsonb_typeof(item->'storage_object_key') <> 'string' THEN
            RETURN false;
        END IF;
        object_key := item->>'storage_object_key';
        IF object_key <> btrim(object_key) OR octet_length(object_key) > 512 OR
           object_key !~ '^[A-Za-z0-9][A-Za-z0-9._/-]*$' OR
           object_key ~ '(^|/)\.\.?(/|$)|[[:cntrl:]\\]' OR
           position('//' IN object_key) > 0 OR left(object_key, 1) = '/' THEN
            RETURN false;
        END IF;
        previous_status := (item->>'status_code')::integer;
    END LOOP;
    RETURN true;
EXCEPTION WHEN OTHERS THEN
    RETURN false;
END;
$$;

CREATE FUNCTION system_configuration_v2_secrets_is_valid(candidate jsonb)
RETURNS boolean
LANGUAGE plpgsql
IMMUTABLE
AS $$
DECLARE
    reference jsonb;
BEGIN
    IF NOT system_configuration_v2_json_keys_exact(
           candidate, ARRAY[]::text[], ARRAY['error_page_storage']
       ) THEN
        RETURN false;
    END IF;
    IF NOT candidate ? 'error_page_storage' THEN RETURN true; END IF;
    reference := candidate->'error_page_storage';
    IF NOT system_configuration_v2_json_keys_exact(reference, ARRAY[
           'key_id','provider','reference','algorithm','ciphertext_sha256'
       ]) OR reference->>'provider' NOT IN ('vault','kms-envelope') OR
       reference->>'algorithm' NOT IN ('aes-256-gcm','chacha20-poly1305','kms-managed') OR
       reference->>'ciphertext_sha256' !~ '^[0-9a-f]{64}$' OR
       NOT system_configuration_v2_safe_label(reference->'reference') OR
       NOT system_configuration_v2_safe_label(reference->'key_id') OR
       position('..' IN reference->>'reference') > 0 OR
       position('//' IN reference->>'reference') > 0 OR
       position('..' IN reference->>'key_id') > 0 OR
       position('//' IN reference->>'key_id') > 0 THEN
        RETURN false;
    END IF;
    RETURN true;
EXCEPTION WHEN OTHERS THEN
    RETURN false;
END;
$$;

CREATE FUNCTION system_configuration_v2_node_monitoring_is_valid(candidate jsonb)
RETURNS boolean
LANGUAGE sql
IMMUTABLE
AS $$
    SELECT system_configuration_v2_json_keys_exact(candidate, ARRAY[
               'port_mode','probe_timeout_ms','probe_interval_ms','failure_debounce_ms',
               'failure_threshold','recovery_debounce_ms','recovery_threshold',
               'recovery_notification_enabled'
           ], ARRAY['custom_port'])
       AND candidate->>'port_mode' IN ('default','custom')
       AND ((candidate->>'port_mode' = 'default' AND NOT candidate ? 'custom_port') OR
            (candidate->>'port_mode' = 'custom' AND candidate ? 'custom_port' AND
             system_configuration_json_integer(candidate->'custom_port', 1, 65535)))
       AND system_configuration_json_integer(candidate->'probe_interval_ms', 1000, 300000)
       AND system_configuration_json_integer(candidate->'probe_timeout_ms', 100, 60000)
       AND (candidate->>'probe_timeout_ms')::integer <= (candidate->>'probe_interval_ms')::integer
       AND system_configuration_json_integer(candidate->'failure_threshold', 1, 20)
       AND system_configuration_json_integer(candidate->'recovery_threshold', 1, 20)
       AND system_configuration_json_integer(candidate->'failure_debounce_ms', 0, 3600000)
       AND system_configuration_json_integer(candidate->'recovery_debounce_ms', 0, 3600000)
       AND jsonb_typeof(candidate->'recovery_notification_enabled') = 'boolean';
$$;

CREATE FUNCTION system_configuration_render_canonical_snapshot(document jsonb)
RETURNS bytea
LANGUAGE sql
IMMUTABLE
STRICT
AS $$
    SELECT convert_to(document::text, 'UTF8');
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
BEGIN
    raw := convert_from(candidate, 'UTF8');
    IF raw <> btrim(raw) THEN RETURN false; END IF;
    document := raw::jsonb;
    IF raw <> document::text OR
       NOT system_configuration_v2_json_keys_exact(document, ARRAY['schema','configuration']) OR
       jsonb_typeof(document->'schema') <> 'string' OR
       document->>'schema' <> 'cdnca.system-configuration/v2' THEN
        RETURN false;
    END IF;
    configuration := document->'configuration';
    IF NOT system_configuration_v2_json_keys_exact(configuration, ARRAY[
           'nginx','secrets','defaults','resources','error_pages'
       ], ARRAY['node_monitoring']) OR
       NOT system_configuration_v2_nginx_is_valid(configuration->'nginx') OR
       NOT system_configuration_v2_defaults_is_valid(configuration->'defaults') OR
       NOT system_configuration_v2_resources_is_valid(configuration->'resources') OR
       NOT system_configuration_v2_error_pages_is_valid(configuration->'error_pages') OR
       NOT system_configuration_v2_secrets_is_valid(configuration->'secrets') OR
       (configuration ? 'node_monitoring' AND
        NOT system_configuration_v2_node_monitoring_is_valid(configuration->'node_monitoring')) THEN
        RETURN false;
    END IF;
    RETURN system_configuration_render_canonical_snapshot(document) = candidate;
EXCEPTION WHEN OTHERS THEN
    RETURN false;
END;
$$;
