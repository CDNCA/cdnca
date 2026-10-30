LOCK TABLE schema_migrations, http_policy_revisions, sites, system_configuration_revisions,
    error_page_rule_revisions, theme_error_pages IN ACCESS EXCLUSIVE MODE;

DO $migration_391_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 391 OR
       (SELECT max(version) FROM schema_migrations) <> 391 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=391 AND
        migration_id='391_http_policy_regex_rules' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 391 down requires the exact verified migration head' USING ERRCODE='P3911';
    END IF;
END;
$migration_391_down$;

-- The 056 validators again (exact/prefix only, no preserve_path); stored
-- revisions are not rewritten.
CREATE OR REPLACE FUNCTION http_policy_rewrites_valid_056(rules jsonb)
RETURNS boolean
LANGUAGE plpgsql
IMMUTABLE
AS $$
DECLARE rule jsonb;
DECLARE other jsonb;
DECLARE rule_kind text;
DECLARE rule_path text;
DECLARE previous_priority numeric;
DECLARE previous_id text;
BEGIN
    IF rules IS NULL OR jsonb_typeof(rules) <> 'array' OR jsonb_array_length(rules) > 128 THEN
        RETURN false;
    END IF;
    IF (SELECT count(*) FROM jsonb_array_elements(rules)) <>
       (SELECT count(DISTINCT element.item_value ->> 'rule_id')
        FROM jsonb_array_elements(rules) AS element(item_value)) THEN
        RETURN false;
    END IF;
    FOR rule IN SELECT element.item_value
                FROM jsonb_array_elements(rules) AS element(item_value) LOOP
        IF NOT http_policy_exact_keys_056(rule,
            ARRAY['rule_id','priority','match_kind','match_path','target_path','preserve_query','preserve_cookie']) OR
           NOT http_policy_identifier_valid_056(rule ->> 'rule_id') OR
           jsonb_typeof(rule -> 'priority') <> 'number' OR (rule ->> 'priority') !~ '^[0-9]{1,10}$' OR
           (rule ->> 'priority')::numeric > 4294967295 OR
           jsonb_typeof(rule -> 'preserve_query') <> 'boolean' OR
           jsonb_typeof(rule -> 'preserve_cookie') <> 'boolean' THEN
            RETURN false;
        END IF;
        rule_kind := rule ->> 'match_kind';
        rule_path := rule ->> 'match_path';
        IF NOT http_policy_path_valid_056(rule_kind, rule_path) OR
           NOT http_policy_path_valid_056(rule_kind, rule ->> 'target_path') OR
           rule_path = rule ->> 'target_path' OR
           (previous_priority IS NOT NULL AND
             ((rule ->> 'priority')::numeric < previous_priority OR
              ((rule ->> 'priority')::numeric = previous_priority AND rule ->> 'rule_id' <= previous_id))) THEN
            RETURN false;
        END IF;
        previous_priority := (rule ->> 'priority')::numeric;
        previous_id := rule ->> 'rule_id';
    END LOOP;

    FOR rule IN SELECT element.item_value
                FROM jsonb_array_elements(rules) AS element(item_value) LOOP
        FOR other IN SELECT element.item_value
                     FROM jsonb_array_elements(rules) AS element(item_value) LOOP
            IF rule ->> 'rule_id' >= other ->> 'rule_id' OR rule ->> 'priority' <> other ->> 'priority' THEN
                CONTINUE;
            END IF;
            IF (rule ->> 'match_kind' = 'exact' AND other ->> 'match_kind' = 'exact' AND
                rule ->> 'match_path' = other ->> 'match_path') OR
               (rule ->> 'match_kind' = 'prefix' AND
                (rule ->> 'match_path' = '/' OR
                 left(other ->> 'match_path', length(rule ->> 'match_path')) = rule ->> 'match_path')) OR
               (other ->> 'match_kind' = 'prefix' AND
                (other ->> 'match_path' = '/' OR
                 left(rule ->> 'match_path', length(other ->> 'match_path')) = other ->> 'match_path')) THEN
                RETURN false;
            END IF;
        END LOOP;
    END LOOP;
    RETURN true;
END;
$$;


CREATE OR REPLACE FUNCTION http_policy_rewrite_chain_valid_056(rules jsonb)
RETURNS boolean
LANGUAGE plpgsql
IMMUTABLE
AS $$
BEGIN
    IF NOT http_policy_rewrites_valid_056(rules) THEN RETURN false; END IF;
    RETURN NOT EXISTS (
        WITH RECURSIVE rule_set AS (
            SELECT row_number() OVER (ORDER BY element.item_value ->> 'rule_id')::integer AS node_id,
                   element.item_value AS rule
            FROM jsonb_array_elements(rules) AS element(item_value)
        ), edges AS (
            SELECT source_rule.node_id AS source_id, target_rule.node_id AS target_id
            FROM rule_set source_rule
            CROSS JOIN rule_set target_rule
            WHERE CASE source_rule.rule ->> 'match_kind'
                WHEN 'exact' THEN
                    (target_rule.rule ->> 'match_kind' = 'exact' AND
                     target_rule.rule ->> 'match_path' = source_rule.rule ->> 'target_path') OR
                    (target_rule.rule ->> 'match_kind' = 'prefix' AND
                     (target_rule.rule ->> 'match_path' = '/' OR
                      left(source_rule.rule ->> 'target_path',
                           length(target_rule.rule ->> 'match_path')) = target_rule.rule ->> 'match_path'))
                ELSE
                    (target_rule.rule ->> 'match_kind' = 'exact' AND
                     (source_rule.rule ->> 'target_path' = '/' OR
                      left(target_rule.rule ->> 'match_path',
                           length(source_rule.rule ->> 'target_path')) = source_rule.rule ->> 'target_path')) OR
                    (target_rule.rule ->> 'match_kind' = 'prefix' AND
                     (source_rule.rule ->> 'target_path' = '/' OR
                      target_rule.rule ->> 'match_path' = '/' OR
                      left(source_rule.rule ->> 'target_path',
                           length(target_rule.rule ->> 'match_path')) = target_rule.rule ->> 'match_path' OR
                      left(target_rule.rule ->> 'match_path',
                           length(source_rule.rule ->> 'target_path')) = source_rule.rule ->> 'target_path'))
            END
        ), reach(source_id, target_id) AS (
            SELECT source_id, target_id FROM edges
            UNION
            SELECT reach.source_id, edges.target_id
            FROM reach JOIN edges ON edges.source_id = reach.target_id
        ), paths(start_id, current_id, depth) AS (
            SELECT source_id, target_id, 2 FROM edges
            UNION
            SELECT paths.start_id, edges.target_id, paths.depth + 1
            FROM paths JOIN edges ON edges.source_id = paths.current_id
            WHERE paths.depth <= 16
        )
        SELECT 1 FROM reach WHERE source_id = target_id
        UNION ALL
        SELECT 1 FROM paths WHERE depth > 16
    );
END;
$$;


CREATE OR REPLACE FUNCTION http_policy_redirects_valid_056(rules jsonb, allowed jsonb)
RETURNS boolean
LANGUAGE plpgsql
IMMUTABLE
AS $$
DECLARE rule jsonb;
DECLARE authority text;
DECLARE target text;
DECLARE target_path text;
DECLARE previous_priority numeric;
DECLARE previous_id text;
BEGIN
    IF rules IS NULL OR jsonb_typeof(rules) <> 'array' OR jsonb_array_length(rules) > 128 OR
       NOT http_policy_authorities_valid_056(allowed) THEN
        RETURN false;
    END IF;
    IF (SELECT count(*) FROM jsonb_array_elements(rules)) <>
       (SELECT count(DISTINCT element.item_value ->> 'rule_id')
        FROM jsonb_array_elements(rules) AS element(item_value)) THEN
        RETURN false;
    END IF;
    FOR rule IN SELECT element.item_value
                FROM jsonb_array_elements(rules) AS element(item_value) LOOP
        IF NOT http_policy_exact_keys_056(rule,
            ARRAY['rule_id','priority','match_kind','match_path','status','target_url','preserve_query']) OR
           NOT http_policy_identifier_valid_056(rule ->> 'rule_id') OR
           jsonb_typeof(rule -> 'priority') <> 'number' OR (rule ->> 'priority') !~ '^[0-9]{1,10}$' OR
           (rule ->> 'priority')::numeric > 4294967295 OR
           jsonb_typeof(rule -> 'status') <> 'number' OR (rule ->> 'status')::integer NOT IN (301,302,307,308) OR
           jsonb_typeof(rule -> 'preserve_query') <> 'boolean' OR
           NOT http_policy_path_valid_056(rule ->> 'match_kind', rule ->> 'match_path') THEN
            RETURN false;
        END IF;
        target := rule ->> 'target_url';
        authority := substring(target FROM '^https?://([^/]+)');
        target_path := substring(target FROM '^https?://[^/]+(/.*)$');
        IF target IS NULL OR octet_length(target) NOT BETWEEN 1 AND 4096 OR
           target !~ '^https?://[^/]+/' OR target !~ '^[ -~]+$' OR
           position(E'\\' in target) > 0 OR position('%' in target) > 0 OR
           position('?' in target) > 0 OR position('#' in target) > 0 OR authority IS NULL OR
           NOT http_policy_authority_valid_056(authority) OR
           NOT http_policy_path_valid_056('exact', target_path) OR
           NOT (allowed ? authority) AND NOT EXISTS (
               SELECT 1
               FROM jsonb_array_elements_text(allowed) AS element(allowed_value)
               WHERE element.allowed_value = authority
           ) OR
           (previous_priority IS NOT NULL AND
             ((rule ->> 'priority')::numeric < previous_priority OR
              ((rule ->> 'priority')::numeric = previous_priority AND rule ->> 'rule_id' <= previous_id))) THEN
            RETURN false;
        END IF;
        previous_priority := (rule ->> 'priority')::numeric;
        previous_id := rule ->> 'rule_id';
    END LOOP;
    RETURN true;
END;
$$;


CREATE OR REPLACE FUNCTION http_policy_rule_conflicts_valid_056(rewrites jsonb, redirects jsonb)
RETURNS boolean
LANGUAGE plpgsql
IMMUTABLE
AS $$
DECLARE combined jsonb;
DECLARE rule jsonb;
DECLARE other jsonb;
BEGIN
    IF rewrites IS NULL OR redirects IS NULL OR
       jsonb_typeof(rewrites) <> 'array' OR jsonb_typeof(redirects) <> 'array' THEN
        RETURN false;
    END IF;
    combined := rewrites || redirects;
    IF (SELECT count(*) FROM jsonb_array_elements(combined)) <>
       (SELECT count(DISTINCT element.item_value ->> 'rule_id')
        FROM jsonb_array_elements(combined) AS element(item_value)) THEN
        RETURN false;
    END IF;
    FOR rule IN SELECT element.item_value
                FROM jsonb_array_elements(combined) AS element(item_value) LOOP
        FOR other IN SELECT element.item_value
                     FROM jsonb_array_elements(combined) AS element(item_value) LOOP
            IF rule ->> 'rule_id' >= other ->> 'rule_id' OR
               rule ->> 'priority' <> other ->> 'priority' THEN
                CONTINUE;
            END IF;
            IF (rule ->> 'match_kind' = 'exact' AND other ->> 'match_kind' = 'exact' AND
                rule ->> 'match_path' = other ->> 'match_path') OR
               (rule ->> 'match_kind' = 'prefix' AND
                (rule ->> 'match_path' = '/' OR
                 left(other ->> 'match_path', length(rule ->> 'match_path')) = rule ->> 'match_path')) OR
               (other ->> 'match_kind' = 'prefix' AND
                (other ->> 'match_path' = '/' OR
                 left(rule ->> 'match_path', length(other ->> 'match_path')) = other ->> 'match_path')) THEN
                RETURN false;
            END IF;
        END LOOP;
    END LOOP;
    RETURN true;
END;
$$;


DROP FUNCTION http_policy_regex_target_valid_391(text);
DROP FUNCTION http_policy_regex_valid_391(text);

ALTER TABLE sites DROP COLUMN https_redirect_exclude_hosts, DROP COLUMN https_redirect_status;
DROP TABLE site_access_write_requests;
DROP TABLE site_access_settings;

CREATE OR REPLACE FUNCTION system_configuration_v2_default_other(candidate jsonb)
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


-- Back to the 054/360 checks: refused while a stored unknown_site rule or
-- theme page uses another status than 404.
ALTER TABLE theme_error_pages DROP CONSTRAINT theme_error_pages_status_391;
ALTER TABLE theme_error_pages ADD CHECK (
    (category = 'edge_connect' AND status_code IN (502, 503, 504)) OR
    (category = 'no_host' AND status_code = 400) OR
    (category = 'unknown_site' AND status_code = 404)
);
ALTER TABLE error_page_rule_revisions DROP CONSTRAINT error_page_rule_revisions_category_391;
ALTER TABLE error_page_rule_revisions ADD CHECK (
    (category IN ('origin_response', 'edge_route')) OR
    (category = 'edge_connect' AND code_from >= 502 AND code_to <= 504) OR
    (category = 'no_host' AND code_from = 400 AND code_to = 400) OR
    (category = 'unknown_site' AND code_from = 404 AND code_to = 404)
);
