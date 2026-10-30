-- 495（r136 tp-b3c-be，本地占位 490，merge-p3 合入改为 495、前驱 494）。
-- B3c 需后端 2/3（cdnfly 新增请求头/新增转向）：HTTP 策略文档
--   * 请求头/响应头动作可带 allow_duplicate（仅 add；省略=false：同名已存在不再添加）；
--     值可引用白名单变量 $name（httppolicycontrol.HeaderVariables），"$$" 是字面 "$"；
--   * rewrites / redirects 规则可带 conditions（高级条件，1..8 条全满足才生效），
--     带条件的规则不参与同优先级冲突判定（按 priority, rule_id 先匹配先生效）。
-- 文档 schema 仍是 cdnca.control.http-policy/v1；Go（httppolicycontrol.normalizeConfig）对正则做 RE2 与有界校验。
LOCK TABLE schema_migrations, http_policy_revisions IN ACCESS EXCLUSIVE MODE;

DO $migration_495_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 494 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 494 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=494 AND
        migration_id='494_site_origin_parity' AND
        checksum_sha256='7571f8ae527eaad466254f810a82b35c9479a5ccb167ec9d0278a80a64db7532' AND
        down_checksum_sha256='1026828343348849ec5d8fb4a2bc7e86cb8737a93d1aede302016790b93031b0' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR to_regprocedure('http_policy_conditions_valid_495(jsonb)') IS NOT NULL THEN
        RAISE EXCEPTION 'migration 495 requires the exact verified 494 release head' USING ERRCODE='P4950';
    END IF;
END;
$migration_495_up$;

-- Header value variables: "$" starts a whitelisted name (longest match) or
-- "$$"; any other "$" is refused.
CREATE FUNCTION http_policy_header_value_variables_valid_495(candidate text)
RETURNS boolean
LANGUAGE sql
IMMUTABLE
AS $$
    SELECT regexp_replace(regexp_replace(candidate, '\$\$', '', 'g'),
        '\$(remote_addr|host|scheme|request_uri|uri|args|request_method|server_port|http_user_agent|http_referer|tls_fp|country|province|city|isp|areacode)(?![a-z0-9_])',
        '', 'g') NOT LIKE '%$%'
$$;

-- 高级条件: 1..8 objects {source, pattern[, name]}; header needs a lower
-- case name, the others none; the pattern is 1..256 printable bytes.
CREATE FUNCTION http_policy_conditions_valid_495(conditions jsonb)
RETURNS boolean
LANGUAGE plpgsql
IMMUTABLE
AS $$
DECLARE condition jsonb;
BEGIN
    IF conditions IS NULL OR jsonb_typeof(conditions) <> 'array' OR
       jsonb_array_length(conditions) NOT BETWEEN 1 AND 8 THEN
        RETURN false;
    END IF;
    FOR condition IN SELECT element.item_value FROM jsonb_array_elements(conditions) AS element(item_value) LOOP
        IF NOT (http_policy_exact_keys_056(condition, ARRAY['source','pattern']) AND
                condition ->> 'source' IN ('host','user_agent','referer','country','accept_language',
                                            'province','city','isp','asn') OR
                http_policy_exact_keys_056(condition, ARRAY['source','name','pattern']) AND
                condition ->> 'source' = 'header' AND jsonb_typeof(condition -> 'name') = 'string' AND
                (condition ->> 'name') ~ '^[a-z0-9][a-z0-9-]{0,63}$') OR
           jsonb_typeof(condition -> 'pattern') <> 'string' OR
           octet_length(condition ->> 'pattern') NOT BETWEEN 1 AND 256 OR
           (condition ->> 'pattern') !~ '^[ -~]+$' THEN
            RETURN false;
        END IF;
    END LOOP;
    RETURN true;
END;
$$;

CREATE OR REPLACE FUNCTION http_policy_header_actions_valid_056(actions jsonb, request_side boolean)
RETURNS boolean
LANGUAGE plpgsql
IMMUTABLE
AS $$
DECLARE action jsonb;
DECLARE value jsonb;
DECLARE kind text;
DECLARE name text;
DECLARE previous_name text;
BEGIN
    IF actions IS NULL OR jsonb_typeof(actions) <> 'array' OR jsonb_array_length(actions) > 64 THEN
        RETURN false;
    END IF;
    FOR action IN SELECT element.item_value
                  FROM jsonb_array_elements(actions) AS element(item_value) LOOP
        IF NOT (http_policy_exact_keys_056(action, ARRAY['kind','name','values']) OR
                http_policy_exact_keys_056(action, ARRAY['kind','name','values','allow_duplicate']) AND
                jsonb_typeof(action -> 'allow_duplicate') = 'boolean' AND action ->> 'kind' = 'add') THEN
            RETURN false;
        END IF;
        kind := action ->> 'kind';
        name := action ->> 'name';
        IF kind NOT IN ('add','set','delete') OR name IS NULL OR name <> lower(name) OR
           NOT http_policy_token_valid_056(name) OR octet_length(name) > 128 OR
           name IN ('connection','content-length','host','keep-alive','proxy-authenticate',
                    'proxy-authorization','proxy-connection','te','trailer','transfer-encoding','upgrade') OR
           name LIKE 'x-cdnca-%' OR
           (request_side AND (name IN ('cookie','forwarded','origin','x-forwarded-for',
                    'x-forwarded-host','x-forwarded-proto','x-real-ip',
                    'access-control-request-headers','access-control-request-method') OR
                    name LIKE 'access-control-%')) OR
           (NOT request_side AND (name IN ('location','refresh','vary') OR name LIKE 'access-control-%')) OR
           (previous_name IS NOT NULL AND name <= previous_name) OR
           jsonb_typeof(action -> 'values') <> 'array' THEN
            RETURN false;
        END IF;
        IF (kind = 'delete' AND jsonb_array_length(action -> 'values') <> 0) OR
           (kind IN ('add','set') AND jsonb_array_length(action -> 'values') NOT BETWEEN 1 AND 16) THEN
            RETURN false;
        END IF;
        FOR value IN SELECT element.item_value
                     FROM jsonb_array_elements(action -> 'values') AS element(item_value) LOOP
            IF jsonb_typeof(value) <> 'string' OR octet_length(value #>> '{}') NOT BETWEEN 1 AND 1024 OR
               (value #>> '{}') !~ '^[ -~]+$' OR NOT http_policy_header_value_variables_valid_495(value #>> '{}') THEN
                RETURN false;
            END IF;
        END LOOP;
        previous_name := name;
    END LOOP;
    RETURN true;
END;
$$;


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
        IF NOT (http_policy_exact_keys_056(rule,
                ARRAY['rule_id','priority','match_kind','match_path','target_path','preserve_query','preserve_cookie']) OR
                http_policy_exact_keys_056(rule,
                ARRAY['rule_id','priority','match_kind','match_path','target_path','preserve_query','preserve_cookie','conditions']) AND
                http_policy_conditions_valid_495(rule -> 'conditions')) OR
           NOT http_policy_identifier_valid_056(rule ->> 'rule_id') OR
           jsonb_typeof(rule -> 'priority') <> 'number' OR (rule ->> 'priority') !~ '^[0-9]{1,10}$' OR
           (rule ->> 'priority')::numeric > 4294967295 OR
           jsonb_typeof(rule -> 'preserve_query') <> 'boolean' OR
           jsonb_typeof(rule -> 'preserve_cookie') <> 'boolean' THEN
            RETURN false;
        END IF;
        rule_kind := rule ->> 'match_kind';
        rule_path := rule ->> 'match_path';
        IF (rule_kind = 'regex' AND (NOT http_policy_regex_valid_391(rule_path) OR
                NOT http_policy_regex_target_valid_391(rule ->> 'target_path'))) OR
           (rule_kind <> 'regex' AND (NOT http_policy_path_valid_056(rule_kind, rule_path) OR
                NOT http_policy_path_valid_056(rule_kind, rule ->> 'target_path') OR
                rule_path = rule ->> 'target_path')) OR
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
            IF rule ->> 'rule_id' >= other ->> 'rule_id' OR rule ->> 'priority' <> other ->> 'priority' OR
               rule ? 'conditions' OR other ? 'conditions' THEN
                CONTINUE;
            END IF;
            IF rule ->> 'match_kind' = 'regex' OR other ->> 'match_kind' = 'regex' OR
               (rule ->> 'match_kind' = 'exact' AND other ->> 'match_kind' = 'exact' AND
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
        IF NOT (http_policy_exact_keys_056(rule,
                ARRAY['rule_id','priority','match_kind','match_path','status','target_url','preserve_query','preserve_path']) OR
                http_policy_exact_keys_056(rule,
                ARRAY['rule_id','priority','match_kind','match_path','status','target_url','preserve_query','preserve_path','conditions']) AND
                http_policy_conditions_valid_495(rule -> 'conditions')) OR
           NOT http_policy_identifier_valid_056(rule ->> 'rule_id') OR
           jsonb_typeof(rule -> 'priority') <> 'number' OR (rule ->> 'priority') !~ '^[0-9]{1,10}$' OR
           (rule ->> 'priority')::numeric > 4294967295 OR
           jsonb_typeof(rule -> 'status') <> 'number' OR (rule ->> 'status')::integer NOT IN (301,302,307,308) OR
           jsonb_typeof(rule -> 'preserve_query') <> 'boolean' OR
           jsonb_typeof(rule -> 'preserve_path') <> 'boolean' OR
           (rule ->> 'match_kind' = 'regex' AND NOT http_policy_regex_valid_391(rule ->> 'match_path')) OR
           (rule ->> 'match_kind' <> 'regex' AND
            NOT http_policy_path_valid_056(rule ->> 'match_kind', rule ->> 'match_path')) OR
           ((rule ->> 'preserve_path')::boolean AND rule ->> 'match_kind' <> 'prefix') THEN
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
           (rule ->> 'match_kind' = 'regex' AND NOT http_policy_regex_target_valid_391(target_path)) OR
           (rule ->> 'match_kind' <> 'regex' AND (rule ->> 'preserve_path')::boolean AND
            NOT http_policy_path_valid_056('prefix', target_path)) OR
           (rule ->> 'match_kind' <> 'regex' AND NOT (rule ->> 'preserve_path')::boolean AND
            NOT http_policy_path_valid_056('exact', target_path)) OR
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
               rule ->> 'priority' <> other ->> 'priority' OR
               rule ? 'conditions' OR other ? 'conditions' THEN
                CONTINUE;
            END IF;
            IF rule ->> 'match_kind' = 'regex' OR other ->> 'match_kind' = 'regex' OR
               (rule ->> 'match_kind' = 'exact' AND other ->> 'match_kind' = 'exact' AND
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

