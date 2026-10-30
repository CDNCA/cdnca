LOCK TABLE schema_migrations, http_policy_revisions IN ACCESS EXCLUSIVE MODE;

DO $migration_495_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 495 OR
       (SELECT max(version) FROM schema_migrations) <> 495 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=495 AND
        migration_id='495_http_policy_header_vars_conditions' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 495 down requires the exact verified migration head' USING ERRCODE='P4951';
    END IF;
    -- Revisions written under 495 may carry allow_duplicate, header value
    -- variables or rule conditions, which the 056/391 contract refuses.
    IF EXISTS (SELECT 1 FROM http_policy_revisions WHERE
               jsonb_path_exists(document, '$.request_headers[*].allow_duplicate') OR
               jsonb_path_exists(document, '$.response_headers[*].allow_duplicate') OR
               jsonb_path_exists(document, '$.rewrites[*].conditions') OR
               jsonb_path_exists(document, '$.redirects[*].conditions') OR
               position('$' in (document -> 'request_headers')::text) > 0 OR
               position('$' in (document -> 'response_headers')::text) > 0) THEN
        RAISE EXCEPTION 'HTTP policy revisions carry header variables, allow_duplicate or rule conditions; rollback of 495 is unsafe' USING ERRCODE='P4952';
    END IF;
END;
$migration_495_down$;

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
        IF NOT http_policy_exact_keys_056(action, ARRAY['kind','name','values']) THEN
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
               (value #>> '{}') !~ '^[ -~]+$' THEN
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
            IF rule ->> 'rule_id' >= other ->> 'rule_id' OR rule ->> 'priority' <> other ->> 'priority' THEN
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
        IF NOT http_policy_exact_keys_056(rule,
            ARRAY['rule_id','priority','match_kind','match_path','status','target_url','preserve_query','preserve_path']) OR
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
               rule ->> 'priority' <> other ->> 'priority' THEN
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


DROP FUNCTION http_policy_conditions_valid_495(jsonb);
DROP FUNCTION http_policy_header_value_variables_valid_495(text);
