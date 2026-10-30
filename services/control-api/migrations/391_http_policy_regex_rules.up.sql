LOCK TABLE schema_migrations, http_policy_revisions, sites, system_configuration_revisions,
    error_page_rule_revisions, theme_error_pages IN ACCESS EXCLUSIVE MODE;

DO $migration_391_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 390 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 390 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=390 AND
        migration_id='390_site_schedule302' AND
        checksum_sha256='f805e5191361bd348ad96744b0df05ad42c329d6c1b9f64c0db5c31b46a66ac8' AND
        down_checksum_sha256='74363990e8e80de3c076aa9a20c057a7143bf0143a5e3673ba173351e4fae76b' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR to_regprocedure('http_policy_regex_valid_391(text)') IS NOT NULL OR
       to_regclass(current_schema() || '.site_access_settings') IS NOT NULL THEN
        RAISE EXCEPTION 'migration 391 requires the exact verified 390 release head' USING ERRCODE='P3910';
    END IF;
END;
$migration_391_up$;

-- r136 ge-access (placeholder number; renumbered on merge), GoEdge 对照 G4:
-- HTTP policy rewrites and redirects match by regex (match_kind 'regex', an
-- anchored "^/" pattern; the target names its capture groups $1..$9), and a
-- prefix redirect may keep the path after its prefix (preserve_path, the
-- target then a directory). Go (httppolicycontrol.normalizeConfig) is the
-- authority on RE2 syntax and group counts; these checks bound the stored
-- document. A regex rule overlaps every rule of its priority; chains through
-- regex rules are bounded by the edge engine (MaxRewriteHops, 508).

CREATE FUNCTION http_policy_regex_valid_391(pattern text)
RETURNS boolean
LANGUAGE sql
IMMUTABLE
AS $$
    SELECT pattern IS NOT NULL AND octet_length(pattern) BETWEEN 2 AND 512 AND
           left(pattern, 2) = '^/' AND pattern ~ '^[ -~]+$'
$$;

-- A regex rule's target path: the path rules of http_policy_path_valid_056
-- (exact) with "$" only as $1..$9.
CREATE FUNCTION http_policy_regex_target_valid_391(candidate text)
RETURNS boolean
LANGUAGE sql
IMMUTABLE
AS $$
    SELECT candidate IS NOT NULL AND octet_length(candidate) BETWEEN 1 AND 2048 AND
           left(candidate, 1) = '/' AND candidate ~ '^[ -~]+$' AND candidate NOT LIKE '%//%' AND
           position(E'\\' in candidate) = 0 AND position('%' in candidate) = 0 AND
           position('?' in candidate) = 0 AND position('#' in candidate) = 0 AND
           candidate NOT LIKE '%/./%' AND candidate NOT LIKE '%/../%' AND
           candidate NOT LIKE '%/.' AND candidate NOT LIKE '%/..' AND
           regexp_replace(candidate, '\$[1-9]', '', 'g') NOT LIKE '%$%'
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
            WHERE source_rule.rule ->> 'match_kind' <> 'regex' AND
                  target_rule.rule ->> 'match_kind' <> 'regex' AND
                  CASE source_rule.rule ->> 'match_kind'
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



-- A site's request handling (r136 ge-access, GoEdge 对照 G4; the published
-- form is edgeconfig.SiteAccess): host redirects, HSTS, compression,
-- per-client limits, basic auth and a maintenance page, stored as the
-- canonical document the site's v2 release carries. Basic auth users carry
-- SHA-256(site_id:username:password) only. A site without a row publishes
-- none of them. A write advances sites.revision (GET ETag / PUT If-Match),
-- which publishes the site as every site setting does.
CREATE TABLE site_access_settings (
    scope_id uuid NOT NULL,
    site_id uuid PRIMARY KEY,
    settings jsonb NOT NULL CHECK (jsonb_typeof(settings) = 'object' AND settings <> '{}'::jsonb
        AND octet_length(settings::text) <= 262144),
    updated_by_user_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    updated_at timestamptz NOT NULL,
    FOREIGN KEY (scope_id, site_id) REFERENCES sites(scope_id, id) ON DELETE CASCADE
);

CREATE INDEX site_access_settings_scope_idx ON site_access_settings (scope_id);

CREATE TABLE site_access_write_requests (
    id uuid PRIMARY KEY,
    actor_scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE RESTRICT,
    actor_user_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    target_scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE RESTRICT,
    site_id uuid NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
    idempotency_key text NOT NULL CHECK (char_length(idempotency_key) BETWEEN 1 AND 128),
    request_digest bytea NOT NULL CHECK (octet_length(request_digest) = 32),
    response_body jsonb NOT NULL CHECK (jsonb_typeof(response_body) = 'object'),
    created_at timestamptz NOT NULL,
    UNIQUE (actor_scope_id, actor_user_id, idempotency_key)
);

CREATE INDEX site_access_write_requests_scope_created_idx
    ON site_access_write_requests (target_scope_id, created_at DESC);

-- Forced HTTPS (FX07, 326) gains its status and the domains it leaves on
-- plain HTTP (GoEdge 对照 G4 缺失 9). The domains are checked against the
-- site's current domains when written (sitecontrol) and when published.
ALTER TABLE sites
    ADD COLUMN https_redirect_status integer NOT NULL DEFAULT 301
        CONSTRAINT sites_https_redirect_status_391 CHECK (https_redirect_status IN (301, 302, 307, 308)),
    ADD COLUMN https_redirect_exclude_hosts text[] NOT NULL DEFAULT ARRAY[]::text[]
        CONSTRAINT sites_https_redirect_exclude_hosts_391 CHECK (cardinality(https_redirect_exclude_hosts) <= 100);

-- System settings > website defaults > other (r136 ge-access): the
-- switches no runtime reads are removed (crawler_policy: CC rules carry
-- crawler handling; block_transparent_proxy, realtime_response_enabled,
-- realtime_send_enabled: nothing behind them). gzip_enabled/gzip_types now
-- reach the edge and load_balancing new sites. 1.0.35 is the initial
-- release: no stored revision is rewritten.
CREATE OR REPLACE FUNCTION system_configuration_v2_default_other(candidate jsonb)
RETURNS boolean
LANGUAGE sql
IMMUTABLE
AS $$
    SELECT system_configuration_v2_json_keys_exact(candidate, ARRAY[
               'gzip_types','gzip_enabled','load_balancing','websocket_enabled'
           ])
       AND candidate->>'load_balancing' IN ('round_robin','ip_hash','url_hash','least_conn','random')
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
       AND jsonb_typeof(candidate->'websocket_enabled') = 'boolean';
$$;


-- Domain mismatch page (GoEdge 对照 G4): the global unknown_site page may
-- answer 403, 404, 410 or 421 (default servers render it; before, they
-- always answered a bare 421). The 054 table check is found by its
-- definition (it is unnamed there).
DO $migration_391_unknown_site$
DECLARE check_name name;
BEGIN
    SELECT conname INTO check_name FROM pg_constraint
    WHERE conrelid = 'error_page_rule_revisions'::regclass AND contype = 'c'
      AND pg_get_constraintdef(oid) LIKE '%unknown_site%code_from = 404%';
    IF check_name IS NULL THEN
        RAISE EXCEPTION 'migration 391: the 054 error page category check is missing' USING ERRCODE='P3910';
    END IF;
    EXECUTE format('ALTER TABLE error_page_rule_revisions DROP CONSTRAINT %I', check_name);
    SELECT conname INTO check_name FROM pg_constraint
    WHERE conrelid = 'theme_error_pages'::regclass AND contype = 'c'
      AND pg_get_constraintdef(oid) LIKE '%unknown_site%status_code = 404%';
    IF check_name IS NULL THEN
        RAISE EXCEPTION 'migration 391: the 360 theme error page check is missing' USING ERRCODE='P3910';
    END IF;
    EXECUTE format('ALTER TABLE theme_error_pages DROP CONSTRAINT %I', check_name);
END;
$migration_391_unknown_site$;

ALTER TABLE error_page_rule_revisions ADD CONSTRAINT error_page_rule_revisions_category_391 CHECK (
    (category IN ('origin_response', 'edge_route')) OR
    (category = 'edge_connect' AND code_from >= 502 AND code_to <= 504) OR
    (category = 'no_host' AND code_from = 400 AND code_to = 400) OR
    (category = 'unknown_site' AND code_from = code_to AND code_from IN (403, 404, 410, 421))
);
ALTER TABLE theme_error_pages ADD CONSTRAINT theme_error_pages_status_391 CHECK (
    (category = 'edge_connect' AND status_code IN (502, 503, 504)) OR
    (category = 'no_host' AND status_code = 400) OR
    (category = 'unknown_site' AND status_code IN (403, 404, 410, 421))
);
