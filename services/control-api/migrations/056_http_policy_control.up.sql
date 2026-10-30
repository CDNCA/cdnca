INSERT INTO permissions (name, description) VALUES
    ('http_policies.read', 'Read tenant site HTTP policies and publication previews'),
    ('http_policies.manage', 'Create, edit, enable, disable, and retire tenant site HTTP policies');

INSERT INTO custom_rbac_permission_catalog (permission_name, step_up_required) VALUES
    ('http_policies.read', false),
    ('http_policies.manage', false);

INSERT INTO role_permissions (role_id, permission_name)
SELECT role.id, permission.name
FROM roles role
CROSS JOIN (VALUES ('http_policies.read'), ('http_policies.manage')) AS permission(name)
WHERE role.system_role AND role.name IN ('platform_owner', 'tenant_owner')
ON CONFLICT DO NOTHING;

INSERT INTO role_permissions (role_id, permission_name)
SELECT role.id, 'http_policies.read'
FROM roles role
WHERE role.system_role AND role.name = 'tenant_viewer'
ON CONFLICT DO NOTHING;

CREATE FUNCTION grant_http_policy_permissions_056()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NOT NEW.system_role THEN
        RETURN NEW;
    END IF;
    IF NEW.name IN ('platform_owner', 'tenant_owner') THEN
        INSERT INTO role_permissions (role_id, permission_name) VALUES
            (NEW.id, 'http_policies.read'),
            (NEW.id, 'http_policies.manage')
        ON CONFLICT DO NOTHING;
    ELSIF NEW.name = 'tenant_viewer' THEN
        INSERT INTO role_permissions (role_id, permission_name)
        VALUES (NEW.id, 'http_policies.read')
        ON CONFLICT DO NOTHING;
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER roles_http_policy_permissions_056
AFTER INSERT ON roles
FOR EACH ROW EXECUTE FUNCTION grant_http_policy_permissions_056();

CREATE TABLE http_policies (
    id uuid PRIMARY KEY,
    tenant_scope_id uuid NOT NULL,
    tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    site_id uuid NOT NULL REFERENCES sites(id) ON DELETE RESTRICT,
    site_owner_user_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    current_revision bigint NOT NULL CHECK (current_revision > 0),
    current_enabled boolean NOT NULL,
    current_deleted boolean NOT NULL DEFAULT false,
    current_document jsonb NOT NULL CHECK (jsonb_typeof(current_document) = 'object'),
    created_by_user_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    deleted_at timestamptz,
    FOREIGN KEY (tenant_scope_id, tenant_id)
        REFERENCES access_scopes(id, tenant_id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_scope_id, site_owner_user_id)
        REFERENCES memberships(scope_id, user_id) ON DELETE RESTRICT,
    UNIQUE (tenant_scope_id, id),
    CHECK (updated_at >= created_at),
    CHECK (current_deleted = (deleted_at IS NOT NULL)),
    CHECK (NOT current_deleted OR NOT current_enabled)
);

CREATE UNIQUE INDEX http_policies_live_site_056
    ON http_policies (tenant_scope_id, site_id)
    WHERE deleted_at IS NULL;
CREATE INDEX http_policies_tenant_page_056
    ON http_policies (tenant_scope_id, created_at DESC, id DESC)
    WHERE deleted_at IS NULL;
CREATE INDEX http_policies_owner_page_056
    ON http_policies (tenant_scope_id, site_owner_user_id, created_at DESC, id DESC)
    WHERE deleted_at IS NULL;

CREATE TABLE http_policy_revisions (
    policy_id uuid NOT NULL,
    tenant_scope_id uuid NOT NULL,
    tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    site_id uuid NOT NULL REFERENCES sites(id) ON DELETE RESTRICT,
    site_owner_user_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    revision bigint NOT NULL CHECK (revision > 0),
    action text NOT NULL CHECK (action IN ('create', 'update', 'enable', 'disable', 'delete')),
    enabled boolean NOT NULL,
    deleted boolean NOT NULL DEFAULT false,
    document jsonb NOT NULL CHECK (jsonb_typeof(document) = 'object'),
    created_by_scope_id uuid NOT NULL,
    created_by_user_id uuid NOT NULL,
    request_id text NOT NULL CHECK (
        octet_length(request_id) BETWEEN 1 AND 128 AND
        request_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]*$'
    ),
    trace_id text NOT NULL CHECK (
        octet_length(trace_id) BETWEEN 1 AND 128 AND
        trace_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]*$'
    ),
    created_at timestamptz NOT NULL,
    PRIMARY KEY (policy_id, revision),
    FOREIGN KEY (tenant_scope_id, tenant_id)
        REFERENCES access_scopes(id, tenant_id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_scope_id, site_owner_user_id)
        REFERENCES memberships(scope_id, user_id) ON DELETE RESTRICT,
    FOREIGN KEY (created_by_scope_id, created_by_user_id)
        REFERENCES memberships(scope_id, user_id) ON DELETE RESTRICT,
    CHECK (NOT deleted OR NOT enabled)
);

CREATE INDEX http_policy_revisions_tenant_056
    ON http_policy_revisions (tenant_scope_id, policy_id, revision DESC);
CREATE INDEX http_policy_revisions_request_056
    ON http_policy_revisions (tenant_scope_id, request_id);

CREATE TABLE http_policy_publication_heads (
    tenant_scope_id uuid PRIMARY KEY REFERENCES access_scopes(id) ON DELETE RESTRICT,
    revision bigint NOT NULL CHECK (revision BETWEEN 1 AND 9007199254740991),
    updated_at timestamptz NOT NULL
);

CREATE TABLE http_policy_write_requests (
    id uuid PRIMARY KEY,
    actor_scope_id uuid NOT NULL,
    actor_user_id uuid NOT NULL,
    target_scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE RESTRICT,
    operation text NOT NULL CHECK (operation IN (
        'http_policy.create', 'http_policy.update', 'http_policy.enable',
        'http_policy.disable', 'http_policy.delete'
    )),
    idempotency_key text NOT NULL CHECK (
        octet_length(idempotency_key) BETWEEN 1 AND 128 AND
        idempotency_key ~ '^[A-Za-z0-9][A-Za-z0-9._:-]*$'
    ),
    request_digest bytea NOT NULL CHECK (octet_length(request_digest) = 32),
    request_id text NOT NULL CHECK (
        octet_length(request_id) BETWEEN 1 AND 128 AND
        request_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]*$'
    ),
    trace_id text NOT NULL CHECK (
        octet_length(trace_id) BETWEEN 1 AND 128 AND
        trace_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]*$'
    ),
    outcome text CHECK (outcome IN ('success', 'entitlement_denied', 'entitlement_unavailable')),
    resource_id uuid,
    response_status integer CHECK (response_status BETWEEN 200 AND 599),
    response_body jsonb CHECK (response_body IS NULL OR jsonb_typeof(response_body) = 'object'),
    created_at timestamptz NOT NULL,
    completed_at timestamptz,
    FOREIGN KEY (actor_scope_id, actor_user_id)
        REFERENCES memberships(scope_id, user_id) ON DELETE RESTRICT,
    UNIQUE (actor_scope_id, actor_user_id, operation, idempotency_key),
    CHECK (
        (completed_at IS NULL AND outcome IS NULL AND resource_id IS NULL AND
         response_status IS NULL AND response_body IS NULL) OR
        (completed_at IS NOT NULL AND outcome IS NOT NULL AND response_status IS NOT NULL AND
         response_body IS NOT NULL AND completed_at >= created_at AND
         ((outcome = 'success' AND resource_id IS NOT NULL AND response_status BETWEEN 200 AND 299) OR
          (outcome <> 'success' AND response_status IN (403, 503))))
    )
);

CREATE INDEX http_policy_write_requests_target_056
    ON http_policy_write_requests (target_scope_id, created_at DESC);

CREATE FUNCTION http_policy_exact_keys_056(candidate jsonb, expected text[])
RETURNS boolean
LANGUAGE sql
IMMUTABLE
AS $$
    SELECT candidate IS NOT NULL AND jsonb_typeof(candidate) = 'object' AND
           COALESCE((SELECT array_agg(key ORDER BY key) FROM jsonb_object_keys(candidate) key), ARRAY[]::text[])
           = (SELECT array_agg(key ORDER BY key) FROM unnest(expected) key)
$$;

CREATE FUNCTION http_policy_identifier_valid_056(candidate text)
RETURNS boolean
LANGUAGE sql
IMMUTABLE
AS $$
    SELECT candidate IS NOT NULL AND octet_length(candidate) BETWEEN 1 AND 128 AND
           candidate ~ '^[A-Za-z0-9._:-]+$'
$$;

CREATE FUNCTION http_policy_token_valid_056(candidate text)
RETURNS boolean
LANGUAGE sql
IMMUTABLE
AS $$
    SELECT candidate IS NOT NULL AND octet_length(candidate) BETWEEN 1 AND 128 AND
           candidate ~ '^[A-Za-z0-9!#$%&''*+.^_`|~-]+$'
$$;

CREATE FUNCTION http_policy_path_valid_056(kind text, candidate text)
RETURNS boolean
LANGUAGE sql
IMMUTABLE
AS $$
    SELECT kind IN ('exact', 'prefix') AND candidate IS NOT NULL AND
           octet_length(candidate) BETWEEN 1 AND 2048 AND left(candidate, 1) = '/' AND
           candidate ~ '^[ -~]+$' AND candidate NOT LIKE '%//%' AND
           position(E'\\' in candidate) = 0 AND position('%' in candidate) = 0 AND
           position('?' in candidate) = 0 AND position('#' in candidate) = 0 AND
           candidate NOT LIKE '%/./%' AND candidate NOT LIKE '%/../%' AND
           candidate NOT LIKE '%/.' AND candidate NOT LIKE '%/..' AND
           (candidate = '/' OR
            (kind = 'exact' AND right(candidate, 1) <> '/') OR
            (kind = 'prefix' AND right(candidate, 1) = '/'))
$$;

CREATE FUNCTION http_policy_hostname_valid_056(candidate text)
RETURNS boolean
LANGUAGE plpgsql
IMMUTABLE
AS $$
DECLARE label text;
BEGIN
    IF candidate IS NULL OR candidate <> lower(candidate) OR
       octet_length(candidate) NOT BETWEEN 1 AND 253 OR right(candidate, 1) = '.' THEN
        RETURN false;
    END IF;
    FOREACH label IN ARRAY string_to_array(candidate, '.') LOOP
        IF octet_length(label) NOT BETWEEN 1 AND 63 OR
           label !~ '^[a-z0-9]([a-z0-9-]*[a-z0-9])?$' THEN
            RETURN false;
        END IF;
    END LOOP;
    RETURN true;
END;
$$;

CREATE FUNCTION http_policy_authority_valid_056(authority text)
RETURNS boolean
LANGUAGE plpgsql
IMMUTABLE
AS $$
DECLARE matched text[];
DECLARE host_part text;
DECLARE port_part text;
DECLARE address inet;
BEGIN
    IF authority IS NULL OR authority <> lower(authority) OR
       octet_length(authority) NOT BETWEEN 1 AND 512 OR
       authority ~ '[[:space:]/\\?#@]' THEN
        RETURN false;
    END IF;
    IF left(authority, 1) = '[' THEN
        matched := regexp_match(authority, '^\[([0-9a-f:.]+)\](:([0-9]+))?$');
        IF matched IS NULL THEN RETURN false; END IF;
        host_part := matched[1];
        port_part := matched[3];
        address := host_part::inet;
        IF family(address) <> 6 OR masklen(address) <> 128 OR
           host(address) <> host_part OR host_part LIKE '::ffff:%' THEN
            RETURN false;
        END IF;
    ELSE
        matched := regexp_match(authority, '^([^:]+)(:([0-9]+))?$');
        IF matched IS NULL THEN RETURN false; END IF;
        host_part := matched[1];
        port_part := matched[3];
        IF host_part ~ '^[0-9]{1,3}(\.[0-9]{1,3}){3}$' THEN
            address := host_part::inet;
            IF family(address) <> 4 OR masklen(address) <> 32 OR host(address) <> host_part THEN
                RETURN false;
            END IF;
        ELSIF NOT http_policy_hostname_valid_056(host_part) THEN
            RETURN false;
        END IF;
    END IF;
    IF port_part IS NOT NULL AND (
        port_part !~ '^[1-9][0-9]{0,4}$' OR port_part::integer > 65535
    ) THEN
        RETURN false;
    END IF;
    RETURN true;
EXCEPTION WHEN invalid_text_representation OR numeric_value_out_of_range THEN
    RETURN false;
END;
$$;

CREATE FUNCTION http_policy_string_array_valid_056(
    candidate jsonb,
    max_items integer,
    require_nonempty boolean,
    allow_wildcard boolean
)
RETURNS boolean
LANGUAGE plpgsql
IMMUTABLE
AS $$
DECLARE item jsonb;
DECLARE value text;
DECLARE count_items integer;
BEGIN
    IF candidate IS NULL OR jsonb_typeof(candidate) <> 'array' THEN
        RETURN false;
    END IF;
    count_items := jsonb_array_length(candidate);
    IF count_items > max_items OR (require_nonempty AND count_items = 0) THEN
        RETURN false;
    END IF;
    IF (SELECT count(*) FROM jsonb_array_elements(candidate)) <>
       (SELECT count(DISTINCT element.item_value #>> '{}')
        FROM jsonb_array_elements(candidate) AS element(item_value)) THEN
        RETURN false;
    END IF;
    FOR item IN SELECT element.item_value
                FROM jsonb_array_elements(candidate) AS element(item_value) LOOP
        IF jsonb_typeof(item) <> 'string' THEN
            RETURN false;
        END IF;
        value := item #>> '{}';
        IF value = '*' AND allow_wildcard THEN
            IF count_items <> 1 THEN RETURN false; END IF;
        ELSIF NOT http_policy_token_valid_056(value) THEN
            RETURN false;
        END IF;
    END LOOP;
    RETURN true;
END;
$$;

CREATE FUNCTION http_policy_header_actions_valid_056(actions jsonb, request_side boolean)
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

CREATE FUNCTION http_policy_rewrites_valid_056(rules jsonb)
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

CREATE FUNCTION http_policy_rewrite_chain_valid_056(rules jsonb)
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

CREATE FUNCTION http_policy_authorities_valid_056(authorities jsonb)
RETURNS boolean
LANGUAGE plpgsql
IMMUTABLE
AS $$
DECLARE item jsonb;
DECLARE value text;
DECLARE previous text;
BEGIN
    IF authorities IS NULL OR jsonb_typeof(authorities) <> 'array' OR jsonb_array_length(authorities) > 64 THEN
        RETURN false;
    END IF;
    FOR item IN SELECT element.item_value
                FROM jsonb_array_elements(authorities) AS element(item_value) LOOP
        IF jsonb_typeof(item) <> 'string' THEN RETURN false; END IF;
        value := item #>> '{}';
        IF NOT http_policy_authority_valid_056(value) OR
           (previous IS NOT NULL AND value <= previous) THEN
            RETURN false;
        END IF;
        previous := value;
    END LOOP;
    RETURN true;
END;
$$;

CREATE FUNCTION http_policy_redirects_valid_056(rules jsonb, allowed jsonb)
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

CREATE FUNCTION http_policy_rule_conflicts_valid_056(rewrites jsonb, redirects jsonb)
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

CREATE FUNCTION http_policy_cors_valid_056(cors jsonb)
RETURNS boolean
LANGUAGE plpgsql
IMMUTABLE
AS $$
DECLARE origin text;
DECLARE token text;
DECLARE previous text;
DECLARE authority text;
BEGIN
    IF cors IS NULL OR jsonb_typeof(cors) = 'null' THEN RETURN true; END IF;
    IF NOT http_policy_exact_keys_056(cors,
        ARRAY['allowed_origins','allowed_methods','allowed_headers','exposed_headers','allow_credentials','max_age_seconds']) OR
       NOT http_policy_string_array_valid_056(cors -> 'allowed_methods', 64, true, false) OR
       NOT http_policy_string_array_valid_056(cors -> 'allowed_headers', 64, false, true) OR
       NOT http_policy_string_array_valid_056(cors -> 'exposed_headers', 64, false, true) OR
       jsonb_typeof(cors -> 'allowed_origins') <> 'array' OR
       jsonb_array_length(cors -> 'allowed_origins') NOT BETWEEN 1 AND 64 OR
       jsonb_typeof(cors -> 'allow_credentials') <> 'boolean' OR
       jsonb_typeof(cors -> 'max_age_seconds') <> 'number' OR
       (cors ->> 'max_age_seconds') !~ '^[0-9]{1,5}$' OR (cors ->> 'max_age_seconds')::integer > 86400 THEN
        RETURN false;
    END IF;
    previous := NULL;
    FOR token IN SELECT element.item_value
                 FROM jsonb_array_elements_text(cors -> 'allowed_methods') AS element(item_value) LOOP
        IF token <> upper(token) OR (previous IS NOT NULL AND token <= previous) THEN RETURN false; END IF;
        previous := token;
    END LOOP;
    previous := NULL;
    FOR token IN SELECT element.item_value
                 FROM jsonb_array_elements_text(cors -> 'allowed_headers') AS element(item_value) LOOP
        IF token <> lower(token) OR (previous IS NOT NULL AND token <= previous) THEN RETURN false; END IF;
        previous := token;
    END LOOP;
    previous := NULL;
    FOR token IN SELECT element.item_value
                 FROM jsonb_array_elements_text(cors -> 'exposed_headers') AS element(item_value) LOOP
        IF token <> lower(token) OR (previous IS NOT NULL AND token <= previous) THEN RETURN false; END IF;
        previous := token;
    END LOOP;
    IF (SELECT count(*) FROM jsonb_array_elements_text(cors -> 'allowed_origins')) <>
       (SELECT count(DISTINCT element.item_value)
        FROM jsonb_array_elements_text(cors -> 'allowed_origins') AS element(item_value)) THEN
        RETURN false;
    END IF;
    previous := NULL;
    FOR origin IN SELECT element.item_value
                  FROM jsonb_array_elements_text(cors -> 'allowed_origins') AS element(item_value) LOOP
        IF origin <> lower(origin) OR (previous IS NOT NULL AND origin <= previous) THEN RETURN false; END IF;
        IF origin = '*' THEN
            IF jsonb_array_length(cors -> 'allowed_origins') <> 1 THEN RETURN false; END IF;
        ELSE
            authority := substring(origin FROM '^https?://(.+)$');
            IF authority IS NULL OR NOT http_policy_authority_valid_056(authority) THEN
                RETURN false;
            END IF;
        END IF;
        previous := origin;
    END LOOP;
    IF (cors ->> 'allow_credentials')::boolean AND (
        cors -> 'allowed_origins' @> '["*"]'::jsonb OR
        cors -> 'allowed_headers' @> '["*"]'::jsonb OR
        cors -> 'exposed_headers' @> '["*"]'::jsonb
    ) THEN
        RETURN false;
    END IF;
    RETURN true;
END;
$$;

CREATE FUNCTION http_policy_document_valid_056(document jsonb)
RETURNS boolean
LANGUAGE plpgsql
IMMUTABLE
AS $$
BEGIN
    RETURN http_policy_exact_keys_056(document, ARRAY[
        'schema_version','policy_id','tenant_scope_id','site_id','site_owner_user_id','revision',
        'max_upload_bytes','request_headers','response_headers','rewrites',
        'redirect_allowed_hosts','redirects','cors','enabled','deleted'
    ]) AND document ->> 'schema_version' = 'cdnca.control.http-policy/v1' AND
        (document ->> 'policy_id')::uuid IS NOT NULL AND
        (document ->> 'tenant_scope_id')::uuid IS NOT NULL AND
        (document ->> 'site_id')::uuid IS NOT NULL AND
        (document ->> 'site_owner_user_id')::uuid IS NOT NULL AND
        jsonb_typeof(document -> 'revision') = 'number' AND
        (document ->> 'revision') ~ '^[0-9]+$' AND (document ->> 'revision')::numeric > 0 AND
        jsonb_typeof(document -> 'max_upload_bytes') = 'number' AND
        (document ->> 'max_upload_bytes') ~ '^[0-9]+$' AND
        (document ->> 'max_upload_bytes')::numeric BETWEEN 1 AND 1073741824 AND
        http_policy_header_actions_valid_056(document -> 'request_headers', true) AND
        http_policy_header_actions_valid_056(document -> 'response_headers', false) AND
        http_policy_rewrite_chain_valid_056(document -> 'rewrites') AND
        http_policy_authorities_valid_056(document -> 'redirect_allowed_hosts') AND
        http_policy_redirects_valid_056(document -> 'redirects', document -> 'redirect_allowed_hosts') AND
        http_policy_rule_conflicts_valid_056(document -> 'rewrites', document -> 'redirects') AND
        http_policy_cors_valid_056(document -> 'cors') AND
        jsonb_typeof(document -> 'enabled') = 'boolean' AND
        jsonb_typeof(document -> 'deleted') = 'boolean' AND
        NOT ((document ->> 'deleted')::boolean AND (document ->> 'enabled')::boolean);
EXCEPTION WHEN invalid_text_representation OR numeric_value_out_of_range THEN
    RETURN false;
END;
$$;

CREATE FUNCTION http_policy_actor_can_056(actor_scope uuid, actor_user uuid, target_scope uuid, permission text)
RETURNS boolean
LANGUAGE plpgsql
STABLE
AS $$
DECLARE actor_kind text;
BEGIN
    SELECT scope.kind INTO actor_kind
    FROM access_scopes scope
    JOIN memberships membership
      ON membership.scope_id = scope.id AND membership.user_id = actor_user
     AND membership.status = 'active'
    JOIN users account ON account.id = membership.user_id AND account.status = 'active'
    WHERE scope.id = actor_scope;
    IF actor_kind = 'tenant' THEN
        RETURN actor_scope = target_scope AND EXISTS (
            SELECT 1 FROM custom_rbac_effective_permissions(actor_scope, actor_user)
            WHERE permission_name = permission
        );
    END IF;
    IF actor_kind = 'platform' THEN
        RETURN EXISTS (
            SELECT 1
            FROM role_assignments assignment
            JOIN role_permissions role_permission ON role_permission.role_id = assignment.role_id
            WHERE assignment.scope_id = actor_scope AND assignment.user_id = actor_user
              AND role_permission.permission_name = permission
        );
    END IF;
    RETURN false;
END;
$$;

CREATE FUNCTION validate_http_policy_revision_056()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE head http_policies%ROWTYPE;
DECLARE site_scope uuid;
DECLARE site_owner uuid;
BEGIN
    PERFORM pg_advisory_xact_lock(hashtextextended('http-policy-publication:' || NEW.tenant_scope_id::text, 0));
    PERFORM pg_advisory_xact_lock(hashtextextended('http-policy:' || NEW.policy_id::text, 0));
    IF NOT http_policy_document_valid_056(NEW.document) THEN
        RAISE EXCEPTION 'invalid HTTP policy document' USING ERRCODE = 'P0001';
    END IF;
    IF NOT http_policy_actor_can_056(
        NEW.created_by_scope_id, NEW.created_by_user_id, NEW.tenant_scope_id, 'http_policies.manage'
    ) THEN
        RAISE EXCEPTION 'HTTP policy actor is not authorized' USING ERRCODE = 'P0001';
    END IF;
    SELECT scope_id, owner_user_id INTO site_scope, site_owner
    FROM sites WHERE id = NEW.site_id AND deleted_at IS NULL;
    IF site_scope IS DISTINCT FROM NEW.tenant_scope_id OR site_owner IS DISTINCT FROM NEW.site_owner_user_id THEN
        RAISE EXCEPTION 'HTTP policy site ownership mismatch' USING ERRCODE = 'P0001';
    END IF;
    IF EXISTS (SELECT 1 FROM access_scopes WHERE id = NEW.created_by_scope_id AND kind = 'tenant') AND
       NEW.created_by_user_id <> NEW.site_owner_user_id THEN
        RAISE EXCEPTION 'tenant actor does not own HTTP policy site' USING ERRCODE = 'P0001';
    END IF;
    IF NEW.document ->> 'policy_id' <> NEW.policy_id::text OR
       NEW.document ->> 'tenant_scope_id' <> NEW.tenant_scope_id::text OR
       NEW.document ->> 'site_id' <> NEW.site_id::text OR
       NEW.document ->> 'site_owner_user_id' <> NEW.site_owner_user_id::text OR
       (NEW.document ->> 'revision')::bigint <> NEW.revision OR
       (NEW.document ->> 'enabled')::boolean IS DISTINCT FROM NEW.enabled OR
       (NEW.document ->> 'deleted')::boolean IS DISTINCT FROM NEW.deleted THEN
        RAISE EXCEPTION 'HTTP policy document does not match revision facts' USING ERRCODE = 'P0001';
    END IF;

    SELECT * INTO head FROM http_policies WHERE id = NEW.policy_id FOR UPDATE;
    IF NOT FOUND THEN
        IF NEW.revision <> 1 OR NEW.action <> 'create' OR NEW.deleted THEN
            RAISE EXCEPTION 'HTTP policy must start with create revision one' USING ERRCODE = 'P0001';
        END IF;
        RETURN NEW;
    END IF;
    IF head.current_deleted OR NEW.action = 'create' OR NEW.revision <> head.current_revision + 1 OR
       NEW.tenant_scope_id <> head.tenant_scope_id OR NEW.tenant_id <> head.tenant_id OR
       NEW.site_id <> head.site_id OR NEW.site_owner_user_id <> head.site_owner_user_id THEN
        RAISE EXCEPTION 'HTTP policy revision is not monotonic or changes identity' USING ERRCODE = 'P0001';
    END IF;
    IF NEW.action = 'update' AND (NEW.enabled <> head.current_enabled OR NEW.deleted) THEN
        RAISE EXCEPTION 'HTTP policy update cannot change state' USING ERRCODE = 'P0001';
    ELSIF NEW.action = 'enable' AND (head.current_enabled OR NOT NEW.enabled OR NEW.deleted) THEN
        RAISE EXCEPTION 'invalid HTTP policy enable transition' USING ERRCODE = 'P0001';
    ELSIF NEW.action = 'disable' AND (NOT head.current_enabled OR NEW.enabled OR NEW.deleted) THEN
        RAISE EXCEPTION 'invalid HTTP policy disable transition' USING ERRCODE = 'P0001';
    ELSIF NEW.action = 'delete' AND (NEW.enabled OR NOT NEW.deleted) THEN
        RAISE EXCEPTION 'invalid HTTP policy delete transition' USING ERRCODE = 'P0001';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER http_policy_revisions_validate_056
BEFORE INSERT ON http_policy_revisions
FOR EACH ROW EXECUTE FUNCTION validate_http_policy_revision_056();

CREATE FUNCTION project_http_policy_revision_056()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.revision = 1 THEN
        INSERT INTO http_policies (
            id, tenant_scope_id, tenant_id, site_id, site_owner_user_id,
            current_revision, current_enabled, current_deleted, current_document,
            created_by_user_id, created_at, updated_at, deleted_at
        ) VALUES (
            NEW.policy_id, NEW.tenant_scope_id, NEW.tenant_id, NEW.site_id, NEW.site_owner_user_id,
            NEW.revision, NEW.enabled, NEW.deleted, NEW.document,
            NEW.created_by_user_id, NEW.created_at, NEW.created_at,
            CASE WHEN NEW.deleted THEN NEW.created_at END
        );
    ELSE
        UPDATE http_policies SET
            current_revision = NEW.revision,
            current_enabled = NEW.enabled,
            current_deleted = NEW.deleted,
            current_document = NEW.document,
            updated_at = NEW.created_at,
            deleted_at = CASE WHEN NEW.deleted THEN NEW.created_at ELSE NULL END
        WHERE id = NEW.policy_id AND current_revision = NEW.revision - 1;
        IF NOT FOUND THEN
            RAISE EXCEPTION 'HTTP policy projection did not advance' USING ERRCODE = 'P0001';
        END IF;
    END IF;
    INSERT INTO http_policy_publication_heads (tenant_scope_id, revision, updated_at)
    VALUES (NEW.tenant_scope_id, 1, NEW.created_at)
    ON CONFLICT (tenant_scope_id) DO UPDATE SET
        revision = http_policy_publication_heads.revision + 1,
        updated_at = EXCLUDED.updated_at
    WHERE http_policy_publication_heads.revision < 9007199254740991;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'HTTP policy publication revision exhausted' USING ERRCODE = 'P0001';
    END IF;
    RETURN NULL;
END;
$$;

CREATE TRIGGER http_policy_revisions_project_056
AFTER INSERT ON http_policy_revisions
FOR EACH ROW EXECUTE FUNCTION project_http_policy_revision_056();

CREATE FUNCTION protect_http_policy_projection_056()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF pg_trigger_depth() < 2 THEN
        RAISE EXCEPTION 'HTTP policy projection is revision-managed' USING ERRCODE = 'P0001';
    END IF;
    RETURN CASE WHEN TG_OP = 'DELETE' THEN OLD ELSE NEW END;
END;
$$;

CREATE TRIGGER http_policies_projection_guard_056
BEFORE INSERT OR UPDATE OR DELETE ON http_policies
FOR EACH ROW EXECUTE FUNCTION protect_http_policy_projection_056();
CREATE TRIGGER http_policies_no_truncate_056
BEFORE TRUNCATE ON http_policies
FOR EACH STATEMENT EXECUTE FUNCTION protect_http_policy_projection_056();
CREATE TRIGGER http_policy_publication_heads_guard_056
BEFORE INSERT OR UPDATE OR DELETE ON http_policy_publication_heads
FOR EACH ROW EXECUTE FUNCTION protect_http_policy_projection_056();
CREATE TRIGGER http_policy_publication_heads_no_truncate_056
BEFORE TRUNCATE ON http_policy_publication_heads
FOR EACH STATEMENT EXECUTE FUNCTION protect_http_policy_projection_056();

CREATE FUNCTION protect_http_policy_revision_056()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'HTTP policy revisions are append-only' USING ERRCODE = 'P0001';
END;
$$;

CREATE TRIGGER http_policy_revisions_append_only_056
BEFORE UPDATE OR DELETE ON http_policy_revisions
FOR EACH ROW EXECUTE FUNCTION protect_http_policy_revision_056();
CREATE TRIGGER http_policy_revisions_no_truncate_056
BEFORE TRUNCATE ON http_policy_revisions
FOR EACH STATEMENT EXECUTE FUNCTION protect_http_policy_revision_056();

CREATE FUNCTION protect_http_policy_write_request_056()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP IN ('DELETE', 'TRUNCATE') THEN
        RAISE EXCEPTION 'HTTP policy write facts cannot be removed' USING ERRCODE = 'P0001';
    END IF;
    IF TG_OP = 'INSERT' THEN
        IF NEW.completed_at IS NOT NULL OR NEW.outcome IS NOT NULL OR NEW.resource_id IS NOT NULL OR
           NEW.response_status IS NOT NULL OR NEW.response_body IS NOT NULL THEN
            RAISE EXCEPTION 'HTTP policy write must start incomplete' USING ERRCODE = 'P0001';
        END IF;
        RETURN NEW;
    END IF;
    IF OLD.completed_at IS NOT NULL OR
       NEW.id IS DISTINCT FROM OLD.id OR NEW.actor_scope_id IS DISTINCT FROM OLD.actor_scope_id OR
       NEW.actor_user_id IS DISTINCT FROM OLD.actor_user_id OR
       NEW.target_scope_id IS DISTINCT FROM OLD.target_scope_id OR
       NEW.operation IS DISTINCT FROM OLD.operation OR
       NEW.idempotency_key IS DISTINCT FROM OLD.idempotency_key OR
       NEW.request_digest IS DISTINCT FROM OLD.request_digest OR
       NEW.request_id IS DISTINCT FROM OLD.request_id OR NEW.trace_id IS DISTINCT FROM OLD.trace_id OR
       NEW.created_at IS DISTINCT FROM OLD.created_at OR NEW.completed_at IS NULL OR
       NEW.outcome IS NULL OR NEW.response_status IS NULL OR NEW.response_body IS NULL THEN
        RAISE EXCEPTION 'invalid HTTP policy write completion' USING ERRCODE = 'P0001';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER http_policy_write_requests_guard_056
BEFORE INSERT OR UPDATE OR DELETE ON http_policy_write_requests
FOR EACH ROW EXECUTE FUNCTION protect_http_policy_write_request_056();
CREATE TRIGGER http_policy_write_requests_no_truncate_056
BEFORE TRUNCATE ON http_policy_write_requests
FOR EACH STATEMENT EXECUTE FUNCTION protect_http_policy_write_request_056();

CREATE FUNCTION assert_http_policy_revision_audited_056()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM audit_events event
        WHERE event.scope_id = NEW.tenant_scope_id
          AND event.actor_user_id = NEW.created_by_user_id
          AND event.action = 'http_policy.' || NEW.action
          AND event.resource_type = 'http_policy'
          AND event.resource_id = NEW.policy_id::text
          AND event.request_id = NEW.request_id
          AND event.result = 'success'
          AND event.payload ->> 'trace_id' = NEW.trace_id
          AND event.payload ->> 'revision' = NEW.revision::text
    ) THEN
        RAISE EXCEPTION 'HTTP policy revision requires matching success audit' USING ERRCODE = 'P0001';
    END IF;
    RETURN NULL;
END;
$$;

CREATE CONSTRAINT TRIGGER http_policy_revisions_audited_056
AFTER INSERT ON http_policy_revisions
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION assert_http_policy_revision_audited_056();
