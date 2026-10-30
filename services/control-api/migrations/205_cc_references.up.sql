LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;

DO $migration_205$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version=204
          AND migration_id='204_platform_brand_assets_permissions'
          AND integrity_state='verified'
          AND metadata_recorded_at IS NOT NULL
          AND applied_at IS NOT NULL
    ) THEN
        RAISE EXCEPTION 'migration 205 requires a verified 204 platform-brand-assets permissions head'
            USING ERRCODE='P2050';
    END IF;
END;
$migration_205$;

CREATE TABLE cc_reference_matchers (
    id uuid PRIMARY KEY,
    scope_id uuid NOT NULL,
    tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    owner_user_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    source_policy_id uuid REFERENCES security_policies(id) ON DELETE SET NULL,
    source_rule_id uuid,
    source_index integer,
    name text NOT NULL CHECK (name=btrim(name) AND char_length(name) BETWEEN 1 AND 128),
    description text NOT NULL DEFAULT '' CHECK (char_length(description) <= 1000),
    field text NOT NULL CHECK (field=btrim(field) AND char_length(field) BETWEEN 1 AND 128),
    operator text NOT NULL CHECK (operator=btrim(operator) AND char_length(operator) BETWEEN 1 AND 128),
    condition_key text NOT NULL DEFAULT '' CHECK (char_length(condition_key) <= 128),
    values jsonb NOT NULL CHECK (jsonb_typeof(values)='array' AND jsonb_array_length(values) <= 100),
    enabled boolean NOT NULL DEFAULT true,
    revision bigint NOT NULL DEFAULT 1 CHECK (revision > 0),
    created_by_user_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    updated_by_user_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    deleted_at timestamptz,
    FOREIGN KEY (scope_id,tenant_id) REFERENCES access_scopes(id,tenant_id) ON DELETE RESTRICT,
    FOREIGN KEY (scope_id,owner_user_id) REFERENCES memberships(scope_id,user_id) ON DELETE RESTRICT
);

CREATE UNIQUE INDEX cc_reference_matchers_scope_name_active_idx
    ON cc_reference_matchers(scope_id,lower(name)) WHERE deleted_at IS NULL;
CREATE UNIQUE INDEX cc_reference_matchers_source_idx
    ON cc_reference_matchers(source_policy_id,source_rule_id,source_index)
    WHERE source_policy_id IS NOT NULL AND deleted_at IS NULL;
CREATE INDEX cc_reference_matchers_scope_created_idx
    ON cc_reference_matchers(scope_id,created_at DESC,id DESC) WHERE deleted_at IS NULL;

CREATE TABLE cc_reference_filters (
    id uuid PRIMARY KEY,
    scope_id uuid NOT NULL,
    tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    owner_user_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    source_policy_id uuid REFERENCES security_policies(id) ON DELETE SET NULL,
    source_rule_id uuid,
    source_index integer,
    name text NOT NULL CHECK (name=btrim(name) AND char_length(name) BETWEEN 1 AND 128),
    description text NOT NULL DEFAULT '' CHECK (char_length(description) <= 1000),
    filter_type text NOT NULL CHECK (filter_type=btrim(filter_type) AND char_length(filter_type) BETWEEN 1 AND 64),
    parameters jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(parameters)='object'),
    enabled boolean NOT NULL DEFAULT true,
    revision bigint NOT NULL DEFAULT 1 CHECK (revision > 0),
    created_by_user_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    updated_by_user_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    deleted_at timestamptz,
    FOREIGN KEY (scope_id,tenant_id) REFERENCES access_scopes(id,tenant_id) ON DELETE RESTRICT,
    FOREIGN KEY (scope_id,owner_user_id) REFERENCES memberships(scope_id,user_id) ON DELETE RESTRICT
);

CREATE UNIQUE INDEX cc_reference_filters_scope_name_active_idx
    ON cc_reference_filters(scope_id,lower(name)) WHERE deleted_at IS NULL;
CREATE UNIQUE INDEX cc_reference_filters_source_idx
    ON cc_reference_filters(source_policy_id,source_rule_id,source_index)
    WHERE source_policy_id IS NOT NULL AND deleted_at IS NULL;
CREATE INDEX cc_reference_filters_scope_created_idx
    ON cc_reference_filters(scope_id,created_at DESC,id DESC) WHERE deleted_at IS NULL;

CREATE TABLE cc_reference_versions (
    reference_kind text NOT NULL CHECK (reference_kind IN ('matcher','filter')),
    reference_id uuid NOT NULL,
    revision bigint NOT NULL CHECK (revision > 0),
    document jsonb NOT NULL CHECK (jsonb_typeof(document)='object'),
    created_by_user_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    created_at timestamptz NOT NULL,
    PRIMARY KEY (reference_kind,reference_id,revision)
);

CREATE TABLE cc_reference_write_requests (
    id uuid PRIMARY KEY,
    actor_user_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    actor_scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE RESTRICT,
    target_scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE RESTRICT,
    reference_kind text NOT NULL CHECK (reference_kind IN ('matcher','filter')),
    operation text NOT NULL CHECK (operation ~ '^(matcher|filter)\.(create|update|delete|enable|disable)$'),
    idempotency_key text NOT NULL CHECK (char_length(idempotency_key) BETWEEN 1 AND 128),
    request_digest bytea NOT NULL CHECK (octet_length(request_digest)=32),
    resource_id uuid,
    response_body jsonb CHECK (response_body IS NULL OR jsonb_typeof(response_body)='object'),
    created_at timestamptz NOT NULL,
    completed_at timestamptz,
    UNIQUE (actor_user_id,reference_kind,operation,idempotency_key),
    CHECK ((completed_at IS NULL AND resource_id IS NULL AND response_body IS NULL) OR
           (completed_at IS NOT NULL AND resource_id IS NOT NULL AND response_body IS NOT NULL))
);
CREATE INDEX cc_reference_write_requests_scope_created_idx
    ON cc_reference_write_requests(target_scope_id,created_at DESC);

-- Materialize the existing CC rule projection so the first release preserves
-- the observed page instead of replacing it with an empty table.
INSERT INTO cc_reference_matchers(
    id,scope_id,tenant_id,owner_user_id,source_policy_id,source_rule_id,source_index,
    name,description,field,operator,condition_key,values,enabled,revision,
    created_by_user_id,updated_by_user_id,created_at,updated_at
)
SELECT gen_random_uuid(),p.scope_id,p.tenant_id,p.owner_user_id,p.id,
       NULLIF(rule.value->>'id','')::uuid,condition.ordinality::integer,
       COALESCE(NULLIF(btrim(rule.value->>'name'),''),p.name),p.description,
       COALESCE(NULLIF(btrim(condition.value->>'field'),''),'all'),
       COALESCE(NULLIF(btrim(condition.value->>'operator'),''),'equals'),
       COALESCE(condition.value->>'key',''),
       COALESCE(condition.value->'values','[]'::jsonb),
       p.enabled AND COALESCE((rule.value->>'enabled')::boolean,true),p.revision,
       p.created_by_user_id,p.updated_by_user_id,p.created_at,p.updated_at
FROM security_policies p
CROSS JOIN LATERAL jsonb_array_elements(p.rules) AS rule(value)
CROSS JOIN LATERAL jsonb_array_elements(
    CASE WHEN jsonb_typeof(rule.value->'conditions')='array' AND jsonb_array_length(rule.value->'conditions') > 0
         THEN rule.value->'conditions'
         ELSE '[{"field":"all","operator":"equals","values":["*"]}]'::jsonb END
) WITH ORDINALITY AS condition(value,ordinality)
WHERE p.kind='cc' AND p.deleted_at IS NULL;

INSERT INTO cc_reference_filters(
    id,scope_id,tenant_id,owner_user_id,source_policy_id,source_rule_id,source_index,
    name,description,filter_type,parameters,enabled,revision,
    created_by_user_id,updated_by_user_id,created_at,updated_at
)
SELECT gen_random_uuid(),p.scope_id,p.tenant_id,p.owner_user_id,p.id,
       NULLIF(rule.value->>'id','')::uuid,rule.ordinality::integer,
       COALESCE(NULLIF(btrim(rule.value->>'name'),''),p.name),p.description,
       CASE
         WHEN COALESCE(rule.value->'action_config'->'rate_limit','null'::jsonb) <> 'null'::jsonb THEN 'req_rate'
         WHEN COALESCE(NULLIF(rule.value->'action_config'->'challenge'->>'type',''),'') <> '' THEN rule.value->'action_config'->'challenge'->>'type'
         WHEN rule.value->>'action'='rate_limit' THEN 'req_rate'
         WHEN rule.value->>'action'='challenge' THEN 'challenge'
         ELSE ''
       END,
       COALESCE(rule.value->'action_config','{}'::jsonb),
       p.enabled AND COALESCE((rule.value->>'enabled')::boolean,true),p.revision,
       p.created_by_user_id,p.updated_by_user_id,p.created_at,p.updated_at
FROM security_policies p
CROSS JOIN LATERAL jsonb_array_elements(p.rules) WITH ORDINALITY AS rule(value,ordinality)
WHERE p.kind='cc' AND p.deleted_at IS NULL
  AND (rule.value->>'action' IN ('rate_limit','challenge')
       OR rule.value->'action_config' ? 'rate_limit'
       OR rule.value->'action_config' ? 'challenge');

INSERT INTO cc_reference_versions(reference_kind,reference_id,revision,document,created_by_user_id,created_at)
SELECT 'matcher',id,revision,jsonb_build_object(
    'id',id,'scope_id',scope_id,'owner_user_id',owner_user_id,'name',name,'description',description,
    'field',field,'operator',operator,'key',condition_key,'values',values,'enabled',enabled,'version',revision
),created_by_user_id,created_at FROM cc_reference_matchers;
INSERT INTO cc_reference_versions(reference_kind,reference_id,revision,document,created_by_user_id,created_at)
SELECT 'filter',id,revision,jsonb_build_object(
    'id',id,'scope_id',scope_id,'owner_user_id',owner_user_id,'name',name,'description',description,
    'type',filter_type,'parameters',parameters,'enabled',enabled,'version',revision
),created_by_user_id,created_at FROM cc_reference_filters;

GRANT USAGE ON SCHEMA public TO cdnca_control_app;
GRANT SELECT,INSERT,UPDATE,DELETE ON TABLE
    cc_reference_matchers,cc_reference_filters,cc_reference_versions,cc_reference_write_requests
    TO cdnca_control_app;
