LOCK TABLE schema_migrations,permissions,roles,role_permissions IN ACCESS EXCLUSIVE MODE;

DO $migration_217$
BEGIN
    IF (SELECT count(*) FROM schema_migrations)<>216 OR
       (SELECT min(version) FROM schema_migrations)<>1 OR
       (SELECT max(version) FROM schema_migrations)<>216 OR EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE migration_id IS NULL OR migration_id='' OR
              checksum_sha256 !~ '^[0-9a-f]{64}$' OR
              down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR
              integrity_state IS DISTINCT FROM 'verified' OR
              metadata_recorded_at IS NULL OR applied_at IS NULL
    ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version=216 AND migration_id='216_identity_user_soft_delete' AND
              checksum_sha256='4ae6bdcbd40648bcc3120e344ebffa2aecbc5f04bfc76d9c21360f014b5a5257' AND
              down_checksum_sha256='24053b96963d8e27bfcbb52e929918d854497b8cee23e1b601ac9b589f9f7e20' AND
              integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
    ) OR to_regclass(current_schema() || '.openresty_security_configs') IS NOT NULL THEN
        RAISE EXCEPTION 'migration 217 requires the exact verified 216 release head and an untouched OpenResty security schema'
            USING ERRCODE='P2170';
    END IF;
END;
$migration_217$;

INSERT INTO permissions(name,description) VALUES
    ('openresty_security.read','Read global and scoped OpenResty CC/WAF configuration'),
    ('openresty_security.manage','Create, update, delete, and publish OpenResty CC/WAF configuration');

INSERT INTO role_permissions(role_id,permission_name)
SELECT role.id,permission.name
FROM roles role
CROSS JOIN (VALUES('openresty_security.read'),('openresty_security.manage')) permission(name)
JOIN access_scopes scope ON scope.id=role.scope_id AND scope.kind IN ('tenant','platform')
WHERE role.system_role AND role.name IN ('tenant_owner','platform_owner')
ON CONFLICT DO NOTHING;

CREATE TABLE openresty_security_configs (
    id uuid PRIMARY KEY CHECK(id<>'00000000-0000-0000-0000-000000000000'::uuid),
    tenant_scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE RESTRICT,
    scope_type text NOT NULL CHECK(scope_type IN ('global','region','node')),
    scope_id text NOT NULL CHECK(scope_id=btrim(scope_id) AND char_length(scope_id) BETWEEN 1 AND 64),
    document jsonb NOT NULL CHECK(jsonb_typeof(document)='object' AND octet_length(document::text)<=4194304),
    document_sha256 bytea NOT NULL CHECK(octet_length(document_sha256)=32),
    key_override boolean NOT NULL DEFAULT false,
    secret_ciphertext bytea CHECK(secret_ciphertext IS NULL OR octet_length(secret_ciphertext) BETWEEN 1 AND 65536),
    revision bigint NOT NULL CHECK(revision>0 AND revision<=9007199254740991),
    created_at timestamptz NOT NULL CHECK(isfinite(created_at)),
    updated_at timestamptz NOT NULL CHECK(isfinite(updated_at) AND updated_at>=created_at),
    deleted_at timestamptz CHECK(deleted_at IS NULL OR isfinite(deleted_at) AND deleted_at>=created_at),
    CHECK((scope_type='global' AND scope_id='0' AND deleted_at IS NULL) OR scope_type IN ('region','node')),
    CHECK(scope_type<>'node' OR scope_id ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'),
    CHECK(secret_ciphertext IS NULL OR key_override)
);

CREATE UNIQUE INDEX openresty_security_configs_active_target_idx
    ON openresty_security_configs(tenant_scope_id,scope_type,scope_id) WHERE deleted_at IS NULL;
CREATE INDEX openresty_security_configs_scope_updated_idx
    ON openresty_security_configs(tenant_scope_id,scope_type,updated_at DESC,id DESC) WHERE deleted_at IS NULL;

CREATE TABLE openresty_security_config_revisions (
    tenant_scope_id uuid NOT NULL,
    config_id uuid NOT NULL,
    revision bigint NOT NULL CHECK(revision>0 AND revision<=9007199254740991),
    scope_type text NOT NULL CHECK(scope_type IN ('global','region','node')),
    scope_id text NOT NULL CHECK(scope_id=btrim(scope_id) AND char_length(scope_id) BETWEEN 1 AND 64),
    operation text NOT NULL CHECK(operation IN ('global.patch','override.create','override.patch','override.delete')),
    document jsonb NOT NULL CHECK(jsonb_typeof(document)='object' AND octet_length(document::text)<=4194304),
    document_sha256 bytea NOT NULL CHECK(octet_length(document_sha256)=32),
    key_configured boolean NOT NULL,
    actor_scope_id uuid NOT NULL,
    actor_user_id uuid NOT NULL,
    request_id text NOT NULL CHECK(char_length(request_id) BETWEEN 1 AND 128),
    created_at timestamptz NOT NULL CHECK(isfinite(created_at)),
    PRIMARY KEY(tenant_scope_id,config_id,revision),
    FOREIGN KEY(actor_scope_id,actor_user_id) REFERENCES memberships(scope_id,user_id) ON DELETE RESTRICT
);

CREATE TABLE openresty_security_write_receipts (
    tenant_scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE RESTRICT,
    idempotency_key text NOT NULL CHECK(idempotency_key ~ '^[A-Za-z0-9._-]{1,128}$'),
    request_sha256 bytea NOT NULL CHECK(octet_length(request_sha256)=32),
    actor_scope_id uuid NOT NULL,
    actor_user_id uuid NOT NULL,
    response_body jsonb NOT NULL CHECK(jsonb_typeof(response_body)='object' AND octet_length(response_body::text)<=4194304),
    created_at timestamptz NOT NULL CHECK(isfinite(created_at)),
    PRIMARY KEY(tenant_scope_id,idempotency_key),
    FOREIGN KEY(actor_scope_id,actor_user_id) REFERENCES memberships(scope_id,user_id) ON DELETE RESTRICT
);

CREATE TABLE openresty_security_publication_outbox (
    id uuid PRIMARY KEY CHECK(id<>'00000000-0000-0000-0000-000000000000'::uuid),
    tenant_scope_id uuid NOT NULL,
    config_id uuid NOT NULL,
    revision bigint NOT NULL CHECK(revision>0 AND revision<=9007199254740991),
    scope_type text NOT NULL CHECK(scope_type IN ('global','region','node')),
    scope_id text NOT NULL,
    operation text NOT NULL CHECK(operation IN ('global.patch','override.create','override.patch','override.delete')),
    document jsonb NOT NULL CHECK(jsonb_typeof(document)='object' AND octet_length(document::text)<=4194304),
    document_sha256 bytea NOT NULL CHECK(octet_length(document_sha256)=32),
    state text NOT NULL CHECK(state IN ('pending','retryable','projected','active','partial','failed','rolled_back')),
    attempts integer NOT NULL DEFAULT 0 CHECK(attempts BETWEEN 0 AND 32),
    available_at timestamptz NOT NULL CHECK(isfinite(available_at)),
    projected_at timestamptz,
    last_error text CHECK(last_error IS NULL OR char_length(last_error)<=2048),
    created_at timestamptz NOT NULL CHECK(isfinite(created_at)),
    updated_at timestamptz NOT NULL CHECK(isfinite(updated_at) AND updated_at>=created_at),
    FOREIGN KEY(tenant_scope_id,config_id,revision)
        REFERENCES openresty_security_config_revisions(tenant_scope_id,config_id,revision) ON DELETE RESTRICT,
    UNIQUE(tenant_scope_id,config_id,revision),
    CHECK((state IN ('projected','active','partial','failed','rolled_back'))=(projected_at IS NOT NULL))
);

CREATE INDEX openresty_security_publication_ready_idx
    ON openresty_security_publication_outbox(available_at,id) WHERE state IN ('pending','retryable');

CREATE TABLE openresty_security_task_outbox (
    id uuid PRIMARY KEY CHECK(id<>'00000000-0000-0000-0000-000000000000'::uuid),
    tenant_scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE RESTRICT,
    task_type text NOT NULL CHECK(task_type='download_cc_img'),
    idempotency_key text NOT NULL CHECK(idempotency_key ~ '^[A-Za-z0-9._-]{1,128}$'),
    state text NOT NULL CHECK(state IN ('pending','retryable','published','completed','failed')),
    attempts integer NOT NULL DEFAULT 0 CHECK(attempts BETWEEN 0 AND 32),
    available_at timestamptz NOT NULL DEFAULT now(),
    last_error text CHECK(last_error IS NULL OR char_length(last_error)<=2048),
    created_at timestamptz NOT NULL CHECK(isfinite(created_at)),
    updated_at timestamptz NOT NULL CHECK(isfinite(updated_at) AND updated_at>=created_at),
    UNIQUE(tenant_scope_id,idempotency_key)
);

CREATE INDEX openresty_security_task_ready_idx
    ON openresty_security_task_outbox(available_at,id) WHERE state IN ('pending','retryable');

CREATE FUNCTION prevent_openresty_security_fact_mutation_217()
RETURNS trigger LANGUAGE plpgsql AS $function$
BEGIN
    RAISE EXCEPTION '% is append-only',TG_TABLE_NAME USING ERRCODE='P2171';
END;
$function$;

CREATE TRIGGER openresty_security_revisions_append_only_217
BEFORE UPDATE OR DELETE ON openresty_security_config_revisions
FOR EACH ROW EXECUTE FUNCTION prevent_openresty_security_fact_mutation_217();
CREATE TRIGGER openresty_security_receipts_append_only_217
BEFORE UPDATE OR DELETE ON openresty_security_write_receipts
FOR EACH ROW EXECUTE FUNCTION prevent_openresty_security_fact_mutation_217();
CREATE TRIGGER openresty_security_revisions_no_truncate_217
BEFORE TRUNCATE ON openresty_security_config_revisions
FOR EACH STATEMENT EXECUTE FUNCTION prevent_openresty_security_fact_mutation_217();
CREATE TRIGGER openresty_security_receipts_no_truncate_217
BEFORE TRUNCATE ON openresty_security_write_receipts
FOR EACH STATEMENT EXECUTE FUNCTION prevent_openresty_security_fact_mutation_217();

CREATE FUNCTION protect_openresty_security_publication_217()
RETURNS trigger LANGUAGE plpgsql AS $function$
BEGIN
    IF TG_OP='DELETE' OR ROW(NEW.id,NEW.tenant_scope_id,NEW.config_id,NEW.revision,NEW.scope_type,NEW.scope_id,
        NEW.operation,NEW.document,NEW.document_sha256,NEW.created_at) IS DISTINCT FROM
        ROW(OLD.id,OLD.tenant_scope_id,OLD.config_id,OLD.revision,OLD.scope_type,OLD.scope_id,
        OLD.operation,OLD.document,OLD.document_sha256,OLD.created_at) THEN
        RAISE EXCEPTION 'OpenResty security publication identity is immutable' USING ERRCODE='P2171';
    END IF;
    IF NOT ((OLD.state='pending' AND NEW.state IN ('retryable','projected')) OR
            (OLD.state='retryable' AND NEW.state IN ('retryable','projected')) OR
            (OLD.state='projected' AND NEW.state IN ('active','partial','failed','rolled_back'))) THEN
        RAISE EXCEPTION 'invalid OpenResty security publication transition' USING ERRCODE='P2171';
    END IF;
    RETURN NEW;
END;
$function$;

CREATE TRIGGER openresty_security_publication_guard_217
BEFORE UPDATE OR DELETE ON openresty_security_publication_outbox
FOR EACH ROW EXECUTE FUNCTION protect_openresty_security_publication_217();
CREATE TRIGGER openresty_security_publication_no_truncate_217
BEFORE TRUNCATE ON openresty_security_publication_outbox
FOR EACH STATEMENT EXECUTE FUNCTION prevent_openresty_security_fact_mutation_217();

REVOKE ALL ON TABLE openresty_security_configs,openresty_security_config_revisions,
    openresty_security_write_receipts,openresty_security_publication_outbox,openresty_security_task_outbox FROM PUBLIC;
GRANT SELECT,INSERT,UPDATE ON TABLE openresty_security_configs,openresty_security_publication_outbox,
    openresty_security_task_outbox TO cdnca_control_app;
GRANT SELECT,INSERT ON TABLE openresty_security_config_revisions,openresty_security_write_receipts TO cdnca_control_app;

