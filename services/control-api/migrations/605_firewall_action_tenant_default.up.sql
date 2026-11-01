-- 605（fw-default，调度预留 control 605）：防火墙动作租户级默认 + 站点恢复继承。
--   用户 10-31："防火墙动作策略需要一个网站一个网站的匹配 太麻烦了吧"。
--   有效策略 = 站点自有策略，否则租户默认，否则系统内置默认（系统默认不下发）。
-- 1) firewall_action_tenant_defaults：每个租户 scope 一份默认（单调 revision、整份不可变修订、写回执幂等）。
--    单独建表而不是在站点表里放哨兵 site_id：站点表主键/外键绑定 sites(scope_id,id)，哨兵行会破坏该约束。
-- 2) 站点头/修订加 inherited：恢复继承 = 写一条 revision+1 的继承修订（文档固定为 {}），不删行，
--    修订表只追加、头不可删的 174 约束不变；同一修订计数让 If-Match 挡住"恢复继承"与"覆盖"的并发。
--    复合外键保证头的 inherited 与其当前修订一致。
-- 前驱：604（api_key_plugin_installation）；原占位 607，hot-p40a 改号 605。
LOCK TABLE schema_migrations, access_scopes, memberships, firewall_action_policy_heads,
    firewall_action_policy_revisions IN ACCESS EXCLUSIVE MODE;

DO $migration_605_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 604 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 604 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=604 AND
        migration_id='604_api_key_plugin_installation' AND
        checksum_sha256='0789ce0c184f68dbb240eb427ffba1bfada973e290d794f918ddca809acceb8a' AND
        down_checksum_sha256='9944a046400c2a6554335cd25d2fc9fdae503351a5d90165c49b6ff0f9cc013c' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR to_regclass('firewall_action_tenant_defaults') IS NOT NULL OR EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name='firewall_action_policy_heads' AND column_name='inherited'
       ) THEN
        RAISE EXCEPTION 'migration 605 requires the exact verified 604 release head' USING ERRCODE='P6050';
    END IF;
END;
$migration_605_up$;

CREATE TABLE firewall_action_tenant_defaults (
    tenant_scope_id uuid PRIMARY KEY REFERENCES access_scopes(id) ON DELETE RESTRICT,
    document jsonb NOT NULL CHECK(jsonb_typeof(document)='object'),
    document_bytes bytea NOT NULL CHECK(octet_length(document_bytes) BETWEEN 2 AND 1048576),
    document_sha256 bytea NOT NULL CHECK(
        octet_length(document_sha256)=32 AND document_sha256=sha256(document_bytes) AND
        document=convert_from(document_bytes,'UTF8')::jsonb
    ),
    revision bigint NOT NULL CHECK(revision BETWEEN 1 AND 9007199254740991),
    created_at timestamptz NOT NULL CHECK(isfinite(created_at)),
    updated_at timestamptz NOT NULL CHECK(isfinite(updated_at) AND updated_at>=created_at)
);

CREATE TABLE firewall_action_tenant_default_revisions (
    tenant_scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE RESTRICT,
    revision bigint NOT NULL CHECK(revision BETWEEN 1 AND 9007199254740991),
    document jsonb NOT NULL CHECK(jsonb_typeof(document)='object'),
    document_bytes bytea NOT NULL CHECK(octet_length(document_bytes) BETWEEN 2 AND 1048576),
    document_sha256 bytea NOT NULL CHECK(
        octet_length(document_sha256)=32 AND document_sha256=sha256(document_bytes) AND
        document=convert_from(document_bytes,'UTF8')::jsonb
    ),
    actor_scope_id uuid NOT NULL,
    actor_user_id uuid NOT NULL,
    request_id text NOT NULL CHECK(request_id ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'),
    created_at timestamptz NOT NULL CHECK(isfinite(created_at)),
    PRIMARY KEY(tenant_scope_id,revision),
    FOREIGN KEY(actor_scope_id,actor_user_id) REFERENCES memberships(scope_id,user_id) ON DELETE RESTRICT
);

ALTER TABLE firewall_action_tenant_defaults
    ADD CONSTRAINT firewall_action_tenant_defaults_current_revision_605
    FOREIGN KEY(tenant_scope_id,revision)
    REFERENCES firewall_action_tenant_default_revisions(tenant_scope_id,revision)
    ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED;

CREATE TABLE firewall_action_tenant_default_receipts (
    tenant_scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE RESTRICT,
    idempotency_key text NOT NULL CHECK(idempotency_key ~ '^[A-Za-z0-9._-]{1,128}$'),
    request_sha256 bytea NOT NULL CHECK(octet_length(request_sha256)=32),
    actor_scope_id uuid NOT NULL,
    actor_user_id uuid NOT NULL,
    response_body jsonb NOT NULL CHECK(jsonb_typeof(response_body)='object' AND octet_length(response_body::text)<=65536),
    created_at timestamptz NOT NULL CHECK(isfinite(created_at)),
    PRIMARY KEY(tenant_scope_id,idempotency_key),
    FOREIGN KEY(actor_scope_id,actor_user_id) REFERENCES memberships(scope_id,user_id) ON DELETE RESTRICT
);

CREATE FUNCTION guard_firewall_action_tenant_default_605()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP='DELETE' OR NEW.tenant_scope_id IS DISTINCT FROM OLD.tenant_scope_id OR
       NEW.created_at IS DISTINCT FROM OLD.created_at OR NEW.updated_at<OLD.updated_at OR
       NEW.revision<>OLD.revision+1 THEN
        RAISE EXCEPTION 'firewall action tenant default must advance one revision at a time' USING ERRCODE='P6051';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER firewall_action_tenant_defaults_guard_605
BEFORE UPDATE OR DELETE ON firewall_action_tenant_defaults
FOR EACH ROW EXECUTE FUNCTION guard_firewall_action_tenant_default_605();
CREATE TRIGGER firewall_action_tenant_default_revisions_immutable_605
BEFORE UPDATE OR DELETE ON firewall_action_tenant_default_revisions
FOR EACH ROW EXECUTE FUNCTION prevent_firewall_action_fact_mutation_174();
CREATE TRIGGER firewall_action_tenant_default_receipts_immutable_605
BEFORE UPDATE OR DELETE ON firewall_action_tenant_default_receipts
FOR EACH ROW EXECUTE FUNCTION prevent_firewall_action_fact_mutation_174();
CREATE TRIGGER firewall_action_tenant_defaults_no_truncate_605
BEFORE TRUNCATE ON firewall_action_tenant_defaults
FOR EACH STATEMENT EXECUTE FUNCTION prevent_firewall_action_fact_truncate_174();
CREATE TRIGGER firewall_action_tenant_default_revisions_no_truncate_605
BEFORE TRUNCATE ON firewall_action_tenant_default_revisions
FOR EACH STATEMENT EXECUTE FUNCTION prevent_firewall_action_fact_truncate_174();
CREATE TRIGGER firewall_action_tenant_default_receipts_no_truncate_605
BEFORE TRUNCATE ON firewall_action_tenant_default_receipts
FOR EACH STATEMENT EXECUTE FUNCTION prevent_firewall_action_fact_truncate_174();

-- 站点恢复继承：继承修订的文档固定为 {}，自有修订不能是 {}。
ALTER TABLE firewall_action_policy_revisions
    ADD COLUMN inherited boolean NOT NULL DEFAULT false,
    ADD CONSTRAINT firewall_action_policy_revisions_inherited_605 CHECK(inherited=(document='{}'::jsonb)),
    ADD CONSTRAINT firewall_action_policy_revisions_inherited_key_605
        UNIQUE(tenant_scope_id,site_id,policy_id,revision,inherited);

ALTER TABLE firewall_action_policy_heads
    ADD COLUMN inherited boolean NOT NULL DEFAULT false,
    ADD CONSTRAINT firewall_action_policy_heads_inherited_605 CHECK(inherited=(document='{}'::jsonb)),
    ADD CONSTRAINT firewall_action_policy_heads_inherited_revision_605
        FOREIGN KEY(tenant_scope_id,site_id,id,revision,inherited)
        REFERENCES firewall_action_policy_revisions(tenant_scope_id,site_id,policy_id,revision,inherited)
        ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED;

-- 发布只读自有策略的候选；继承站点的文档由租户默认合成，不进 outbox。
CREATE FUNCTION guard_firewall_action_inherited_outbox_605()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF EXISTS (SELECT 1 FROM firewall_action_policy_revisions
               WHERE tenant_scope_id=NEW.tenant_scope_id AND site_id=NEW.site_id AND
                     revision=NEW.revision AND inherited) THEN
        RAISE EXCEPTION 'inherited firewall action revisions are not published' USING ERRCODE='P6052';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER firewall_action_outbox_inherited_605
BEFORE INSERT ON firewall_action_publication_outbox
FOR EACH ROW EXECUTE FUNCTION guard_firewall_action_inherited_outbox_605();

REVOKE ALL ON firewall_action_tenant_defaults, firewall_action_tenant_default_revisions,
    firewall_action_tenant_default_receipts FROM PUBLIC;
