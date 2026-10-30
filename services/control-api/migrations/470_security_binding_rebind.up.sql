LOCK TABLE schema_migrations, security_policy_site_bindings, security_policy_publications IN ACCESS EXCLUSIVE MODE;

DO $migration_470_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 469 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 469 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=469 AND
        migration_id='469_escalate_cname_notice' AND
        checksum_sha256='aa849a7b833d78a97c94665790a403c2240775cce17686d07bdcf56efb3f959f' AND
        down_checksum_sha256='83464b6343256e4b45087e0eeeda7f852906e868879bf10ba115e094142fd00a' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema=current_schema() AND table_name='security_policy_publications' AND column_name IN ('detach','expected_active_policy_id')
       ) OR (
        SELECT count(*) FROM pg_constraint
        WHERE conrelid='security_policy_site_bindings'::regclass AND contype='c' AND
              pg_get_constraintdef(oid) LIKE '%active_policy_version <= last_claimed_policy_version%'
       ) <> 1 THEN
        RAISE EXCEPTION 'migration 470 requires the exact verified 469 release head' USING ERRCODE='P4700';
    END IF;
END;
$migration_470_up$;

-- 470（r136 sec-rebind）：站点安全规则换绑与撤下。
-- 绑定行仍按 (tenant_scope_id, site_id, policy_kind) 唯一，policy_id 表示「当前生效的库」；
-- 一次发布（申领）可以指向另一个库（换绑），也可以是撤下（detach：当前生效库与版本，生效后
-- active_policy_version 置空，节点不再执行该类型规则）。生效时 policy_id 改为该次发布的库；
-- 失败、取消、过期不动绑定，原库继续生效。版本号只在同一个库内比较。

-- 跨库后版本号不可比：去掉 active_policy_version <= last_claimed_policy_version。
DO $migration_470_check$
DECLARE
    name text;
BEGIN
    SELECT conname INTO name FROM pg_constraint
    WHERE conrelid='security_policy_site_bindings'::regclass AND contype='c' AND
          pg_get_constraintdef(oid) LIKE '%active_policy_version <= last_claimed_policy_version%';
    EXECUTE format('ALTER TABLE security_policy_site_bindings DROP CONSTRAINT %I', name);
END;
$migration_470_check$;
ALTER TABLE security_policy_site_bindings
    ADD CONSTRAINT security_policy_site_bindings_active_claimed_470
    CHECK (active_policy_version IS NULL OR last_claimed_policy_version IS NOT NULL);

ALTER TABLE security_policy_publications
    ADD COLUMN detach boolean NOT NULL DEFAULT false,
    ADD COLUMN expected_active_policy_id uuid;

-- 470 之前绑定的库从不变化：发布时生效的库就是本次发布的库。
ALTER TABLE security_policy_publications DISABLE TRIGGER security_policy_publications_append_only;
UPDATE security_policy_publications SET expected_active_policy_id=policy_id WHERE expected_active_version > 0;
ALTER TABLE security_policy_publications ENABLE TRIGGER security_policy_publications_append_only;

ALTER TABLE security_policy_publications
    ADD CONSTRAINT security_policy_publications_expected_active_470 CHECK (
        (expected_active_version = 0) = (expected_active_policy_id IS NULL)
    ),
    ADD CONSTRAINT security_policy_publications_expected_active_version_470
        FOREIGN KEY (expected_active_policy_id, expected_active_version)
        REFERENCES security_policy_versions(policy_id, revision) ON DELETE RESTRICT,
    ADD CONSTRAINT security_policy_publications_detach_470 CHECK (
        NOT detach OR (expected_active_policy_id = policy_id AND expected_active_version = policy_version)
    );

-- 申领：同一个库仍要求版本单调（大于生效版本、大于该库上次申领版本）；换库不比版本；
-- 新绑定的库不能是已删除的库；撤下只能撤当前生效的库与版本（库可以已删除）；
-- 撤下之后重新发布同一个库，不再和撤下那次的版本比较。
CREATE OR REPLACE FUNCTION validate_security_policy_publication_insert()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    binding security_policy_site_bindings%ROWTYPE;
    last_policy_id uuid;
    last_detach boolean := false;
BEGIN
    SELECT * INTO binding FROM security_policy_site_bindings
    WHERE id = NEW.binding_id FOR UPDATE;
    IF FOUND AND binding.last_bundle_id IS NOT NULL THEN
        SELECT policy_id, detach INTO last_policy_id, last_detach FROM security_policy_publications WHERE id = binding.last_bundle_id;
    END IF;
    -- 未写明发布时生效库的写入方（470 之前的写法）：生效库就是绑定当前的库。
    IF binding.id IS NOT NULL AND NEW.expected_active_version > 0 AND NEW.expected_active_policy_id IS NULL THEN
        NEW.expected_active_policy_id := binding.policy_id;
    END IF;
    IF binding.id IS NULL OR binding.tenant_scope_id <> NEW.tenant_scope_id OR
       binding.site_id <> NEW.site_id OR
       binding.policy_kind <> NEW.policy_kind OR binding.revision <> NEW.expected_binding_revision OR
       COALESCE(binding.active_policy_version, 0) <> NEW.expected_active_version OR
       (NEW.expected_active_version > 0 AND NEW.expected_active_policy_id IS DISTINCT FROM binding.policy_id) OR
       (NEW.detach AND (binding.active_policy_version IS NULL OR NEW.policy_id <> binding.policy_id OR
                        NEW.policy_version <> binding.active_policy_version)) OR
       (NOT NEW.detach AND EXISTS (
           SELECT 1 FROM security_policies policy WHERE policy.id = NEW.policy_id AND policy.deleted_at IS NOT NULL
       )) OR
       (NOT NEW.detach AND NEW.policy_id = binding.policy_id AND (
           NEW.policy_version <= COALESCE(binding.active_policy_version, 0) OR
           (binding.last_claimed_policy_version IS NOT NULL AND last_policy_id = NEW.policy_id AND NOT last_detach AND
            NEW.policy_version <= binding.last_claimed_policy_version)
       )) THEN
        RAISE EXCEPTION 'security publication binding or version conflict';
    END IF;
    RETURN NEW;
END;
$$;

-- 绑定行：policy_id 只能在生效时改成本次申领（last_bundle_id）的库；生效版本可以随换绑变小，
-- 也可以因撤下变成空；生效版本必须有对应库的非撤下发布。
CREATE OR REPLACE FUNCTION protect_security_policy_site_binding()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
	IF TG_OP IN ('DELETE', 'TRUNCATE') THEN
		RAISE EXCEPTION 'security policy site bindings cannot be deleted';
    END IF;
    IF ROW(NEW.id, NEW.tenant_scope_id, NEW.site_id, NEW.policy_kind, NEW.created_at)
       IS DISTINCT FROM
       ROW(OLD.id, OLD.tenant_scope_id, OLD.site_id, OLD.policy_kind, OLD.created_at) OR
       NEW.revision <> OLD.revision + 1 OR NEW.updated_at < OLD.updated_at OR
       (NEW.policy_id IS DISTINCT FROM OLD.policy_id AND (
           NEW.last_bundle_id IS DISTINCT FROM OLD.last_bundle_id OR NOT EXISTS (
               SELECT 1 FROM security_policy_publications publication
               WHERE publication.id = NEW.last_bundle_id AND publication.policy_id = NEW.policy_id
           ))) OR
       (OLD.active_policy_version IS NOT NULL AND NEW.policy_id = OLD.policy_id AND
        NEW.active_policy_version IS NOT NULL AND NEW.active_policy_version < OLD.active_policy_version) OR
       (OLD.active_policy_version IS NOT NULL AND NEW.active_policy_version IS NULL AND NOT EXISTS (
           SELECT 1 FROM security_policy_publications publication
           WHERE publication.id = NEW.last_bundle_id AND publication.detach
       )) OR
       (OLD.last_claimed_policy_version IS NOT NULL AND NEW.last_claimed_policy_version IS NULL) OR
       (NEW.last_bundle_id IS NOT NULL AND NOT EXISTS (
           SELECT 1 FROM security_policy_publications publication
           WHERE publication.id = NEW.last_bundle_id AND publication.binding_id = NEW.id
             AND publication.tenant_scope_id = NEW.tenant_scope_id
             AND publication.policy_version = NEW.last_claimed_policy_version
       )) OR
       (NEW.active_policy_version IS NOT NULL AND NOT EXISTS (
           SELECT 1 FROM security_policy_publications publication
           WHERE publication.binding_id = NEW.id
             AND publication.tenant_scope_id = NEW.tenant_scope_id
             AND publication.policy_id = NEW.policy_id
             AND publication.policy_version = NEW.active_policy_version
             AND NOT publication.detach
       )) THEN
        RAISE EXCEPTION 'invalid security policy site binding transition';
    END IF;
    RETURN NEW;
END;
$$;

-- 换绑可能版本号不变（A v1 → B v1）：库变化也要触发聚合边缘同步。
DROP TRIGGER aggregated_edge_site_activated_375 ON security_policy_site_bindings;
CREATE TRIGGER aggregated_edge_site_activated_375 AFTER UPDATE OF active_policy_version, policy_id ON security_policy_site_bindings
    FOR EACH ROW WHEN (OLD.active_policy_version IS DISTINCT FROM NEW.active_policy_version OR
                       OLD.policy_id IS DISTINCT FROM NEW.policy_id)
    EXECUTE FUNCTION aggregated_edge_site_changed_375();
