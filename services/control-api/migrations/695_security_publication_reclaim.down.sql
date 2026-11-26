-- 695 回退：validate_security_policy_publication_insert 恢复 470 的定义（已写入的重新申领发布是历史行，不改写）。
LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;
LOCK TABLE security_policy_site_bindings, security_policy_publications IN SHARE ROW EXCLUSIVE MODE;

DO $migration_695_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 695 OR
       (SELECT max(version) FROM schema_migrations) <> 695 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=695 AND
        migration_id='695_security_publication_reclaim' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 695 down requires the exact verified migration head' USING ERRCODE='P6951';
    END IF;
END;
$migration_695_down$;

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
