-- 613 回退：两处引用判定恢复 551/085 原文（已删站点的绑定重新算引用）。
-- 已软删的证书不可变，回退不影响已完成的删除，所以不需要拒绝回滚。
LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;

DO $migration_613_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 613 OR
       (SELECT max(version) FROM schema_migrations) <> 613 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=613 AND
        migration_id='613_certificate_binding_deleted_site' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 613 down requires the exact verified migration head' USING ERRCODE='P6131';
    END IF;
END;
$migration_613_down$;

CREATE OR REPLACE FUNCTION certificate_asset_bound_551(scope_id uuid, asset_id uuid)
RETURNS boolean LANGUAGE sql STABLE SET search_path FROM CURRENT AS $$
    SELECT EXISTS (
        SELECT 1 FROM (
            SELECT DISTINCT ON (fact.site_id) fact.action, fact.asset_id
            FROM certificate_site_binding_facts fact
            WHERE fact.tenant_scope_id = $1
            ORDER BY fact.site_id, fact.sequence DESC
        ) current_binding
        WHERE current_binding.action = 'bind' AND current_binding.asset_id = $2
    )
$$;

CREATE OR REPLACE FUNCTION protect_certificate_asset()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP IN ('DELETE', 'TRUNCATE') THEN
        RAISE EXCEPTION 'certificate assets cannot be physically removed';
    END IF;
    IF TG_OP = 'INSERT' THEN
        IF NEW.revision <> 1 OR NEW.deleted_at IS NOT NULL OR NEW.deleted_by_user_id IS NOT NULL
           OR NEW.deleted_by_scope_id IS NOT NULL THEN
            RAISE EXCEPTION 'certificate asset must start at revision one without a tombstone';
        END IF;
        RETURN NEW;
    END IF;
    IF OLD.deleted_at IS NOT NULL THEN
        RAISE EXCEPTION 'deleted certificate asset is immutable';
    END IF;
    IF NEW.tenant_scope_id IS DISTINCT FROM OLD.tenant_scope_id
       OR NEW.id IS DISTINCT FROM OLD.id
       OR NEW.name IS DISTINCT FROM OLD.name
       OR NEW.source IS DISTINCT FROM OLD.source
       OR NEW.created_by_scope_id IS DISTINCT FROM OLD.created_by_scope_id
       OR NEW.created_by_user_id IS DISTINCT FROM OLD.created_by_user_id
       OR NEW.created_at IS DISTINCT FROM OLD.created_at
       OR NEW.revision <> OLD.revision + 1
       OR NEW.updated_at < OLD.updated_at THEN
        RAISE EXCEPTION 'certificate asset revision must advance by one';
    END IF;
    IF NEW.deleted_at IS NOT NULL AND EXISTS (
        SELECT 1
        FROM (
            SELECT DISTINCT ON (site_id) site_id, action, asset_id
            FROM certificate_site_binding_facts
            WHERE tenant_scope_id = OLD.tenant_scope_id
            ORDER BY site_id, sequence DESC
        ) current_binding
        WHERE current_binding.action = 'bind' AND current_binding.asset_id = OLD.id
    ) THEN
        RAISE EXCEPTION 'referenced certificate asset cannot be deleted';
    END IF;
    RETURN NEW;
END;
$$;
