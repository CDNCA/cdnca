-- 613（r136 cert-publish-fix 第 5 项，COORD.md 11-01 登记 control 613，前驱 612_certificate_unpublish_noop）：
--   73 实测：站点 e1035b-site 删除（204，软删）后，它绑定的证书删除返回 409 certificate_asset_referenced。
--   "证书仍被网站引用"只看站点最后一条绑定事实是否为 bind，不管站点已软删；对已删站点解绑又 404，
--   没有正规接口能解开。站点软删不可恢复（没有任何路径把 sites.deleted_at 改回 NULL），
--   已删站点的绑定不再生效，不算引用。
--   改两处判定，规则只有一份：
--   - certificate_asset_bound_551（禁用证书的兜底触发器与 Go 的删除/禁用判定都调用它）排除已软删站点；
--   - protect_certificate_asset（085，证书软删兜底）改为调用 certificate_asset_bound_551。
--   存量"站点已删、绑定未释放"的数据自动不再算引用，无需回填。
LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;

DO $migration_613_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 612 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 612 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=612 AND
        migration_id='612_certificate_unpublish_noop' AND
        checksum_sha256='88d0d565e361e4613bf5a53230c3823ff4e2ff3c5fc55a2e33db0f2cea326920' AND
        down_checksum_sha256='890d4dedf565629e9e0ed512a18f997fa387cd90c0cd85aa31ca186b2bf6c94d' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR NOT EXISTS (
        SELECT 1 FROM pg_proc WHERE proname='certificate_asset_bound_551'
          AND pronamespace=current_schema()::regnamespace
       ) THEN
        RAISE EXCEPTION 'migration 613 requires the exact verified 612 release head' USING ERRCODE='P6130';
    END IF;
END;
$migration_613_up$;

-- 当前被网站绑定的证书：站点最后一条绑定事实是 bind，且站点未软删。
CREATE OR REPLACE FUNCTION certificate_asset_bound_551(scope_id uuid, asset_id uuid)
RETURNS boolean LANGUAGE sql STABLE SET search_path FROM CURRENT AS $$
    SELECT EXISTS (
        SELECT 1 FROM (
            SELECT DISTINCT ON (fact.site_id) fact.site_id, fact.action, fact.asset_id
            FROM certificate_site_binding_facts fact
            WHERE fact.tenant_scope_id = $1
            ORDER BY fact.site_id, fact.sequence DESC
        ) current_binding
        WHERE current_binding.action = 'bind' AND current_binding.asset_id = $2
          AND NOT EXISTS (
            SELECT 1 FROM sites site
            WHERE site.id = current_binding.site_id AND site.scope_id = $1 AND site.deleted_at IS NOT NULL
          )
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
    IF NEW.deleted_at IS NOT NULL AND certificate_asset_bound_551(OLD.tenant_scope_id, OLD.id) THEN
        RAISE EXCEPTION 'referenced certificate asset cannot be deleted';
    END IF;
    RETURN NEW;
END;
$$;
