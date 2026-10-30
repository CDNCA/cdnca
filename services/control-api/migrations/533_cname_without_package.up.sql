-- 533（fix-nopkg，用户 10-26 22:5x 批准方案 B）：站点没选套餐也生成 CNAME。
-- 前驱 532（fix-adminall），守卫钉 532 校验和。
LOCK TABLE schema_migrations, node_line_groups, cname_allocation_targets, cname_allocation_intents, sites
    IN ACCESS EXCLUSIVE MODE;

DO $migration_533_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 532 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 532 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=532 AND
        migration_id='532_platform_admin_all_tenants' AND
        checksum_sha256='30db4d5210181ea5220c65e495ca0a3e0ac8f5e6938e941ab1e98b4ca958ed0f' AND
        down_checksum_sha256='46c3d75d37cccb42112e186112ce65be5f653418db06020329cc2f0d106fbe87' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR EXISTS (
        SELECT 1 FROM information_schema.columns WHERE table_schema=current_schema()
          AND table_name='node_line_groups' AND column_name='is_platform_default'
       ) THEN
        RAISE EXCEPTION 'migration 533 requires the exact verified 532 release head' USING ERRCODE='P5330';
    END IF;
END;
$migration_533_up$;

-- 平台默认线路组：没选套餐的网站冻结 CNAME 目标 IP 时用它（cnameallocation insertFrozenTarget）。
-- 全平台至多一个；只能是平台作用域、普通用途、未删除的线路组；删除时自动取消。
ALTER TABLE node_line_groups ADD COLUMN is_platform_default boolean NOT NULL DEFAULT false;
CREATE UNIQUE INDEX node_line_groups_platform_default_533_key ON node_line_groups ((is_platform_default))
    WHERE is_platform_default;

CREATE FUNCTION assert_node_line_group_platform_default_533()
RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF NEW.deleted_at IS NOT NULL THEN
        NEW.is_platform_default := false;
    END IF;
    IF NEW.is_platform_default AND (NEW.purpose <> 'general' OR NOT EXISTS (
        SELECT 1 FROM access_scopes scope WHERE scope.id=NEW.tenant_scope_id AND scope.kind='platform')) THEN
        RAISE EXCEPTION 'only a general platform line group can be the platform default' USING ERRCODE='P5332';
    END IF;
    RETURN NEW;
END;
$$;
DO $migration_533_path$
BEGIN
    EXECUTE format('ALTER FUNCTION %I.assert_node_line_group_platform_default_533() SET search_path = pg_catalog, %I, pg_temp',
        current_schema(), current_schema());
END;
$migration_533_path$;
REVOKE ALL ON FUNCTION assert_node_line_group_platform_default_533() FROM PUBLIC;
-- "pl" 排在 protect_revision 之前：删除时先清标识，再走墓碑检查。
CREATE TRIGGER node_line_groups_platform_default_533
BEFORE INSERT OR UPDATE ON node_line_groups
FOR EACH ROW EXECUTE FUNCTION assert_node_line_group_platform_default_533();

-- 234 的线路组保护：设/取消平台默认只改这一列，不推进修订（修订快照不含该列）。
CREATE OR REPLACE FUNCTION protect_node_line_group()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'UPDATE' AND OLD.deleted_at IS NULL AND NEW.deleted_at IS NULL
       AND NEW.is_platform_default IS DISTINCT FROM OLD.is_platform_default
       AND to_jsonb(NEW) - 'is_platform_default' = to_jsonb(OLD) - 'is_platform_default' THEN
        RETURN NEW;
    END IF;
    IF TG_OP IN ('DELETE', 'TRUNCATE') THEN
        RAISE EXCEPTION 'node line groups cannot be physically deleted';
    END IF;
    IF TG_OP = 'INSERT' THEN
        IF NEW.resolved_value IS NULL OR NEW.resolved_value = '' THEN
            NEW.resolved_value := 'lg-' || replace(NEW.id::text, '-', '');
        END IF;
        IF NEW.ipv4_resolved_value IS NULL OR NEW.ipv4_resolved_value = '' THEN
            NEW.ipv4_resolved_value := 'v4-' || replace(NEW.id::text, '-', '');
        END IF;
        IF NEW.current_revision <> 1 OR NEW.deleted_at IS NOT NULL OR NEW.deleted_by_user_id IS NOT NULL THEN
            RAISE EXCEPTION 'node line group initial revision must be one without a tombstone';
        END IF;
        RETURN NEW;
    END IF;
    IF OLD.deleted_at IS NOT NULL THEN
        RAISE EXCEPTION 'deleted node line groups are immutable';
    END IF;
    IF NEW.deleted_at IS NOT NULL THEN
        IF NEW.id IS DISTINCT FROM OLD.id
           OR NEW.tenant_scope_id IS DISTINCT FROM OLD.tenant_scope_id
           OR NEW.name IS DISTINCT FROM OLD.name
           OR NEW.region IS DISTINCT FROM OLD.region
           OR NEW.resolved_value IS DISTINCT FROM OLD.resolved_value
           OR NEW.ipv4_resolved_value IS DISTINCT FROM OLD.ipv4_resolved_value
           OR NEW.l2_config_id IS DISTINCT FROM OLD.l2_config_id
           OR NEW.failover_mode IS DISTINCT FROM OLD.failover_mode
           OR NEW.note IS DISTINCT FROM OLD.note
           OR NEW.sort_order IS DISTINCT FROM OLD.sort_order
           OR NEW.current_revision IS DISTINCT FROM OLD.current_revision
           OR NEW.created_by_user_id IS DISTINCT FROM OLD.created_by_user_id
           OR NEW.created_at IS DISTINCT FROM OLD.created_at
           OR NEW.deleted_by_user_id IS NULL
           OR NEW.updated_by_user_id IS DISTINCT FROM NEW.deleted_by_user_id
           OR NEW.updated_at IS DISTINCT FROM NEW.deleted_at
           OR NEW.updated_at < OLD.updated_at THEN
            RAISE EXCEPTION 'node line group tombstone must preserve immutable configuration facts';
        END IF;
        RETURN NEW;
    END IF;
    IF NEW.deleted_by_user_id IS NOT NULL
       OR NEW.id IS DISTINCT FROM OLD.id
       OR NEW.tenant_scope_id IS DISTINCT FROM OLD.tenant_scope_id
       OR NEW.created_by_user_id IS DISTINCT FROM OLD.created_by_user_id
       OR NEW.created_at IS DISTINCT FROM OLD.created_at
       OR NEW.current_revision <> OLD.current_revision + 1
       OR NEW.updated_at < OLD.updated_at THEN
        RAISE EXCEPTION 'node line group revision must advance by one';
    END IF;
    RETURN NEW;
END;
$$;

-- 没选套餐的网站：意图与冻结目标不带套餐（126 的复合外键在列为空时不校验）。
ALTER TABLE cname_allocation_targets ALTER COLUMN package_subscription_id DROP NOT NULL;
ALTER TABLE cname_allocation_intents ALTER COLUMN package_subscription_id DROP NOT NULL,
    ADD CONSTRAINT cname_allocation_intents_no_package_533_check
        CHECK (package_subscription_id IS NOT NULL OR mode='site');

-- 479 的网站 CNAME 校验：意图套餐与网站套餐按 IS NOT DISTINCT FROM 比较（都为空时也匹配）。
CREATE OR REPLACE FUNCTION validate_sites_cname_authority_113()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
	intent_match record;
    binding_row cname_site_bindings%ROWTYPE;
    allocation_row cname_allocations%ROWTYPE;
    claim_row cname_hostname_claims%ROWTYPE;
    lkg_allocation_row cname_allocations%ROWTYPE;
    lkg_claim_row cname_hostname_claims%ROWTYPE;
    zone_default boolean;
BEGIN
    IF NEW.cname_mode IS NULL THEN RETURN NULL; END IF;
	SELECT intent.*,job.state AS intent_job_state INTO intent_match FROM cname_allocation_intents intent
    JOIN background_jobs job ON job.tenant_id=intent.tenant_id AND job.id=intent.job_id
    WHERE intent.tenant_scope_id=NEW.scope_id AND intent.site_id=NEW.id
      AND intent.package_subscription_id IS NOT DISTINCT FROM NEW.package_subscription_id
      AND intent.mode=NEW.cname_mode AND intent.domain=NEW.cname_domain
      AND intent.hostname=NEW.cname_hostname2 AND intent.job_id=NEW.cname_task_id
      AND job.kind='dns.cname.intent'
      AND job.state IN ('queued','running','failed','cancelled') ORDER BY intent.created_at DESC LIMIT 1;
    IF intent_match.job_id IS NOT NULL THEN
			IF ((intent_match.intent_job_state IN ('queued','running') AND NEW.cname_state<>'pending') OR
			    (intent_match.intent_job_state IN ('failed','cancelled') AND NEW.cname_state<>'failed')) OR NEW.cname_current_revision IS NULL OR
           (TG_OP='INSERT' AND (NEW.cname<>'' OR NEW.cname_lkg_revision IS NOT NULL)) OR
           (TG_OP='UPDATE' AND (NEW.cname IS DISTINCT FROM OLD.cname OR
                                NEW.cname_lkg_revision IS DISTINCT FROM OLD.cname_lkg_revision)) THEN
            RAISE EXCEPTION 'site CNAME intent projection is invalid' USING ERRCODE='P1264';
        END IF;
        RETURN NULL;
    END IF;
    SELECT * INTO binding_row FROM cname_site_bindings WHERE tenant_scope_id=NEW.scope_id AND site_id=NEW.id;
    SELECT * INTO allocation_row FROM cname_allocations WHERE tenant_scope_id=NEW.scope_id AND id=binding_row.current_allocation_id;
    SELECT * INTO claim_row FROM cname_hostname_claims WHERE id=allocation_row.current_claim_id AND allocation_id=allocation_row.id;
    SELECT is_default INTO zone_default FROM dns_zones WHERE scope_id=claim_row.tenant_scope_id AND id=claim_row.zone_id;
    IF binding_row.site_id IS NULL OR allocation_row.id IS NULL OR claim_row.id IS NULL OR
       allocation_row.mode IS DISTINCT FROM NEW.cname_mode OR allocation_row.state IS DISTINCT FROM NEW.cname_state OR
       allocation_row.job_id IS DISTINCT FROM NEW.cname_task_id OR
       allocation_row.current_revision IS DISTINCT FROM NEW.cname_current_revision OR
       (NEW.cname_domain<>'' AND NEW.cname_domain IS DISTINCT FROM claim_row.domain) OR
       (NEW.cname_domain='' AND zone_default IS DISTINCT FROM true) OR
       (NEW.cname_hostname2='' AND claim_row.explicit_hostname) OR
       (NEW.cname_hostname2<>'' AND (NOT claim_row.explicit_hostname OR NEW.cname_hostname2 IS DISTINCT FROM claim_row.hostname)) THEN
        RAISE EXCEPTION 'site CNAME projection does not match durable allocation authority' USING ERRCODE='P1134';
    END IF;
    IF binding_row.lkg_allocation_id IS NULL THEN
        IF NEW.cname_lkg_revision IS NOT NULL OR NEW.cname<>'' THEN
            RAISE EXCEPTION 'site CNAME without LKG allocation is invalid' USING ERRCODE='P1134';
        END IF;
    ELSE
        SELECT * INTO lkg_allocation_row FROM cname_allocations WHERE tenant_scope_id=NEW.scope_id AND id=binding_row.lkg_allocation_id;
        SELECT * INTO lkg_claim_row FROM cname_hostname_claims WHERE id=lkg_allocation_row.lkg_claim_id AND allocation_id=lkg_allocation_row.id;
        IF lkg_allocation_row.id IS NULL OR lkg_claim_row.id IS NULL OR
           lkg_allocation_row.owner_user_id IS DISTINCT FROM NEW.owner_user_id OR
           lkg_allocation_row.lkg_revision IS DISTINCT FROM NEW.cname_lkg_revision OR
           lkg_claim_row.hostname IS DISTINCT FROM NEW.cname THEN
            RAISE EXCEPTION 'site CNAME LKG projection does not match durable claim' USING ERRCODE='P1134';
        END IF;
    END IF;
    RETURN NULL;
END;
$$;
