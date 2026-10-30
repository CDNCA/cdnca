LOCK TABLE schema_migrations, escalate_package_policies, package_products IN ACCESS EXCLUSIVE MODE;

DO $migration_484_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 483 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 483 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=483 AND
        migration_id='483_reseller_billing' AND
        checksum_sha256='062c1b0db7110049aef458683e9d3214c2d74dba683005e7d66642b367294d6f' AND
        down_checksum_sha256='1c03ce007118f84f1bbc03df23cb38b5fe7cf9c2f5daad5da4e290e2178a096c' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR to_regprocedure('guard_escalate_package_policy_460()') IS NULL OR NOT EXISTS (
        SELECT 1 FROM information_schema.columns WHERE table_schema=current_schema() AND
        table_name='package_products' AND column_name='owner_scope_id') THEN
        RAISE EXCEPTION 'migration 484 requires the exact verified 483 release head' USING ERRCODE='P4840';
    END IF;
    -- 484 之前只有平台能写策略（PUT 路由 platformOnly），所有者必然等于套餐所有者；不符说明数据被手工改过，拒绝而不是改写。
    IF EXISTS (SELECT 1 FROM escalate_package_policies policy JOIN package_products product ON product.id = policy.product_id
        WHERE policy.owner_scope_id <> product.owner_scope_id) THEN
        RAISE EXCEPTION 'migration 484 found escalation policies owned by another scope than their package' USING ERRCODE='P4841';
    END IF;
END;
$migration_484_up$;

-- 484（r136 rs-04-escalate，ADR 0018 §7 / RS-04；482 = RS-07、483 = RS-03 本地占位，合入时按集成头改号并重钉前驱）。
-- 代理商给自己名下的套餐配攻击自动升级 A/B/C（10-22 19:10：A/B/C 由套餐所有者设置）：策略所有者必须是套餐所有者。
-- B/C 的线路组可用性与等级仍由 460 守卫判（scope_may_use_line_group_460(owner, …)，代理商只能选平台授权给它的组）。
--
-- 错误码：P4840 前驱不符；P4841 存量策略所有者与套餐所有者不符；P4842 策略所有者须为套餐所有者；P4843 down 前驱不符。

CREATE FUNCTION guard_escalate_policy_owner_484() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM package_products product
        WHERE product.id = NEW.product_id AND product.owner_scope_id = NEW.owner_scope_id) THEN
        RAISE EXCEPTION 'escalation policy owner is the package owner' USING ERRCODE='P4842';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER escalate_package_policies_owner_484
BEFORE INSERT OR UPDATE ON escalate_package_policies
FOR EACH ROW EXECUTE FUNCTION guard_escalate_policy_owner_484();

DO $migration_484_path$
BEGIN
    EXECUTE format('ALTER FUNCTION %I.guard_escalate_policy_owner_484() SET search_path = pg_catalog, %I, pg_temp',
        current_schema(), current_schema());
END;
$migration_484_path$;

REVOKE ALL ON FUNCTION guard_escalate_policy_owner_484() FROM PUBLIC;
