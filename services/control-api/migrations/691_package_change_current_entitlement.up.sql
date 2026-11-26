-- 691（前驱 690_source_ip_header_reset）。
-- 升级/降级在 package_subscription_entitlement_versions 追加当前权益，package_subscriptions 上的
-- product_id/product_revision/product_snapshot 仍是初购事实（261：不可变的历史审计记录，这里不改）。
-- 站点读写、编译限额与能力、线路拓扑、CNAME 上下文改读「当前生效权益」：
--   package_subscription_current_product_id / _snapshot(订阅, 时刻) = 该时刻生效的权益版本
--   （package_subscription_effective_entitlement_revision，同作用域），没有生效版本时回落到订阅行。
-- 定时生效（next_cycle）的改套餐到生效时刻才改变编译结果：到期扫描按
-- package_entitlement_republication_marks 记下已为哪个权益版本发布过，生效版本越过标记且其间有
-- upgrade/downgrade 时发布一次（立即生效的改套餐在履约事务里已发布并写标记）。
-- 错误码：头检查 P6910；down 头检查 P6911。
LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;

DO $migration_691_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 690 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 690 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=690 AND
        migration_id='690_source_ip_header_reset' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR
       to_regprocedure('package_subscription_effective_entitlement_revision(uuid,timestamptz)') IS NULL OR
       to_regprocedure('package_subscription_current_product_id(uuid,timestamptz)') IS NOT NULL OR
       to_regprocedure('package_subscription_current_product_snapshot(uuid,timestamptz)') IS NOT NULL OR
       to_regclass(current_schema() || '.package_entitlement_republication_marks') IS NOT NULL THEN
        RAISE EXCEPTION 'migration 691 requires the exact verified 690 release head' USING ERRCODE='P6910';
    END IF;
END;
$migration_691_up$;

CREATE FUNCTION package_subscription_current_product_id(p_subscription uuid, p_at timestamptz)
RETURNS uuid LANGUAGE sql STABLE AS $$
 SELECT coalesce(e.product_id,s.product_id) FROM package_subscriptions s
 LEFT JOIN package_subscription_entitlement_versions e ON e.subscription_id=s.id AND e.tenant_scope_id=s.tenant_scope_id
  AND e.revision=package_subscription_effective_entitlement_revision(s.id,p_at)
 WHERE s.id=p_subscription;
$$;

CREATE FUNCTION package_subscription_current_product_snapshot(p_subscription uuid, p_at timestamptz)
RETURNS jsonb LANGUAGE sql STABLE AS $$
 SELECT coalesce(e.product_snapshot,s.product_snapshot) FROM package_subscriptions s
 LEFT JOIN package_subscription_entitlement_versions e ON e.subscription_id=s.id AND e.tenant_scope_id=s.tenant_scope_id
  AND e.revision=package_subscription_effective_entitlement_revision(s.id,p_at)
 WHERE s.id=p_subscription;
$$;

CREATE TABLE package_entitlement_republication_marks (
    subscription_id uuid PRIMARY KEY REFERENCES package_subscriptions(id) ON DELETE CASCADE,
    tenant_scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE RESTRICT,
    entitlement_revision bigint NOT NULL CHECK (entitlement_revision > 0),
    observed_at timestamptz NOT NULL CHECK (isfinite(observed_at))
);
