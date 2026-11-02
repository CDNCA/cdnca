-- 614（r136 fix-siteadd，COORD.md 11-01 登记 control 614，前驱 613_certificate_binding_deleted_site）：
--   1.0.35 全新安装实测：用户自己购买开通的套餐（含 0 元免费套餐）下建站一律 400 validation_error。
--   建站（prepareCNAMEWriteIntent）、CNAME 分配与 sites_package_subscription_owner_113_fk
--   都要求订阅在 package_monitor_subscription_owners 有归属行；该表只由后台开通
--   （packagesubscription.Open）写，购买履约从未写过。代码已改为购买履约时写入
--   （source_kind='commerce_fulfillment'），这里回填存量：没有归属行、由一条购买履约开通的订阅，
--   按 078 触发器的同一证明（该修订恰好一条履约、订单属于该用户、状态版本的所有者一致）补一行。
--   成员已停用或是平台成员的订阅不满足 078 触发器，跳过（与购买时同样不可建站）。
LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;

DO $migration_614_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 613 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 613 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=613 AND
        migration_id='613_certificate_binding_deleted_site' AND
        checksum_sha256='31f4381f7704eaa74bd365dad3f9e6336be01e4657af41b75afbab85be39829e' AND
        down_checksum_sha256='6d3f5415483f464835fb4dcdc2978999ad85d26d5af5c07f418eaa96e2cc6ca5' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) THEN
        RAISE EXCEPTION 'migration 614 requires the exact verified 613 release head' USING ERRCODE='P6140';
    END IF;
END;
$migration_614_up$;

INSERT INTO package_monitor_subscription_owners (
    subscription_id, state_revision, tenant_scope_id, owner_user_id,
    source_kind, source_fulfillment_id, created_at
)
SELECT fulfillment.subscription_id, fulfillment.subscription_revision, fulfillment.tenant_scope_id,
       package_order.user_id, 'commerce_fulfillment', fulfillment.id, fulfillment.fulfilled_at
FROM package_order_fulfillments AS fulfillment
JOIN package_orders AS package_order
  ON package_order.id = fulfillment.order_id
 AND package_order.tenant_scope_id = fulfillment.tenant_scope_id
 AND package_order.operation = 'purchase'
 AND package_order.product_kind = 'package_subscription'
 AND (package_order.subscription_id IS NULL OR package_order.subscription_id = fulfillment.subscription_id)
JOIN package_subscription_state_versions AS state
  ON state.subscription_id = fulfillment.subscription_id
 AND state.revision = fulfillment.subscription_revision
 AND state.tenant_scope_id = fulfillment.tenant_scope_id
 AND state.owner_user_id = package_order.user_id
JOIN memberships AS membership
  ON membership.scope_id = fulfillment.tenant_scope_id
 AND membership.user_id = package_order.user_id
 AND membership.status = 'active'
WHERE fulfillment.subscription_id IS NOT NULL
  AND NOT EXISTS (
    SELECT 1 FROM package_monitor_subscription_owners AS owner
    WHERE owner.subscription_id = fulfillment.subscription_id
  )
  AND (SELECT count(*) FROM package_order_fulfillments AS same_revision
       WHERE same_revision.subscription_id = fulfillment.subscription_id
         AND same_revision.subscription_revision = fulfillment.subscription_revision) = 1
  AND NOT EXISTS (
    SELECT 1 FROM memberships AS platform_membership
    JOIN access_scopes AS platform_scope
      ON platform_scope.id = platform_membership.scope_id AND platform_scope.kind = 'platform'
    WHERE platform_membership.user_id = package_order.user_id
  );
