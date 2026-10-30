-- 535（r136 fix-certowner，主会话 10-27 分配）：ACME 签发的证书记录所属用户。
-- 用户 10-27 反馈：ACME 证书列表显示"历史归属未记录"。根因：acmedispatch 导入 ACME 证书时
-- 不传 OwnerUserID，certificateasset 只给"租户会话手动上传"记 owner，ACME 资产一律 NULL。
-- 本迁移：
--   1) resolve_certificate_order_owner_535(租户 scope, 订单)：ACME 证书所属用户的唯一规则，
--      主控导入新 ACME 资产时调用（certificateasset importPreparedInTx），这里同用它回填。
--      按顺序取第一个"该租户 active 成员且账号 active"的用户：
--        ① 续签订单：父订单已签发资产的所属用户（续签沿用原证书归属）；
--        ② 下单人（certificate_orders.created_by_user_id）是该租户成员；
--        ③ 平台管理员代办：该租户唯一的 tenant_owner 成员（1.0.35 每个用户一个独立租户）；
--        ④ 该租户唯一的成员。
--      都不满足返回 NULL（页面显示"未指定用户"）。订单不记录站点，"网站入口申请"的站点所属用户
--      即该租户的用户，由 ③/④ 覆盖。
--   2) 回填：未删除、source='acme'、owner_user_id IS NULL 的资产按其首个版本的订单回填，按创建
--      时间先后逐条处理（续签资产能用上刚回填的父资产归属）。276 规定 owner 不可变、039/085 规定
--      资产更新须推进 revision 并复核操作人：回填补的是漏记的事实而非用户修改，故在本迁移内
--      （ACCESS EXCLUSIVE 锁下）临时停用这三个触发器，revision/updated_* 不变，结束即恢复。
-- 前驱 534，守卫钉 534 校验和。
LOCK TABLE schema_migrations, certificate_assets, certificate_asset_versions, certificate_orders,
    memberships, users, role_assignments, roles
IN ACCESS EXCLUSIVE MODE;

DO $migration_535_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 534 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 534 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=534 AND
        migration_id='534_platform_admin_period_reset_identity_review' AND
        checksum_sha256='ab837e36214ae42554bdea18dfa50379c64d9de308fa83914e51645e3b79e4c0' AND
        down_checksum_sha256='f68aa663825934ce5f9c2db599a7f586d663fdc4f27b0f01c8d70f85c40b645d' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR to_regprocedure('resolve_certificate_order_owner_535(uuid,uuid)') IS NOT NULL THEN
        RAISE EXCEPTION 'migration 535 requires the exact verified 534 release head' USING ERRCODE='P5350';
    END IF;
END;
$migration_535_up$;

CREATE FUNCTION resolve_certificate_order_owner_535(p_scope_id uuid, p_order_id uuid)
RETURNS uuid
LANGUAGE sql
STABLE
AS $$
    WITH active_member AS (
        SELECT membership.user_id
        FROM memberships membership
        JOIN users account ON account.id = membership.user_id AND account.status = 'active'
        WHERE membership.scope_id = p_scope_id AND membership.status = 'active'
    ), candidate AS (
        SELECT 1 AS rank, asset.owner_user_id AS user_id
        FROM certificate_orders child
        JOIN certificate_orders parent
          ON parent.scope_id = child.scope_id AND parent.id = child.renewal_of_order_id
        JOIN certificate_assets asset
          ON asset.tenant_scope_id = parent.scope_id AND asset.id = parent.issued_asset_id
        WHERE child.scope_id = p_scope_id AND child.id = p_order_id
        UNION ALL
        SELECT 2, certificate_order.created_by_user_id
        FROM certificate_orders certificate_order
        WHERE certificate_order.scope_id = p_scope_id AND certificate_order.id = p_order_id
        UNION ALL
        SELECT 3, min(owner_member.user_id::text)::uuid
        FROM active_member owner_member
        JOIN role_assignments assignment
          ON assignment.scope_id = p_scope_id AND assignment.user_id = owner_member.user_id
        JOIN roles role
          ON role.scope_id = assignment.scope_id AND role.id = assignment.role_id AND role.name = 'tenant_owner'
        HAVING count(DISTINCT owner_member.user_id) = 1
        UNION ALL
        SELECT 4, min(active_member.user_id::text)::uuid
        FROM active_member
        HAVING count(*) = 1
    )
    SELECT candidate.user_id
    FROM candidate
    JOIN active_member ON active_member.user_id = candidate.user_id
    ORDER BY candidate.rank
    LIMIT 1
$$;

ALTER TABLE certificate_assets DISABLE TRIGGER certificate_assets_protect;
ALTER TABLE certificate_assets DISABLE TRIGGER certificate_assets_owner_immutable_276;
ALTER TABLE certificate_assets DISABLE TRIGGER certificate_assets_actor_target_085;

DO $migration_535_backfill$
DECLARE
    item record;
BEGIN
    FOR item IN
        SELECT asset.tenant_scope_id, asset.id, version.acme_order_id
        FROM certificate_assets asset
        JOIN certificate_asset_versions version
          ON version.tenant_scope_id = asset.tenant_scope_id AND version.asset_id = asset.id
         AND version.version = 1
        WHERE asset.source = 'acme' AND asset.owner_user_id IS NULL AND asset.deleted_at IS NULL
          AND version.acme_order_id IS NOT NULL
        ORDER BY asset.created_at, asset.id
    LOOP
        UPDATE certificate_assets
        SET owner_user_id = resolve_certificate_order_owner_535(item.tenant_scope_id, item.acme_order_id)
        WHERE tenant_scope_id = item.tenant_scope_id AND id = item.id;
    END LOOP;
END;
$migration_535_backfill$;

ALTER TABLE certificate_assets ENABLE TRIGGER certificate_assets_protect;
ALTER TABLE certificate_assets ENABLE TRIGGER certificate_assets_owner_immutable_276;
ALTER TABLE certificate_assets ENABLE TRIGGER certificate_assets_actor_target_085;
