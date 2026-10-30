-- 498（r136 tp-b5b，主会话 10-25：最底层用户不能有管理员才有的能力）。分支占位 490（守卫指 489），
-- merge-p4 改号 498、前驱重钉 497（常量集中在 tenant_order_records_read_only_498_contract_test.go）。
-- 租户侧订单写入接口已撤：从 tenant_owner 收回 billing.order_records.manage；
-- "看全租户订单"拆成只读码 billing.order_records.read 发给 tenant_owner，新建 tenant_owner 同样只拿只读码。
LOCK TABLE schema_migrations, permissions, custom_rbac_permission_catalog, access_scopes,
    roles, role_permissions, account_order_records IN ACCESS EXCLUSIVE MODE;

DO $migration_498_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 497 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 497 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=497 AND
        migration_id='497_system_configuration_trim_region_overrides' AND
        checksum_sha256='1d70f77b38fee7d68a22643bc3511ad9d8d50b008a494e707444d4b8cc659fbc' AND
        down_checksum_sha256='8086cfce6e06bc5c1a414e0cf87e16bf107f929760495e5991243da74e1a680f' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR NOT EXISTS (SELECT 1 FROM permissions WHERE name='billing.order_records.manage')
         OR EXISTS (SELECT 1 FROM permissions WHERE name='billing.order_records.read') THEN
        RAISE EXCEPTION 'migration 498 requires the exact verified 497 release head' USING ERRCODE='P4980';
    END IF;
END;
$migration_498_up$;

INSERT INTO permissions(name,description) VALUES
    ('billing.order_records.read','View every member''s order records in the tenant');
INSERT INTO custom_rbac_permission_catalog(permission_name,step_up_required)
VALUES ('billing.order_records.read',false);

INSERT INTO role_permissions(role_id,permission_name)
SELECT role.id,'billing.order_records.read'
FROM roles role
JOIN access_scopes scope ON scope.id=role.scope_id AND scope.kind='tenant'
WHERE role.system_role AND role.name='tenant_owner'
ON CONFLICT DO NOTHING;

-- 系统角色上目录内权限的删除被 role_permissions_system_role_guard 拦住（042），只在本事务内临时停用。
ALTER TABLE role_permissions DISABLE TRIGGER role_permissions_system_role_guard;
DELETE FROM role_permissions grant_row
USING roles role, access_scopes scope
WHERE grant_row.role_id=role.id AND scope.id=role.scope_id AND scope.kind='tenant' AND
      role.system_role AND role.name='tenant_owner' AND
      grant_row.permission_name='billing.order_records.manage';
ALTER TABLE role_permissions ENABLE TRIGGER role_permissions_system_role_guard;

DROP TRIGGER roles_account_order_record_permission_207 ON roles;

CREATE FUNCTION grant_account_order_record_read_permission_498()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.system_role AND NEW.name='tenant_owner' AND EXISTS (
        SELECT 1 FROM access_scopes WHERE id=NEW.scope_id AND kind='tenant'
    ) THEN
        INSERT INTO role_permissions(role_id,permission_name)
        VALUES(NEW.id,'billing.order_records.read') ON CONFLICT DO NOTHING;
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER roles_account_order_record_read_permission_498
AFTER INSERT ON roles
FOR EACH ROW EXECUTE FUNCTION grant_account_order_record_read_permission_498();

REVOKE ALL ON FUNCTION grant_account_order_record_read_permission_498() FROM PUBLIC;

-- 订单记录改为只由平台管理员录入：207 把录入/修改人外键指向目标租户的成员，平台管理员不是租户成员，
-- 管理员端 /v1/admin/account/orders 因此一直写不进库（23503）。录入/修改人改指 users(id)。
ALTER TABLE account_order_records
    DROP CONSTRAINT account_order_records_tenant_scope_id_created_by_user_id_fkey,
    DROP CONSTRAINT account_order_records_tenant_scope_id_updated_by_user_id_fkey,
    ADD CONSTRAINT account_order_records_created_by_user_498_fkey
        FOREIGN KEY(created_by_user_id) REFERENCES users(id) ON DELETE RESTRICT,
    ADD CONSTRAINT account_order_records_updated_by_user_498_fkey
        FOREIGN KEY(updated_by_user_id) REFERENCES users(id) ON DELETE RESTRICT;

DO $migration_498_check$
BEGIN
    IF EXISTS (
        SELECT 1 FROM role_permissions grant_row
        JOIN roles role ON role.id=grant_row.role_id
        JOIN access_scopes scope ON scope.id=role.scope_id
        WHERE scope.kind='tenant' AND role.system_role AND
              grant_row.permission_name='billing.order_records.manage'
    ) THEN
        RAISE EXCEPTION 'tenant system roles still hold billing.order_records.manage' USING ERRCODE='P4981';
    END IF;
END;
$migration_498_check$;
