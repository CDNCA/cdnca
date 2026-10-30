-- 522（r136 approval-center）回退：删审批中心两张表与 approvals.* 权限码。
LOCK TABLE schema_migrations, permissions, roles, role_permissions IN ACCESS EXCLUSIVE MODE;

DO $migration_522_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 522 OR
       (SELECT max(version) FROM schema_migrations) <> 522 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=522 AND
        migration_id='522_approval_center' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 522 down requires the exact verified migration head' USING ERRCODE='P5221';
    END IF;
END;
$migration_522_down$;

DROP TABLE approval_requests;
DROP TABLE approval_center_settings;

-- 系统角色上的删除被 role_permissions_system_role_guard 拦住（042），只在本事务内临时停用。
ALTER TABLE role_permissions DISABLE TRIGGER role_permissions_system_role_guard;
DELETE FROM role_permissions WHERE permission_name IN ('approvals.read', 'approvals.approve', 'approvals.manage');
ALTER TABLE role_permissions ENABLE TRIGGER role_permissions_system_role_guard;
DELETE FROM permissions WHERE name IN ('approvals.read', 'approvals.approve', 'approvals.manage');
