-- 498（r136 tp-b5b）回退：tenant_owner 收回只读码、重新拿回 billing.order_records.manage，恢复 207 的新建角色触发器。
LOCK TABLE schema_migrations, permissions, custom_rbac_permission_catalog, access_scopes,
    roles, role_permissions, account_order_records IN ACCESS EXCLUSIVE MODE;

DO $migration_498_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 498 OR
       (SELECT max(version) FROM schema_migrations) <> 498 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=498 AND
        migration_id='498_tenant_order_records_read_only' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 498 down requires the exact verified migration head' USING ERRCODE='P4982';
    END IF;
    IF EXISTS (
        SELECT 1 FROM role_permissions grant_row
        JOIN roles role ON role.id=grant_row.role_id
        WHERE grant_row.permission_name='billing.order_records.read' AND NOT role.system_role
    ) THEN
        RAISE EXCEPTION 'rollback requires custom billing.order_records.read grants to be removed'
            USING ERRCODE='P4983';
    END IF;
    IF EXISTS (
        SELECT 1 FROM account_order_records record
        WHERE NOT EXISTS (SELECT 1 FROM memberships m WHERE m.scope_id=record.tenant_scope_id AND m.user_id=record.created_by_user_id)
           OR NOT EXISTS (SELECT 1 FROM memberships m WHERE m.scope_id=record.tenant_scope_id AND m.user_id=record.updated_by_user_id)
    ) THEN
        RAISE EXCEPTION 'rollback would orphan administrator-entered order records' USING ERRCODE='P4984';
    END IF;
END;
$migration_498_down$;

ALTER TABLE account_order_records
    DROP CONSTRAINT account_order_records_created_by_user_498_fkey,
    DROP CONSTRAINT account_order_records_updated_by_user_498_fkey,
    ADD CONSTRAINT account_order_records_tenant_scope_id_created_by_user_id_fkey
        FOREIGN KEY(tenant_scope_id,created_by_user_id) REFERENCES memberships(scope_id,user_id) ON DELETE RESTRICT,
    ADD CONSTRAINT account_order_records_tenant_scope_id_updated_by_user_id_fkey
        FOREIGN KEY(tenant_scope_id,updated_by_user_id) REFERENCES memberships(scope_id,user_id) ON DELETE RESTRICT;

DROP TRIGGER roles_account_order_record_read_permission_498 ON roles;
DROP FUNCTION grant_account_order_record_read_permission_498();

CREATE TRIGGER roles_account_order_record_permission_207
AFTER INSERT ON roles
FOR EACH ROW EXECUTE FUNCTION grant_account_order_record_permission_207();

INSERT INTO role_permissions(role_id,permission_name)
SELECT role.id,'billing.order_records.manage'
FROM roles role
JOIN access_scopes scope ON scope.id=role.scope_id AND scope.kind='tenant'
WHERE role.system_role AND role.name='tenant_owner'
ON CONFLICT DO NOTHING;

ALTER TABLE role_permissions DISABLE TRIGGER role_permissions_system_role_guard;
DELETE FROM role_permissions WHERE permission_name='billing.order_records.read';
ALTER TABLE role_permissions ENABLE TRIGGER role_permissions_system_role_guard;
DELETE FROM custom_rbac_permission_catalog WHERE permission_name='billing.order_records.read';
DELETE FROM permissions WHERE name='billing.order_records.read';
