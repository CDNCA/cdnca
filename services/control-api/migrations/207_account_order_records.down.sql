LOCK TABLE schema_migrations, permissions, custom_rbac_permission_catalog, roles, role_permissions,
    account_order_records, account_order_record_events,
    account_order_record_write_receipts IN ACCESS EXCLUSIVE MODE;

DO $migration_207_down$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version=207
          AND migration_id='207_account_order_records'
          AND integrity_state='verified'
          AND metadata_recorded_at IS NOT NULL
          AND applied_at IS NOT NULL
    ) THEN
        RAISE EXCEPTION 'migration 207 rollback requires a verified 207 account-order head'
            USING ERRCODE='P2070';
    END IF;
    IF EXISTS(SELECT 1 FROM account_order_records) OR
       EXISTS(SELECT 1 FROM account_order_record_events) OR
       EXISTS(SELECT 1 FROM account_order_record_write_receipts) THEN
        RAISE EXCEPTION 'rollback would discard account order record facts'
            USING ERRCODE='P2074';
    END IF;
    IF EXISTS (
        SELECT 1 FROM role_permissions grant_row
        JOIN roles role ON role.id=grant_row.role_id
        WHERE grant_row.permission_name='billing.order_records.manage'
          AND NOT role.system_role
    ) THEN
        RAISE EXCEPTION 'rollback requires custom account order record grants to be removed'
            USING ERRCODE='P2075';
    END IF;
END;
$migration_207_down$;

REVOKE SELECT,INSERT,UPDATE ON account_order_records FROM cdnca_control_app;
REVOKE SELECT,INSERT ON account_order_record_events,account_order_record_write_receipts
    FROM cdnca_control_app;

DROP TRIGGER account_order_record_write_receipts_append_only_207
    ON account_order_record_write_receipts;
DROP TRIGGER account_order_record_events_append_only_207 ON account_order_record_events;
DROP TRIGGER account_order_records_no_truncate_207 ON account_order_records;
DROP TRIGGER account_order_records_head_guard_207 ON account_order_records;
DROP TRIGGER roles_account_order_record_permission_207 ON roles;
DROP FUNCTION prevent_account_order_record_fact_mutation_207();
DROP FUNCTION guard_account_order_record_head_207();
DROP FUNCTION grant_account_order_record_permission_207();
DROP TABLE account_order_record_write_receipts;
DROP TABLE account_order_record_events;
DROP TABLE account_order_records;

DELETE FROM custom_rbac_permission_catalog
WHERE permission_name='billing.order_records.manage';
DELETE FROM role_permissions WHERE permission_name='billing.order_records.manage';
DELETE FROM permissions
WHERE name='billing.order_records.manage';
