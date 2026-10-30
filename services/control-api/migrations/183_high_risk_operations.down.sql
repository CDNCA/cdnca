LOCK TABLE schema_migrations,permissions,custom_rbac_permission_catalog,roles,role_permissions,
    high_risk_operation_receipts,high_risk_operations,background_jobs,audit_events IN ACCESS EXCLUSIVE MODE;

DO $migration_183_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations)<>183 OR
       (SELECT min(version) FROM schema_migrations)<>1 OR
       (SELECT max(version) FROM schema_migrations)<>183 OR EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE migration_id IS NULL OR migration_id='' OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
              down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR integrity_state IS DISTINCT FROM 'verified' OR
              metadata_recorded_at IS NULL OR applied_at IS NULL
    ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version=183 AND migration_id='183_high_risk_operations' AND
              checksum_sha256='6b9944051f89399f001da2943cc9407904961c2149b4f3091c42b3e9dadca590' AND
              integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
    ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version=182 AND migration_id='182_node_isolation' AND
              checksum_sha256='bfc432e0cdf91e7f0d666c0229b98dee466ee26c729f4c98b77166b0cc4cd962' AND
              down_checksum_sha256='3f7b6dedf1749eae0f699e616731604f4a31609c36097def4ffbbeae21d58a27' AND
              integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
    ) THEN
        RAISE EXCEPTION 'migration 183 rollback requires the exact verified 183 and 182 release heads'
            USING ERRCODE='P1830';
    END IF;
    IF EXISTS (SELECT 1 FROM high_risk_operations) OR
       EXISTS (SELECT 1 FROM high_risk_operation_receipts) OR
       EXISTS (SELECT 1 FROM background_jobs WHERE kind='system.high_risk_operation.v1') OR
       EXISTS (SELECT 1 FROM audit_events WHERE action LIKE 'system_operation.%' OR
                                              resource_type='high_risk_operation') THEN
        RAISE EXCEPTION 'migration 183 rollback would discard high-risk operation, job, receipt, or audit facts'
            USING ERRCODE='P1831';
    END IF;
    IF EXISTS (
        SELECT 1 FROM role_permissions grant_row
        JOIN roles role ON role.id=grant_row.role_id
        WHERE grant_row.permission_name IN ('system_operations.manage','system_operations.execute')
          AND NOT role.system_role
    ) OR EXISTS (
        SELECT 1 FROM custom_role_revisions revision
        WHERE 'system_operations.manage'=ANY(revision.permissions) OR
              'system_operations.execute'=ANY(revision.permissions)
    ) THEN
        RAISE EXCEPTION 'migration 183 rollback requires all non-system high-risk operation grants to be removed'
            USING ERRCODE='P1832';
    END IF;
END;
$migration_183_down$;

DROP TRIGGER high_risk_operation_receipts_no_truncate_183 ON high_risk_operation_receipts;
DROP TRIGGER high_risk_operation_receipts_append_only_183 ON high_risk_operation_receipts;
DROP TRIGGER high_risk_operation_receipts_validate_183 ON high_risk_operation_receipts;
DROP TRIGGER high_risk_operations_no_truncate_183 ON high_risk_operations;
DROP TRIGGER high_risk_operations_guard_183 ON high_risk_operations;
DROP TRIGGER roles_high_risk_operation_permission_183 ON roles;

DROP TABLE high_risk_operation_receipts;
DROP TABLE high_risk_operations;

DROP FUNCTION reject_high_risk_operation_receipt_mutation_183();
DROP FUNCTION validate_high_risk_operation_receipt_183();
DROP FUNCTION reject_high_risk_operation_truncate_183();
DROP FUNCTION protect_high_risk_operation_183();
DROP FUNCTION grant_high_risk_operation_permission_183();

DELETE FROM custom_rbac_permission_catalog
WHERE permission_name IN ('system_operations.manage','system_operations.execute');
DELETE FROM role_permissions
WHERE permission_name IN ('system_operations.manage','system_operations.execute');
DELETE FROM permissions
WHERE name IN ('system_operations.manage','system_operations.execute');
