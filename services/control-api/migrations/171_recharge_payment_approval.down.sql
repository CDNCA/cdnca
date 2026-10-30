LOCK TABLE schema_migrations,permissions,custom_rbac_permission_catalog,roles,role_permissions,
    recharge_payment_approval_requests_v1,recharge_payment_approval_decisions_v1,
    recharge_payment_approval_executions_v1,recharge_payment_approval_receipts_v1 IN ACCESS EXCLUSIVE MODE;

DO $migration_171$
BEGIN
    IF (SELECT count(*) FROM schema_migrations)<>171 OR
       (SELECT min(version) FROM schema_migrations)<>1 OR
       (SELECT max(version) FROM schema_migrations)<>171 OR EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE migration_id IS NULL OR migration_id='' OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
              down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR integrity_state IS DISTINCT FROM 'verified' OR
              metadata_recorded_at IS NULL OR applied_at IS NULL
    ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version=171 AND migration_id='171_recharge_payment_approval' AND
		      checksum_sha256='0acba33bda1accbd9a4ae03eaebcb6fbd495be78c8e5fcb84a7fa57abf561ab9' AND
              integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
    ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version=170 AND migration_id='170_node_configuration_hpke' AND
              checksum_sha256='140d1689a8d3ce17e34cc8bc46598711364d9fe129ec36bb3e5f591c71f8f089' AND
              down_checksum_sha256='02db4682dcbcabdf057a714cfd10cd32332e5b8540872d41697cb78483fa2609' AND
              integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
    ) THEN
        RAISE EXCEPTION 'migration 171 rollback requires the exact verified 171 head' USING ERRCODE='P1710';
    END IF;
    IF EXISTS(SELECT 1 FROM recharge_payment_approval_requests_v1) OR
       EXISTS(SELECT 1 FROM recharge_payment_approval_decisions_v1) OR
       EXISTS(SELECT 1 FROM recharge_payment_approval_executions_v1) OR
       EXISTS(SELECT 1 FROM recharge_payment_approval_receipts_v1) THEN
        RAISE EXCEPTION 'migration 171 rollback would discard recharge payment approval facts' USING ERRCODE='P1718';
    END IF;
    IF EXISTS (
        SELECT 1 FROM role_permissions grant_row
        JOIN roles role ON role.id=grant_row.role_id
        WHERE grant_row.permission_name='billing.recharges.approve' AND NOT role.system_role
    ) THEN
        RAISE EXCEPTION 'migration 171 rollback requires non-system approval grants to be removed' USING ERRCODE='P1719';
    END IF;
END;
$migration_171$;

DROP TRIGGER recharge_payment_approval_receipts_truncate_171 ON recharge_payment_approval_receipts_v1;
DROP TRIGGER recharge_payment_approval_executions_truncate_171 ON recharge_payment_approval_executions_v1;
DROP TRIGGER recharge_payment_approval_decisions_truncate_171 ON recharge_payment_approval_decisions_v1;
DROP TRIGGER recharge_payment_approval_requests_truncate_171 ON recharge_payment_approval_requests_v1;
DROP TRIGGER recharge_payment_approval_receipts_immutable_171 ON recharge_payment_approval_receipts_v1;
DROP TRIGGER recharge_payment_approval_executions_immutable_171 ON recharge_payment_approval_executions_v1;
DROP TRIGGER recharge_payment_approval_decisions_immutable_171 ON recharge_payment_approval_decisions_v1;
DROP TRIGGER recharge_payment_approval_requests_immutable_171 ON recharge_payment_approval_requests_v1;
DROP TRIGGER recharge_payment_approval_executions_validate_171 ON recharge_payment_approval_executions_v1;
DROP TRIGGER recharge_payment_approval_decisions_validate_171 ON recharge_payment_approval_decisions_v1;
DROP TRIGGER recharge_payment_approval_requests_validate_171 ON recharge_payment_approval_requests_v1;
DROP TRIGGER roles_recharge_payment_approval_permission_171 ON roles;

DROP TABLE recharge_payment_approval_receipts_v1;
DROP TABLE recharge_payment_approval_executions_v1;
DROP TABLE recharge_payment_approval_decisions_v1;
DROP TABLE recharge_payment_approval_requests_v1;

DROP FUNCTION prevent_recharge_payment_approval_truncate_171();
DROP FUNCTION prevent_recharge_payment_approval_mutation_171();
DROP FUNCTION validate_recharge_payment_approval_171();
DROP FUNCTION grant_recharge_payment_approval_permission_171();

DELETE FROM custom_rbac_permission_catalog WHERE permission_name='billing.recharges.approve';
DELETE FROM role_permissions WHERE permission_name='billing.recharges.approve';
DELETE FROM permissions WHERE name='billing.recharges.approve';
