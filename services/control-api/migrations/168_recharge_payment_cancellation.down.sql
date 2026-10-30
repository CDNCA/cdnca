LOCK TABLE schema_migrations,permissions,custom_rbac_permission_catalog,roles,role_permissions,
    recharge_payment_cancellations_v1,recharge_payment_cancellation_attempts_v1 IN ACCESS EXCLUSIVE MODE;

DO $migration_168$
BEGIN
    IF (SELECT count(*) FROM schema_migrations)<>168 OR
       (SELECT min(version) FROM schema_migrations)<>1 OR
       (SELECT max(version) FROM schema_migrations)<>168 OR EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE migration_id IS NULL OR migration_id='' OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
              down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR integrity_state IS DISTINCT FROM 'verified' OR
              metadata_recorded_at IS NULL OR applied_at IS NULL
    ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version=168 AND migration_id='168_recharge_payment_cancellation' AND
              checksum_sha256='afbcb3861d04a9d76933ca497789000dbcfec30cf5bfa2a3f1640775b303ecba' AND
              integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
    ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version=167 AND migration_id='167_http_policy_edge_source_revision' AND
              checksum_sha256='a4409fe5ab7ced09a42212526a956979a1dabe2d6a036fbb59a8169f0fdaf1e3' AND
              down_checksum_sha256='23784306af9c4f4dc12439b019961e650891b3db9ac01f2ebb2853e08ed73da4' AND
              integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
    ) THEN
        RAISE EXCEPTION 'migration 168 rollback requires the exact verified 168 head' USING ERRCODE='P1680';
    END IF;
    IF EXISTS (SELECT 1 FROM recharge_payment_cancellations_v1) OR
       EXISTS (SELECT 1 FROM recharge_payment_cancellation_attempts_v1) THEN
        RAISE EXCEPTION 'migration 168 rollback would discard recharge payment cancellation facts' USING ERRCODE='P1683';
    END IF;
    IF EXISTS (
        SELECT 1 FROM role_permissions grant_row
        JOIN roles role ON role.id=grant_row.role_id
        WHERE grant_row.permission_name='billing.recharges.cancel' AND NOT role.system_role
    ) THEN
        RAISE EXCEPTION 'migration 168 rollback requires non-system cancellation grants to be removed' USING ERRCODE='P1684';
    END IF;
END;
$migration_168$;

DROP TRIGGER recharge_payment_cancellation_attempts_truncate_168 ON recharge_payment_cancellation_attempts_v1;
DROP TRIGGER recharge_payment_cancellations_truncate_168 ON recharge_payment_cancellations_v1;
DROP TRIGGER recharge_payment_cancellation_attempts_validate_168 ON recharge_payment_cancellation_attempts_v1;
DROP TRIGGER recharge_payment_cancellation_attempts_append_only_168 ON recharge_payment_cancellation_attempts_v1;
DROP TRIGGER recharge_payment_cancellations_guard_168 ON recharge_payment_cancellations_v1;
DROP TRIGGER roles_recharge_payment_cancel_permission_168 ON roles;

DROP TABLE recharge_payment_cancellation_attempts_v1;
DROP TABLE recharge_payment_cancellations_v1;

DROP FUNCTION prevent_recharge_payment_cancellation_truncate_168();
DROP FUNCTION prevent_recharge_payment_cancellation_attempt_mutation_168();
DROP FUNCTION validate_recharge_payment_cancellation_attempt_168();
DROP FUNCTION guard_recharge_payment_cancellation_head_168();
DROP FUNCTION grant_recharge_payment_cancel_permission_168();

DELETE FROM custom_rbac_permission_catalog WHERE permission_name='billing.recharges.cancel';
DELETE FROM role_permissions WHERE permission_name='billing.recharges.cancel';
DELETE FROM permissions WHERE name='billing.recharges.cancel';
