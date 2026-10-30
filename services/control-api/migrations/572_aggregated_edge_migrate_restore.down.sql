-- 572（fix-cfundo）回退：删迁入撤回列，状态回到五种（存在 restoring/restored 记录时回退失败）。
LOCK TABLE schema_migrations, cdn_import_migrations IN ACCESS EXCLUSIVE MODE;

DO $migration_572_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 572 OR
       (SELECT max(version) FROM schema_migrations) <> 572 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=572 AND
        migration_id='572_aggregated_edge_migrate_restore' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 572 down requires the exact verified migration head' USING ERRCODE='P5721';
    END IF;
END;
$migration_572_down$;

ALTER TABLE cdn_import_migrations
    DROP CONSTRAINT cdn_import_migrations_supply_572_check,
    DROP CONSTRAINT cdn_import_migrations_restored_572_check,
    DROP COLUMN restored_at, DROP COLUMN restored_by, DROP COLUMN restore_error_code, DROP COLUMN restore_result,
    DROP COLUMN hostname_remote_id, DROP COLUMN binding, DROP COLUMN supply_id,
    DROP CONSTRAINT cdn_import_migrations_state_check,
    ADD CONSTRAINT cdn_import_migrations_state_check CHECK (
        state IN ('planned', 'applied', 'failed', 'cancelled', 'superseded'));
