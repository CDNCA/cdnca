-- 645 回退：恢复 plugin_local_disables.reason（列名与 CHECK 与 644 相同）。回退时仍在停用中的行没有原因可还原，
-- 统一填「未填写」；其余与 644 一致。
LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;

DO $migration_645_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 645 OR
       (SELECT max(version) FROM schema_migrations) <> 645 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=645 AND
        migration_id='645_plugin_local_disables_no_reason' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 645 down requires the exact verified migration head' USING ERRCODE='P6451';
    END IF;
END;
$migration_645_down$;

ALTER TABLE plugin_local_disables ADD COLUMN reason text NOT NULL DEFAULT '未填写'
    CHECK (char_length(reason) BETWEEN 1 AND 500);
ALTER TABLE plugin_local_disables ALTER COLUMN reason DROP DEFAULT;
