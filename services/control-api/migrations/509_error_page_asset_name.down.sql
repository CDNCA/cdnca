-- 509（r136 be-gap-2）回退：去掉错误页资产名称。名称只用于显示，回退直接丢弃。
LOCK TABLE schema_migrations, error_page_assets IN ACCESS EXCLUSIVE MODE;

DO $migration_509_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 509 OR
       (SELECT max(version) FROM schema_migrations) <> 509 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=509 AND
        migration_id='509_error_page_asset_name' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 509 down requires the exact verified migration head' USING ERRCODE='P5091';
    END IF;
END;
$migration_509_down$;

ALTER TABLE error_page_assets DROP COLUMN name;
