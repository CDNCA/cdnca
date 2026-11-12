LOCK TABLE schema_migrations, sites, cname_label_settings IN ACCESS EXCLUSIVE MODE;

DO $migration_658_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 658 OR
       (SELECT max(version) FROM schema_migrations) <> 658 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=658 AND migration_id='658_cname_custom_label' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 658 down requires the exact verified migration head' USING ERRCODE='P6583';
    END IF;
    -- 已设置的名称或前缀无法用 657 的结构表达。
    IF EXISTS (SELECT 1 FROM sites WHERE cname_custom_label IS NOT NULL) OR
       EXISTS (SELECT 1 FROM cname_label_settings) THEN
        RAISE EXCEPTION 'migration 658 rollback would drop custom CNAME names' USING ERRCODE='P6584';
    END IF;
END;
$migration_658_down$;

DROP TABLE cname_label_settings;
ALTER TABLE sites DROP CONSTRAINT sites_cname_custom_label_658_check, DROP COLUMN cname_custom_label;
