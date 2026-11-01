-- 602 回退：migration_marker 改回 030 的旧值并恢复 030 的 CHECK（存量行一一对应改回，不丢数据）。
LOCK TABLE schema_migrations, url_auth_policies IN ACCESS EXCLUSIVE MODE;

DO $migration_602_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 602 OR
       (SELECT max(version) FROM schema_migrations) <> 602 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=602 AND
        migration_id='602_url_auth_legacy_marker' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 602 down requires the exact verified migration head' USING ERRCODE='P6021';
    END IF;
END;
$migration_602_down$;

ALTER TABLE url_auth_policies DROP CONSTRAINT url_auth_policies_migration_marker_check;
UPDATE url_auth_policies SET migration_marker = 'cdnfly_type_a_md5' WHERE migration_marker = 'legacy_type_a_md5';
UPDATE url_auth_policies SET migration_marker = 'cdnfly_type_b_md5' WHERE migration_marker = 'legacy_type_b_md5';
ALTER TABLE url_auth_policies ADD CONSTRAINT url_auth_policies_migration_marker_check
    CHECK (migration_marker IN ('cdnfly_type_a_md5', 'cdnfly_type_b_md5'));
