-- 602（r136 fix-urlauthname，主会话预留 control 602，前驱 601 = fix-chaintenant）：
-- URL 鉴权迁移来源枚举去品牌名（用户 10-29 定"值也改掉"）：
--   url_auth_policies.migration_marker 'cdnfly_type_a_md5'/'cdnfly_type_b_md5' 改为 'legacy_type_a_md5'/'legacy_type_b_md5'。
-- 030 已上线不改；本迁移按 PG 自动命名的列约束 url_auth_policies_migration_marker_check 删旧 CHECK、改写存量行、加只含新值的 CHECK。
LOCK TABLE schema_migrations, url_auth_policies IN ACCESS EXCLUSIVE MODE;

DO $migration_602_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 601 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 601 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=601 AND
        migration_id='601_aggregated_edge_tenant_chain' AND
        checksum_sha256='376d89284298907cee97b51501691ac64e39f00d9d5f0722e2d2fa5eceaa1311' AND
        down_checksum_sha256='7327430409a8df4d9e1bc80fb8f0c7df287744afd2af53566717d9dcae4fd1bc' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR NOT EXISTS (
        SELECT 1 FROM pg_catalog.pg_constraint
        WHERE conrelid='url_auth_policies'::regclass AND conname='url_auth_policies_migration_marker_check'
       ) THEN
        RAISE EXCEPTION 'migration 602 requires the exact verified 601 release head' USING ERRCODE='P6020';
    END IF;
END;
$migration_602_up$;

ALTER TABLE url_auth_policies DROP CONSTRAINT url_auth_policies_migration_marker_check;
UPDATE url_auth_policies SET migration_marker = 'legacy_type_a_md5' WHERE migration_marker = 'cdnfly_type_a_md5';
UPDATE url_auth_policies SET migration_marker = 'legacy_type_b_md5' WHERE migration_marker = 'cdnfly_type_b_md5';
ALTER TABLE url_auth_policies ADD CONSTRAINT url_auth_policies_migration_marker_check
    CHECK (migration_marker IN ('legacy_type_a_md5', 'legacy_type_b_md5'));
