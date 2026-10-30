LOCK TABLE schema_migrations, l4_stream_user_defaults
IN ACCESS EXCLUSIVE MODE;

DO $migration_237$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 236 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 236 OR EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE migration_id IS NULL OR migration_id = '' OR
              checksum_sha256 IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
              down_checksum_sha256 IS NULL OR down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR
              integrity_state IS DISTINCT FROM 'verified' OR
              metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version = 236 AND migration_id = '236_l4_stream_groups_and_defaults' AND
              checksum_sha256 = 'cd3ae7c94469bcc37595e8169ff431ef7e46580ee3369bc127ee2305f751f65f' AND
              down_checksum_sha256 = '2cf881d6a733b8a48bc05ed5df2c5340741981c841f1a6da8c1e4b84f8c767fb' AND
              integrity_state = 'verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR to_regclass(current_schema() || '.l4_stream_user_defaults') IS NULL THEN
        RAISE EXCEPTION 'migration 237 requires the exact verified 236 release head and the stream defaults table'
            USING ERRCODE = 'P2370';
    END IF;
END;
$migration_237$;

-- 删除默认设置时先 SELECT ... FOR UPDATE 锁行再删（store_defaults.go 的 lockUserDefault），
-- 而 236 只给了 SELECT/INSERT/DELETE，行锁要求的 UPDATE 缺失，删除会以 42501 收场。
-- 补齐 UPDATE 后权限矩阵与同一批次的 l4_stream_groups（arwd）一致。
DO $l4_stream_user_defaults_lock_grant$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'cdnca_control_app') THEN
        GRANT UPDATE ON l4_stream_user_defaults TO cdnca_control_app;
    END IF;
END;
$l4_stream_user_defaults_lock_grant$;
