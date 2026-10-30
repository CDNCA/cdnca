LOCK TABLE schema_migrations, l4_stream_group_display_id_sequences,
    l4_stream_user_default_display_id_sequences
IN ACCESS EXCLUSIVE MODE;

DO $migration_238_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 237 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 237 OR EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE migration_id IS NULL OR migration_id = '' OR
              checksum_sha256 IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
              down_checksum_sha256 IS NULL OR down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR
              integrity_state IS DISTINCT FROM 'verified' OR
              metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version = 237 AND migration_id = '237_l4_stream_user_defaults_lock_grant' AND
              checksum_sha256 = 'e45850337ba6918c65ee6887926cd991644025e8bf8aad12353081b7fdb2611a' AND
              down_checksum_sha256 = '9e4c9ccbbbcaa02d75794eb43ccb7bb4961bbbbb0532d05dd306c1ec63757791' AND
              integrity_state = 'verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR to_regclass(current_schema() || '.l4_stream_group_display_id_sequences') IS NULL OR
          to_regclass(current_schema() || '.l4_stream_user_default_display_id_sequences') IS NULL THEN
        RAISE EXCEPTION 'migration 238 requires the exact verified 237 release head'
            USING ERRCODE = 'P2380';
    END IF;
END;
$migration_238_up$;

-- 236 给这两张序列表只发了 SELECT/INSERT/UPDATE，而同族其余 9 张 display_id_sequences
-- 一律是 rwdD。序列表只被 allocate_* 触发器的 INSERT ... ON CONFLICT DO UPDATE 写入，
-- 运行期不删行，所以这不是一个已发生的故障，只是同族内的不一致；补齐 DELETE 让
-- 「序列表 = rwdD」成为可断言的规律，后续不再逐个甄别。
-- 同类但故意不补的：l4_stream_group_default_write_requests / region_catalog_write_requests
-- 缺 DELETE 是配合各自的 immutable 触发器；l4_stream_group_members 缺 UPDATE 是因为
-- 代码只做 INSERT/DELETE，ON CONFLICT DO NOTHING 不需要 UPDATE。
DO $l4_stream_sequence_delete_grants$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'cdnca_control_app') THEN
        GRANT DELETE ON l4_stream_group_display_id_sequences TO cdnca_control_app;
        GRANT DELETE ON l4_stream_user_default_display_id_sequences TO cdnca_control_app;
    END IF;
END;
$l4_stream_sequence_delete_grants$;
