-- 660：前驱钉 659_check_function_search_path。
-- 状态页开箱即用。
--   status_page_components.hidden：组件隐藏（公开页与总体状态都不含，仍保留历史采样）。
--   status_page_settings.lines_synced_at：线路组首次自动同步时间；空表示还没同步过，
--     此时「没有任何组件」才按线路组各建一个，已有组件则只登记现有线路组。
--   status_page_line_group_seen：已处理过的线路组；管理员删掉的组件不会被再次加回，新建的线路组才会自动加入。
-- 权限沿用 system_configuration.read / manage，不新增权限码。老数据不回填。
LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;

DO $migration_660_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 659 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 659 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=659 AND
        migration_id='659_check_function_search_path' AND
        checksum_sha256='7aea7d61832ba9cd4a6d49ca499ea67ae34b97f10f70cd405171fa44ba2297ef' AND
        down_checksum_sha256='a8923a33f36182c9ff4179faf2ac56dbcc00639e7aa3430660b2a99ff5e6ded4' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema=current_schema()
        AND table_name='status_page_components' AND column_name='hidden')
         OR to_regclass(current_schema() || '.status_page_line_group_seen') IS NOT NULL THEN
        RAISE EXCEPTION 'migration 660 requires the exact verified 659 release head' USING ERRCODE='P6600';
    END IF;
END;
$migration_660_up$;

ALTER TABLE status_page_components ADD COLUMN hidden boolean NOT NULL DEFAULT false;
ALTER TABLE status_page_settings ADD COLUMN lines_synced_at timestamptz;

CREATE TABLE status_page_line_group_seen (
    line_group_id uuid PRIMARY KEY,
    seen_at timestamptz NOT NULL
);
GRANT SELECT, INSERT, UPDATE, DELETE ON status_page_line_group_seen TO cdnca_control_app, cdnca_control_runtime;
