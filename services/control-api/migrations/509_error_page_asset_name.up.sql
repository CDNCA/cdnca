-- 509（r136 be-gap-2，s4b 遗留"错误页资产缺名称字段"；本地占位 500 接 s5b 的 499，merge-p7 改号为 509 接 508）。
-- 错误页资产加名称：上传时由用户给出（文件名或自填），列表与站点高级设置下拉显示名称，不再只显示类型·大小·ID。
-- 已有资产名称为空，界面按原来的"类型·大小·ID 前 8 位"显示。名称不参与内容寻址、扫描与发布。
LOCK TABLE schema_migrations, error_page_assets IN ACCESS EXCLUSIVE MODE;

DO $migration_509_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 508 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 508 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=508 AND
        migration_id='508_package_traffic_stream_suspensions' AND
        checksum_sha256='55cca49a9f2d6f3b6e2628cba132b23cf3ecf6b1e362ee0553ee69927fc30b04' AND
        down_checksum_sha256='bf804a262b71532ae58794ff6114f99af92da76dcf8016d6556d1cf4718023c0' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR EXISTS (
        SELECT 1 FROM information_schema.columns WHERE table_schema=current_schema() AND
        table_name='error_page_assets' AND column_name='name'
       ) THEN
        RAISE EXCEPTION 'migration 509 requires the exact verified 508 release head' USING ERRCODE='P5090';
    END IF;
END;
$migration_509_up$;

-- 1..128 个字符，不含控制字符、首尾不留空白；'' = 未命名（旧资产）。
ALTER TABLE error_page_assets
    ADD COLUMN name text NOT NULL DEFAULT '' CHECK (
        name = '' OR (char_length(name) BETWEEN 1 AND 128 AND name !~ '[[:cntrl:]]' AND name = btrim(name))
    );
