-- 572（fix-cfundo，主会话 10-27 预留；占位，合入时由主会话改号与改钉前驱，前驱暂钉 555_aggregated_edge_observability）：
-- 迁入 Cloudflare 可撤回（方案 B：同一对象只有一个主人）。
-- 确认迁入时向导用所选账号找到（或新建）该账号的配置同步供给，先建同名 custom hostname 并登记为
-- 该站点在该供给下的资源（site_supply_cdn_resources），解析改完后自动建绑定，此后由配置同步接管。
-- 撤回迁入按计划逆序恢复解析，解除本次向导建的绑定（由同步删除 hostname），迁入记录写 restored；
-- 单步失败停在 restoring，可继续撤回。
LOCK TABLE schema_migrations, cdn_import_migrations IN ACCESS EXCLUSIVE MODE;

DO $migration_572_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 571 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 571 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=571 AND
        migration_id='571_node_line_backup_states' AND
        checksum_sha256='338092a939360bd9f3e15e5acc20b7d29bf8fb6119dece51262360df4d073e75' AND
        down_checksum_sha256='c4b307ac6ad2674f8b30fb439559e071729a8457d8906f0d62166aae726e3b64' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR EXISTS (
        SELECT 1 FROM information_schema.columns WHERE table_schema=current_schema() AND
        table_name='cdn_import_migrations' AND column_name='restored_at'
       ) THEN
        RAISE EXCEPTION 'migration 572 requires the exact verified 571 release head' USING ERRCODE='P5720';
    END IF;
END;
$migration_572_up$;

-- supply_id: the config_sync supply that took the hostname over (set at
-- confirm). binding: '' none (yet), 'created' the wizard created the
-- binding, 'reused' the site was already bound to that supply (the undo
-- keeps it). hostname_remote_id: the custom hostname the wizard created
-- ('' = it reused the one sync had recorded). restore_result: per-record
-- outcome of the undo (retries skip what is done).
ALTER TABLE cdn_import_migrations
    DROP CONSTRAINT cdn_import_migrations_state_check,
    ADD CONSTRAINT cdn_import_migrations_state_check CHECK (
        state IN ('planned', 'applied', 'failed', 'cancelled', 'superseded', 'restoring', 'restored')),
    ADD COLUMN supply_id uuid REFERENCES site_supplies(id) ON DELETE RESTRICT,
    ADD COLUMN binding text NOT NULL DEFAULT '' CHECK (binding IN ('', 'created', 'reused')),
    ADD COLUMN hostname_remote_id text NOT NULL DEFAULT '' CHECK (
        char_length(hostname_remote_id) <= 512 AND hostname_remote_id !~ '[[:cntrl:]]'),
    ADD COLUMN restore_result jsonb NOT NULL DEFAULT '[]'::jsonb CHECK (
        jsonb_typeof(restore_result) = 'array' AND octet_length(restore_result::text) <= 65536),
    ADD COLUMN restore_error_code text NOT NULL DEFAULT '' CHECK (char_length(restore_error_code) <= 64),
    ADD COLUMN restored_by uuid REFERENCES users(id) ON DELETE RESTRICT,
    ADD COLUMN restored_at timestamptz CHECK (restored_at IS NULL OR isfinite(restored_at)),
    ADD CONSTRAINT cdn_import_migrations_restored_572_check CHECK ((state = 'restored') = (restored_at IS NOT NULL)),
    ADD CONSTRAINT cdn_import_migrations_supply_572_check CHECK (binding = '' OR supply_id IS NOT NULL);
