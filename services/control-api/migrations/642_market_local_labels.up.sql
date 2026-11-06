-- 642（订阅方本机别名与备注；前驱 641_market_node_settings）。
--   site_supplies.local_alias / local_note、market_subscribed_nodes.local_alias / local_note：买方主控给订阅（供给）与
--   订阅节点设的本机别名与备注，只存本机、不发市场。页面有别名时显示别名，原名（卖家报价名）始终在悬停/小字里。
--   site_supplies.name 本身改由同步写成卖家报价名（代码，不在本迁移里改数据）。
-- 只加列，不改已有数据。
LOCK TABLE schema_migrations, site_supplies, market_subscribed_nodes IN ACCESS EXCLUSIVE MODE;

DO $migration_642_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 641 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 641 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=641 AND migration_id='641_market_node_settings' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) THEN
        RAISE EXCEPTION 'migration 642 requires the verified 641 release head' USING ERRCODE='P6420';
    END IF;
END;
$migration_642_up$;

ALTER TABLE site_supplies
    ADD COLUMN local_alias text NOT NULL DEFAULT '',
    ADD COLUMN local_note text NOT NULL DEFAULT '';
ALTER TABLE site_supplies ADD CONSTRAINT site_supplies_local_label_642_check CHECK (
    local_alias = btrim(local_alias) AND char_length(local_alias) <= 64 AND local_alias !~ '[[:cntrl:]]' AND
    char_length(local_note) <= 500 AND local_note !~ '[\x01-\x09\x0b-\x1f\x7f]' AND
    (kind = 'market_subscription' OR (local_alias = '' AND local_note = '')));

ALTER TABLE market_subscribed_nodes
    ADD COLUMN local_alias text NOT NULL DEFAULT '',
    ADD COLUMN local_note text NOT NULL DEFAULT '';
ALTER TABLE market_subscribed_nodes ADD CONSTRAINT market_subscribed_nodes_local_label_642_check CHECK (
    local_alias = btrim(local_alias) AND char_length(local_alias) <= 64 AND local_alias !~ '[[:cntrl:]]' AND
    char_length(local_note) <= 500 AND local_note !~ '[\x01-\x09\x0b-\x1f\x7f]');
