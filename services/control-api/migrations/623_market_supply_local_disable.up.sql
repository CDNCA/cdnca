-- 623（前驱 622）。
-- 节点管理「订阅节点」页：
--   1. site_supplies.local_disabled_at：本机停用整条市场供给。非空时本机 DNS 不再指向它
--      （cnameallocation.SupplyTargets 跳过），不退订、不停卖家节点，
--      绑定与站点下发照旧，照常计费。只对 market_subscription 有意义。
--   2. site_supply_leaf_sites.blockers / blockers_revision：最近一次下发时该供货节点组对站点配置的
--      拒绝或提示原因（siteconf.Blocker 数组，如 unsupported_waf 带 CRS 档位），让页面回答
--      "本机站点的 WAF/CC 规则在这些节点上是否生效"。只做展示，不参与回执与回滚判断。
LOCK TABLE schema_migrations, site_supplies, site_supply_leaf_sites IN ACCESS EXCLUSIVE MODE;

DO $migration_623_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 622 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 622 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=622 AND migration_id='622_market_terms_notice_sla' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) THEN
        RAISE EXCEPTION 'migration 623 requires the verified 622 release head' USING ERRCODE='P6230';
    END IF;
END;
$migration_623_up$;

ALTER TABLE site_supplies ADD COLUMN local_disabled_at timestamptz;
ALTER TABLE site_supplies ADD CONSTRAINT site_supplies_local_disabled_623_check
    CHECK (local_disabled_at IS NULL OR kind = 'market_subscription');

ALTER TABLE site_supply_leaf_sites
    ADD COLUMN blockers jsonb NOT NULL DEFAULT '[]'::jsonb,
    ADD COLUMN blockers_revision bigint NOT NULL DEFAULT 0;
ALTER TABLE site_supply_leaf_sites ADD CONSTRAINT site_supply_leaf_sites_blockers_623_check
    CHECK (jsonb_typeof(blockers) = 'array' AND jsonb_array_length(blockers) <= 64 AND blockers_revision >= 0);
