-- 576（fix-mktsiteconf4，占位号，合入时由主会话按集成头顺延并改钉前驱；前驱暂钉集成头 554_node_bandwidth_alerts）。
-- 区域目录增加标准地理代码，市场按站点下发时条件回源的节点区域跨主控按它映射：
--   country_code：ISO 3166-1 alpha-2 大写两位（如 CN、US），空 = 未设置；
--   province_code：中国按 GB/T 2260 省级 6 位码（如 440000），只在 country_code='CN' 时可填，其它国家留空。
-- 管理员在区域管理里选，默认空；未设置国家的区域被订阅方条件回源引用时阻断市场下发。
-- 用户 10-17：1.0.35 为初始版本、上线全部重装，不做旧版兼容。
LOCK TABLE schema_migrations, region_catalog IN ACCESS EXCLUSIVE MODE;

DO $migration_576_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 575 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 575 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=575 AND
        migration_id='575_node_install_trust_alerts' AND
        checksum_sha256='fb2ce0b9da4793addebaca843b2248e35358f530241325b1fa0a1445ac49aa8d' AND
        down_checksum_sha256='e57449a01afb6076e6414297ca5f03edbd7da6135695a326c1e1b8a6702f1ca0' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR EXISTS (
        SELECT 1 FROM information_schema.columns WHERE table_schema=current_schema() AND
            table_name='region_catalog' AND column_name IN ('country_code', 'province_code')
       ) THEN
        RAISE EXCEPTION 'migration 576 requires the exact verified 575 release head' USING ERRCODE='P5760';
    END IF;
END;
$migration_576_up$;

ALTER TABLE region_catalog
    ADD COLUMN country_code text NOT NULL DEFAULT '',
    ADD COLUMN province_code text NOT NULL DEFAULT '',
    ADD CONSTRAINT region_catalog_country_code_576_check CHECK (country_code = '' OR country_code ~ '^[A-Z]{2}$'),
    ADD CONSTRAINT region_catalog_province_code_576_check CHECK (
        province_code = '' OR country_code = 'CN' AND province_code ~ '^[1-8][0-9]0000$'
    );
