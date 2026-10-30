-- 550（fix-cnamerand，用户 10-27 16:3x）：多个 CNAME 域名时新网站随机分配。
-- dns_zones.random_allocation：该 CNAME 域名参与随机分配。没有指定 CNAME 域名的新 CNAME（未绑定套餐的网站、
-- 未指定域名的四层转发）在勾选的、状态正常且 DNS 服务商未停用的区里均匀随机取一个（可跨服务商）；
-- 一个都没勾选时仍用默认区（is_default）。已分配的 CNAME 不因开关变化迁移（internal/cnameallocation
-- resolveZoneAuthority 先保留站点已有的区）。
-- 平台 DNS 配置（platform_system_other_settings.settings->'dns_config'->'zones'[].random_allocation）随同步
-- 写入各租户副本（internal/dnsacme syncPlatformZones）；开关不是区的权威字段（089 摘要不含），不推高 revision。
-- 默认 false：升级后行为不变（全部走默认区）。
-- 前驱 546（fix-ticket2 ticket_notification_choices），守卫钉 546 校验和；547（fix-nodeipgeo）、548（fix-pkgmkt
-- 预留）合入后须改钉 548。
LOCK TABLE schema_migrations, dns_zones IN ACCESS EXCLUSIVE MODE;

DO $migration_550_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 549 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 549 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=549 AND
        migration_id='549_package_addon_purchase' AND
        checksum_sha256='2044dcce620031ed9f6175d7d324daea65e9d3319946c70c845c0b9247cb4b90' AND
        down_checksum_sha256='90ef797a77989fcaae49bdcb092d233ee761cefd157ee7dcbf0ed33f224827c0' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR EXISTS (
        SELECT 1 FROM information_schema.columns WHERE table_schema=current_schema() AND
        table_name='dns_zones' AND column_name='random_allocation'
       ) THEN
        RAISE EXCEPTION 'migration 550 requires the exact verified 549 release head' USING ERRCODE='P5500';
    END IF;
END;
$migration_550_up$;

ALTER TABLE dns_zones ADD COLUMN random_allocation boolean NOT NULL DEFAULT false;

-- 分配按作用域取勾选的区。
CREATE INDEX dns_zones_random_allocation_550_idx ON dns_zones (scope_id) WHERE random_allocation;
