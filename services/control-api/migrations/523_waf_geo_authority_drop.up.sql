-- 523（r136 wafgeo-check，分支占位 523；merge-p9 改为 523，守卫钉前驱 522 的 migration_id / checksum_sha256 /
-- down_checksum_sha256）。
-- 删除 144 的 WAF 地区策略（waf_geo_*）：签名发布物只写进 waf_geo_publications，主控与节点都没有读者，
-- 用户设的地区策略从未下发生效。按国家/地区屏蔽由 WAF 规则库的 country 条件（节点 IP 情报库判定）提供。
-- 1.0.35 全新安装、不兼容旧主控，存量行不迁移，随表一起删除。
LOCK TABLE schema_migrations, waf_geo_site_heads, waf_geo_catalog_revisions,
    waf_geo_publications, waf_geo_binding_transitions IN ACCESS EXCLUSIVE MODE;

DO $migration_523_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 522 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 522 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=522 AND
        migration_id='522_approval_center' AND
        checksum_sha256='9e260151953eddb91c6142bbbc0de3e3d6e5b85df8a093731da8d62b9b723b8f' AND
        down_checksum_sha256='ee13721bcd5edd674f411ba6f69b2b0ec0c708718ea27c6badd77af0c83c9992' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=144 AND migration_id='144_waf_geo_authority' AND
        checksum_sha256='7fac4e1bdec793d461ef3a1735c81d4b7c020dd876fa565dd919a68bb493ce95'
       ) OR to_regclass(current_schema() || '.waf_geo_site_heads') IS NULL OR
          to_regprocedure(current_schema() || '.prevent_waf_geo_truncate_144()') IS NULL THEN
        RAISE EXCEPTION 'migration 523 requires the exact verified 522 release head' USING ERRCODE='P5230';
    END IF;
END;
$migration_523_up$;

DROP TABLE waf_geo_binding_transitions;
DROP TABLE waf_geo_publications;
ALTER TABLE waf_geo_site_heads
    DROP CONSTRAINT waf_geo_site_heads_lkg_144_fk,
    DROP CONSTRAINT waf_geo_site_heads_active_144_fk,
    DROP CONSTRAINT waf_geo_site_heads_latest_144_fk;
DROP TABLE waf_geo_catalog_revisions;
DROP TABLE waf_geo_site_heads;
DROP FUNCTION prevent_waf_geo_truncate_144();
DROP FUNCTION validate_waf_geo_head_transition_144();
DROP FUNCTION protect_waf_geo_transition_144();
DROP FUNCTION protect_waf_geo_publication_144();
DROP FUNCTION protect_waf_geo_revision_144();
DROP FUNCTION valid_waf_geo_trusted_crawlers_144(jsonb);
