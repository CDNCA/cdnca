-- 629（前驱 628 global_firewall_redelivery）：
-- 节点市场供给组（隐藏线路组 purpose='market_supply'，427）可以引用卖家自己的 L2 配置，市场站点
-- 「跟随套餐」时按它走 L2 回源。供给组没有区域（节点市场按节点 IP 归属分区，线路组 region 为空），
-- 504 的「配置区域为空或与线路组相同」会把卖家任何设了区域的 L2 配置拒掉；供给组不按区域匹配：
--   - assert_line_group_l2_config_504：market_supply 组只要求引用同作用域未删除的配置；
--   - protect_referenced_l2_config_504：改配置区域时不再因 market_supply 组拒绝（删除仍拒绝）。
-- 普通线路组规则不变。
LOCK TABLE schema_migrations, node_line_groups, l2_topology_configs IN ACCESS EXCLUSIVE MODE;

DO $migration_629_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 628 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 628 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=628 AND
        migration_id='628_global_firewall_redelivery' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR to_regprocedure(current_schema() || '.assert_line_group_l2_config_504()') IS NULL OR
          to_regprocedure(current_schema() || '.protect_referenced_l2_config_504()') IS NULL THEN
        RAISE EXCEPTION 'migration 629 requires the exact verified 628 release head' USING ERRCODE='P6290';
    END IF;
END;
$migration_629_up$;

-- 线路组只能引用同作用域未删除的 L2 配置；普通线路组还要求配置区域为空（默认）或与线路组相同。
CREATE OR REPLACE FUNCTION assert_line_group_l2_config_504()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    config_region text;
BEGIN
    IF NEW.l2_config_id IS NULL OR NEW.deleted_at IS NOT NULL THEN
        RETURN NEW;
    END IF;
    SELECT region INTO config_region FROM l2_topology_configs
    WHERE tenant_scope_id = NEW.tenant_scope_id AND id = NEW.l2_config_id AND deleted_at IS NULL
    FOR SHARE;
    IF NOT FOUND OR (NEW.purpose <> 'market_supply' AND config_region <> ''
                     AND config_region IS DISTINCT FROM NEW.region) THEN
        RAISE EXCEPTION 'line group L2 configuration % is not a live L2 configuration of the scope and region',
            NEW.l2_config_id USING ERRCODE = 'P5043';
    END IF;
    RETURN NEW;
END;
$$;

-- 被线路组或站点（custom）引用的 L2 配置不能删除，也不能改到与引用它的普通线路组不同的区域。
CREATE OR REPLACE FUNCTION protect_referenced_l2_config_504()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF OLD.deleted_at IS NOT NULL THEN
        RETURN NEW;
    END IF;
    IF NEW.deleted_at IS NOT NULL AND (
        EXISTS (SELECT 1 FROM node_line_groups line_group
                WHERE line_group.tenant_scope_id = OLD.tenant_scope_id AND line_group.l2_config_id = OLD.id
                  AND line_group.deleted_at IS NULL) OR
        EXISTS (SELECT 1 FROM site_origin_pools pool JOIN sites site ON site.id = pool.site_id
                WHERE pool.l2_config_id = OLD.id AND site.scope_id = OLD.tenant_scope_id
                  AND site.deleted_at IS NULL)
    ) THEN
        RAISE EXCEPTION 'L2 configuration % is used by a line group or a site', OLD.id USING ERRCODE = 'P5044';
    END IF;
    IF NEW.region <> '' AND NEW.region IS DISTINCT FROM OLD.region AND EXISTS (
        SELECT 1 FROM node_line_groups line_group
        WHERE line_group.tenant_scope_id = OLD.tenant_scope_id AND line_group.l2_config_id = OLD.id
          AND line_group.deleted_at IS NULL AND line_group.purpose <> 'market_supply'
          AND line_group.region IS DISTINCT FROM NEW.region
    ) THEN
        RAISE EXCEPTION 'L2 configuration % is used by a line group of another region', OLD.id USING ERRCODE = 'P5044';
    END IF;
    RETURN NEW;
END;
$$;
