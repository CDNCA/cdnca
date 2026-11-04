-- 629 回退：两个 504 函数恢复原文（供给组也按区域匹配）。有供给组引用了区域不同的 L2 配置时
-- 628 的规则装不下它，拒绝回退；卖家先在供货管理里把这些供给组的 L2 配置清掉或换成区域为空的配置。
LOCK TABLE schema_migrations, node_line_groups, l2_topology_configs IN ACCESS EXCLUSIVE MODE;

DO $migration_629_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 629 OR
       (SELECT max(version) FROM schema_migrations) <> 629 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=629 AND
        migration_id='629_market_supply_l2_config' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 629 down requires the exact verified migration head' USING ERRCODE='P6291';
    END IF;
    IF EXISTS (
        SELECT 1 FROM node_line_groups line_group JOIN l2_topology_configs config
          ON config.tenant_scope_id = line_group.tenant_scope_id AND config.id = line_group.l2_config_id
        WHERE line_group.purpose = 'market_supply' AND line_group.deleted_at IS NULL
          AND config.region <> '' AND config.region IS DISTINCT FROM line_group.region
    ) THEN
        RAISE EXCEPTION 'market supply groups use L2 configurations of another region' USING ERRCODE='P6292';
    END IF;
END;
$migration_629_down$;

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
    IF NOT FOUND OR (config_region <> '' AND config_region IS DISTINCT FROM NEW.region) THEN
        RAISE EXCEPTION 'line group L2 configuration % is not a live L2 configuration of the scope and region',
            NEW.l2_config_id USING ERRCODE = 'P5043';
    END IF;
    RETURN NEW;
END;
$$;

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
          AND line_group.deleted_at IS NULL AND line_group.region IS DISTINCT FROM NEW.region
    ) THEN
        RAISE EXCEPTION 'L2 configuration % is used by a line group of another region', OLD.id USING ERRCODE = 'P5044';
    END IF;
    RETURN NEW;
END;
$$;
