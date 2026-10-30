-- 504（r136 s5c A19，主会话 10-25 12:1x 定唯一语义；本地占位 497，merge-p6 改号 504（前驱 503））。
-- 线路组的 L2 配置 = L2 拓扑配置（l2_topology_configs），不再是另一条线路组：
-- 234 的自引用外键/检查/引用触发器换成指向 l2_topology_configs 的外键与触发器。
-- 存量指向线路组的值从未在发布中生效，清空（当前行与历史修订一致清空）。
LOCK TABLE schema_migrations, node_line_groups, node_line_group_revisions, l2_topology_configs,
    l2_topology_conditions, l2_topology_nodes, site_origin_pools IN ACCESS EXCLUSIVE MODE;

DO $migration_504_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 503 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 503 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=503 AND
        migration_id='503_site_sync_status_derived' AND
        checksum_sha256='6d01563e0763f0f33da5b9592cc49e5a0695f88bb67860f4ee3f7c62add8accb' AND
        down_checksum_sha256='1a29a4bb749ebcb41be720c00ab010d8b2c5deaff622a39369b656cebeb3e0e1' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR to_regprocedure(current_schema() || '.assert_node_line_group_reference_234()') IS NULL OR
          to_regprocedure(current_schema() || '.assert_line_group_l2_config_504()') IS NOT NULL THEN
        RAISE EXCEPTION 'migration 504 requires the exact verified 503 release head' USING ERRCODE='P5040';
    END IF;
END;
$migration_504_up$;

DROP TRIGGER node_line_groups_reference_insert_234 ON node_line_groups;
DROP TRIGGER node_line_groups_reference_update_234 ON node_line_groups;
DROP FUNCTION assert_node_line_group_reference_234();

ALTER TABLE node_line_groups
    DROP CONSTRAINT node_line_groups_l2_scope_234_fk,
    DROP CONSTRAINT node_line_groups_l2_not_self_234_check;
ALTER TABLE node_line_group_revisions
    DROP CONSTRAINT node_line_group_revisions_l2_scope_234_fk,
    DROP CONSTRAINT node_line_group_revisions_l2_not_self_234_check;

-- 旧语义（另一条线路组）的存量值：当前行与修订同时清空，修订快照一致性不变。
ALTER TABLE node_line_groups DISABLE TRIGGER node_line_groups_protect_revision;
UPDATE node_line_groups SET l2_config_id = NULL WHERE l2_config_id IS NOT NULL;
ALTER TABLE node_line_groups ENABLE TRIGGER node_line_groups_protect_revision;
ALTER TABLE node_line_group_revisions DISABLE TRIGGER node_line_group_revisions_immutable;
ALTER TABLE node_line_group_revisions DISABLE TRIGGER node_line_group_revisions_health_complete;
UPDATE node_line_group_revisions SET l2_config_id = NULL WHERE l2_config_id IS NOT NULL;
ALTER TABLE node_line_group_revisions ENABLE TRIGGER node_line_group_revisions_immutable;
ALTER TABLE node_line_group_revisions ENABLE TRIGGER node_line_group_revisions_health_complete;

ALTER TABLE node_line_groups
    ADD CONSTRAINT node_line_groups_l2_config_504_fk
        FOREIGN KEY (tenant_scope_id, l2_config_id)
        REFERENCES l2_topology_configs(tenant_scope_id, id) ON DELETE RESTRICT;
ALTER TABLE node_line_group_revisions
    ADD CONSTRAINT node_line_group_revisions_l2_config_504_fk
        FOREIGN KEY (tenant_scope_id, l2_config_id)
        REFERENCES l2_topology_configs(tenant_scope_id, id) ON DELETE RESTRICT;

-- 线路组只能引用同作用域未删除的 L2 配置；配置区域为空（默认）或与线路组相同。
CREATE FUNCTION assert_line_group_l2_config_504()
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

CREATE TRIGGER node_line_groups_l2_config_504
BEFORE INSERT OR UPDATE OF tenant_scope_id, region, l2_config_id, deleted_at ON node_line_groups
FOR EACH ROW EXECUTE FUNCTION assert_line_group_l2_config_504();

-- 被线路组或站点（custom）引用的 L2 配置不能删除，也不能改到与引用线路组不同的区域。
CREATE FUNCTION protect_referenced_l2_config_504()
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

CREATE TRIGGER l2_topology_configs_referenced_504
BEFORE UPDATE OF region, deleted_at ON l2_topology_configs
FOR EACH ROW EXECUTE FUNCTION protect_referenced_l2_config_504();

-- L2 配置、条件、成员会进入站点运行时（A19）：改动推进该作用域的边缘源修订，
-- 自动发布据此重新下发。
CREATE FUNCTION advance_l2_topology_edge_source_revision_504()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    PERFORM advance_edge_configuration_scope_revision(
        CASE WHEN TG_OP = 'DELETE' THEN OLD.tenant_scope_id ELSE NEW.tenant_scope_id END);
    RETURN NULL;
END;
$$;

CREATE TRIGGER zz_l2_topology_configs_edge_revision_504
AFTER INSERT OR UPDATE ON l2_topology_configs
FOR EACH ROW EXECUTE FUNCTION advance_l2_topology_edge_source_revision_504();
CREATE TRIGGER zz_l2_topology_conditions_edge_revision_504
AFTER INSERT OR UPDATE ON l2_topology_conditions
FOR EACH ROW EXECUTE FUNCTION advance_l2_topology_edge_source_revision_504();
CREATE TRIGGER zz_l2_topology_nodes_edge_revision_504
AFTER INSERT OR UPDATE ON l2_topology_nodes
FOR EACH ROW EXECUTE FUNCTION advance_l2_topology_edge_source_revision_504();
