-- 504（r136 s5c A19）回退：线路组引用 L2 拓扑配置时 503 无法表达，拒绝回退。
LOCK TABLE schema_migrations, node_line_groups, node_line_group_revisions, l2_topology_configs,
    l2_topology_conditions, l2_topology_nodes, site_origin_pools IN ACCESS EXCLUSIVE MODE;

DO $migration_504_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 504 OR
       (SELECT max(version) FROM schema_migrations) <> 504 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=504 AND
        migration_id='504_line_group_l2_topology_config' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 504 down requires the exact verified migration head' USING ERRCODE='P5041';
    END IF;
    IF EXISTS (SELECT 1 FROM node_line_groups WHERE l2_config_id IS NOT NULL) OR
       EXISTS (SELECT 1 FROM node_line_group_revisions WHERE l2_config_id IS NOT NULL) THEN
        RAISE EXCEPTION 'retain line group L2 topology configurations during binary rollback' USING ERRCODE='P5042';
    END IF;
END;
$migration_504_down$;

DROP TRIGGER zz_l2_topology_nodes_edge_revision_504 ON l2_topology_nodes;
DROP TRIGGER zz_l2_topology_conditions_edge_revision_504 ON l2_topology_conditions;
DROP TRIGGER zz_l2_topology_configs_edge_revision_504 ON l2_topology_configs;
DROP FUNCTION advance_l2_topology_edge_source_revision_504();
DROP TRIGGER l2_topology_configs_referenced_504 ON l2_topology_configs;
DROP FUNCTION protect_referenced_l2_config_504();
DROP TRIGGER node_line_groups_l2_config_504 ON node_line_groups;
DROP FUNCTION assert_line_group_l2_config_504();

ALTER TABLE node_line_group_revisions DROP CONSTRAINT node_line_group_revisions_l2_config_504_fk;
ALTER TABLE node_line_groups DROP CONSTRAINT node_line_groups_l2_config_504_fk;

ALTER TABLE node_line_groups
    ADD CONSTRAINT node_line_groups_l2_not_self_234_check CHECK (
        l2_config_id IS NULL OR l2_config_id <> id
    ),
    ADD CONSTRAINT node_line_groups_l2_scope_234_fk
        FOREIGN KEY (tenant_scope_id, l2_config_id)
        REFERENCES node_line_groups(tenant_scope_id, id)
        ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED;
ALTER TABLE node_line_group_revisions
    ADD CONSTRAINT node_line_group_revisions_l2_not_self_234_check CHECK (
        l2_config_id IS NULL OR l2_config_id <> line_group_id
    ),
    ADD CONSTRAINT node_line_group_revisions_l2_scope_234_fk
        FOREIGN KEY (tenant_scope_id, l2_config_id)
        REFERENCES node_line_groups(tenant_scope_id, id)
        ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED;

CREATE FUNCTION assert_node_line_group_reference_234()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    target_region text;
    target_l2_config_id uuid;
BEGIN
    IF NEW.l2_config_id IS NOT NULL THEN
        IF NEW.l2_config_id = NEW.id THEN
            RAISE EXCEPTION 'node line group cannot reference itself as L2 configuration'
                USING ERRCODE = 'P2342';
        END IF;
        SELECT region, l2_config_id INTO target_region, target_l2_config_id
        FROM node_line_groups
        WHERE tenant_scope_id = NEW.tenant_scope_id
          AND id = NEW.l2_config_id
          AND deleted_at IS NULL
        FOR KEY SHARE;
        IF NOT FOUND OR target_l2_config_id IS NOT NULL OR target_region IS DISTINCT FROM NEW.region THEN
            RAISE EXCEPTION 'L2 configuration must be an active standalone line group in the same scope and region'
                USING ERRCODE = 'P2342';
        END IF;
    END IF;
    IF EXISTS (
        SELECT 1 FROM node_line_groups dependent
        WHERE dependent.tenant_scope_id = NEW.tenant_scope_id
          AND dependent.l2_config_id = NEW.id
          AND dependent.deleted_at IS NULL
          AND (NEW.deleted_at IS NOT NULL OR NEW.l2_config_id IS NOT NULL OR
               dependent.region IS DISTINCT FROM NEW.region)
    ) THEN
        RAISE EXCEPTION 'referenced L2 configuration cannot be deleted, nested, or moved to another region'
            USING ERRCODE = 'P2342';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER node_line_groups_reference_insert_234
BEFORE INSERT ON node_line_groups
FOR EACH ROW EXECUTE FUNCTION assert_node_line_group_reference_234();

CREATE TRIGGER node_line_groups_reference_update_234
BEFORE UPDATE OF tenant_scope_id, id, region, l2_config_id, deleted_at ON node_line_groups
FOR EACH ROW EXECUTE FUNCTION assert_node_line_group_reference_234();
