-- 547（fix-nodeipgeo）回退：删自动解析表、人工字段键与约束、节点归属摘要列。生效值 ip_location 保留。
LOCK TABLE schema_migrations, nodes, edge_node_network_marks IN ACCESS EXCLUSIVE MODE;

DO $migration_547_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 547 OR
       (SELECT max(version) FROM schema_migrations) <> 547 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=547 AND
        migration_id='547_node_ip_location_resolution' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 547 down requires the exact verified migration head' USING ERRCODE='P5471';
    END IF;
END;
$migration_547_down$;

ALTER TABLE edge_node_network_marks DROP COLUMN locations_sha256;
ALTER TABLE nodes DROP CONSTRAINT nodes_ip_location_manual_547_check;
UPDATE nodes SET management_settings = management_settings - 'ip_location_manual' WHERE management_settings ? 'ip_location_manual';
DROP TABLE node_ip_location_resolutions;
