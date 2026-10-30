LOCK TABLE schema_migrations, nodes, l2_topology_configs, l2_topology_conditions,
    l2_topology_nodes, l2_topology_write_requests
IN ACCESS EXCLUSIVE MODE;

DO $migration_241_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 241 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 241 OR EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE migration_id IS NULL OR migration_id = '' OR
              checksum_sha256 IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
              down_checksum_sha256 IS NULL OR down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR
              integrity_state IS DISTINCT FROM 'verified' OR
              metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version = 241 AND migration_id = '241_l2_topology_management' AND
              checksum_sha256 = 'da19054e99340bce06c1bf8b64b99bb986ed05ef951085e8c8936b871308ee63' AND
              integrity_state = 'verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR to_regclass(current_schema() || '.l2_topology_configs') IS NULL OR
            to_regclass(current_schema() || '.l2_topology_conditions') IS NULL OR
            to_regclass(current_schema() || '.l2_topology_nodes') IS NULL OR
            to_regclass(current_schema() || '.l2_topology_write_requests') IS NULL OR
            to_regprocedure(current_schema() || '.protect_l2_topology_write_request_241()') IS NULL THEN
        RAISE EXCEPTION 'migration 241 rollback requires the exact verified 241 release head'
            USING ERRCODE = 'P2411';
    END IF;
    IF EXISTS (SELECT 1 FROM l2_topology_configs) OR
       EXISTS (SELECT 1 FROM l2_topology_conditions) OR
       EXISTS (SELECT 1 FROM l2_topology_nodes) OR
       EXISTS (SELECT 1 FROM l2_topology_write_requests) THEN
        RAISE EXCEPTION 'migration 241 rollback cannot discard L2 topology data or idempotency receipts'
            USING ERRCODE = 'P2411';
    END IF;
END;
$migration_241_down$;

DO $l2_topology_runtime_revokes$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'cdnca_control_app') THEN
        REVOKE USAGE, SELECT ON SEQUENCE l2_topology_configs_display_id_seq,
            l2_topology_conditions_display_id_seq, l2_topology_nodes_display_id_seq FROM cdnca_control_app;
        REVOKE SELECT, INSERT, UPDATE ON l2_topology_configs, l2_topology_conditions,
            l2_topology_nodes, l2_topology_write_requests FROM cdnca_control_app;
    END IF;
END;
$l2_topology_runtime_revokes$;

DROP TRIGGER l2_topology_write_requests_truncate_241 ON l2_topology_write_requests;
DROP TRIGGER l2_topology_write_requests_immutable_241 ON l2_topology_write_requests;
DROP FUNCTION protect_l2_topology_write_request_241();

DROP TABLE l2_topology_write_requests;
DROP INDEX l2_topology_nodes_scope_config_sort_241_idx;
DROP INDEX l2_topology_nodes_scope_node_active_241_idx;
DROP TABLE l2_topology_nodes;
DROP INDEX l2_topology_conditions_scope_name_241_idx;
DROP TABLE l2_topology_conditions;
DROP INDEX l2_topology_configs_scope_name_241_idx;
DROP TABLE l2_topology_configs;

ALTER TABLE nodes DROP CONSTRAINT nodes_scope_id_241_unique;
