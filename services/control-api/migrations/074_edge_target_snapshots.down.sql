LOCK TABLE node_line_endpoints IN ACCESS EXCLUSIVE MODE;
LOCK TABLE edge_target_snapshots IN ACCESS EXCLUSIVE MODE;
LOCK TABLE edge_target_snapshot_nodes IN ACCESS EXCLUSIVE MODE;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM edge_target_snapshots)
       OR EXISTS (SELECT 1 FROM node_line_endpoints WHERE node_id IS NOT NULL) THEN
        RAISE EXCEPTION 'edge target snapshot facts prevent rollback' USING ERRCODE = '55000';
    END IF;
END;
$$;

DROP TRIGGER edge_target_snapshot_nodes_complete_074 ON edge_target_snapshot_nodes;
DROP TRIGGER edge_target_snapshots_complete_074 ON edge_target_snapshots;
DROP TRIGGER edge_target_snapshot_nodes_prevent_truncate_074 ON edge_target_snapshot_nodes;
DROP TRIGGER edge_target_snapshot_nodes_immutable_074 ON edge_target_snapshot_nodes;
DROP TRIGGER edge_target_snapshots_prevent_truncate_074 ON edge_target_snapshots;
DROP TRIGGER edge_target_snapshots_immutable_074 ON edge_target_snapshots;

DROP FUNCTION assert_edge_target_snapshot_complete_074();
DROP FUNCTION assert_edge_target_snapshot_parent_complete_074();
DROP FUNCTION protect_edge_target_snapshot_nodes_074();
DROP FUNCTION protect_edge_target_snapshot_074();

DROP TABLE edge_target_snapshot_nodes;
DROP TABLE edge_target_snapshots;

DROP INDEX node_line_endpoints_node_idx;
ALTER TABLE node_line_endpoints
    DROP CONSTRAINT node_line_endpoints_node_scope_fk,
    DROP COLUMN node_id;
