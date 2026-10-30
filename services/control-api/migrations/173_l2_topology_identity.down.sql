LOCK TABLE schema_migrations,edge_target_snapshots,edge_target_snapshot_nodes,edge_target_snapshot_identities IN ACCESS EXCLUSIVE MODE;

DO $migration_173_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations)<>173 OR
       (SELECT max(version) FROM schema_migrations)<>173 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=173 AND migration_id='173_l2_topology_identity' AND
          checksum_sha256='fa59baaceb977e0973c1061b9d9028e835de54a0be9e86dbec88780aced1e970' AND
          integrity_state='verified'
    ) THEN
        RAISE EXCEPTION 'migration 173 rollback requires the exact verified 173 head' USING ERRCODE='P1733';
    END IF;
    IF EXISTS (SELECT 1 FROM edge_target_snapshot_identities) OR EXISTS (
        SELECT 1 FROM edge_target_snapshots
        GROUP BY tenant_scope_id,source_line_group_id,source_revision HAVING count(*)>1
    ) THEN
        RAISE EXCEPTION 'migration 173 rollback refuses to discard durable topology identity history' USING ERRCODE='P1736';
    END IF;
END;
$migration_173_down$;

DROP TRIGGER edge_target_snapshot_identities_prevent_truncate_173 ON edge_target_snapshot_identities;
DROP TRIGGER edge_target_snapshot_identities_immutable_173 ON edge_target_snapshot_identities;
DROP FUNCTION protect_edge_target_snapshot_identity_173();
DROP TABLE edge_target_snapshot_identities;
DROP INDEX edge_target_snapshots_source_revision_idx;
ALTER TABLE edge_target_snapshots
    ADD CONSTRAINT edge_target_snapshots_tenant_scope_id_source_line_group_id_source_revision_key
    UNIQUE (tenant_scope_id, source_line_group_id, source_revision);
