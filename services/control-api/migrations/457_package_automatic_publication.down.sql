LOCK TABLE schema_migrations, edge_automatic_publication_policy_facts IN ACCESS EXCLUSIVE MODE;

DO $migration_457_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 457 OR
       (SELECT max(version) FROM schema_migrations) <> 457 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=457 AND
        migration_id='457_package_automatic_publication' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 457 down requires the exact verified migration head' USING ERRCODE='P4571';
    END IF;
    -- Policy facts are append-only: a policy without nodes cannot be removed,
    -- so the 086 check cannot come back while one exists.
    IF EXISTS (SELECT 1 FROM edge_automatic_publication_policy_facts
               WHERE mode='automatic' AND cardinality(node_ids)=0 AND target_snapshot_id IS NULL) THEN
        RAISE EXCEPTION 'migration 457 rollback would invalidate automatic publication policies without nodes'
            USING ERRCODE='P4572';
    END IF;
END;
$migration_457_down$;

ALTER TABLE edge_automatic_publication_policy_facts
    DROP CONSTRAINT edge_automatic_publication_policy_facts_check;
ALTER TABLE edge_automatic_publication_policy_facts
    ADD CONSTRAINT edge_automatic_publication_policy_facts_check CHECK (
        (mode = 'manual' AND cardinality(node_ids) = 0 AND target_snapshot_id IS NULL AND
         target_snapshot_revision IS NULL AND target_snapshot_sha256 IS NULL) OR
        (mode = 'automatic' AND (
            (cardinality(node_ids) BETWEEN 1 AND 10000 AND target_snapshot_id IS NULL AND
             target_snapshot_revision IS NULL AND target_snapshot_sha256 IS NULL) OR
            (cardinality(node_ids) = 0 AND target_snapshot_id IS NOT NULL AND
             target_snapshot_revision > 0 AND octet_length(target_snapshot_sha256) = 32)
        ))
    );
