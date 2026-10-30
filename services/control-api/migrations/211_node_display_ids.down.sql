LOCK TABLE schema_migrations, nodes, node_display_id_sequences IN ACCESS EXCLUSIVE MODE;

DO $migration_211_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations)<>211 OR
       (SELECT max(version) FROM schema_migrations)<>211 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version=211 AND migration_id='211_node_display_ids' AND
              integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
    ) THEN
        RAISE EXCEPTION 'migration 211 rollback requires the exact verified 211 release head'
            USING ERRCODE='P2110';
    END IF;
END;
$migration_211_down$;

ALTER TABLE nodes
    DROP CONSTRAINT nodes_scope_display_id_unique,
    DROP CONSTRAINT nodes_display_id_positive,
    DROP COLUMN display_id;

DROP TABLE node_display_id_sequences;
