LOCK TABLE schema_migrations, node_line_groups, node_scheduling_write_requests,
    node_line_group_display_id_sequences IN ACCESS EXCLUSIVE MODE;

DO $migration_215_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations)<>215 OR
       (SELECT min(version) FROM schema_migrations)<>1 OR
       (SELECT max(version) FROM schema_migrations)<>215 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version=215 AND migration_id='215_node_line_group_display_ids' AND
              integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
    ) THEN
        RAISE EXCEPTION 'migration 215 rollback requires the exact verified 215 release head'
            USING ERRCODE='P2150';
    END IF;
END;
$migration_215_down$;

DROP TRIGGER node_line_groups_display_id_215 ON node_line_groups;
DROP TRIGGER node_line_groups_display_id_immutable_215 ON node_line_groups;
DROP FUNCTION allocate_node_line_group_display_id_215();
DROP FUNCTION protect_node_line_group_display_id_215();

ALTER TABLE node_scheduling_write_requests DISABLE TRIGGER node_scheduling_write_requests_state;
UPDATE node_scheduling_write_requests
SET response_body=response_body #- '{group,display_id}'
WHERE completed_at IS NOT NULL AND response_body IS NOT NULL AND
      jsonb_typeof(response_body->'group')='object';
ALTER TABLE node_scheduling_write_requests ENABLE TRIGGER node_scheduling_write_requests_state;

ALTER TABLE node_line_groups
    DROP CONSTRAINT node_line_groups_scope_display_id_unique,
    DROP CONSTRAINT node_line_groups_display_id_positive,
    DROP COLUMN display_id;

DROP TABLE node_line_group_display_id_sequences;
