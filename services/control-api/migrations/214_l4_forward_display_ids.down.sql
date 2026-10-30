LOCK TABLE schema_migrations, l4_forwards, l4_write_requests,
    l4_forward_display_id_sequences IN ACCESS EXCLUSIVE MODE;

DO $migration_214_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations)<>214 OR
       (SELECT min(version) FROM schema_migrations)<>1 OR
       (SELECT max(version) FROM schema_migrations)<>214 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version=214 AND migration_id='214_l4_forward_display_ids' AND
              integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
    ) THEN
        RAISE EXCEPTION 'migration 214 rollback requires the exact verified 214 release head'
            USING ERRCODE='P2140';
    END IF;
END;
$migration_214_down$;

DROP TRIGGER l4_forwards_display_id_214 ON l4_forwards;
DROP TRIGGER l4_forwards_display_id_immutable_214 ON l4_forwards;
DROP FUNCTION allocate_l4_forward_display_id_214();
DROP FUNCTION protect_l4_forward_display_id_214();

UPDATE l4_write_requests
SET response_body=response_body-'display_id'
WHERE completed_at IS NOT NULL AND response_body IS NOT NULL AND
      operation IN ('stream.create','stream.update');

ALTER TABLE l4_forwards
    DROP CONSTRAINT l4_forwards_scope_display_id_unique,
    DROP CONSTRAINT l4_forwards_display_id_positive,
    DROP COLUMN display_id;

DROP TABLE l4_forward_display_id_sequences;
