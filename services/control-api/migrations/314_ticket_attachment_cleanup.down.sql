LOCK TABLE schema_migrations, ticket_attachments IN ACCESS EXCLUSIVE MODE;

DO $migration_314_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 314 OR
       (SELECT max(version) FROM schema_migrations) <> 314 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=314 AND
        migration_id='314_ticket_attachment_cleanup' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 314 down requires the exact verified migration head' USING ERRCODE='P3141';
    END IF;
END;
$migration_314_down$;

REVOKE DELETE ON ticket_attachments FROM cdnca_control_app, cdnca_control_runtime;
DROP TRIGGER ticket_attachments_delete_guard_314 ON ticket_attachments;
DROP FUNCTION ticket_attachments_delete_guard_314();
DROP INDEX ticket_attachments_expiry_314_idx;
