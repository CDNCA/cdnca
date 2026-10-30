LOCK TABLE schema_migrations, ticket_attachments IN ACCESS EXCLUSIVE MODE;

DO $migration_314_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 313 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 313 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=313 AND
        migration_id='313_waf_rule_subscriptions' AND
        checksum_sha256='8e1b9f23e46e67bcaab4ea91655cde81a18c3f0395ea1906b1d9e19f76cce4b3' AND
        down_checksum_sha256='07bde19bbb5ad2a98f80df7ae103f24129cfbbff02ac539117e1e7e15f84fcb6' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR checksum_sha256 IS NULL OR
        down_checksum_sha256 IS NULL OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR to_regclass(current_schema() || '.ticket_attachments_expiry_314_idx') IS NOT NULL THEN
        RAISE EXCEPTION 'migration 314 requires the exact verified 313 release head' USING ERRCODE='P3140';
    END IF;
END;
$migration_314_up$;

-- Unbound uploads older than 24 hours are removed by the control-api cleanup
-- worker (internal/tickets CleanupPendingAttachments): object first, then the
-- row. Bound attachments are never deleted: the trigger refuses it even for
-- the runtime roles that now hold DELETE.
CREATE INDEX ticket_attachments_expiry_314_idx ON ticket_attachments (created_at) WHERE message_id IS NULL;

CREATE FUNCTION ticket_attachments_delete_guard_314()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF OLD.message_id IS NOT NULL THEN
        RAISE EXCEPTION 'bound ticket attachments cannot be deleted' USING ERRCODE='P3142';
    END IF;
    RETURN OLD;
END;
$$;

CREATE TRIGGER ticket_attachments_delete_guard_314
BEFORE DELETE ON ticket_attachments
FOR EACH ROW EXECUTE FUNCTION ticket_attachments_delete_guard_314();

GRANT DELETE ON ticket_attachments TO cdnca_control_app, cdnca_control_runtime;
