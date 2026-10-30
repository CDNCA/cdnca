LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;

DO $migration_188_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 188 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 188 OR EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE migration_id IS NULL OR migration_id = '' OR
              checksum_sha256 IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
              down_checksum_sha256 IS NULL OR down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR
              integrity_state IS DISTINCT FROM 'verified' OR metadata_recorded_at IS NULL OR applied_at IS NULL
    ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version=188 AND migration_id='188_plugin_webhook_installation_binding' AND
              checksum_sha256='d3dd872b493087fb38318949831c0997ad22615177447a6fed8cf5384d3323d2' AND
              integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
    ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version=187 AND migration_id='187_deployment_domain_event_source_outbox' AND
              checksum_sha256='1d7132c342f82b1445ef0be83968704465fd26659915ecb24d2c566e082e2be4' AND
              down_checksum_sha256='cd9144e913d60826c7e5742ab02e23ad8de2905f42282376b90caee2c32a4422' AND
              integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
    ) THEN
        RAISE EXCEPTION 'migration 188 rollback requires the exact verified 188 and 187 release heads'
            USING ERRCODE='P1880';
    END IF;
    IF EXISTS (SELECT 1 FROM plugin_webhook_subscriptions WHERE installation_authorization_id IS NOT NULL) THEN
        RAISE EXCEPTION 'rollback would discard plugin webhook installation bindings'
            USING ERRCODE='P1881';
    END IF;
END;
$migration_188_down$;

DROP TRIGGER plugin_webhook_subscriptions_installation_binding_188 ON plugin_webhook_subscriptions;
DROP FUNCTION validate_plugin_webhook_installation_binding_188();
DROP INDEX plugin_webhook_subscriptions_installation_binding_188_idx;

ALTER TABLE plugin_webhook_subscriptions
    DROP CONSTRAINT plugin_webhook_subscriptions_installation_binding_188_fk,
    DROP CONSTRAINT plugin_webhook_subscriptions_installation_binding_shape_188,
    DROP COLUMN installation_authorization_id,
    DROP COLUMN installation_id,
    DROP COLUMN plugin_id;
