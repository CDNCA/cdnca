LOCK TABLE schema_migrations, notification_delivery_facts_108 IN ACCESS EXCLUSIVE MODE;

DO $migration_253_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 253 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 253 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=253 AND migration_id='253_notification_dispatch_observation'
          AND checksum_sha256='12f42726891c1364d408e1fb2b8ec35d645a53eb8ccc04a4a8aa20d2388f1b83' AND integrity_state='verified'
    ) OR EXISTS (
        SELECT 1 FROM notification_delivery_facts_108
        WHERE recipient_address_masked IS NOT NULL OR provider_call_started_at IS NOT NULL
    ) THEN
        RAISE EXCEPTION 'migration 253 rollback requires unused observation fields; preserve recorded delivery history and deploy a compatible binary' USING ERRCODE='P2531';
    END IF;
END;
$migration_253_down$;

ALTER TABLE notification_delivery_facts_108
    DROP CONSTRAINT notification_dispatch_observation_253,
    DROP COLUMN recipient_address_masked,
    DROP COLUMN provider_call_started_at;
