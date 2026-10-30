LOCK TABLE schema_migrations, deployment_domain_event_source_outbox,
    deployment_domain_event_fanout_receipts IN ACCESS EXCLUSIVE MODE;

DO $migration_189_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 189 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 189 OR EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE migration_id IS NULL OR migration_id = '' OR
              checksum_sha256 IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
              down_checksum_sha256 IS NULL OR down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR
              integrity_state IS DISTINCT FROM 'verified' OR metadata_recorded_at IS NULL OR applied_at IS NULL
    ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version=189 AND migration_id='189_deployment_domain_event_fanout' AND
              integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
    ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version=188 AND migration_id='188_plugin_webhook_installation_binding' AND
              checksum_sha256='d3dd872b493087fb38318949831c0997ad22615177447a6fed8cf5384d3323d2' AND
              down_checksum_sha256='8ef29275c68d9f2416397bdb5d3e028dbd0b900e515e1eb13813ff8245144ecd' AND
              integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
    ) THEN
        RAISE EXCEPTION 'migration 189 rollback requires the exact verified release heads'
            USING ERRCODE='P1890';
    END IF;
    IF EXISTS (SELECT 1 FROM deployment_domain_event_fanout_receipts) THEN
        RAISE EXCEPTION 'rollback would discard deployment fanout receipts' USING ERRCODE='P1894';
    END IF;
END;
$migration_189_down$;

DROP TRIGGER deployment_domain_event_fanout_receipt_guard_189 ON deployment_domain_event_fanout_receipts;
DROP FUNCTION validate_deployment_domain_event_fanout_receipt_189();
DROP INDEX deployment_domain_event_fanout_receipts_pending_idx;
DROP INDEX deployment_domain_event_fanout_receipts_subscription_idx;
DROP TABLE deployment_domain_event_fanout_receipts;
