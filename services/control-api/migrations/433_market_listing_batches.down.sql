LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;

DO $migration_433_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 433 OR
       (SELECT max(version) FROM schema_migrations) <> 433 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=433 AND
        migration_id='433_market_listing_batches' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 433 down requires the exact verified migration head' USING ERRCODE='P4332';
    END IF;
END;
$migration_433_down$;

-- Batch items only make resubmission idempotent and templates are console
-- presets: neither is needed to serve what was already listed.
DROP TABLE market_listing_batch_items;
DROP TABLE market_listing_templates;
DROP FUNCTION assert_market_listing_platform_scope_433();
