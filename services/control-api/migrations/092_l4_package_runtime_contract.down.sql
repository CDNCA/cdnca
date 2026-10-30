LOCK TABLE schema_migrations,
    package_subscriptions,
    l4_forwards,
    l4_scope_publish_counters,
    l4_publish_intents,
    l4_write_requests,
    edge_automatic_publication_requests
IN ACCESS EXCLUSIVE MODE;

DO $$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 92 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 92 OR EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$'
           OR down_checksum_sha256 !~ '^[0-9a-f]{64}$'
           OR integrity_state <> 'verified' OR metadata_recorded_at IS NULL OR applied_at IS NULL
    ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version = 92
          AND migration_id = '092_l4_package_runtime_contract'
          AND checksum_sha256 = '5b9d6ced167be563e6dfdbe022681b7ed6842728a831597389a3a4e9280d8c6d'
          AND integrity_state = 'verified'
    ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version = 91
          AND migration_id = '091_notification_control_idempotency_receipts'
          AND checksum_sha256 = '9c556085f7396024a5011f74b06e0a6e3b83f5f6c5ab050b4b5c7b2ad036758c'
          AND down_checksum_sha256 = '7999ad3ae6ecf6b0eb182a1de59e82a37570264223a64f112c7bf8a8b8da8e04'
          AND integrity_state = 'verified'
    ) THEN
        RAISE EXCEPTION 'migration 092 rollback requires the verified 092 head'
            USING ERRCODE = 'P9200';
    END IF;
    IF EXISTS (SELECT 1 FROM l4_forwards) OR
       EXISTS (SELECT 1 FROM l4_scope_publish_counters) OR
       EXISTS (SELECT 1 FROM l4_publish_intents) OR
       EXISTS (SELECT 1 FROM l4_write_requests) OR
       EXISTS (SELECT 1 FROM edge_automatic_publication_requests WHERE source_kind = 'l4') THEN
        RAISE EXCEPTION 'migration 092 rollback would discard L4 package/runtime facts'
            USING ERRCODE = 'P9201';
    END IF;
END;
$$;

ALTER TABLE edge_automatic_publication_requests
    DROP CONSTRAINT edge_automatic_publication_l4_intent_092,
    DROP CONSTRAINT edge_automatic_publication_l4_intent_presence_092,
    DROP COLUMN publish_intent_id;

ALTER TABLE l4_publish_intents
    DROP CONSTRAINT l4_publish_intents_request_identity_092,
    DROP CONSTRAINT l4_publish_intents_runtime_spec_092,
    DROP CONSTRAINT l4_publish_intents_stream_scope_092,
    DROP COLUMN configuration_source_revision,
    ADD CONSTRAINT l4_publish_intents_runtime_spec_check
        CHECK (jsonb_typeof(runtime_spec) = 'object');

DROP FUNCTION validate_l4_runtime_spec_092(uuid, jsonb);

ALTER TABLE l4_forwards
    DROP CONSTRAINT l4_forwards_id_scope_092,
    DROP CONSTRAINT l4_forwards_scope_package_092,
    DROP COLUMN max_connections_per_client,
    DROP COLUMN package_subscription_id;

ALTER TABLE package_subscriptions
    DROP CONSTRAINT package_subscriptions_tenant_id_092;
