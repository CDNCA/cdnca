LOCK TABLE schema_migrations,
    plugin_webhook_subscriptions,
    plugin_webhook_events,
    plugin_webhook_deliveries,
    plugin_webhook_outbox,
    plugin_webhook_write_requests,
    plugin_webhook_rate_events,
    plugin_webhook_entitlement_decisions,
    plugin_webhook_domain_contract_123_backup
IN ACCESS EXCLUSIVE MODE;

DO $$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 123 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 123 OR EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE migration_id IS NULL OR checksum_sha256 IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$'
           OR down_checksum_sha256 IS NULL OR down_checksum_sha256 !~ '^[0-9a-f]{64}$'
           OR integrity_state IS DISTINCT FROM 'verified' OR metadata_recorded_at IS NULL OR applied_at IS NULL
    ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version = 123
          AND migration_id = '123_plugin_webhook_domain_event_producer'
          AND integrity_state = 'verified'
          AND metadata_recorded_at IS NOT NULL
          AND applied_at IS NOT NULL
    ) THEN
        RAISE EXCEPTION 'migration 123 rollback requires the exact verified release head'
            USING ERRCODE = 'P1230';
    END IF;
    IF EXISTS (
        SELECT 1 FROM plugin_webhook_subscriptions
        WHERE event_types <> ARRAY['io.cdnca.webhook.v1.test']::text[]
    ) OR EXISTS (
        SELECT 1 FROM plugin_webhook_events
        WHERE event_type <> 'io.cdnca.webhook.v1.test'
    ) OR EXISTS (
        SELECT 1 FROM plugin_webhook_write_requests
        WHERE operation = 'plugin_webhook.domain_event.publish'
    ) OR EXISTS (
        SELECT 1 FROM plugin_webhook_rate_events
        WHERE operation = 'plugin_webhook.domain_event.publish'
    ) THEN
        RAISE EXCEPTION 'migration 123 rollback would discard domain webhook facts'
            USING ERRCODE = 'P1232';
    END IF;
END;
$$;

DO $$
DECLARE
    definition text;
BEGIN
    FOR definition IN
        SELECT backup.definition
        FROM plugin_webhook_domain_contract_123_backup backup
        ORDER BY backup.function_name
    LOOP
        EXECUTE definition;
    END LOOP;
END;
$$;

ALTER TABLE plugin_webhook_write_requests
    DROP CONSTRAINT plugin_webhook_write_requests_operation_123,
    DROP CONSTRAINT plugin_webhook_write_requests_response_status_123,
    DROP CONSTRAINT plugin_webhook_write_requests_result_shape_123,
    DROP CONSTRAINT plugin_webhook_write_requests_response_body_123,
    ADD CONSTRAINT plugin_webhook_write_requests_operation_check CHECK (operation IN (
        'plugin_webhook.subscription.create',
        'plugin_webhook.test_delivery.create',
        'plugin_webhook.delivery.replay',
        'plugin_webhook.secret.rotate',
        'plugin_webhook.secret.activate',
        'plugin_webhook.subscription.revoke'
    )),
    ADD CONSTRAINT plugin_webhook_write_requests_check CHECK (
        response_status IS NULL OR response_status = CASE
            WHEN operation IN ('plugin_webhook.subscription.create', 'plugin_webhook.secret.rotate') THEN 201
            WHEN operation IN ('plugin_webhook.test_delivery.create', 'plugin_webhook.delivery.replay') THEN 202
            ELSE 200
        END
    ),
    ADD CONSTRAINT plugin_webhook_write_requests_check2 CHECK (
        (operation = 'plugin_webhook.subscription.create' AND delivery_id IS NULL AND rotation_id IS NULL) OR
        (operation IN ('plugin_webhook.test_delivery.create', 'plugin_webhook.delivery.replay') AND
         delivery_id IS NOT NULL AND rotation_id IS NULL) OR
        (operation IN ('plugin_webhook.secret.rotate', 'plugin_webhook.secret.activate') AND
         delivery_id IS NULL AND rotation_id IS NOT NULL) OR
        (operation = 'plugin_webhook.subscription.revoke' AND delivery_id IS NULL AND rotation_id IS NULL)
    ),
    ADD CONSTRAINT plugin_webhook_write_requests_check3 CHECK (
        response_body IS NULL OR
        (operation IN ('plugin_webhook.subscription.create', 'plugin_webhook.subscription.revoke') AND
         response_body = jsonb_build_object('subscription_id', subscription_id::text)) OR
        (operation = 'plugin_webhook.secret.activate' AND response_body = jsonb_build_object(
             'subscription_id', subscription_id::text, 'rotation_id', rotation_id::text
         )) OR
        (operation IN ('plugin_webhook.test_delivery.create', 'plugin_webhook.delivery.replay') AND
         response_body = jsonb_build_object(
             'subscription_id', subscription_id::text, 'delivery_id', delivery_id::text
         )) OR
        (operation = 'plugin_webhook.secret.rotate' AND response_body = jsonb_build_object(
             'subscription_id', subscription_id::text, 'rotation_id', rotation_id::text
         ))
    );

ALTER TABLE plugin_webhook_rate_events
    DROP CONSTRAINT plugin_webhook_rate_events_operation_123,
    ADD CONSTRAINT plugin_webhook_rate_events_operation_check CHECK (operation IN (
        'plugin_webhook.subscription.create',
        'plugin_webhook.test_delivery.create',
        'plugin_webhook.delivery.replay',
        'plugin_webhook.secret.rotate'
    ));

DROP TABLE plugin_webhook_domain_contract_123_backup;
