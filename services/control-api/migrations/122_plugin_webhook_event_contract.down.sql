LOCK TABLE schema_migrations,
    plugin_webhook_subscriptions,
    plugin_webhook_events,
    plugin_webhook_event_contracts_122
IN ACCESS EXCLUSIVE MODE;

DO $$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 122 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 122 OR EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE migration_id IS NULL OR checksum_sha256 IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$'
           OR down_checksum_sha256 IS NULL OR down_checksum_sha256 !~ '^[0-9a-f]{64}$'
           OR integrity_state IS DISTINCT FROM 'verified' OR metadata_recorded_at IS NULL OR applied_at IS NULL
    ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version = 122
          AND migration_id = '122_plugin_webhook_event_contract'
          AND integrity_state = 'verified'
          AND metadata_recorded_at IS NOT NULL
          AND applied_at IS NOT NULL
    ) THEN
        RAISE EXCEPTION 'migration 122 rollback requires the exact verified release head'
            USING ERRCODE = 'P1220';
    END IF;
    IF EXISTS (
        SELECT 1 FROM plugin_webhook_subscriptions
        WHERE event_types <> ARRAY['io.cdnca.webhook.v1.test']::text[]
    ) OR EXISTS (
        SELECT 1 FROM plugin_webhook_events
        WHERE event_type <> 'io.cdnca.webhook.v1.test'
           OR data IS DISTINCT FROM jsonb_build_object(
               'subscription_id', subscription_id::text, 'test', true)
    ) THEN
        RAISE EXCEPTION 'migration 122 rollback would discard non-test webhook contract data'
            USING ERRCODE = 'P1222';
    END IF;
END;
$$;

DROP TRIGGER plugin_webhook_subscriptions_contract_122 ON plugin_webhook_subscriptions;
DROP FUNCTION validate_plugin_webhook_subscription_contract_122();
DROP TRIGGER plugin_webhook_event_contracts_no_truncate_122 ON plugin_webhook_event_contracts_122;
DROP TRIGGER plugin_webhook_event_contracts_protect_122 ON plugin_webhook_event_contracts_122;
DROP FUNCTION protect_plugin_webhook_event_contract_122();

ALTER TABLE plugin_webhook_subscriptions
    DROP CONSTRAINT plugin_webhook_subscriptions_event_types_shape_122,
    ADD CONSTRAINT plugin_webhook_subscriptions_event_types_check
        CHECK (event_types = ARRAY['io.cdnca.webhook.v1.test']::text[]);

ALTER TABLE plugin_webhook_events
    DROP CONSTRAINT plugin_webhook_events_event_type_shape_122,
    ADD CONSTRAINT plugin_webhook_events_event_type_check
        CHECK (event_type = 'io.cdnca.webhook.v1.test'),
    ADD CONSTRAINT plugin_webhook_events_data_check
        CHECK (data = jsonb_build_object('subscription_id', subscription_id::text, 'test', true));

CREATE OR REPLACE FUNCTION plugin_webhook_canonical_body_084(
    event_id_value uuid,
    tenant_id_value uuid,
    event_type_value text,
    subject_value text,
    event_time_value timestamptz,
    request_id_value text,
    traceparent_value text,
    sequence_value numeric,
    data_value jsonb
)
RETURNS bytea
LANGUAGE plpgsql
IMMUTABLE
PARALLEL SAFE
AS $$
DECLARE
    event_time_text text;
BEGIN
    event_time_text := to_char(
        event_time_value AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS'
    );
    IF to_char(event_time_value AT TIME ZONE 'UTC', 'US') = '000000' THEN
        event_time_text := event_time_text || 'Z';
    ELSE
        event_time_text := event_time_text || '.' ||
            rtrim(to_char(event_time_value AT TIME ZONE 'UTC', 'US'), '0') || 'Z';
    END IF;
    RETURN convert_to(
        '{"specversion":"1.0","id":' || to_jsonb(event_id_value::text)::text ||
        ',"source":"/control-plane/plugin-webhooks","type":' || to_jsonb(event_type_value)::text ||
        ',"subject":' || to_jsonb(subject_value)::text ||
        ',"time":' || to_jsonb(event_time_text)::text ||
        ',"datacontenttype":"application/json"' ||
        ',"dataschema":"https://schemas.cdnca.example/marketplace/v1/webhook-test-event.schema.json"' ||
        ',"tenant_id":' || to_jsonb(tenant_id_value::text)::text ||
        ',"request_id":' || to_jsonb(request_id_value)::text ||
        CASE WHEN traceparent_value IS NULL THEN '' ELSE
            ',"traceparent":' || to_jsonb(traceparent_value)::text
        END ||
        ',"sequence":' || sequence_value::text ||
        ',"data":{"subscription_id":' ||
            to_jsonb(data_value ->> 'subscription_id')::text ||
            ',"test":' || (data_value -> 'test')::text || '}}',
        'UTF8'
    );
END;
$$;

CREATE OR REPLACE FUNCTION validate_plugin_webhook_event_body_084()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    event_tenant_id uuid;
    parsed_body jsonb;
    expected_body bytea;
    expected_json jsonb;
BEGIN
    SELECT scope.tenant_id INTO event_tenant_id
    FROM access_scopes scope
    WHERE scope.id = NEW.tenant_scope_id AND scope.kind = 'tenant'
    FOR SHARE;
    BEGIN
        parsed_body := convert_from(NEW.canonical_body, 'UTF8')::jsonb;
    EXCEPTION WHEN OTHERS THEN
        RAISE EXCEPTION 'plugin webhook canonical body is not valid UTF-8 JSON'
            USING ERRCODE = 'P8404';
    END;
    expected_body := plugin_webhook_canonical_body_084(
        NEW.id, event_tenant_id, NEW.event_type, NEW.subject, NEW.event_time,
        NEW.request_id, NEW.traceparent, NEW.sequence, NEW.data
    );
    expected_json := convert_from(expected_body, 'UTF8')::jsonb;
    IF event_tenant_id IS NULL OR parsed_body IS DISTINCT FROM expected_json OR
       NEW.canonical_body IS DISTINCT FROM expected_body OR
       NEW.body_sha256 IS DISTINCT FROM sha256(NEW.canonical_body) THEN
        RAISE EXCEPTION 'plugin webhook canonical body does not match the event fact'
            USING ERRCODE = 'P8404';
    END IF;
    RETURN NEW;
END;
$$;

DROP TABLE plugin_webhook_event_contracts_122;
DROP FUNCTION plugin_webhook_json_canonical_122(jsonb);
DROP FUNCTION plugin_webhook_json_string_122(text);
DROP FUNCTION plugin_webhook_data_valid_122(text, uuid, jsonb);
DROP FUNCTION plugin_webhook_event_types_shape_122(text[]);
DROP FUNCTION plugin_webhook_event_type_valid_122(text);
