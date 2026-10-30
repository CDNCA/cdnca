LOCK TABLE schema_migrations,
    plugin_webhook_subscriptions,
    plugin_webhook_events
IN ACCESS EXCLUSIVE MODE;

DO $$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 121 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 121 OR EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE migration_id IS NULL OR checksum_sha256 IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$'
           OR down_checksum_sha256 IS NULL OR down_checksum_sha256 !~ '^[0-9a-f]{64}$'
           OR integrity_state IS DISTINCT FROM 'verified' OR metadata_recorded_at IS NULL OR applied_at IS NULL
    ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version = 121
          AND migration_id = '121_package_monitor_alert_acknowledgement'
          AND checksum_sha256 = 'b0b22d4317e5e250bee2a9734bab7028d0a0438cc78c54a5b1a0fc7f62633a6f'
          AND down_checksum_sha256 = '37ac1bc284dcd9ef6cd88ee18fb6285cba5a06fa099de6ad284db8d64164a4a5'
          AND integrity_state = 'verified'
          AND metadata_recorded_at IS NOT NULL
          AND applied_at IS NOT NULL
    ) THEN
        RAISE EXCEPTION 'migration 122 requires the exact verified 121 release head'
            USING ERRCODE = 'P1220';
    END IF;
END;
$$;

CREATE TABLE plugin_webhook_event_contracts_122 (
    event_type text PRIMARY KEY CHECK (
        event_type ~ '^io\.cdnca\.[a-z][a-z0-9_]*\.v[1-9][0-9]*\.[a-z][a-z0-9_]*$'
        AND octet_length(event_type) <= 160
    ),
    schema_uri text NOT NULL CHECK (
        schema_uri = 'https://schemas.cdnca.example/marketplace/v1/webhook-test-event.schema.json' OR
        schema_uri = 'https://schemas.cdnca.example/marketplace/v1/domain-event.schema.json'
    ),
    status text NOT NULL CHECK (status IN ('reserved', 'active', 'deprecated')),
    max_data_fields smallint NOT NULL CHECK (max_data_fields BETWEEN 2 AND 16),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp() CHECK (isfinite(created_at))
);

INSERT INTO plugin_webhook_event_contracts_122(event_type, schema_uri, status, max_data_fields)
VALUES
    ('io.cdnca.certificate.v1.status_changed', 'https://schemas.cdnca.example/marketplace/v1/domain-event.schema.json', 'reserved', 16),
    ('io.cdnca.deployment.v1.status_changed', 'https://schemas.cdnca.example/marketplace/v1/domain-event.schema.json', 'reserved', 16),
    ('io.cdnca.dns.v1.changed', 'https://schemas.cdnca.example/marketplace/v1/domain-event.schema.json', 'reserved', 16),
    ('io.cdnca.dns.v1.deleted', 'https://schemas.cdnca.example/marketplace/v1/domain-event.schema.json', 'reserved', 16),
    ('io.cdnca.node.v1.status_changed', 'https://schemas.cdnca.example/marketplace/v1/domain-event.schema.json', 'reserved', 16),
    ('io.cdnca.security.v1.incident_detected', 'https://schemas.cdnca.example/marketplace/v1/domain-event.schema.json', 'reserved', 16),
    ('io.cdnca.site.v1.updated', 'https://schemas.cdnca.example/marketplace/v1/domain-event.schema.json', 'reserved', 16),
    ('io.cdnca.usage.v1.threshold_reached', 'https://schemas.cdnca.example/marketplace/v1/domain-event.schema.json', 'reserved', 16),
    ('io.cdnca.webhook.v1.test', 'https://schemas.cdnca.example/marketplace/v1/webhook-test-event.schema.json', 'active', 10);

CREATE FUNCTION plugin_webhook_event_type_valid_122(value text)
RETURNS boolean
LANGUAGE sql
IMMUTABLE
STRICT
PARALLEL SAFE
AS $$
    SELECT value ~ '^io\.cdnca\.[a-z][a-z0-9_]*\.v[1-9][0-9]*\.[a-z][a-z0-9_]*$'
       AND octet_length(value) BETWEEN 1 AND 160;
$$;

CREATE FUNCTION plugin_webhook_event_types_shape_122(value text[])
RETURNS boolean
LANGUAGE sql
IMMUTABLE
STRICT
PARALLEL SAFE
AS $$
    SELECT cardinality(value) BETWEEN 1 AND 16
       AND (SELECT count(*) = count(DISTINCT event_type)
            FROM unnest(value) AS event_type)
       AND NOT EXISTS (
            SELECT 1 FROM unnest(value) AS event_type
            WHERE NOT plugin_webhook_event_type_valid_122(event_type)
       );
$$;

CREATE FUNCTION plugin_webhook_data_valid_122(
    event_type_value text,
    subscription_value uuid,
    data_value jsonb
)
RETURNS boolean
LANGUAGE plpgsql
IMMUTABLE
STRICT
PARALLEL SAFE
AS $$
DECLARE
    key_name text;
    key_value jsonb;
    field_count integer;
BEGIN
    IF jsonb_typeof(data_value) IS DISTINCT FROM 'object' OR
       data_value ->> 'subscription_id' IS DISTINCT FROM subscription_value::text OR
       (event_type_value = 'io.cdnca.webhook.v1.test' AND
        (jsonb_typeof(data_value -> 'test') IS DISTINCT FROM 'boolean' OR
         data_value -> 'test' IS DISTINCT FROM 'true'::jsonb)) OR
       (event_type_value <> 'io.cdnca.webhook.v1.test' AND data_value ? 'test') THEN
        RETURN false;
    END IF;
    SELECT count(*) INTO field_count FROM jsonb_object_keys(data_value);
    IF field_count < 1 OR field_count > 16 OR octet_length(data_value::text) > 65536 THEN
        RETURN false;
    END IF;
    FOR key_name, key_value IN SELECT key, value FROM jsonb_each(data_value) LOOP
        IF key_name = 'subscription_id' OR key_name = 'test' THEN
            CONTINUE;
        END IF;
        IF key_name !~ '^x_[a-z][a-z0-9_]{0,63}$' OR jsonb_typeof(key_value) = 'null' THEN
            RETURN false;
        END IF;
    END LOOP;
    RETURN true;
END;
$$;

CREATE FUNCTION protect_plugin_webhook_event_contract_122()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP <> 'INSERT' THEN
        RAISE EXCEPTION 'plugin webhook event contracts are append-only'
            USING ERRCODE = 'P8403';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER plugin_webhook_event_contracts_protect_122
BEFORE UPDATE OR DELETE ON plugin_webhook_event_contracts_122
FOR EACH ROW EXECUTE FUNCTION protect_plugin_webhook_event_contract_122();

CREATE TRIGGER plugin_webhook_event_contracts_no_truncate_122
BEFORE TRUNCATE ON plugin_webhook_event_contracts_122
FOR EACH STATEMENT EXECUTE FUNCTION prevent_plugin_webhook_truncate_084();

ALTER TABLE plugin_webhook_subscriptions
    DROP CONSTRAINT plugin_webhook_subscriptions_event_types_check,
    ADD CONSTRAINT plugin_webhook_subscriptions_event_types_shape_122
        CHECK (plugin_webhook_event_types_shape_122(event_types));

CREATE FUNCTION validate_plugin_webhook_subscription_contract_122()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM unnest(NEW.event_types) AS requested(event_type)
        JOIN plugin_webhook_event_contracts_122 contract
          ON contract.event_type = requested.event_type
        WHERE contract.status IN ('reserved', 'active')
    ) OR (
        SELECT count(*) FROM unnest(NEW.event_types) AS requested(event_type)
        JOIN plugin_webhook_event_contracts_122 contract
          ON contract.event_type = requested.event_type
        WHERE contract.status IN ('reserved', 'active')
    ) <> cardinality(NEW.event_types) THEN
        RAISE EXCEPTION 'plugin webhook subscription contains an unknown or unavailable event type'
            USING ERRCODE = 'P8404';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER plugin_webhook_subscriptions_contract_122
BEFORE INSERT OR UPDATE ON plugin_webhook_subscriptions
FOR EACH ROW EXECUTE FUNCTION validate_plugin_webhook_subscription_contract_122();

ALTER TABLE plugin_webhook_events
    DROP CONSTRAINT plugin_webhook_events_event_type_check,
    DROP CONSTRAINT plugin_webhook_events_data_check,
    ADD CONSTRAINT plugin_webhook_events_event_type_shape_122
        CHECK (plugin_webhook_event_type_valid_122(event_type));

CREATE FUNCTION plugin_webhook_json_string_122(value text)
RETURNS text
LANGUAGE sql
IMMUTABLE
STRICT
PARALLEL SAFE
AS $$
    SELECT replace(replace(replace(replace(replace(
        to_json(value)::text,
        '&', E'\\u0026'),
        '<', E'\\u003c'),
        '>', E'\\u003e'),
        U&'\2028', E'\\u2028'),
        U&'\2029', E'\\u2029');
$$;

CREATE FUNCTION plugin_webhook_json_canonical_122(value jsonb)
RETURNS text
LANGUAGE plpgsql
IMMUTABLE
STRICT
PARALLEL SAFE
AS $$
DECLARE
    canonical text;
BEGIN
    CASE jsonb_typeof(value)
        WHEN 'object' THEN
            SELECT '{' || COALESCE(string_agg(
                plugin_webhook_json_string_122(member_key) || ':' ||
                plugin_webhook_json_canonical_122(member_value),
                ',' ORDER BY member_key COLLATE "C"
            ), '') || '}'
            INTO canonical
            FROM jsonb_each(value) AS members(member_key, member_value);
        WHEN 'array' THEN
            SELECT '[' || COALESCE(string_agg(
                plugin_webhook_json_canonical_122(element_value),
                ',' ORDER BY element_order
            ), '') || ']'
            INTO canonical
            FROM jsonb_array_elements(value) WITH ORDINALITY
                AS elements(element_value, element_order);
        WHEN 'string' THEN
            canonical := plugin_webhook_json_string_122(value #>> '{}');
        ELSE
            canonical := value::text;
    END CASE;
    RETURN canonical;
END;
$$;

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
    schema_uri text;
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
    schema_uri := CASE WHEN event_type_value = 'io.cdnca.webhook.v1.test'
        THEN 'https://schemas.cdnca.example/marketplace/v1/webhook-test-event.schema.json'
        ELSE 'https://schemas.cdnca.example/marketplace/v1/domain-event.schema.json'
    END;
    RETURN convert_to(
        '{"specversion":"1.0","id":' || to_jsonb(event_id_value::text)::text ||
        ',"source":"/control-plane/plugin-webhooks","type":' || to_jsonb(event_type_value)::text ||
        ',"subject":' || to_jsonb(subject_value)::text ||
        ',"time":' || to_jsonb(event_time_text)::text ||
        ',"datacontenttype":"application/json"' ||
        ',"dataschema":' || to_jsonb(schema_uri)::text ||
        ',"tenant_id":' || to_jsonb(tenant_id_value::text)::text ||
        ',"request_id":' || to_jsonb(request_id_value)::text ||
        CASE WHEN traceparent_value IS NULL THEN '' ELSE
            ',"traceparent":' || to_jsonb(traceparent_value)::text
        END ||
        ',"sequence":' || sequence_value::text ||
        ',"data":' || plugin_webhook_json_canonical_122(data_value),
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
    subscription_events text[];
    contract_schema text;
    contract_max_fields integer;
BEGIN
    SELECT scope.tenant_id INTO event_tenant_id
    FROM access_scopes scope
    WHERE scope.id = NEW.tenant_scope_id AND scope.kind = 'tenant'
    FOR SHARE;
    SELECT subscription.event_types INTO subscription_events
    FROM plugin_webhook_subscriptions subscription
    WHERE subscription.tenant_scope_id = NEW.tenant_scope_id
      AND subscription.id = NEW.subscription_id
    FOR SHARE;
    SELECT contract.schema_uri, contract.max_data_fields
      INTO contract_schema, contract_max_fields
    FROM plugin_webhook_event_contracts_122 contract
    WHERE contract.event_type = NEW.event_type
      AND contract.status IN ('reserved', 'active');
    IF event_tenant_id IS NULL OR contract_schema IS NULL OR
       (SELECT count(*) FROM jsonb_object_keys(NEW.data)) > contract_max_fields OR
       NOT (NEW.event_type = ANY(subscription_events)) OR
       NOT plugin_webhook_data_valid_122(NEW.event_type, NEW.subscription_id, NEW.data) THEN
        RAISE EXCEPTION 'plugin webhook event contract is invalid'
            USING ERRCODE = 'P8404';
    END IF;
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
    IF parsed_body IS DISTINCT FROM expected_json OR
       NEW.canonical_body IS DISTINCT FROM expected_body OR
       NEW.body_sha256 IS DISTINCT FROM sha256(NEW.canonical_body) THEN
        RAISE EXCEPTION 'plugin webhook canonical body does not match the event fact'
            USING ERRCODE = 'P8404';
    END IF;
    RETURN NEW;
END;
$$;

REVOKE ALL ON TABLE plugin_webhook_event_contracts_122 FROM PUBLIC;
GRANT SELECT ON TABLE plugin_webhook_event_contracts_122
    TO cdnca_control_app, cdnca_plugin_webhook_runtime;
REVOKE ALL ON FUNCTION plugin_webhook_event_type_valid_122(text) FROM PUBLIC;
REVOKE ALL ON FUNCTION plugin_webhook_event_types_shape_122(text[]) FROM PUBLIC;
REVOKE ALL ON FUNCTION plugin_webhook_data_valid_122(text, uuid, jsonb) FROM PUBLIC;
REVOKE ALL ON FUNCTION plugin_webhook_json_string_122(text) FROM PUBLIC;
REVOKE ALL ON FUNCTION plugin_webhook_json_canonical_122(jsonb) FROM PUBLIC;
REVOKE ALL ON FUNCTION validate_plugin_webhook_subscription_contract_122() FROM PUBLIC;
REVOKE ALL ON FUNCTION protect_plugin_webhook_event_contract_122() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION plugin_webhook_event_type_valid_122(text),
    plugin_webhook_event_types_shape_122(text[]),
    plugin_webhook_data_valid_122(text, uuid, jsonb),
    plugin_webhook_json_string_122(text),
    plugin_webhook_json_canonical_122(jsonb),
    validate_plugin_webhook_subscription_contract_122(),
    protect_plugin_webhook_event_contract_122()
    TO cdnca_control_app, cdnca_plugin_webhook_runtime;
