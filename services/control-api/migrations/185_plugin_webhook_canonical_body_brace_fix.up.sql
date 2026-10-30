LOCK TABLE schema_migrations,plugin_webhook_events IN ACCESS EXCLUSIVE MODE;

DO $migration_185$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 184 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 184 OR EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE migration_id IS NULL OR migration_id='' OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
              down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR integrity_state IS DISTINCT FROM 'verified' OR
              metadata_recorded_at IS NULL OR applied_at IS NULL
    ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version=184 AND migration_id='184_analytics_realtime_source_window_authority' AND
              checksum_sha256='667f64f3907c25e555778df5005ce4b7a28b83fa24b0c93139785ac52d3c14e6' AND
              down_checksum_sha256='9addb38601c01e7566a7285e1dcccf174e187ef8a99b2de7b576093e68cec233' AND
              integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
    ) THEN
        RAISE EXCEPTION 'migration 185 requires the exact verified 184 release head'
            USING ERRCODE='P1850';
    END IF;
END;
$migration_185$;

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
        ',"data":' || plugin_webhook_json_canonical_122(data_value) || '}',
        'UTF8'
    );
END;
$$;

REVOKE ALL ON FUNCTION plugin_webhook_canonical_body_084(uuid, uuid, text, text, timestamptz, text, text, numeric, jsonb) FROM PUBLIC;
