LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;
LOCK TABLE package_subscriptions,
    l4_forwards,
    l4_scope_publish_counters,
    l4_publish_intents,
    l4_write_requests,
    edge_automatic_publication_requests
IN ACCESS EXCLUSIVE MODE;

DO $$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 91 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 91 OR EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$'
           OR down_checksum_sha256 !~ '^[0-9a-f]{64}$'
           OR integrity_state <> 'verified' OR metadata_recorded_at IS NULL OR applied_at IS NULL
    ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version = 91
          AND migration_id = '091_notification_control_idempotency_receipts'
          AND checksum_sha256 = '9c556085f7396024a5011f74b06e0a6e3b83f5f6c5ab050b4b5c7b2ad036758c'
          AND down_checksum_sha256 = '7999ad3ae6ecf6b0eb182a1de59e82a37570264223a64f112c7bf8a8b8da8e04'
          AND integrity_state = 'verified'
    ) THEN
        RAISE EXCEPTION 'migration 092 requires the exact verified 091 release head'
            USING ERRCODE = 'P9200';
    END IF;
    IF EXISTS (SELECT 1 FROM l4_forwards) OR
       EXISTS (SELECT 1 FROM l4_scope_publish_counters) OR
       EXISTS (SELECT 1 FROM l4_publish_intents) OR
       EXISTS (SELECT 1 FROM l4_write_requests) OR
       EXISTS (SELECT 1 FROM edge_automatic_publication_requests WHERE source_kind = 'l4') THEN
        RAISE EXCEPTION 'migration 092 cannot infer package and runtime identity for existing L4 facts'
            USING ERRCODE = 'P9201';
    END IF;
END;
$$;

ALTER TABLE package_subscriptions
    ADD CONSTRAINT package_subscriptions_tenant_id_092
    UNIQUE (tenant_scope_id, id);

ALTER TABLE l4_forwards
    ADD COLUMN package_subscription_id uuid NOT NULL,
    ADD COLUMN max_connections_per_client integer NOT NULL
        CHECK (max_connections_per_client BETWEEN 1 AND 10000),
    ADD CONSTRAINT l4_forwards_scope_package_092
        FOREIGN KEY (scope_id, package_subscription_id)
        REFERENCES package_subscriptions(tenant_scope_id, id) ON DELETE RESTRICT,
    ADD CONSTRAINT l4_forwards_id_scope_092 UNIQUE (id, scope_id);

CREATE FUNCTION validate_l4_runtime_spec_092(target_stream_id uuid, runtime_spec jsonb)
RETURNS boolean
LANGUAGE plpgsql
IMMUTABLE
AS $$
DECLARE
    origin jsonb;
    protocol text;
    top_level_keys text[];
    origin_keys text[];
BEGIN
    IF target_stream_id IS NULL OR runtime_spec IS NULL OR
       jsonb_typeof(runtime_spec) <> 'object' THEN
        RETURN false;
    END IF;
    SELECT array_agg(key ORDER BY key) INTO top_level_keys
    FROM jsonb_object_keys(runtime_spec) AS keys(key);
    IF top_level_keys IS DISTINCT FROM ARRAY[
        'balance','connect_timeout_ms','drain_timeout_ms','id','listen_port',
        'max_connections_per_client','origins','protocol','proxy_protocol_inbound',
        'proxy_protocol_outbound','proxy_protocol_v1','response_timeout_ms'
    ]::text[] OR
       jsonb_typeof(runtime_spec -> 'id') <> 'string' OR
       jsonb_typeof(runtime_spec -> 'protocol') <> 'string' OR
       jsonb_typeof(runtime_spec -> 'listen_port') <> 'number' OR
       jsonb_typeof(runtime_spec -> 'balance') <> 'string' OR
       jsonb_typeof(runtime_spec -> 'origins') <> 'array' OR
       jsonb_typeof(runtime_spec -> 'connect_timeout_ms') <> 'number' OR
       jsonb_typeof(runtime_spec -> 'response_timeout_ms') <> 'number' OR
       jsonb_typeof(runtime_spec -> 'max_connections_per_client') <> 'number' OR
       jsonb_typeof(runtime_spec -> 'drain_timeout_ms') <> 'number' OR
       jsonb_typeof(runtime_spec -> 'proxy_protocol_inbound') <> 'boolean' OR
       jsonb_typeof(runtime_spec -> 'proxy_protocol_outbound') <> 'boolean' OR
       jsonb_typeof(runtime_spec -> 'proxy_protocol_v1') <> 'boolean' OR
       jsonb_array_length(runtime_spec -> 'origins') <> 1 THEN
        RETURN false;
    END IF;
    origin := runtime_spec -> 'origins' -> 0;
    IF jsonb_typeof(origin) <> 'object' THEN
        RETURN false;
    END IF;
    SELECT array_agg(key ORDER BY key) INTO origin_keys
    FROM jsonb_object_keys(origin) AS keys(key);
    IF origin_keys IS DISTINCT FROM ARRAY[
        'fail_timeout_ms','host','max_fails','port','state','weight'
    ]::text[] OR
       jsonb_typeof(origin -> 'host') <> 'string' OR
       jsonb_typeof(origin -> 'port') <> 'number' OR
       jsonb_typeof(origin -> 'weight') <> 'number' OR
       jsonb_typeof(origin -> 'state') <> 'string' OR
       jsonb_typeof(origin -> 'max_fails') <> 'number' OR
       jsonb_typeof(origin -> 'fail_timeout_ms') <> 'number' THEN
        RETURN false;
    END IF;
    protocol := runtime_spec ->> 'protocol';
    RETURN COALESCE(runtime_spec ->> 'id' = 'stream_' || replace(target_stream_id::text, '-', '')
       AND protocol IN ('tcp', 'udp')
       AND (runtime_spec ->> 'listen_port')::integer BETWEEN 1 AND 65535
       AND runtime_spec ->> 'balance' = 'round_robin'
       AND char_length(origin ->> 'host') BETWEEN 1 AND 253
       AND (origin ->> 'port')::integer BETWEEN 1 AND 65535
       AND (origin ->> 'weight')::integer = 1
       AND origin ->> 'state' = 'primary'
       AND (origin ->> 'max_fails')::integer = 3
       AND (origin ->> 'fail_timeout_ms')::integer = 10000
       AND (runtime_spec ->> 'connect_timeout_ms')::integer BETWEEN 50 AND 30000
       AND (runtime_spec ->> 'response_timeout_ms')::integer BETWEEN 100 AND 600000
       AND (runtime_spec ->> 'max_connections_per_client')::integer BETWEEN 1 AND 10000
       AND (runtime_spec ->> 'drain_timeout_ms')::integer = 30000
       AND NOT (runtime_spec ->> 'proxy_protocol_inbound')::boolean
       AND (runtime_spec ->> 'proxy_protocol_outbound')::boolean =
           (runtime_spec ->> 'proxy_protocol_v1')::boolean
       AND (protocol = 'tcp' OR NOT (runtime_spec ->> 'proxy_protocol_v1')::boolean), false);
EXCEPTION WHEN OTHERS THEN
    RETURN false;
END;
$$;

REVOKE ALL ON FUNCTION validate_l4_runtime_spec_092(uuid, jsonb) FROM PUBLIC;

ALTER TABLE l4_publish_intents
    DROP CONSTRAINT l4_publish_intents_runtime_spec_check,
    ADD COLUMN configuration_source_revision bigint NOT NULL
        CHECK (configuration_source_revision > 0),
    ADD CONSTRAINT l4_publish_intents_stream_scope_092
        FOREIGN KEY (stream_id, scope_id)
        REFERENCES l4_forwards(id, scope_id) ON DELETE RESTRICT,
    ADD CONSTRAINT l4_publish_intents_runtime_spec_092
        CHECK (validate_l4_runtime_spec_092(stream_id, runtime_spec)),
    ADD CONSTRAINT l4_publish_intents_request_identity_092
        UNIQUE (id, scope_id, stream_id, configuration_source_revision);

ALTER TABLE edge_automatic_publication_requests
    ADD COLUMN publish_intent_id uuid,
    ADD CONSTRAINT edge_automatic_publication_l4_intent_presence_092 CHECK (
        (source_kind = 'site' AND publish_intent_id IS NULL) OR
        (source_kind = 'l4' AND publish_intent_id IS NOT NULL)
    ),
    ADD CONSTRAINT edge_automatic_publication_l4_intent_092
        FOREIGN KEY (publish_intent_id, target_scope_id, source_resource_id, source_revision)
        REFERENCES l4_publish_intents(id, scope_id, stream_id, configuration_source_revision)
        ON DELETE RESTRICT;
