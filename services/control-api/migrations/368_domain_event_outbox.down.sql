LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;

DO $migration_368_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 368 OR
       (SELECT max(version) FROM schema_migrations) <> 368 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=368 AND migration_id='368_domain_event_outbox' AND
        integrity_state='verified'
       ) THEN
        RAISE EXCEPTION 'migration 368 down requires the verified 368 head' USING ERRCODE='P3689';
    END IF;
    IF EXISTS (SELECT 1 FROM domain_event_outbox_368) OR
       EXISTS (SELECT 1 FROM plugin_webhook_events WHERE event_type <> 'io.cdnca.webhook.v1.test') THEN
        RAISE EXCEPTION 'migration 368 down would discard domain event history' USING ERRCODE='P3689';
    END IF;
END;
$migration_368_down$;

LOCK TABLE sites, plugin_webhook_subscriptions, plugin_webhook_events, plugin_webhook_deliveries,
    plugin_webhook_event_contracts_122 IN ACCESS EXCLUSIVE MODE;

DROP TRIGGER sites_emit_site_updated_event_368 ON sites;
DROP FUNCTION emit_site_updated_event_368();
DROP TRIGGER plugin_webhook_deliveries_domain_scope_368 ON plugin_webhook_deliveries;
DROP TABLE domain_event_fanout_receipts_368;
DROP TABLE domain_event_outbox_368;
DROP TABLE domain_event_subject_heads_368;
DROP FUNCTION domain_event_append_368(uuid, text, uuid, uuid, text, text, timestamptz, jsonb);
DROP FUNCTION validate_domain_event_delivery_scope_368();
DROP FUNCTION validate_domain_event_fanout_receipt_368();
DROP FUNCTION protect_domain_event_subject_head_368();
DROP FUNCTION validate_domain_event_outbox_368();

ALTER TABLE plugin_webhook_events
    DROP CONSTRAINT plugin_webhook_events_subject_368,
    DROP CONSTRAINT plugin_webhook_events_test_data_368,
    ADD CONSTRAINT plugin_webhook_events_check CHECK (subject = 'webhook_subscription/' || subscription_id::text),
    ADD CONSTRAINT plugin_webhook_events_check1
        CHECK (data = jsonb_build_object('subscription_id', subscription_id::text, 'test', true));

CREATE OR REPLACE FUNCTION plugin_webhook_data_valid_122(
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

CREATE OR REPLACE FUNCTION validate_plugin_webhook_subscription_contract_122()
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

DROP FUNCTION domain_event_payload_valid_368(text, jsonb);
DROP FUNCTION domain_event_value_valid_368(text, text[], jsonb);

ALTER TABLE plugin_webhook_event_contracts_122 DISABLE TRIGGER plugin_webhook_event_contracts_protect_122;
UPDATE plugin_webhook_event_contracts_122 SET status='reserved'
WHERE event_type IN ('io.cdnca.deployment.v1.status_changed','io.cdnca.site.v1.updated');
ALTER TABLE plugin_webhook_event_contracts_122 ENABLE TRIGGER plugin_webhook_event_contracts_protect_122;

DROP TABLE domain_event_contract_fields_368;
DROP TABLE domain_event_types_368;
DROP FUNCTION protect_domain_event_contract_368();

-- Restore the 187/189 deployment-only outbox exactly.
CREATE TABLE deployment_domain_event_source_outbox (
    id uuid PRIMARY KEY,
    event_type text NOT NULL CHECK (event_type = 'io.cdnca.deployment.v1.status_changed'),
    tenant_scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE RESTRICT,
    configuration_scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE RESTRICT,
    deployment_id uuid NOT NULL,
    node_id uuid NOT NULL REFERENCES nodes(id) ON DELETE RESTRICT,
    rollout_id uuid NOT NULL REFERENCES rollouts(id) ON DELETE RESTRICT,
    attempt integer NOT NULL CHECK (attempt > 0),
    transition_sequence bigint NOT NULL CHECK (transition_sequence > 0),
    state text NOT NULL CHECK (
        state IN ('queued','delivered','staged','prechecked','activated','healthy',
                  'failed','reverting','reverted','rollback_failed')
    ),
    request_id uuid NOT NULL,
    occurred_at timestamptz NOT NULL,
    payload bytea NOT NULL CHECK (octet_length(payload) BETWEEN 2 AND 65536),
    payload_sha256 bytea NOT NULL CHECK (octet_length(payload_sha256) = 32),
    dedup_key text NOT NULL CHECK (
        char_length(dedup_key) BETWEEN 1 AND 512 AND dedup_key = btrim(dedup_key)
    ),
    delivery_state text NOT NULL DEFAULT 'pending' CHECK (
        delivery_state IN ('pending','leased','published','failed')
    ),
    lease_token uuid,
    lease_expires_at timestamptz,
    publish_attempts integer NOT NULL DEFAULT 0 CHECK (publish_attempts >= 0),
    available_at timestamptz NOT NULL,
    published_at timestamptz,
    last_error text CHECK (last_error IS NULL OR char_length(last_error) <= 2048),
    created_at timestamptz NOT NULL,
    FOREIGN KEY (deployment_id,attempt) REFERENCES node_deployments(id,attempt) ON DELETE RESTRICT,
    UNIQUE (deployment_id,attempt,transition_sequence),
    UNIQUE (dedup_key),
    CHECK ((delivery_state = 'leased') = (lease_token IS NOT NULL AND lease_expires_at IS NOT NULL)),
    CHECK (delivery_state <> 'leased' OR lease_expires_at > available_at),
    CHECK ((delivery_state = 'published') = (published_at IS NOT NULL)),
    CHECK (delivery_state <> 'published' OR lease_token IS NULL),
    CHECK (published_at IS NULL OR published_at >= created_at)
);

CREATE INDEX deployment_domain_event_source_outbox_pending_idx
    ON deployment_domain_event_source_outbox (available_at,id)
    WHERE delivery_state IN ('pending','failed');

CREATE INDEX deployment_domain_event_source_outbox_lease_idx
    ON deployment_domain_event_source_outbox (lease_expires_at,id)
    WHERE delivery_state = 'leased';

CREATE FUNCTION validate_deployment_domain_event_source_outbox()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    document jsonb;
    document_field_count bigint;
    bound_scope_id uuid;
    bound_node_id uuid;
    bound_rollout_id uuid;
    bound_transition_sequence bigint;
    bound_state text;
    bound_occurred_at timestamptz;
    bound_received_at timestamptz;
    occurred_at_text text;
    expected_payload bytea;
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'deployment domain event source outbox is append-only';
    END IF;

    BEGIN
        document := convert_from(NEW.payload,'UTF8')::jsonb;
        SELECT count(*) INTO document_field_count FROM jsonb_object_keys(document);
    EXCEPTION WHEN OTHERS THEN
        RAISE EXCEPTION 'invalid deployment domain event source payload';
    END;
    occurred_at_text := to_char(NEW.occurred_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS');
    IF to_char(NEW.occurred_at AT TIME ZONE 'UTC','US')='000000' THEN
        occurred_at_text := occurred_at_text||'Z';
    ELSE
        occurred_at_text := occurred_at_text||'.'||
            rtrim(to_char(NEW.occurred_at AT TIME ZONE 'UTC','US'),'0')||'Z';
    END IF;
    expected_payload := convert_to(
        '{"configuration_scope_id":'||to_jsonb(NEW.configuration_scope_id::text)::text||
        ',"deployment_id":'||to_jsonb(NEW.deployment_id::text)::text||
        ',"event_id":'||to_jsonb(NEW.id::text)::text||
        ',"node_id":'||to_jsonb(NEW.node_id::text)::text||
        ',"rollout_id":'||to_jsonb(NEW.rollout_id::text)::text||
        ',"attempt":'||NEW.attempt::text||
        ',"transition_sequence":'||NEW.transition_sequence::text||
        ',"state":'||to_jsonb(NEW.state)::text||
        ',"request_id":'||to_jsonb(NEW.request_id::text)::text||
        ',"occurred_at":'||to_jsonb(occurred_at_text)::text||
        ',"tenant_scope_id":'||to_jsonb(NEW.tenant_scope_id::text)::text||'}','UTF8');
    IF NEW.payload IS DISTINCT FROM expected_payload OR
       sha256(NEW.payload) IS DISTINCT FROM NEW.payload_sha256 OR
       jsonb_typeof(document)<>'object' OR document_field_count<>11 OR NOT
       (document ?& ARRAY['configuration_scope_id','deployment_id','event_id','node_id','rollout_id',
          'attempt','transition_sequence','state','request_id','occurred_at','tenant_scope_id']) OR
       document ?| ARRAY['command','command_bytes','secret','token','private_key'] OR
       document->>'configuration_scope_id' IS DISTINCT FROM NEW.configuration_scope_id::text OR
       document->>'deployment_id' IS DISTINCT FROM NEW.deployment_id::text OR
       document->>'event_id' IS DISTINCT FROM NEW.id::text OR
       document->>'node_id' IS DISTINCT FROM NEW.node_id::text OR
       document->>'rollout_id' IS DISTINCT FROM NEW.rollout_id::text OR
       document->'attempt' IS DISTINCT FROM to_jsonb(NEW.attempt) OR
       document->'transition_sequence' IS DISTINCT FROM to_jsonb(NEW.transition_sequence) OR
       document->>'state' IS DISTINCT FROM NEW.state OR
       document->>'request_id' IS DISTINCT FROM NEW.request_id::text OR
       (document->>'occurred_at')::timestamptz IS DISTINCT FROM NEW.occurred_at OR
       document->>'tenant_scope_id' IS DISTINCT FROM NEW.tenant_scope_id::text OR
       NEW.dedup_key IS DISTINCT FROM NEW.event_type||'/'||NEW.deployment_id::text||'/'||
           NEW.attempt::text||'/'||NEW.transition_sequence::text THEN
        RAISE EXCEPTION 'deployment domain event source payload binding failed';
    END IF;

    SELECT rollout.configuration_scope_id,deployment.node_id,deployment.rollout_id
    INTO bound_scope_id,bound_node_id,bound_rollout_id
    FROM node_deployments deployment
    JOIN rollouts rollout ON rollout.id=deployment.rollout_id
    WHERE deployment.id=NEW.deployment_id AND deployment.attempt=NEW.attempt
    FOR KEY SHARE OF deployment,rollout;
    IF NOT FOUND OR NEW.tenant_scope_id IS DISTINCT FROM bound_scope_id OR
       NEW.configuration_scope_id IS DISTINCT FROM bound_scope_id OR
       NEW.node_id IS DISTINCT FROM bound_node_id OR NEW.rollout_id IS DISTINCT FROM bound_rollout_id THEN
        RAISE EXCEPTION 'deployment domain event source relation binding failed';
    END IF;

    SELECT transition_sequence,state,occurred_at,received_at
    INTO bound_transition_sequence,bound_state,bound_occurred_at,bound_received_at
    FROM deployment_status_events
    WHERE event_id=NEW.id AND deployment_id=NEW.deployment_id AND attempt=NEW.attempt
    FOR KEY SHARE;
    IF NOT FOUND OR NEW.transition_sequence IS DISTINCT FROM bound_transition_sequence OR
       NEW.state IS DISTINCT FROM bound_state OR NEW.occurred_at IS DISTINCT FROM bound_occurred_at OR
       NEW.created_at IS DISTINCT FROM bound_received_at THEN
        RAISE EXCEPTION 'deployment domain event source status fact binding failed';
    END IF;

    IF TG_OP = 'INSERT' THEN
        IF NEW.delivery_state<>'pending' OR NEW.lease_token IS NOT NULL OR NEW.lease_expires_at IS NOT NULL OR
           NEW.publish_attempts<>0 OR NEW.published_at IS NOT NULL OR NEW.last_error IS NOT NULL OR
           NEW.available_at IS DISTINCT FROM NEW.created_at THEN
            RAISE EXCEPTION 'invalid initial deployment domain event source lease state';
        END IF;
        RETURN NEW;
    END IF;

    IF ROW(NEW.id,NEW.event_type,NEW.tenant_scope_id,NEW.configuration_scope_id,NEW.deployment_id,
           NEW.node_id,NEW.rollout_id,NEW.attempt,NEW.transition_sequence,NEW.state,NEW.request_id,
           NEW.occurred_at,NEW.payload,NEW.payload_sha256,NEW.dedup_key,NEW.created_at)
       IS DISTINCT FROM
       ROW(OLD.id,OLD.event_type,OLD.tenant_scope_id,OLD.configuration_scope_id,OLD.deployment_id,
           OLD.node_id,OLD.rollout_id,OLD.attempt,OLD.transition_sequence,OLD.state,OLD.request_id,
           OLD.occurred_at,OLD.payload,OLD.payload_sha256,OLD.dedup_key,OLD.created_at) THEN
        RAISE EXCEPTION 'deployment domain event source outbox fact is immutable';
    END IF;
    IF OLD.delivery_state IN ('pending','failed') AND NEW.delivery_state='leased' THEN
        IF NEW.lease_token IS NULL OR NEW.lease_expires_at<=transaction_timestamp() OR
           OLD.available_at>transaction_timestamp() OR NEW.publish_attempts<>OLD.publish_attempts+1 OR
           NEW.available_at IS DISTINCT FROM OLD.available_at OR NEW.published_at IS NOT NULL OR
           NEW.last_error IS NOT NULL THEN
            RAISE EXCEPTION 'invalid deployment domain event source lease claim';
        END IF;
    ELSIF OLD.delivery_state='leased' AND NEW.delivery_state='published' THEN
        IF NEW.lease_token IS NOT NULL OR NEW.lease_expires_at IS NOT NULL OR
           NEW.publish_attempts<>OLD.publish_attempts OR NEW.available_at IS DISTINCT FROM OLD.available_at OR
           NEW.published_at IS NULL OR NEW.published_at<NEW.created_at OR NEW.last_error IS NOT NULL THEN
            RAISE EXCEPTION 'invalid deployment domain event source publication';
        END IF;
    ELSIF OLD.delivery_state='leased' AND NEW.delivery_state='failed' THEN
        IF NEW.lease_token IS NOT NULL OR NEW.lease_expires_at IS NOT NULL OR
           NEW.publish_attempts<>OLD.publish_attempts OR NEW.available_at<transaction_timestamp() OR
           NEW.published_at IS NOT NULL OR NEW.last_error IS NULL OR NEW.last_error='' THEN
            RAISE EXCEPTION 'invalid deployment domain event source retry settlement';
        END IF;
    ELSE
        RAISE EXCEPTION 'invalid deployment domain event source lease transition';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER deployment_domain_event_source_outbox_append_only
BEFORE INSERT OR UPDATE OR DELETE ON deployment_domain_event_source_outbox
FOR EACH ROW EXECUTE FUNCTION validate_deployment_domain_event_source_outbox();

REVOKE ALL ON FUNCTION validate_deployment_domain_event_source_outbox() FROM PUBLIC;

LOCK TABLE deployment_domain_event_source_outbox IN ACCESS EXCLUSIVE MODE;

CREATE TABLE deployment_domain_event_fanout_receipts (
    source_id uuid NOT NULL REFERENCES deployment_domain_event_source_outbox(id) ON DELETE RESTRICT,
    tenant_scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE RESTRICT,
    subscription_id uuid NOT NULL,
    installation_authorization_id uuid NOT NULL,
    installation_id uuid NOT NULL,
    plugin_id text NOT NULL CHECK (btrim(plugin_id) <> '' AND octet_length(plugin_id) <= 256),
    status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','published','failed')),
    attempts integer NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    event_id uuid,
    delivery_id uuid,
    error text CHECK (error IS NULL OR char_length(error) <= 2048),
    created_at timestamptz NOT NULL,
    completed_at timestamptz,
    PRIMARY KEY (source_id, subscription_id),
    FOREIGN KEY (tenant_scope_id, subscription_id)
        REFERENCES plugin_webhook_subscriptions(tenant_scope_id, id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_scope_id, installation_authorization_id)
        REFERENCES plugin_installation_heads(tenant_scope_id, authorization_id) ON DELETE RESTRICT,
    CHECK ((status='pending' AND completed_at IS NULL AND error IS NULL AND event_id IS NULL AND delivery_id IS NULL) OR
           (status='published' AND completed_at IS NOT NULL AND error IS NULL AND event_id IS NOT NULL AND delivery_id IS NOT NULL) OR
           (status='failed' AND completed_at IS NOT NULL AND error IS NOT NULL AND char_length(btrim(error)) > 0 AND event_id IS NULL AND delivery_id IS NULL)),
    CHECK ((event_id IS NULL) = (delivery_id IS NULL)),
    CHECK (completed_at IS NULL OR completed_at >= created_at)
);

CREATE INDEX deployment_domain_event_fanout_receipts_pending_idx
    ON deployment_domain_event_fanout_receipts(source_id, subscription_id)
    WHERE status='pending';

CREATE INDEX deployment_domain_event_fanout_receipts_subscription_idx
    ON deployment_domain_event_fanout_receipts(tenant_scope_id, subscription_id, created_at DESC);

CREATE FUNCTION validate_deployment_domain_event_fanout_receipt_189()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP='UPDATE' AND
       ROW(NEW.source_id,NEW.tenant_scope_id,NEW.subscription_id,NEW.installation_authorization_id,
           NEW.installation_id,NEW.plugin_id,NEW.created_at) IS DISTINCT FROM
       ROW(OLD.source_id,OLD.tenant_scope_id,OLD.subscription_id,OLD.installation_authorization_id,
           OLD.installation_id,OLD.plugin_id,OLD.created_at) THEN
        RAISE EXCEPTION 'deployment fanout receipt identity is immutable' USING ERRCODE='P1891';
    END IF;
    IF TG_OP='DELETE' THEN
        RAISE EXCEPTION 'deployment fanout receipts are append-only' USING ERRCODE='P1892';
    END IF;
    IF TG_OP='UPDATE' AND OLD.status IN ('published','failed') AND
       ROW(NEW.status,NEW.attempts,NEW.event_id,NEW.delivery_id,NEW.error,NEW.completed_at) IS DISTINCT FROM
       ROW(OLD.status,OLD.attempts,OLD.event_id,OLD.delivery_id,OLD.error,OLD.completed_at) THEN
        RAISE EXCEPTION 'deployment fanout receipt terminal state is immutable' USING ERRCODE='P1895';
    END IF;
    IF TG_OP='UPDATE' AND NEW.attempts < OLD.attempts THEN
        RAISE EXCEPTION 'deployment fanout receipt attempts cannot decrease' USING ERRCODE='P1896';
    END IF;
    IF NEW.status='pending' AND NEW.attempts < 0 THEN
        RAISE EXCEPTION 'deployment fanout receipt attempts are invalid' USING ERRCODE='P1893';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER deployment_domain_event_fanout_receipt_guard_189
BEFORE INSERT OR UPDATE OR DELETE ON deployment_domain_event_fanout_receipts
FOR EACH ROW EXECUTE FUNCTION validate_deployment_domain_event_fanout_receipt_189();

REVOKE ALL ON FUNCTION validate_deployment_domain_event_fanout_receipt_189() FROM PUBLIC;

-- The recreated tables return to the 367 head shape: 284 node purge (cascade
-- foreign keys, purge-exempt delete triggers) and 289 agent queue (the named
-- state_289 check that 289 down replaces).
ALTER TABLE deployment_domain_event_fanout_receipts DROP CONSTRAINT deployment_domain_event_fanout_receipts_source_id_fkey,
    ADD CONSTRAINT deployment_domain_event_fanout_receipts_source_id_fkey FOREIGN KEY (source_id) REFERENCES deployment_domain_event_source_outbox(id) ON DELETE CASCADE;
ALTER TABLE deployment_domain_event_source_outbox DROP CONSTRAINT deployment_domain_event_source_outbo_deployment_id_attempt_fkey,
    ADD CONSTRAINT deployment_domain_event_source_outbo_deployment_id_attempt_fkey FOREIGN KEY (deployment_id, attempt) REFERENCES node_deployments(id, attempt) ON DELETE CASCADE;
ALTER TABLE deployment_domain_event_source_outbox DROP CONSTRAINT deployment_domain_event_source_outbox_node_id_fkey,
    ADD CONSTRAINT deployment_domain_event_source_outbox_node_id_fkey FOREIGN KEY (node_id) REFERENCES nodes(id) ON DELETE CASCADE;
ALTER TABLE deployment_domain_event_source_outbox DROP CONSTRAINT deployment_domain_event_source_outbox_state_check;
ALTER TABLE deployment_domain_event_source_outbox ADD CONSTRAINT deployment_domain_event_source_outbox_state_289
    CHECK (state IN ('queued','delivered','agent_queued','started','staged','prechecked','activated','healthy',
        'failed','reverting','reverted','rollback_failed'));
DROP TRIGGER deployment_domain_event_fanout_receipt_guard_189 ON deployment_domain_event_fanout_receipts;
CREATE TRIGGER deployment_domain_event_fanout_receipt_guard_189 BEFORE INSERT OR UPDATE ON deployment_domain_event_fanout_receipts FOR EACH ROW EXECUTE FUNCTION validate_deployment_domain_event_fanout_receipt_189();
CREATE TRIGGER deployment_domain_event_fanout_receipt_guard_189_del BEFORE DELETE ON deployment_domain_event_fanout_receipts FOR EACH ROW
    WHEN (NOT node_purge_in_progress()) EXECUTE FUNCTION validate_deployment_domain_event_fanout_receipt_189();
DROP TRIGGER deployment_domain_event_source_outbox_append_only ON deployment_domain_event_source_outbox;
CREATE TRIGGER deployment_domain_event_source_outbox_append_only BEFORE INSERT OR UPDATE ON deployment_domain_event_source_outbox FOR EACH ROW EXECUTE FUNCTION validate_deployment_domain_event_source_outbox();
CREATE TRIGGER deployment_domain_event_source_outbox_append_only_del BEFORE DELETE ON deployment_domain_event_source_outbox FOR EACH ROW
    WHEN (NOT node_purge_permits(OLD.node_id)) EXECUTE FUNCTION validate_deployment_domain_event_source_outbox();
