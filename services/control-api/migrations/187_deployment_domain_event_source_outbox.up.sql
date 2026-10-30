LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;

DO $migration_187$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 186 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 186 OR EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE migration_id IS NULL OR migration_id = '' OR
              checksum_sha256 IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
              down_checksum_sha256 IS NULL OR down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR
              integrity_state IS DISTINCT FROM 'verified' OR metadata_recorded_at IS NULL OR applied_at IS NULL
    ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version=186 AND migration_id='186_site_domain_export_rbac' AND
              checksum_sha256='fa30f9adc3f68d6bddca97311f1345fb39327cb06cb28e8d640ee824e4466203' AND
              down_checksum_sha256='a10c012d16f9bf4e00789b8ba5a96ee59607509cd557e2051e6de3b4a0049fef' AND
              integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
    ) THEN
        RAISE EXCEPTION 'migration 187 requires the exact verified 186 release head'
            USING ERRCODE='P1870';
    END IF;
END;
$migration_187$;

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
