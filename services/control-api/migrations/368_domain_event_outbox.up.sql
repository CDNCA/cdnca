LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;

DO $migration_368_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 367 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 367 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=367 AND
        migration_id='367_ip_intel_updates' AND
        checksum_sha256='955b1067c671e95b8936a8104fca76c2f8915fbcba4c461392a097e1047fe515' AND
        down_checksum_sha256='7996a514fc7658985bb94fbec64b504b5a24b3192ab5f9c07743d22e0fa9f8b5' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 368 requires the exact verified 367 release head' USING ERRCODE='P3680';
    END IF;
END;
$migration_368_up$;

-- PA-20: one generic, transactional domain event outbox for every public
-- plugin event. Migrations 187/189 held a deployment-only outbox; 1.0.35 is a
-- fresh-install baseline, so they are replaced instead of bridged.
LOCK TABLE sites, plugin_webhook_subscriptions, plugin_webhook_events, plugin_webhook_deliveries,
    plugin_webhook_event_contracts_122, deployment_domain_event_fanout_receipts,
    deployment_domain_event_source_outbox IN ACCESS EXCLUSIVE MODE;

-- Contract registry ---------------------------------------------------------

CREATE TABLE domain_event_types_368 (
    event_type text PRIMARY KEY REFERENCES plugin_webhook_event_contracts_122(event_type) ON DELETE RESTRICT,
    subject_kind text NOT NULL CHECK (subject_kind ~ '^[a-z][a-z0-9_]{0,31}$'),
    required_permission text NOT NULL CHECK (required_permission ~ '^events\.[a-z][a-z0-9_]*\.read$'),
    site_bound boolean NOT NULL
);

CREATE TABLE domain_event_contract_fields_368 (
    event_type text NOT NULL REFERENCES domain_event_types_368(event_type) ON DELETE RESTRICT,
    field_name text NOT NULL CHECK (field_name ~ '^[a-z][a-z0-9_]{0,63}$' AND
        field_name NOT IN ('subscription_id','subject_sequence','test')),
    kind text NOT NULL CHECK (kind IN ('uuid','string','integer','timestamp','string_array')),
    required boolean NOT NULL,
    allowed_values text[] CHECK (allowed_values IS NULL OR
        (cardinality(allowed_values) BETWEEN 1 AND 64 AND kind IN ('string','string_array'))),
    PRIMARY KEY (event_type, field_name)
);

INSERT INTO domain_event_types_368(event_type, subject_kind, required_permission, site_bound) VALUES
    ('io.cdnca.deployment.v1.status_changed', 'deployment', 'events.deployment.read', false),
    ('io.cdnca.site.v1.updated', 'site', 'events.site.read', true);

INSERT INTO domain_event_contract_fields_368(event_type, field_name, kind, required, allowed_values) VALUES
    ('io.cdnca.deployment.v1.status_changed', 'deployment_id', 'uuid', true, NULL),
    ('io.cdnca.deployment.v1.status_changed', 'rollout_id', 'uuid', true, NULL),
    ('io.cdnca.deployment.v1.status_changed', 'node_id', 'uuid', true, NULL),
    ('io.cdnca.deployment.v1.status_changed', 'attempt', 'integer', true, NULL),
    ('io.cdnca.deployment.v1.status_changed', 'transition_sequence', 'integer', true, NULL),
    ('io.cdnca.deployment.v1.status_changed', 'state', 'string', true,
        ARRAY['queued','delivered','agent_queued','started','staged','prechecked','activated','healthy',
              'failed','reverting','reverted','rollback_failed']),
    ('io.cdnca.site.v1.updated', 'site_id', 'uuid', true, NULL),
    ('io.cdnca.site.v1.updated', 'change', 'string', true,
        ARRAY['created','updated','enabled','disabled','deleted']),
    ('io.cdnca.site.v1.updated', 'changed_fields', 'string_array', true,
        ARRAY['domains','origins','ports','https','line_group','status','settings']);

CREATE FUNCTION protect_domain_event_contract_368()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'domain event contracts change only by migration' USING ERRCODE='P3681';
END;
$$;

CREATE TRIGGER domain_event_types_protect_368
BEFORE UPDATE OR DELETE ON domain_event_types_368
FOR EACH ROW EXECUTE FUNCTION protect_domain_event_contract_368();
CREATE TRIGGER domain_event_contract_fields_protect_368
BEFORE UPDATE OR DELETE ON domain_event_contract_fields_368
FOR EACH ROW EXECUTE FUNCTION protect_domain_event_contract_368();

-- The generic outbox replaces the deployment-only 187/189 tables.
DROP TABLE deployment_domain_event_fanout_receipts;
DROP FUNCTION validate_deployment_domain_event_fanout_receipt_189();
DROP TABLE deployment_domain_event_source_outbox;
DROP FUNCTION validate_deployment_domain_event_source_outbox();

-- Activate the two first-batch events; reserved events stay unsubscribable.
ALTER TABLE plugin_webhook_event_contracts_122 DISABLE TRIGGER plugin_webhook_event_contracts_protect_122;
UPDATE plugin_webhook_event_contracts_122 SET status='active'
WHERE event_type IN ('io.cdnca.deployment.v1.status_changed','io.cdnca.site.v1.updated');
ALTER TABLE plugin_webhook_event_contracts_122 ENABLE TRIGGER plugin_webhook_event_contracts_protect_122;

-- Payload validation (mirrors internal/domaineventsource/contract.go) -------

CREATE FUNCTION domain_event_value_valid_368(kind text, allowed_values text[], value jsonb)
RETURNS boolean LANGUAGE plpgsql IMMUTABLE PARALLEL SAFE AS $$
DECLARE
    item jsonb;
    seen text[] := ARRAY[]::text[];
BEGIN
    IF value IS NULL THEN
        RETURN false;
    END IF;
    CASE kind
    WHEN 'uuid' THEN
        RETURN jsonb_typeof(value)='string' AND
            value #>> '{}' ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$';
    WHEN 'string' THEN
        RETURN jsonb_typeof(value)='string' AND char_length(value #>> '{}') BETWEEN 1 AND 256 AND
            value #>> '{}' = btrim(value #>> '{}') AND
            (allowed_values IS NULL OR value #>> '{}' = ANY(allowed_values));
    WHEN 'integer' THEN
        RETURN jsonb_typeof(value)='number' AND value::text ~ '^(0|[1-9][0-9]{0,17})$';
    WHEN 'timestamp' THEN
        RETURN jsonb_typeof(value)='string' AND
            value #>> '{}' ~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]{1,6})?Z$';
    WHEN 'string_array' THEN
        IF jsonb_typeof(value) <> 'array' OR jsonb_array_length(value) > 32 THEN
            RETURN false;
        END IF;
        FOR item IN SELECT element FROM jsonb_array_elements(value) AS element LOOP
            IF jsonb_typeof(item) <> 'string' OR item #>> '{}' !~ '^[a-z][a-z0-9_]{0,63}$' OR
               item #>> '{}' = ANY(seen) OR
               (allowed_values IS NOT NULL AND NOT (item #>> '{}' = ANY(allowed_values))) THEN
                RETURN false;
            END IF;
            seen := seen || (item #>> '{}');
        END LOOP;
        RETURN true;
    ELSE
        RETURN false;
    END CASE;
END;
$$;

-- domain_event_payload_valid_368 checks the stored source payload: exactly the
-- declared fields, required ones present, each of its declared kind.
CREATE FUNCTION domain_event_payload_valid_368(event_type_value text, payload jsonb)
RETURNS boolean LANGUAGE plpgsql STABLE PARALLEL SAFE AS $$
DECLARE
    key_name text;
    key_value jsonb;
    field record;
BEGIN
    IF jsonb_typeof(payload) IS DISTINCT FROM 'object' OR
       NOT EXISTS (SELECT 1 FROM domain_event_types_368 WHERE event_type=event_type_value) THEN
        RETURN false;
    END IF;
    FOR key_name, key_value IN SELECT key, value FROM jsonb_each(payload) LOOP
        SELECT kind, allowed_values INTO field FROM domain_event_contract_fields_368
        WHERE event_type=event_type_value AND field_name=key_name;
        IF NOT FOUND OR NOT domain_event_value_valid_368(field.kind, field.allowed_values, key_value) THEN
            RETURN false;
        END IF;
    END LOOP;
    RETURN NOT EXISTS (
        SELECT 1 FROM domain_event_contract_fields_368
        WHERE event_type=event_type_value AND required AND NOT (payload ? field_name)
    );
END;
$$;

-- Webhook event data: test events keep {subscription_id,test:true}; domain
-- events carry subscription_id + subject_sequence + their contract fields.
CREATE OR REPLACE FUNCTION plugin_webhook_data_valid_122(
    event_type_value text,
    subscription_value uuid,
    data_value jsonb
)
RETURNS boolean LANGUAGE plpgsql STABLE STRICT PARALLEL SAFE AS $$
BEGIN
    IF jsonb_typeof(data_value) IS DISTINCT FROM 'object' OR
       data_value ->> 'subscription_id' IS DISTINCT FROM subscription_value::text OR
       jsonb_typeof(data_value -> 'subscription_id') IS DISTINCT FROM 'string' OR
       octet_length(data_value::text) > 65536 OR
       (SELECT count(*) FROM jsonb_object_keys(data_value)) > 16 THEN
        RETURN false;
    END IF;
    IF event_type_value = 'io.cdnca.webhook.v1.test' THEN
        RETURN data_value = jsonb_build_object('subscription_id', subscription_value::text, 'test', true);
    END IF;
    RETURN jsonb_typeof(data_value -> 'subject_sequence') = 'number' AND
        (data_value -> 'subject_sequence')::text ~ '^[1-9][0-9]{0,17}$' AND
        domain_event_payload_valid_368(event_type_value, data_value - 'subscription_id' - 'subject_sequence');
END;
$$;

ALTER TABLE plugin_webhook_events
    DROP CONSTRAINT plugin_webhook_events_check,
    DROP CONSTRAINT plugin_webhook_events_check1,
    ADD CONSTRAINT plugin_webhook_events_subject_368 CHECK (
        (event_type = 'io.cdnca.webhook.v1.test' AND subject = 'webhook_subscription/' || subscription_id::text) OR
        (event_type <> 'io.cdnca.webhook.v1.test' AND
         subject ~ '^[a-z][a-z0-9_]{0,31}/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$')
    ),
    ADD CONSTRAINT plugin_webhook_events_test_data_368 CHECK (
        event_type <> 'io.cdnca.webhook.v1.test' OR
        data = jsonb_build_object('subscription_id', subscription_id::text, 'test', true)
    );

-- Only active contracts are subscribable (reserved ones were accepted before).
CREATE OR REPLACE FUNCTION validate_plugin_webhook_subscription_contract_122()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF (SELECT count(*) FROM unnest(NEW.event_types) AS requested(event_type)
        JOIN plugin_webhook_event_contracts_122 contract ON contract.event_type = requested.event_type
        WHERE contract.status = 'active') <> cardinality(NEW.event_types) THEN
        RAISE EXCEPTION 'plugin webhook subscription contains an unknown or unavailable event type'
            USING ERRCODE = 'P8404';
    END IF;
    RETURN NEW;
END;
$$;

-- Generic source outbox -----------------------------------------------------

CREATE TABLE domain_event_subject_heads_368 (
    tenant_scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE RESTRICT,
    event_type text NOT NULL REFERENCES domain_event_types_368(event_type) ON DELETE RESTRICT,
    subject text NOT NULL,
    last_sequence bigint NOT NULL CHECK (last_sequence >= 0),
    PRIMARY KEY (tenant_scope_id, event_type, subject)
);

CREATE TABLE domain_event_outbox_368 (
    id uuid PRIMARY KEY,
    event_type text NOT NULL REFERENCES domain_event_types_368(event_type) ON DELETE RESTRICT,
    tenant_scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE RESTRICT,
    site_id uuid,
    subject text NOT NULL CHECK (
        subject ~ '^[a-z][a-z0-9_]{0,31}/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'),
    subject_sequence bigint NOT NULL CHECK (subject_sequence > 0),
    dedup_key text NOT NULL UNIQUE CHECK (char_length(dedup_key) BETWEEN 1 AND 512 AND dedup_key = btrim(dedup_key)),
    occurred_at timestamptz NOT NULL CHECK (isfinite(occurred_at) AND date_trunc('microseconds', occurred_at) = occurred_at),
    payload jsonb NOT NULL CHECK (octet_length(payload::text) BETWEEN 2 AND 16384),
    delivery_state text NOT NULL DEFAULT 'pending' CHECK (delivery_state IN ('pending','leased','published','failed')),
    lease_token uuid,
    lease_expires_at timestamptz,
    publish_attempts integer NOT NULL DEFAULT 0 CHECK (publish_attempts >= 0),
    available_at timestamptz NOT NULL,
    published_at timestamptz,
    last_error text CHECK (last_error IS NULL OR char_length(last_error) <= 2048),
    created_at timestamptz NOT NULL,
    UNIQUE (tenant_scope_id, event_type, subject, subject_sequence),
    FOREIGN KEY (tenant_scope_id, event_type, subject)
        REFERENCES domain_event_subject_heads_368(tenant_scope_id, event_type, subject) ON DELETE RESTRICT,
    CHECK ((delivery_state = 'leased') = (lease_token IS NOT NULL AND lease_expires_at IS NOT NULL)),
    CHECK ((delivery_state = 'published') = (published_at IS NOT NULL)),
    CHECK (published_at IS NULL OR published_at >= created_at)
);

CREATE INDEX domain_event_outbox_368_ready_idx
    ON domain_event_outbox_368 (available_at, id) WHERE delivery_state IN ('pending','failed');
CREATE INDEX domain_event_outbox_368_lease_idx
    ON domain_event_outbox_368 (lease_expires_at, id) WHERE delivery_state = 'leased';
CREATE INDEX domain_event_outbox_368_unpublished_subject_idx
    ON domain_event_outbox_368 (tenant_scope_id, event_type, subject, subject_sequence)
    WHERE delivery_state <> 'published';
CREATE INDEX domain_event_outbox_368_replay_idx
    ON domain_event_outbox_368 (tenant_scope_id, occurred_at, id);

CREATE FUNCTION validate_domain_event_outbox_368()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    tenant_kind text;
    contract record;
    site_scope uuid;
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'domain event outbox is append-only' USING ERRCODE='P3682';
    END IF;
    IF TG_OP = 'INSERT' THEN
        SELECT kind INTO tenant_kind FROM access_scopes WHERE id=NEW.tenant_scope_id;
        SELECT subject_kind, site_bound INTO contract FROM domain_event_types_368 WHERE event_type=NEW.event_type;
        IF tenant_kind IS DISTINCT FROM 'tenant' OR contract IS NULL OR
           split_part(NEW.subject, '/', 1) <> contract.subject_kind OR
           contract.site_bound <> (NEW.site_id IS NOT NULL) OR
           (NEW.site_id IS NOT NULL AND NEW.payload ->> 'site_id' IS DISTINCT FROM NEW.site_id::text) OR
           NOT domain_event_payload_valid_368(NEW.event_type, NEW.payload) THEN
            RAISE EXCEPTION 'domain event source fact violates its contract' USING ERRCODE='P3683';
        END IF;
        -- A site that still exists must belong to the event tenant (a deleted
        -- site may outlive its row: site.updated "deleted" is such a fact).
        IF NEW.site_id IS NOT NULL THEN
            SELECT scope_id INTO site_scope FROM sites WHERE id=NEW.site_id;
            IF FOUND AND site_scope IS DISTINCT FROM NEW.tenant_scope_id THEN
                RAISE EXCEPTION 'domain event site belongs to another tenant' USING ERRCODE='P3683';
            END IF;
        END IF;
        IF NEW.delivery_state<>'pending' OR NEW.lease_token IS NOT NULL OR NEW.lease_expires_at IS NOT NULL OR
           NEW.publish_attempts<>0 OR NEW.published_at IS NOT NULL OR NEW.last_error IS NOT NULL OR
           NEW.available_at IS DISTINCT FROM NEW.created_at THEN
            RAISE EXCEPTION 'invalid initial domain event lease state' USING ERRCODE='P3683';
        END IF;
        RETURN NEW;
    END IF;
    IF ROW(NEW.id,NEW.event_type,NEW.tenant_scope_id,NEW.site_id,NEW.subject,NEW.subject_sequence,
           NEW.dedup_key,NEW.occurred_at,NEW.payload,NEW.created_at) IS DISTINCT FROM
       ROW(OLD.id,OLD.event_type,OLD.tenant_scope_id,OLD.site_id,OLD.subject,OLD.subject_sequence,
           OLD.dedup_key,OLD.occurred_at,OLD.payload,OLD.created_at) THEN
        RAISE EXCEPTION 'domain event source fact is immutable' USING ERRCODE='P3684';
    END IF;
    IF OLD.delivery_state IN ('pending','failed') AND NEW.delivery_state='leased' THEN
        IF NEW.lease_expires_at<=transaction_timestamp() OR OLD.available_at>clock_timestamp() OR
           NEW.publish_attempts<>OLD.publish_attempts+1 OR NEW.available_at IS DISTINCT FROM OLD.available_at OR
           NEW.last_error IS NOT NULL THEN
            RAISE EXCEPTION 'invalid domain event lease claim' USING ERRCODE='P3684';
        END IF;
    ELSIF OLD.delivery_state='leased' AND NEW.delivery_state='published' THEN
        IF NEW.publish_attempts<>OLD.publish_attempts OR NEW.last_error IS NOT NULL THEN
            RAISE EXCEPTION 'invalid domain event publication' USING ERRCODE='P3684';
        END IF;
    ELSIF OLD.delivery_state='leased' AND NEW.delivery_state='failed' THEN
        IF NEW.publish_attempts<>OLD.publish_attempts OR NEW.last_error IS NULL OR NEW.last_error='' THEN
            RAISE EXCEPTION 'invalid domain event retry settlement' USING ERRCODE='P3684';
        END IF;
    ELSE
        RAISE EXCEPTION 'invalid domain event lease transition' USING ERRCODE='P3684';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER domain_event_outbox_guard_368
BEFORE INSERT OR UPDATE OR DELETE ON domain_event_outbox_368
FOR EACH ROW EXECUTE FUNCTION validate_domain_event_outbox_368();

CREATE FUNCTION protect_domain_event_subject_head_368()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP='DELETE' OR NEW.last_sequence < OLD.last_sequence OR
       ROW(NEW.tenant_scope_id,NEW.event_type,NEW.subject) IS DISTINCT FROM
       ROW(OLD.tenant_scope_id,OLD.event_type,OLD.subject) THEN
        RAISE EXCEPTION 'domain event subject heads only advance' USING ERRCODE='P3685';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER domain_event_subject_heads_guard_368
BEFORE UPDATE OR DELETE ON domain_event_subject_heads_368
FOR EACH ROW EXECUTE FUNCTION protect_domain_event_subject_head_368();

-- domain_event_append_368 is the only writer of the outbox. The subject head
-- row lock serialises writers of one subject, so a later writer waits for the
-- earlier commit and subject_sequence follows commit order. A repeated dedup
-- key with the same fact is an idempotent replay; a different fact is a
-- conflict (reported, not raised, so the caller's transaction stays usable).
-- occurred_at is clamped to the append clock: a source clock ahead of the
-- control plane (agent skew) must not produce an event "from the future",
-- which the webhook event clock (migration 124) rejects. It is therefore not
-- part of the dedup identity.
CREATE FUNCTION domain_event_append_368(
    p_id uuid, p_event_type text, p_tenant_scope_id uuid, p_site_id uuid, p_subject text,
    p_dedup_key text, p_occurred_at timestamptz, p_payload jsonb)
RETURNS TABLE(id uuid, subject_sequence bigint, replayed boolean, conflict boolean)
LANGUAGE plpgsql AS $$
DECLARE
    existing record;
    next_sequence bigint;
    now_value timestamptz := clock_timestamp();
BEGIN
    INSERT INTO domain_event_subject_heads_368(tenant_scope_id, event_type, subject, last_sequence)
    VALUES (p_tenant_scope_id, p_event_type, p_subject, 0)
    ON CONFLICT ON CONSTRAINT domain_event_subject_heads_368_pkey DO NOTHING;
    SELECT head.last_sequence INTO next_sequence FROM domain_event_subject_heads_368 head
    WHERE head.tenant_scope_id=p_tenant_scope_id AND head.event_type=p_event_type AND head.subject=p_subject
    FOR UPDATE;
    SELECT outbox.id, outbox.subject_sequence, outbox.event_type, outbox.tenant_scope_id, outbox.site_id,
           outbox.subject, outbox.payload
    INTO existing FROM domain_event_outbox_368 outbox WHERE outbox.dedup_key=p_dedup_key;
    IF FOUND THEN
        RETURN QUERY SELECT existing.id, existing.subject_sequence, true,
            ROW(existing.id, existing.event_type, existing.tenant_scope_id, existing.site_id, existing.subject,
                existing.payload) IS DISTINCT FROM
            ROW(p_id, p_event_type, p_tenant_scope_id, p_site_id, p_subject, p_payload);
        RETURN;
    END IF;
    next_sequence := next_sequence + 1;
    UPDATE domain_event_subject_heads_368 head SET last_sequence=next_sequence
    WHERE head.tenant_scope_id=p_tenant_scope_id AND head.event_type=p_event_type AND head.subject=p_subject;
    INSERT INTO domain_event_outbox_368(id, event_type, tenant_scope_id, site_id, subject, subject_sequence,
        dedup_key, occurred_at, payload, available_at, created_at)
    VALUES (p_id, p_event_type, p_tenant_scope_id, p_site_id, p_subject, next_sequence,
        p_dedup_key, LEAST(date_trunc('microseconds', p_occurred_at), date_trunc('microseconds', now_value)),
        p_payload, now_value, now_value);
    RETURN QUERY SELECT p_id, next_sequence, false, false;
END;
$$;

-- Per-subscription fanout receipts (generalises 189) ------------------------

CREATE TABLE domain_event_fanout_receipts_368 (
    source_id uuid NOT NULL REFERENCES domain_event_outbox_368(id) ON DELETE RESTRICT,
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
           (status='failed' AND completed_at IS NOT NULL AND error IS NOT NULL AND btrim(error) <> '' AND
            event_id IS NULL AND delivery_id IS NULL)),
    CHECK (completed_at IS NULL OR completed_at >= created_at)
);

CREATE INDEX domain_event_fanout_receipts_368_pending_idx
    ON domain_event_fanout_receipts_368(source_id, subscription_id) WHERE status='pending';
CREATE INDEX domain_event_fanout_receipts_368_subscription_idx
    ON domain_event_fanout_receipts_368(tenant_scope_id, subscription_id, created_at DESC);

CREATE FUNCTION validate_domain_event_fanout_receipt_368()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP='DELETE' THEN
        RAISE EXCEPTION 'domain event fanout receipts are append-only' USING ERRCODE='P3686';
    END IF;
    IF TG_OP='UPDATE' AND (
       ROW(NEW.source_id,NEW.tenant_scope_id,NEW.subscription_id,NEW.installation_authorization_id,
           NEW.installation_id,NEW.plugin_id,NEW.created_at) IS DISTINCT FROM
       ROW(OLD.source_id,OLD.tenant_scope_id,OLD.subscription_id,OLD.installation_authorization_id,
           OLD.installation_id,OLD.plugin_id,OLD.created_at) OR
       NEW.attempts < OLD.attempts OR
       (OLD.status <> 'pending' AND
        ROW(NEW.status,NEW.attempts,NEW.event_id,NEW.delivery_id,NEW.error,NEW.completed_at) IS DISTINCT FROM
        ROW(OLD.status,OLD.attempts,OLD.event_id,OLD.delivery_id,OLD.error,OLD.completed_at))) THEN
        RAISE EXCEPTION 'domain event fanout receipt transition is invalid' USING ERRCODE='P3686';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER domain_event_fanout_receipts_guard_368
BEFORE INSERT OR UPDATE OR DELETE ON domain_event_fanout_receipts_368
FOR EACH ROW EXECUTE FUNCTION validate_domain_event_fanout_receipt_368();

-- Every domain event delivery (first send and replay) re-checks the bound
-- installation: it must still be enabled and hold the event's permission.
-- Revoking a permission therefore also stops replays of older events.
CREATE FUNCTION validate_domain_event_delivery_scope_368()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    delivered_type text;
    required_scope text;
BEGIN
    SELECT event.event_type INTO delivered_type FROM plugin_webhook_events event
    WHERE event.tenant_scope_id=NEW.tenant_scope_id AND event.subscription_id=NEW.subscription_id
      AND event.id=NEW.event_id;
    IF delivered_type IS NULL OR delivered_type = 'io.cdnca.webhook.v1.test' THEN
        RETURN NEW;
    END IF;
    SELECT required_permission INTO required_scope FROM domain_event_types_368 WHERE event_type=delivered_type;
    IF required_scope IS NULL OR NOT EXISTS (
        SELECT 1 FROM plugin_webhook_subscriptions subscription
        JOIN plugin_installation_heads installation
          ON installation.tenant_scope_id=subscription.tenant_scope_id
         AND installation.authorization_id=subscription.installation_authorization_id
         AND installation.installation_id=subscription.installation_id
         AND installation.plugin_id=subscription.plugin_id
        WHERE subscription.tenant_scope_id=NEW.tenant_scope_id AND subscription.id=NEW.subscription_id
          AND installation.status='enabled' AND required_scope = ANY(installation.approved_scopes)
    ) THEN
        RAISE EXCEPTION 'plugin installation lacks the event permission' USING ERRCODE='P3687';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER plugin_webhook_deliveries_domain_scope_368
BEFORE INSERT ON plugin_webhook_deliveries
FOR EACH ROW EXECUTE FUNCTION validate_domain_event_delivery_scope_368();

-- site.updated producer -----------------------------------------------------
-- Every site write path bumps sites.revision in its own transaction (site
-- create/update/origin/delete/batch, lock, conditional origin, sold package,
-- domain ownership claim, traffic suspension, identity hold, status recovery).
-- A deferred constraint trigger turns each committed revision into one fact in
-- that same transaction, so no write path can forget the event. It runs at
-- commit so site_domain_facts written after the UPDATE are visible.
-- Revision-free runtime projections (ipv6 runtime, CNAME allocation) emit
-- nothing. Platform-scope (default) sites are no tenant's site.
CREATE FUNCTION emit_site_updated_event_368()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    scope_kind text;
    change_value text;
    fields text[] := ARRAY[]::text[];
    dedup text;
    at_value timestamptz;
BEGIN
    SELECT kind INTO scope_kind FROM access_scopes WHERE id=NEW.scope_id;
    IF scope_kind IS DISTINCT FROM 'tenant' THEN
        RETURN NULL;
    END IF;
    IF TG_OP = 'INSERT' THEN
        change_value := 'created';
        dedup := 'site/' || NEW.id::text || '/' || NEW.revision::text;
        at_value := COALESCE(NEW.created_at, clock_timestamp());
    ELSIF OLD.deleted_at IS NULL AND NEW.deleted_at IS NOT NULL THEN
        change_value := 'deleted';
        fields := ARRAY['status'];
        dedup := 'site/' || NEW.id::text || '/' || NEW.revision::text || '/deleted';
        at_value := NEW.deleted_at;
    ELSIF NEW.revision IS DISTINCT FROM OLD.revision THEN
        change_value := CASE
            WHEN NEW.enabled AND NOT OLD.enabled THEN 'enabled'
            WHEN OLD.enabled AND NOT NEW.enabled THEN 'disabled'
            ELSE 'updated' END;
        IF ROW(NEW.domain, NEW.cname, NEW.cname_mode, NEW.cname_domain, NEW.cname_hostname2) IS DISTINCT FROM
           ROW(OLD.domain, OLD.cname, OLD.cname_mode, OLD.cname_domain, OLD.cname_hostname2) OR EXISTS (
            SELECT 1 FROM site_domain_facts fact WHERE fact.site_id=NEW.id AND fact.site_revision=NEW.revision) THEN
            fields := fields || 'domains'::text;
        END IF;
        IF ROW(NEW.origins, NEW.origin_hosts) IS DISTINCT FROM ROW(OLD.origins, OLD.origin_hosts) THEN
            fields := fields || 'origins'::text;
        END IF;
        IF ROW(NEW.http_ports, NEW.https_ports) IS DISTINCT FROM ROW(OLD.http_ports, OLD.https_ports) THEN
            fields := fields || 'ports'::text;
        END IF;
        IF ROW(NEW.https_enabled, NEW.tls_protocols, NEW.force_https, NEW.https_redirect_port) IS DISTINCT FROM
           ROW(OLD.https_enabled, OLD.tls_protocols, OLD.force_https, OLD.https_redirect_port) THEN
            fields := fields || 'https'::text;
        END IF;
        IF ROW(NEW.node_group_id, NEW.region_id, NEW.package_id, NEW.package_subscription_id) IS DISTINCT FROM
           ROW(OLD.node_group_id, OLD.region_id, OLD.package_id, OLD.package_subscription_id) THEN
            fields := fields || 'line_group'::text;
        END IF;
        IF ROW(NEW.enabled, NEW.status, NEW.lock_reason) IS DISTINCT FROM ROW(OLD.enabled, OLD.status, OLD.lock_reason) THEN
            fields := fields || 'status'::text;
        END IF;
        IF cardinality(fields) = 0 THEN
            fields := ARRAY['settings'];
        END IF;
        dedup := 'site/' || NEW.id::text || '/' || NEW.revision::text;
        at_value := COALESCE(NEW.updated_at, clock_timestamp());
    ELSE
        RETURN NULL;
    END IF;
    PERFORM domain_event_append_368(gen_random_uuid(), 'io.cdnca.site.v1.updated', NEW.scope_id, NEW.id,
        'site/' || NEW.id::text, dedup, at_value,
        jsonb_build_object('site_id', NEW.id::text, 'change', change_value, 'changed_fields', to_jsonb(fields)));
    RETURN NULL;
END;
$$;

CREATE CONSTRAINT TRIGGER sites_emit_site_updated_event_368
AFTER INSERT OR UPDATE ON sites
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION emit_site_updated_event_368();

REVOKE ALL ON FUNCTION protect_domain_event_contract_368(), domain_event_value_valid_368(text, text[], jsonb),
    domain_event_payload_valid_368(text, jsonb), validate_domain_event_outbox_368(),
    protect_domain_event_subject_head_368(),
    domain_event_append_368(uuid, text, uuid, uuid, text, text, timestamptz, jsonb),
    validate_domain_event_fanout_receipt_368(), validate_domain_event_delivery_scope_368(),
    emit_site_updated_event_368() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION domain_event_value_valid_368(text, text[], jsonb),
    domain_event_payload_valid_368(text, jsonb),
    domain_event_append_368(uuid, text, uuid, uuid, text, text, timestamptz, jsonb)
    TO cdnca_control_app, cdnca_control_runtime, cdnca_plugin_webhook_runtime;
GRANT SELECT ON domain_event_types_368, domain_event_contract_fields_368
    TO cdnca_control_app, cdnca_control_runtime, cdnca_plugin_webhook_runtime;
GRANT SELECT, INSERT, UPDATE ON domain_event_subject_heads_368, domain_event_outbox_368,
    domain_event_fanout_receipts_368 TO cdnca_control_app, cdnca_control_runtime;
