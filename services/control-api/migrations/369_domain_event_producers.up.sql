LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;

DO $migration_369_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 368 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 368 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=368 AND
        migration_id='368_domain_event_outbox' AND
        checksum_sha256='e9f9ae32d271771a2e33eb6c05421003ac74af60606e6c82a322e32f310edae7' AND
        down_checksum_sha256='9358a26e2b893f9ad3d62b30fbbd29a51bd2a35a97202957d588f854ea7f2168' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 369 requires the exact verified 368 release head' USING ERRCODE='P3690';
    END IF;
END;
$migration_369_up$;

-- PA-24: certificate, node, usage and security events. Each producer is a
-- trigger on the table that already records the business fact, so the event
-- commits or rolls back with it and no write path can skip it.
LOCK TABLE certificate_orders, node_presence, nodes, package_monitor_transition_facts,
    package_cycle_enforcement_transitions, cc_auto_switch_notification_windows,
    plugin_webhook_event_contracts_122, domain_event_types_368, domain_event_contract_fields_368
    IN ACCESS EXCLUSIVE MODE;

INSERT INTO domain_event_types_368(event_type, subject_kind, required_permission, site_bound) VALUES
    ('io.cdnca.certificate.v1.status_changed', 'certificate_order', 'events.certificate.read', false),
    ('io.cdnca.node.v1.status_changed', 'node', 'events.node.read', false),
    ('io.cdnca.usage.v1.threshold_reached', 'package_subscription', 'events.usage.read', false),
    ('io.cdnca.security.v1.incident_detected', 'site', 'events.security.read', true);

INSERT INTO domain_event_contract_fields_368(event_type, field_name, kind, required, allowed_values) VALUES
    ('io.cdnca.certificate.v1.status_changed', 'order_id', 'uuid', true, NULL),
    ('io.cdnca.certificate.v1.status_changed', 'status', 'string', true,
        ARRAY['pending','validating','issuing','issued','deploying','active','renewal_due','failed','revoked']),
    ('io.cdnca.certificate.v1.status_changed', 'previous_status', 'string', false,
        ARRAY['pending','validating','issuing','issued','deploying','active','renewal_due','failed','revoked']),
    ('io.cdnca.certificate.v1.status_changed', 'revision', 'integer', true, NULL),
    ('io.cdnca.certificate.v1.status_changed', 'renewal_of_order_id', 'uuid', false, NULL),
    ('io.cdnca.certificate.v1.status_changed', 'not_after', 'timestamp', false, NULL),
    ('io.cdnca.node.v1.status_changed', 'node_id', 'uuid', true, NULL),
    ('io.cdnca.node.v1.status_changed', 'kind', 'string', true, ARRAY['presence','admin']),
    ('io.cdnca.node.v1.status_changed', 'status', 'string', true,
        ARRAY['online','offline','pending','active','draining','disabled','retired']),
    ('io.cdnca.node.v1.status_changed', 'previous_status', 'string', false,
        ARRAY['online','offline','pending','active','draining','disabled','retired']),
    ('io.cdnca.node.v1.status_changed', 'revision', 'integer', true, NULL),
    ('io.cdnca.usage.v1.threshold_reached', 'package_subscription_id', 'uuid', true, NULL),
    ('io.cdnca.usage.v1.threshold_reached', 'source', 'string', true, ARRAY['monitor','enforcement']),
    ('io.cdnca.usage.v1.threshold_reached', 'metric', 'string', true,
        ARRAY['traffic_bytes','bandwidth_bps','connections','sites','expiration']),
    ('io.cdnca.usage.v1.threshold_reached', 'phase', 'string', true,
        ARRAY['triggered','recovered','suspended','resumed']),
    ('io.cdnca.usage.v1.threshold_reached', 'period_key', 'string', true, NULL),
    ('io.cdnca.usage.v1.threshold_reached', 'observed_value', 'integer', false, NULL),
    ('io.cdnca.usage.v1.threshold_reached', 'revision', 'integer', true, NULL),
    ('io.cdnca.security.v1.incident_detected', 'site_id', 'uuid', true, NULL),
    ('io.cdnca.security.v1.incident_detected', 'category', 'string', true, ARRAY['cc_auto_switch']),
    ('io.cdnca.security.v1.incident_detected', 'incident_sequence', 'integer', true, NULL),
    ('io.cdnca.security.v1.incident_detected', 'node_id', 'uuid', true, NULL),
    ('io.cdnca.security.v1.incident_detected', 'started_at', 'timestamp', true, NULL);

ALTER TABLE plugin_webhook_event_contracts_122 DISABLE TRIGGER plugin_webhook_event_contracts_protect_122;
UPDATE plugin_webhook_event_contracts_122 SET status='active'
WHERE event_type IN ('io.cdnca.certificate.v1.status_changed','io.cdnca.node.v1.status_changed',
                     'io.cdnca.usage.v1.threshold_reached','io.cdnca.security.v1.incident_detected');
ALTER TABLE plugin_webhook_event_contracts_122 ENABLE TRIGGER plugin_webhook_event_contracts_protect_122;

-- Contract timestamp text: UTC, microseconds without trailing zeros, Z.
CREATE FUNCTION domain_event_timestamp_369(value timestamptz)
RETURNS text LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE AS $$
    SELECT to_char(value AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS') ||
        CASE WHEN to_char(value AT TIME ZONE 'UTC', 'US') = '000000' THEN ''
             ELSE '.' || rtrim(to_char(value AT TIME ZONE 'UTC', 'US'), '0') END || 'Z';
$$;

-- certificate.status_changed: every status of a tenant ACME order (the 048
-- state machine bumps revision on each transition, so revision is the key).
CREATE FUNCTION emit_certificate_status_event_369()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    previous text;
BEGIN
    IF TG_OP = 'UPDATE' THEN
        IF NEW.status IS NOT DISTINCT FROM OLD.status THEN
            RETURN NULL;
        END IF;
        previous := OLD.status;
    END IF;
    IF (SELECT kind FROM access_scopes WHERE id=NEW.scope_id) IS DISTINCT FROM 'tenant' THEN
        RETURN NULL;
    END IF;
    PERFORM domain_event_append_368(gen_random_uuid(), 'io.cdnca.certificate.v1.status_changed', NEW.scope_id, NULL,
        'certificate_order/' || NEW.id::text, 'certificate_order/' || NEW.id::text || '/' || NEW.revision::text,
        COALESCE(NEW.updated_at, clock_timestamp()),
        jsonb_strip_nulls(jsonb_build_object('order_id', NEW.id::text, 'status', NEW.status,
            'previous_status', previous, 'revision', NEW.revision,
            'renewal_of_order_id', NEW.renewal_of_order_id::text,
            'not_after', domain_event_timestamp_369(NEW.not_after))));
    RETURN NULL;
END;
$$;

CREATE TRIGGER certificate_orders_emit_status_event_369
AFTER INSERT OR UPDATE OF status ON certificate_orders
FOR EACH ROW EXECUTE FUNCTION emit_certificate_status_event_369();

-- node.status_changed: nodes are usually platform-shared, so one fact is
-- written per tenant the node serves: the node's own tenant scope (seller
-- node) and every tenant configuration scope the node carries
-- (node_config_state, the same proof ccautoswitch uses). No IP is published.
CREATE FUNCTION append_node_status_events_369(node_value uuid, kind_value text, status_value text,
    previous_value text, revision_value bigint, at_value timestamptz)
RETURNS void LANGUAGE plpgsql AS $$
DECLARE
    tenant uuid;
BEGIN
    FOR tenant IN
        SELECT DISTINCT carried.scope_id FROM (
            SELECT node.scope_id FROM nodes node WHERE node.id=node_value
            UNION
            SELECT state.configuration_scope_id FROM node_config_state state WHERE state.node_id=node_value
        ) carried
        JOIN access_scopes scope ON scope.id=carried.scope_id AND scope.kind='tenant'
        ORDER BY carried.scope_id
    LOOP
        PERFORM domain_event_append_368(gen_random_uuid(), 'io.cdnca.node.v1.status_changed', tenant, NULL,
            'node/' || node_value::text,
            'node/' || node_value::text || '/' || kind_value || '/' || revision_value::text || '/' || tenant::text,
            at_value,
            jsonb_strip_nulls(jsonb_build_object('node_id', node_value::text, 'kind', kind_value,
                'status', status_value, 'previous_status', previous_value, 'revision', revision_value)));
    END LOOP;
END;
$$;

CREATE FUNCTION emit_node_presence_event_369()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'UPDATE' AND NEW.status IS NOT DISTINCT FROM OLD.status THEN
        RETURN NULL;
    END IF;
    PERFORM append_node_status_events_369(NEW.node_id, 'presence', NEW.status,
        CASE WHEN TG_OP = 'UPDATE' THEN OLD.status END, NEW.revision, COALESCE(NEW.updated_at, clock_timestamp()));
    RETURN NULL;
END;
$$;

CREATE TRIGGER node_presence_emit_status_event_369
AFTER INSERT OR UPDATE OF status ON node_presence
FOR EACH ROW EXECUTE FUNCTION emit_node_presence_event_369();

CREATE FUNCTION emit_node_admin_event_369()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.admin_state IS NOT DISTINCT FROM OLD.admin_state THEN
        RETURN NULL;
    END IF;
    PERFORM append_node_status_events_369(NEW.id, 'admin', NEW.admin_state, OLD.admin_state, NEW.revision,
        COALESCE(NEW.updated_at, clock_timestamp()));
    RETURN NULL;
END;
$$;

CREATE TRIGGER nodes_emit_admin_event_369
AFTER UPDATE OF admin_state ON nodes
FOR EACH ROW EXECUTE FUNCTION emit_node_admin_event_369();

-- usage.threshold_reached (monitor): package monitor alert transitions that
-- notified the tenant (triggered/recovered); one fact per alert revision.
CREATE FUNCTION emit_usage_monitor_event_369()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.phase NOT IN ('triggered','recovered') OR
       (SELECT kind FROM access_scopes WHERE id=NEW.tenant_scope_id) IS DISTINCT FROM 'tenant' THEN
        RETURN NULL;
    END IF;
    PERFORM domain_event_append_368(gen_random_uuid(), 'io.cdnca.usage.v1.threshold_reached', NEW.tenant_scope_id,
        NULL, 'package_subscription/' || NEW.subscription_id::text,
        'usage/monitor/' || NEW.alert_id::text || '/' || NEW.revision::text, NEW.observed_at,
        jsonb_strip_nulls(jsonb_build_object('package_subscription_id', NEW.subscription_id::text,
            'source', 'monitor', 'metric', NEW.metric, 'phase', NEW.phase, 'period_key', NEW.period_key,
            'observed_value', CASE WHEN NEW.metric <> 'expiration' AND NEW.observed_value BETWEEN 0 AND 999999999999999999
                THEN to_jsonb(trunc(NEW.observed_value)::bigint) END,
            'revision', NEW.revision)));
    RETURN NULL;
END;
$$;

CREATE TRIGGER package_monitor_transition_facts_emit_usage_event_369
AFTER INSERT ON package_monitor_transition_facts
FOR EACH ROW EXECUTE FUNCTION emit_usage_monitor_event_369();

-- usage.threshold_reached (enforcement): the package cycle suspends for an
-- exceeded quota, or resumes after one. Manual overrides are not usage.
CREATE FUNCTION emit_usage_enforcement_event_369()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    previous record;
    phase_value text;
    reason text;
BEGIN
    IF (SELECT kind FROM access_scopes WHERE id=NEW.tenant_scope_id) IS DISTINCT FROM 'tenant' THEN
        RETURN NULL;
    END IF;
    SELECT status, reason_code INTO previous FROM package_cycle_enforcement_transitions
    WHERE tenant_scope_id=NEW.tenant_scope_id AND subscription_id=NEW.subscription_id AND revision < NEW.revision
    ORDER BY revision DESC LIMIT 1;
    IF NEW.status = 'suspended' AND previous.status IS DISTINCT FROM 'suspended' THEN
        phase_value := 'suspended';
        reason := NEW.reason_code;
    ELSIF NEW.status = 'active' AND previous.status = 'suspended' THEN
        phase_value := 'resumed';
        reason := previous.reason_code;
    ELSE
        RETURN NULL;
    END IF;
    reason := CASE reason WHEN 'traffic_exceeded' THEN 'traffic_bytes' WHEN 'bandwidth_exceeded' THEN 'bandwidth_bps'
        WHEN 'connections_exceeded' THEN 'connections' WHEN 'sites_exceeded' THEN 'sites' END;
    IF reason IS NULL THEN
        RETURN NULL;
    END IF;
    PERFORM domain_event_append_368(gen_random_uuid(), 'io.cdnca.usage.v1.threshold_reached', NEW.tenant_scope_id,
        NULL, 'package_subscription/' || NEW.subscription_id::text,
        'usage/enforcement/' || NEW.subscription_id::text || '/' || NEW.revision::text, NEW.created_at,
        jsonb_build_object('package_subscription_id', NEW.subscription_id::text, 'source', 'enforcement',
            'metric', reason, 'phase', phase_value, 'period_key', NEW.period_key, 'revision', NEW.revision));
    RETURN NULL;
END;
$$;

CREATE TRIGGER package_cycle_enforcement_emit_usage_event_369
AFTER INSERT ON package_cycle_enforcement_transitions
FOR EACH ROW EXECUTE FUNCTION emit_usage_enforcement_event_369();

-- security.incident_detected: each CC auto-switch notification window (a new
-- window, or a new sequence after the previous window expired). The window
-- holds no client address; only site, first node and start time are published.
CREATE FUNCTION emit_cc_incident_event_369()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    tenant uuid;
BEGIN
    IF TG_OP = 'UPDATE' AND NEW.sequence IS NOT DISTINCT FROM OLD.sequence THEN
        RETURN NULL;
    END IF;
    SELECT site.scope_id INTO tenant FROM sites site
    JOIN access_scopes scope ON scope.id=site.scope_id AND scope.kind='tenant'
    WHERE site.id=NEW.site_id;
    IF tenant IS NULL THEN
        RETURN NULL;
    END IF;
    PERFORM domain_event_append_368(gen_random_uuid(), 'io.cdnca.security.v1.incident_detected', tenant, NEW.site_id,
        'site/' || NEW.site_id::text, 'security/cc_auto_switch/' || NEW.site_id::text || '/' || NEW.sequence::text,
        NEW.window_started_at,
        jsonb_build_object('site_id', NEW.site_id::text, 'category', 'cc_auto_switch',
            'incident_sequence', NEW.sequence, 'node_id', NEW.first_node_id::text,
            'started_at', domain_event_timestamp_369(NEW.window_started_at)));
    RETURN NULL;
END;
$$;

CREATE TRIGGER cc_auto_switch_windows_emit_incident_event_369
AFTER INSERT OR UPDATE OF sequence ON cc_auto_switch_notification_windows
FOR EACH ROW EXECUTE FUNCTION emit_cc_incident_event_369();

REVOKE ALL ON FUNCTION domain_event_timestamp_369(timestamptz), emit_certificate_status_event_369(),
    append_node_status_events_369(uuid, text, text, text, bigint, timestamptz), emit_node_presence_event_369(),
    emit_node_admin_event_369(), emit_usage_monitor_event_369(), emit_usage_enforcement_event_369(),
    emit_cc_incident_event_369() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION domain_event_timestamp_369(timestamptz)
    TO cdnca_control_app, cdnca_control_runtime, cdnca_plugin_webhook_runtime;
