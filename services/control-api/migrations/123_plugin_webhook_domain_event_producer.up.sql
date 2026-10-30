LOCK TABLE schema_migrations,
    plugin_webhook_subscriptions,
    plugin_webhook_events,
    plugin_webhook_deliveries,
    plugin_webhook_outbox,
    plugin_webhook_write_requests,
    plugin_webhook_rate_events,
    plugin_webhook_entitlement_decisions
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
          AND checksum_sha256 = '358b0e639ffa5290cd4146826beb29ac22d114abfb7ae7ce00675cbdc71236cb'
          AND down_checksum_sha256 = 'cbb00f190518cd10509dc9014e0f35431e02d7c88e5678e5c3182afff959ccea'
          AND integrity_state = 'verified'
          AND metadata_recorded_at IS NOT NULL
          AND applied_at IS NOT NULL
    ) THEN
        RAISE EXCEPTION 'migration 123 requires the exact verified 122 release head'
            USING ERRCODE = 'P1230';
    END IF;
END;
$$;

-- Keep an exact, transactional restore point for the trigger functions whose
-- operation dispatch is extended below.  The table is dropped by the down.
CREATE TABLE plugin_webhook_domain_contract_123_backup (
    function_name text PRIMARY KEY,
    definition text NOT NULL
);

INSERT INTO plugin_webhook_domain_contract_123_backup(function_name, definition)
VALUES
    ('record_plugin_webhook_entitlement_decision_084', pg_get_functiondef('record_plugin_webhook_entitlement_decision_084()'::regprocedure)),
    ('validate_plugin_webhook_audit_084', pg_get_functiondef('validate_plugin_webhook_audit_084()'::regprocedure)),
    ('validate_plugin_webhook_command_facts_084', pg_get_functiondef('validate_plugin_webhook_command_facts_084()'::regprocedure)),
    ('validate_plugin_webhook_write_request_result_084', pg_get_functiondef('validate_plugin_webhook_write_request_result_084()'::regprocedure)),
    ('validate_plugin_webhook_entitlement_decision_084', pg_get_functiondef('validate_plugin_webhook_entitlement_decision_084()'::regprocedure)),
    ('enforce_plugin_webhook_rate_084', pg_get_functiondef('enforce_plugin_webhook_rate_084()'::regprocedure));

DO $rewrite$
DECLARE
    definition text;
    before_definition text;
BEGIN
    SELECT pg_get_functiondef('record_plugin_webhook_entitlement_decision_084()'::regprocedure)
      INTO definition;
    before_definition := definition;
    definition := replace(definition,
        $$'plugin_webhook.delivery.replay',
        'plugin_webhook.secret.rotate'$$,
        $$'plugin_webhook.delivery.replay',
        'plugin_webhook.domain_event.publish',
        'plugin_webhook.secret.rotate'$$);
    IF definition = before_definition THEN
        RAISE EXCEPTION 'migration 123 entitlement operation marker is missing'
            USING ERRCODE = 'P1231';
    END IF;
    before_definition := definition;
    definition := replace(definition,
        $$ELSIF NEW.operation IN ('plugin_webhook.test_delivery.create', 'plugin_webhook.delivery.replay') THEN$$,
        $$ELSIF NEW.operation IN ('plugin_webhook.test_delivery.create', 'plugin_webhook.delivery.replay', 'plugin_webhook.domain_event.publish') THEN$$);
    IF definition = before_definition THEN
        RAISE EXCEPTION 'migration 123 entitlement decision marker is missing'
            USING ERRCODE = 'P1231';
    END IF;
    EXECUTE definition;
END;
$rewrite$;

DO $rewrite$
DECLARE
    definition text;
    before_definition text;
BEGIN
    SELECT pg_get_functiondef('validate_plugin_webhook_audit_084()'::regprocedure)
      INTO definition;
    before_definition := definition;
    definition := replace(definition,
        $$'plugin_webhook.test_delivery.create', 'plugin_webhook.delivery.replay'$$,
        $$'plugin_webhook.test_delivery.create', 'plugin_webhook.domain_event.publish', 'plugin_webhook.delivery.replay'$$);
    IF definition = before_definition THEN
        RAISE EXCEPTION 'migration 123 audit operation marker is missing'
            USING ERRCODE = 'P1231';
    END IF;
    EXECUTE definition;
END;
$rewrite$;

DO $rewrite$
DECLARE
    definition text;
    before_definition text;
BEGIN
    SELECT pg_get_functiondef('validate_plugin_webhook_command_facts_084()'::regprocedure)
      INTO definition;
    before_definition := definition;
    definition := replace(definition,
        $$    checked_event uuid;
    checked_replay uuid;$$,
        $$    checked_event uuid;
    checked_event_type text;
    checked_replay uuid;$$);
    IF definition = before_definition THEN
        RAISE EXCEPTION 'migration 123 command facts declaration marker is missing'
            USING ERRCODE = 'P1231';
    END IF;
    before_definition := definition;
    definition := replace(definition,
        $$checked_operation := CASE WHEN NEW.replay_of IS NULL THEN
            'plugin_webhook.test_delivery.create'
        ELSE
            'plugin_webhook.delivery.replay'
        END;$$,
        $$IF checked_replay IS NOT NULL THEN
            checked_operation := 'plugin_webhook.delivery.replay';
        ELSE
            SELECT event.event_type INTO checked_event_type
            FROM plugin_webhook_events event
            WHERE event.tenant_scope_id = checked_scope
              AND event.subscription_id = checked_subscription
              AND event.id = checked_event;
            checked_operation := CASE WHEN checked_event_type = 'io.cdnca.webhook.v1.test'
                THEN 'plugin_webhook.test_delivery.create'
                ELSE 'plugin_webhook.domain_event.publish'
            END;
        END IF;$$);
    IF definition = before_definition THEN
        RAISE EXCEPTION 'migration 123 command facts operation marker is missing'
            USING ERRCODE = 'P1231';
    END IF;
    EXECUTE definition;
END;
$rewrite$;

DO $rewrite$
DECLARE
    definition text;
    before_definition text;
BEGIN
    SELECT pg_get_functiondef('validate_plugin_webhook_write_request_result_084()'::regprocedure)
      INTO definition;
    before_definition := definition;
    definition := replace(definition,
        $$        'plugin_webhook.delivery.replay',
        'plugin_webhook.secret.rotate'$$,
        $$        'plugin_webhook.delivery.replay',
        'plugin_webhook.domain_event.publish',
        'plugin_webhook.secret.rotate'$$);
    IF definition = before_definition THEN
        RAISE EXCEPTION 'migration 123 result operation marker is missing'
            USING ERRCODE = 'P1231';
    END IF;
    before_definition := definition;
    definition := replace(definition,
        $$ELSIF NEW.operation IN ('plugin_webhook.test_delivery.create', 'plugin_webhook.delivery.replay') THEN$$,
        $$ELSIF NEW.operation IN ('plugin_webhook.test_delivery.create', 'plugin_webhook.delivery.replay', 'plugin_webhook.domain_event.publish') THEN$$);
    IF definition = before_definition THEN
        RAISE EXCEPTION 'migration 123 result status marker is missing'
            USING ERRCODE = 'P1231';
    END IF;
    before_definition := definition;
    definition := replace(definition,
        $$        FROM plugin_webhook_deliveries delivery
        WHERE delivery.tenant_scope_id = NEW.tenant_scope_id$$,
        $$        FROM plugin_webhook_deliveries delivery
        JOIN plugin_webhook_events event
          ON event.tenant_scope_id = delivery.tenant_scope_id
         AND event.subscription_id = delivery.subscription_id
         AND event.id = delivery.event_id
        WHERE delivery.tenant_scope_id = NEW.tenant_scope_id$$);
    IF definition = before_definition THEN
        RAISE EXCEPTION 'migration 123 result join marker is missing'
            USING ERRCODE = 'P1231';
    END IF;
    before_definition := definition;
    definition := replace(definition,
        $$((NEW.operation = 'plugin_webhook.test_delivery.create' AND delivery.replay_of IS NULL) OR
               (NEW.operation = 'plugin_webhook.delivery.replay' AND delivery.replay_of IS NOT NULL))$$,
        $$((NEW.operation = 'plugin_webhook.test_delivery.create' AND delivery.replay_of IS NULL
                AND event.event_type = 'io.cdnca.webhook.v1.test') OR
               (NEW.operation = 'plugin_webhook.domain_event.publish' AND delivery.replay_of IS NULL
                AND event.event_type <> 'io.cdnca.webhook.v1.test') OR
               (NEW.operation = 'plugin_webhook.delivery.replay' AND delivery.replay_of IS NOT NULL))$$);
    IF definition = before_definition THEN
        RAISE EXCEPTION 'migration 123 result shape marker is missing'
            USING ERRCODE = 'P1231';
    END IF;
    EXECUTE definition;
END;
$rewrite$;

DO $rewrite$
DECLARE
    definition text;
    before_definition text;
BEGIN
    SELECT pg_get_functiondef('validate_plugin_webhook_entitlement_decision_084()'::regprocedure)
      INTO definition;
    before_definition := definition;
    definition := replace(definition,
        $$'plugin_webhook.test_delivery.create', 'plugin_webhook.delivery.replay'$$,
        $$'plugin_webhook.test_delivery.create', 'plugin_webhook.domain_event.publish', 'plugin_webhook.delivery.replay'$$);
    IF definition = before_definition THEN
        RAISE EXCEPTION 'migration 123 entitlement validation marker is missing'
            USING ERRCODE = 'P1231';
    END IF;
    EXECUTE definition;
END;
$rewrite$;

DO $rewrite$
DECLARE
    definition text;
    before_definition text;
BEGIN
    SELECT pg_get_functiondef('enforce_plugin_webhook_rate_084()'::regprocedure)
      INTO definition;
    before_definition := definition;
    definition := replace(definition,
        $$    ELSE
        SELECT count(*) INTO subscription_allowed FROM plugin_webhook_rate_events$$,
        $$    ELSIF NEW.operation = 'plugin_webhook.domain_event.publish' THEN
        RETURN NEW;
    ELSE
        SELECT count(*) INTO subscription_allowed FROM plugin_webhook_rate_events$$);
    IF definition = before_definition THEN
        RAISE EXCEPTION 'migration 123 rate operation marker is missing'
            USING ERRCODE = 'P1231';
    END IF;
    EXECUTE definition;
END;
$rewrite$;

DO $$
DECLARE
    constraint_name name;
BEGIN
    FOREACH constraint_name IN ARRAY ARRAY[
        'plugin_webhook_write_requests_operation_check'::name,
        'plugin_webhook_write_requests_check'::name,
        'plugin_webhook_write_requests_check2'::name,
        'plugin_webhook_write_requests_check3'::name,
        'plugin_webhook_rate_events_operation_check'::name
    ] LOOP
        IF NOT EXISTS (
            SELECT 1
            FROM pg_constraint
            WHERE conname = constraint_name
              AND contype = 'c'
              AND conrelid = CASE
                  WHEN constraint_name::text LIKE 'plugin_webhook_write_requests_%'
                      THEN 'plugin_webhook_write_requests'::regclass
                  ELSE 'plugin_webhook_rate_events'::regclass
              END
        ) THEN
            RAISE EXCEPTION 'migration 123 expected legacy constraint % is missing', constraint_name
                USING ERRCODE = 'P1231';
        END IF;
    END LOOP;
    ALTER TABLE plugin_webhook_write_requests
        DROP CONSTRAINT plugin_webhook_write_requests_operation_check,
        DROP CONSTRAINT plugin_webhook_write_requests_check,
        DROP CONSTRAINT plugin_webhook_write_requests_check2,
        DROP CONSTRAINT plugin_webhook_write_requests_check3;
    ALTER TABLE plugin_webhook_rate_events
        DROP CONSTRAINT plugin_webhook_rate_events_operation_check;
/*
    Legacy definitions are deliberately identified by exact names above. A
    predecessor that changes one of these definitions must receive a new
    migration instead of being silently rewritten here.
*/
END;
$$;

ALTER TABLE plugin_webhook_write_requests
    ADD CONSTRAINT plugin_webhook_write_requests_operation_123 CHECK (operation IN (
        'plugin_webhook.subscription.create',
        'plugin_webhook.test_delivery.create',
        'plugin_webhook.domain_event.publish',
        'plugin_webhook.delivery.replay',
        'plugin_webhook.secret.rotate',
        'plugin_webhook.secret.activate',
        'plugin_webhook.subscription.revoke'
    )),
    ADD CONSTRAINT plugin_webhook_write_requests_response_status_123 CHECK (
        response_status IS NULL OR response_status = CASE
            WHEN operation IN ('plugin_webhook.subscription.create', 'plugin_webhook.secret.rotate') THEN 201
            WHEN operation IN ('plugin_webhook.test_delivery.create', 'plugin_webhook.domain_event.publish', 'plugin_webhook.delivery.replay') THEN 202
            ELSE 200
        END
    ),
    ADD CONSTRAINT plugin_webhook_write_requests_result_shape_123 CHECK (
        (operation = 'plugin_webhook.subscription.create' AND delivery_id IS NULL AND rotation_id IS NULL) OR
        (operation IN ('plugin_webhook.test_delivery.create', 'plugin_webhook.domain_event.publish', 'plugin_webhook.delivery.replay') AND
         delivery_id IS NOT NULL AND rotation_id IS NULL) OR
        (operation IN ('plugin_webhook.secret.rotate', 'plugin_webhook.secret.activate') AND
         delivery_id IS NULL AND rotation_id IS NOT NULL) OR
        (operation = 'plugin_webhook.subscription.revoke' AND delivery_id IS NULL AND rotation_id IS NULL)
    ),
    ADD CONSTRAINT plugin_webhook_write_requests_response_body_123 CHECK (
        response_body IS NULL OR
        (operation IN ('plugin_webhook.subscription.create', 'plugin_webhook.subscription.revoke') AND
         response_body = jsonb_build_object('subscription_id', subscription_id::text)) OR
        (operation = 'plugin_webhook.secret.activate' AND response_body = jsonb_build_object(
             'subscription_id', subscription_id::text, 'rotation_id', rotation_id::text
         )) OR
        (operation IN ('plugin_webhook.test_delivery.create', 'plugin_webhook.domain_event.publish', 'plugin_webhook.delivery.replay') AND
         response_body = jsonb_build_object(
             'subscription_id', subscription_id::text, 'delivery_id', delivery_id::text
         )) OR
        (operation = 'plugin_webhook.secret.rotate' AND response_body = jsonb_build_object(
             'subscription_id', subscription_id::text, 'rotation_id', rotation_id::text
         ))
    );

ALTER TABLE plugin_webhook_rate_events
    ADD CONSTRAINT plugin_webhook_rate_events_operation_123 CHECK (operation IN (
        'plugin_webhook.subscription.create',
        'plugin_webhook.test_delivery.create',
        'plugin_webhook.domain_event.publish',
        'plugin_webhook.delivery.replay',
        'plugin_webhook.secret.rotate'
    ));
