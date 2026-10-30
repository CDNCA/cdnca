LOCK TABLE schema_migrations,
    security_policy_activation_candidates,
    security_policy_activation_rollouts,
    security_policy_activation_recovery_rollouts,
    security_policy_activation_events,
    security_policy_activation_config_facts,
    rollouts
IN ACCESS EXCLUSIVE MODE;

DO $$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 88 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 88 OR EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$'
           OR down_checksum_sha256 !~ '^[0-9a-f]{64}$'
           OR integrity_state <> 'verified' OR metadata_recorded_at IS NULL OR applied_at IS NULL
    ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version=88 AND migration_id='088_security_policy_activation' AND integrity_state='verified'
    ) THEN
        RAISE EXCEPTION 'migration 088 rollback requires the verified 088 head' USING ERRCODE = 'P8800';
    END IF;
    IF EXISTS (SELECT 1 FROM security_policy_activation_candidates) OR
       EXISTS (SELECT 1 FROM security_policy_activation_config_facts) OR
       EXISTS (SELECT 1 FROM security_policy_activation_rollouts) OR
       EXISTS (SELECT 1 FROM security_policy_activation_recovery_rollouts) OR
       EXISTS (SELECT 1 FROM security_policy_activation_events) THEN
        RAISE EXCEPTION 'migration 088 rollback would discard security activation facts' USING ERRCODE = 'P8801';
    END IF;
END;
$$;

CREATE OR REPLACE FUNCTION assert_rollout_contract_046()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.contract_version <> 1 OR NEW.status = 'building' THEN
        RETURN NULL;
    END IF;
    IF NEW.revision = 1 THEN
        IF NOT EXISTS (
            SELECT 1 FROM edge_config_publications publication
            WHERE publication.rollout_id = NEW.id AND publication.contract_version = 1
        ) THEN
            RAISE EXCEPTION 'contract rollout requires an audited publication' USING ERRCODE = 'P0001';
        END IF;
        RETURN NULL;
    END IF;
    IF NOT EXISTS (
        SELECT 1
        FROM edge_rollout_write_requests request
        JOIN audit_events event
          ON event.scope_id = request.actor_scope_id
         AND event.actor_user_id = request.actor_user_id
         AND event.action = request.operation
         AND event.resource_type = 'edge_rollout'
         AND event.resource_id = request.rollout_id::text
         AND event.request_id = request.request_id::text
         AND event.result = 'success'
        WHERE request.configuration_scope_id = NEW.configuration_scope_id
          AND request.rollout_id = NEW.id
          AND request.expected_revision = NEW.revision - 1
          AND request.operation = CASE
              WHEN NEW.status = 'cancelled' THEN 'edge_rollout.cancel'
              ELSE 'edge_rollout.retry'
          END
          AND request.completed_at IS NOT NULL
    ) THEN
        RAISE EXCEPTION 'rollout command requires matching request and audit' USING ERRCODE = 'P0001';
    END IF;
    RETURN NULL;
END;
$$;

DROP TRIGGER security_policy_activation_events_no_truncate ON security_policy_activation_events;
DROP TRIGGER security_policy_activation_events_append_only ON security_policy_activation_events;
DROP TRIGGER security_policy_activation_recovery_rollouts_no_truncate ON security_policy_activation_recovery_rollouts;
DROP TRIGGER security_policy_activation_recovery_rollouts_append_only ON security_policy_activation_recovery_rollouts;
DROP TRIGGER security_policy_activation_rollouts_no_truncate ON security_policy_activation_rollouts;
DROP TRIGGER security_policy_activation_rollouts_append_only ON security_policy_activation_rollouts;
DROP TRIGGER security_policy_activation_config_facts_no_truncate ON security_policy_activation_config_facts;
DROP TRIGGER security_policy_activation_config_facts_append_only ON security_policy_activation_config_facts;
DROP TRIGGER security_policy_activation_candidates_no_truncate ON security_policy_activation_candidates;
DROP TRIGGER security_policy_activation_candidates_protected ON security_policy_activation_candidates;
DROP TRIGGER security_policy_activation_recovery_rollouts_validate ON security_policy_activation_recovery_rollouts;
DROP TRIGGER security_policy_activation_rollouts_validate ON security_policy_activation_rollouts;
DROP FUNCTION prevent_security_policy_activation_fact_mutation();
DROP FUNCTION protect_security_policy_activation_candidate();
DROP FUNCTION security_policy_activation_phase_healthy_088(uuid,text);
DROP FUNCTION security_policy_activation_recovered_088(uuid);
DROP FUNCTION validate_security_policy_activation_recovery_rollout_088();
DROP FUNCTION validate_security_policy_activation_rollout_088();
DROP TABLE security_policy_activation_events;
DROP TABLE security_policy_activation_recovery_rollouts;
DROP TABLE security_policy_activation_rollouts;
DROP TABLE security_policy_activation_candidates;
DROP TABLE security_policy_activation_config_facts;
DROP FUNCTION valid_security_activation_nodes_088(uuid[]);
