LOCK TABLE schema_migrations, node_deployments, deployment_status_events, deployment_domain_event_source_outbox
    IN ACCESS EXCLUSIVE MODE;

DO $migration_289_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 289 OR
       (SELECT max(version) FROM schema_migrations) <> 289 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=289 AND
        migration_id='289_node_deployment_agent_queue' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 289 down requires the exact verified migration head' USING ERRCODE='P2891';
    END IF;
    -- 288 has no agent queue; refuse rather than rewrite recorded facts.
    IF EXISTS (SELECT 1 FROM node_deployments WHERE state IN ('agent_queued','started')) OR
       EXISTS (SELECT 1 FROM deployment_status_events WHERE state IN ('agent_queued','started')) OR
       EXISTS (SELECT 1 FROM deployment_domain_event_source_outbox WHERE state IN ('agent_queued','started')) THEN
        RAISE EXCEPTION 'migration 289 down cannot drop agent queue states that are recorded' USING ERRCODE='P2891';
    END IF;
END;
$migration_289_down$;

CREATE OR REPLACE FUNCTION enforce_node_deployment_state_046() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF OLD.state = NEW.state THEN
        RETURN NEW;
    END IF;
    IF OLD.state = 'queued' AND NEW.state IN ('delivered', 'cancelled') THEN
        RETURN NEW;
    END IF;
    IF OLD.state = 'delivered' AND NEW.state IN ('staged', 'failed') THEN
        RETURN NEW;
    END IF;
    IF OLD.state = 'staged' AND NEW.state IN ('prechecked', 'failed') THEN
        RETURN NEW;
    END IF;
    IF OLD.state = 'prechecked' AND NEW.state IN ('activated', 'reverting', 'failed') THEN
        RETURN NEW;
    END IF;
    IF OLD.state = 'activated' AND NEW.state IN ('healthy', 'reverting') THEN
        RETURN NEW;
    END IF;
    IF OLD.state = 'reverting' AND NEW.state IN ('reverted', 'failed', 'rollback_failed') THEN
        RETURN NEW;
    END IF;
    RAISE EXCEPTION 'invalid node deployment state transition' USING ERRCODE = 'P0001';
END;
$$;

ALTER TABLE deployment_domain_event_source_outbox DROP CONSTRAINT deployment_domain_event_source_outbox_state_289;
ALTER TABLE deployment_domain_event_source_outbox ADD CONSTRAINT deployment_domain_event_source_outbox_state_check
    CHECK (state IN ('queued','delivered','staged','prechecked','activated','healthy','failed','reverting',
        'reverted','rollback_failed'));
ALTER TABLE deployment_status_events DROP CONSTRAINT deployment_status_events_state_289;
ALTER TABLE deployment_status_events ADD CONSTRAINT deployment_status_events_state_check CHECK (state IN (
    'queued','delivered','staged','prechecked','activated','healthy','failed','reverting','reverted',
    'rollback_failed'));
ALTER TABLE node_deployments DROP CONSTRAINT node_deployments_state_289;
ALTER TABLE node_deployments ADD CONSTRAINT node_deployments_state_046 CHECK (state IN (
    'queued','delivered','staged','prechecked','activated','healthy','failed','reverting','reverted',
    'rollback_failed','cancelled'));
