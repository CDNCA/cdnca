LOCK TABLE schema_migrations, node_deployments, deployment_status_events, deployment_domain_event_source_outbox
    IN ACCESS EXCLUSIVE MODE;

DO $migration_289_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 288 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 288 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=288 AND
        migration_id='288_node_scope_config_state' AND
        checksum_sha256='2064bbd569ac159ed70c69691a62aff1986484205589e2dd742cab689cfa3c84' AND
        down_checksum_sha256='b2661e04bcd03edadc8468a3fca241330180e2e857f41981bad48465598ba140' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR checksum_sha256 IS NULL OR
        down_checksum_sha256 IS NULL OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname='node_deployments_state_046') THEN
        RAISE EXCEPTION 'migration 289 requires the exact verified 288 release head' USING ERRCODE='P2890';
    END IF;
END;
$migration_289_up$;

-- A MULTI_TENANT_RUNTIME agent applies one scope at a time, so a delivered
-- deployment may wait in the agent queue (agent_queued) before it starts.
-- Both states are in flight; neither changes the running configuration.
ALTER TABLE node_deployments DROP CONSTRAINT node_deployments_state_046;
ALTER TABLE node_deployments ADD CONSTRAINT node_deployments_state_289 CHECK (state IN (
    'queued','delivered','agent_queued','started','staged','prechecked','activated','healthy','failed',
    'reverting','reverted','rollback_failed','cancelled'));
ALTER TABLE deployment_status_events DROP CONSTRAINT deployment_status_events_state_check;
ALTER TABLE deployment_status_events ADD CONSTRAINT deployment_status_events_state_289 CHECK (state IN (
    'queued','delivered','agent_queued','started','staged','prechecked','activated','healthy','failed',
    'reverting','reverted','rollback_failed'));
ALTER TABLE deployment_domain_event_source_outbox DROP CONSTRAINT deployment_domain_event_source_outbox_state_check;
ALTER TABLE deployment_domain_event_source_outbox ADD CONSTRAINT deployment_domain_event_source_outbox_state_289
    CHECK (state IN ('queued','delivered','agent_queued','started','staged','prechecked','activated','healthy',
        'failed','reverting','reverted','rollback_failed'));

CREATE OR REPLACE FUNCTION enforce_node_deployment_state_046() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF OLD.state = NEW.state THEN
        RETURN NEW;
    END IF;
    IF OLD.state = 'queued' AND NEW.state IN ('delivered', 'cancelled') THEN
        RETURN NEW;
    END IF;
    IF OLD.state = 'delivered' AND NEW.state IN ('agent_queued', 'staged', 'failed') THEN
        RETURN NEW;
    END IF;
    IF OLD.state = 'agent_queued' AND NEW.state IN ('started', 'failed') THEN
        RETURN NEW;
    END IF;
    IF OLD.state = 'started' AND NEW.state IN ('staged', 'failed') THEN
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
