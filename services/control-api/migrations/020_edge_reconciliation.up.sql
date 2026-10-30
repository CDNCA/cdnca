ALTER TABLE node_config_state
    ADD COLUMN reconciliation_required boolean NOT NULL DEFAULT false,
    ADD COLUMN reconciliation_reason text,
    ADD COLUMN reconciliation_deployment_id uuid,
    ADD COLUMN reconciliation_deployment_attempt integer,
    ADD COLUMN reconciliation_requested_at timestamptz,
    ADD CONSTRAINT node_config_state_reconciliation_source_fk
        FOREIGN KEY (reconciliation_deployment_id, reconciliation_deployment_attempt)
        REFERENCES node_deployments(id, attempt) ON DELETE RESTRICT,
    ADD CONSTRAINT node_config_state_reconciliation_consistent_chk CHECK (
        (NOT reconciliation_required AND reconciliation_reason IS NULL AND
         reconciliation_deployment_id IS NULL AND reconciliation_deployment_attempt IS NULL AND
         reconciliation_requested_at IS NULL) OR
        (reconciliation_required AND reconciliation_reason = 'rollback_failed' AND
         reconciliation_deployment_id IS NOT NULL AND reconciliation_deployment_attempt > 0 AND
         reconciliation_requested_at IS NOT NULL)
    );

WITH latest_deployment AS (
    SELECT DISTINCT ON (node_id)
           node_id, id, attempt, state, updated_at
    FROM node_deployments
    ORDER BY node_id, updated_at DESC, created_at DESC, attempt DESC, id DESC
)
UPDATE node_config_state state
SET reconciliation_required = true,
    reconciliation_reason = 'rollback_failed',
    reconciliation_deployment_id = latest.id,
    reconciliation_deployment_attempt = latest.attempt,
    reconciliation_requested_at = latest.updated_at,
    revision = state.revision + 1,
    updated_at = GREATEST(state.updated_at, latest.updated_at)
FROM latest_deployment latest
WHERE latest.node_id = state.node_id AND latest.state = 'rollback_failed';

CREATE TABLE node_config_reconciliations (
    id uuid PRIMARY KEY,
    request_id uuid NOT NULL UNIQUE,
    request_digest bytea NOT NULL CHECK (octet_length(request_digest) = 32),
    node_id uuid NOT NULL REFERENCES nodes(id) ON DELETE RESTRICT,
    configuration_scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE RESTRICT,
    source_deployment_id uuid NOT NULL,
    source_deployment_attempt integer NOT NULL CHECK (source_deployment_attempt > 0),
    previous_config_version_id uuid,
    observed_config_version_id uuid,
    resolution text NOT NULL CHECK (resolution IN ('agent_observed', 'operator_confirmed')),
    evidence text NOT NULL CHECK (
        evidence = btrim(evidence) AND char_length(evidence) BETWEEN 1 AND 512
    ),
    reconciled_at timestamptz NOT NULL,
    FOREIGN KEY (source_deployment_id, source_deployment_attempt)
        REFERENCES node_deployments(id, attempt) ON DELETE RESTRICT,
    FOREIGN KEY (configuration_scope_id, previous_config_version_id)
        REFERENCES config_versions(configuration_scope_id, id) ON DELETE RESTRICT,
    FOREIGN KEY (configuration_scope_id, observed_config_version_id)
        REFERENCES config_versions(configuration_scope_id, id) ON DELETE RESTRICT
);

CREATE FUNCTION prevent_node_config_reconciliation_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'node config reconciliations are append-only';
END;
$$;

CREATE TRIGGER node_config_reconciliations_append_only
BEFORE UPDATE OR DELETE ON node_config_reconciliations
FOR EACH ROW EXECUTE FUNCTION prevent_node_config_reconciliation_mutation();

CREATE FUNCTION reject_node_deployment_during_reconciliation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    blocked boolean;
BEGIN
    SELECT reconciliation_required INTO blocked
    FROM node_config_state
    WHERE node_id = NEW.node_id;
    IF blocked THEN
        RAISE EXCEPTION 'node configuration reconciliation is required'
            USING ERRCODE = '23514', CONSTRAINT = 'node_deployments_reconciliation_gate';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER node_deployments_reconciliation_gate
BEFORE INSERT ON node_deployments
FOR EACH ROW EXECUTE FUNCTION reject_node_deployment_during_reconciliation();
