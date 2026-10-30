DROP TRIGGER IF EXISTS node_deployments_reconciliation_gate ON node_deployments;
DROP FUNCTION IF EXISTS reject_node_deployment_during_reconciliation();

DROP TRIGGER IF EXISTS node_config_reconciliations_append_only ON node_config_reconciliations;
DROP FUNCTION IF EXISTS prevent_node_config_reconciliation_mutation();
DROP TABLE IF EXISTS node_config_reconciliations;

ALTER TABLE node_config_state
    DROP CONSTRAINT IF EXISTS node_config_state_reconciliation_consistent_chk,
    DROP CONSTRAINT IF EXISTS node_config_state_reconciliation_source_fk,
    DROP COLUMN IF EXISTS reconciliation_requested_at,
    DROP COLUMN IF EXISTS reconciliation_deployment_attempt,
    DROP COLUMN IF EXISTS reconciliation_deployment_id,
    DROP COLUMN IF EXISTS reconciliation_reason,
    DROP COLUMN IF EXISTS reconciliation_required;
