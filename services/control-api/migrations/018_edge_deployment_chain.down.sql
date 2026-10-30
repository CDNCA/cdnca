DROP TABLE IF EXISTS artifact_fetch_requests;

DROP TRIGGER IF EXISTS deployment_status_events_append_only ON deployment_status_events;
DROP FUNCTION IF EXISTS prevent_deployment_status_event_mutation();
DROP TABLE IF EXISTS deployment_status_events;

DROP TRIGGER IF EXISTS edge_command_outbox_payload_immutable ON edge_command_outbox;
DROP FUNCTION IF EXISTS protect_edge_command_outbox_payload();
DROP TABLE IF EXISTS edge_command_outbox;

DROP TRIGGER IF EXISTS node_deployment_artifacts_immutable ON node_deployment_artifacts;
DROP FUNCTION IF EXISTS prevent_node_deployment_artifact_mutation();
DROP TABLE IF EXISTS node_deployment_artifacts;

DROP TRIGGER IF EXISTS node_deployment_commands_immutable ON node_deployments;
DROP FUNCTION IF EXISTS protect_node_deployment_command();
DROP INDEX IF EXISTS node_deployments_one_active_per_node_idx;
DROP TABLE IF EXISTS node_deployments;
DROP TABLE IF EXISTS node_config_state;
DROP TABLE IF EXISTS rollouts;

DROP TRIGGER IF EXISTS configuration_artifacts_immutable ON configuration_artifacts;
DROP FUNCTION IF EXISTS protect_configuration_artifact_mutation();
DROP TABLE IF EXISTS configuration_artifacts;

DROP TRIGGER IF EXISTS config_versions_immutable_after_release ON config_versions;
DROP FUNCTION IF EXISTS protect_config_version_mutation();
DROP TABLE IF EXISTS config_versions;

DROP TRIGGER IF EXISTS artifact_signing_keys_immutable ON artifact_signing_keys;
DROP FUNCTION IF EXISTS prevent_artifact_signing_key_mutation();
DROP TABLE IF EXISTS artifact_signing_keys;
