LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;

DO $migration_284_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 283 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 283 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=283 AND
        migration_id='283_security_custom_rule_report_state' AND
        checksum_sha256='fcd817b0bdf2157651205b47d94aa83027a1d3c5bd6dd158067d60d700f0a079' AND
        down_checksum_sha256='4163b07aacb95be5707172b137e23998aec5c2676a5557b85ab52997e34d8280' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR checksum_sha256 IS NULL OR
        down_checksum_sha256 IS NULL OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR to_regclass(current_schema() || '.node_purged_ids') IS NOT NULL OR
       to_regprocedure(current_schema() || '.node_purge_permits(uuid)') IS NOT NULL THEN
        RAISE EXCEPTION 'migration 284 requires the exact verified 283 release head' USING ERRCODE='P2840';
    END IF;
END;
$migration_284_up$;

-- Physical node deletion ("purge"). Deleting a node removes the node row and,
-- through ON DELETE CASCADE, every row that only describes that node
-- (certificates, identity, sessions, telemetry, deployment receipts,
-- reconciliations, cache task projections, ...). What happened stays in
-- audit_events, which does not reference nodes.
--
-- Append-only / immutable guards keep their meaning: UPDATE and a direct
-- DELETE are still rejected. Only a DELETE that the foreign-key cascade of a
-- node purge issues is let through, and only for the node being purged:
--   * the application sets SET LOCAL cdnca.node_purge = '<node id>' in the
--     purge transaction right before DELETE FROM nodes;
--   * pg_trigger_depth() > 0 — the row is deleted by a referential action
--     (or a trigger), never by a top-level statement;
--   * the named node row is already gone in this transaction's snapshot,
--     which is only true after its DELETE ran;
--   * row-level guards on tables with node_id also require OLD.node_id to be
--     that node.
-- A top-level DELETE on a protected table therefore fails exactly as before,
-- with or without the setting.
CREATE FUNCTION node_purge_permits(target uuid) RETURNS boolean
LANGUAGE sql STABLE PARALLEL SAFE AS $function$
    SELECT target IS NOT NULL AND pg_trigger_depth() > 0 AND
           current_setting('cdnca.node_purge', true) ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' AND
           current_setting('cdnca.node_purge', true)::uuid = target AND
           NOT EXISTS (SELECT 1 FROM nodes WHERE id = target)
$function$;

-- For guards on rows without a node_id column (children of a node-owned
-- row) and statement-level guards: a purge cascade of the named node is in
-- progress.
CREATE FUNCTION node_purge_in_progress() RETURNS boolean
LANGUAGE sql STABLE PARALLEL SAFE AS $function$
    SELECT CASE WHEN current_setting('cdnca.node_purge', true) ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
                THEN node_purge_permits(current_setting('cdnca.node_purge', true)::uuid)
                ELSE false END
$function$;

-- IDs of purged nodes are never handed out again: a self-registered node ID
-- is derived from the machine fingerprint, and per-node state outside the
-- database (durable command consumers named after the node ID, upgrade
-- command history without a node foreign key) must not attach to a new node.
CREATE TABLE node_purged_ids (
    node_id uuid PRIMARY KEY,
    scope_id uuid NOT NULL,
    purged_at timestamptz NOT NULL
);

-- Business references stay restricted: a node that the current revision of a
-- live line group still lists cannot be deleted (historical revisions and
-- deleted groups cascade). l2_topology_nodes keeps ON DELETE RESTRICT; the
-- application removes soft-deleted memberships itself before the purge.
CREATE FUNCTION guard_node_line_endpoint_purge_284() RETURNS trigger
LANGUAGE plpgsql AS $function$
BEGIN
    IF EXISTS (
        SELECT 1 FROM node_line_groups line_group
        WHERE line_group.tenant_scope_id = OLD.tenant_scope_id AND line_group.id = OLD.line_group_id
          AND line_group.current_revision = OLD.config_revision AND line_group.deleted_at IS NULL
    ) THEN
        RAISE EXCEPTION 'node is still listed by the current revision of a line group'
            USING ERRCODE = '23001';
    END IF;
    RETURN OLD;
END;
$function$;

-- Foreign keys of node-owned rows: ON DELETE RESTRICT -> ON DELETE CASCADE.
ALTER TABLE acme_http01_overlay_deployment_events DROP CONSTRAINT acme_http01_overlay_deploymen_deployment_id_deployment_att_fkey,
    ADD CONSTRAINT acme_http01_overlay_deploymen_deployment_id_deployment_att_fkey FOREIGN KEY (deployment_id, deployment_attempt) REFERENCES acme_http01_overlay_deployments(id, attempt) ON DELETE CASCADE;
ALTER TABLE acme_http01_overlay_deployments DROP CONSTRAINT acme_http01_overlay_deployments_version_id_node_id_fkey,
    ADD CONSTRAINT acme_http01_overlay_deployments_version_id_node_id_fkey FOREIGN KEY (version_id, node_id) REFERENCES acme_http01_overlay_targets(version_id, node_id) ON DELETE CASCADE;
ALTER TABLE acme_http01_overlay_outbox DROP CONSTRAINT acme_http01_overlay_outbox_deployment_id_deployment_attem_fkey1,
    ADD CONSTRAINT acme_http01_overlay_outbox_deployment_id_deployment_attem_fkey1 FOREIGN KEY (deployment_id, deployment_attempt, version_id, node_id) REFERENCES acme_http01_overlay_deployments(id, attempt, version_id, node_id) ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED;
ALTER TABLE acme_http01_overlay_outbox DROP CONSTRAINT acme_http01_overlay_outbox_deployment_id_deployment_attemp_fkey,
    ADD CONSTRAINT acme_http01_overlay_outbox_deployment_id_deployment_attemp_fkey FOREIGN KEY (deployment_id, deployment_attempt) REFERENCES acme_http01_overlay_deployments(id, attempt) ON DELETE CASCADE;
ALTER TABLE acme_http01_overlay_outbox DROP CONSTRAINT acme_http01_overlay_outbox_version_id_node_id_fkey,
    ADD CONSTRAINT acme_http01_overlay_outbox_version_id_node_id_fkey FOREIGN KEY (version_id, node_id) REFERENCES acme_http01_overlay_targets(version_id, node_id) ON DELETE CASCADE;
ALTER TABLE acme_http01_overlay_outbox_attempts DROP CONSTRAINT acme_http01_overlay_outbox_attempts_outbox_id_fkey,
    ADD CONSTRAINT acme_http01_overlay_outbox_attempts_outbox_id_fkey FOREIGN KEY (outbox_id) REFERENCES acme_http01_overlay_outbox(id) ON DELETE CASCADE;
ALTER TABLE acme_http01_overlay_outbox_states DROP CONSTRAINT acme_http01_overlay_outbox_states_outbox_id_fkey,
    ADD CONSTRAINT acme_http01_overlay_outbox_states_outbox_id_fkey FOREIGN KEY (outbox_id) REFERENCES acme_http01_overlay_outbox(id) ON DELETE CASCADE;
ALTER TABLE acme_http01_overlay_targets DROP CONSTRAINT acme_http01_overlay_targets_tenant_scope_id_node_id_fkey,
    ADD CONSTRAINT acme_http01_overlay_targets_tenant_scope_id_node_id_fkey FOREIGN KEY (tenant_scope_id, node_id) REFERENCES nodes(scope_id, id) ON DELETE CASCADE;
ALTER TABLE artifact_fetch_requests DROP CONSTRAINT artifact_fetch_requests_deployment_id_attempt_artifact_id_fkey,
    ADD CONSTRAINT artifact_fetch_requests_deployment_id_attempt_artifact_id_fkey FOREIGN KEY (deployment_id, attempt, artifact_id) REFERENCES node_deployment_artifacts(deployment_id, deployment_attempt, artifact_id) ON DELETE CASCADE;
ALTER TABLE artifact_fetch_requests DROP CONSTRAINT artifact_fetch_requests_node_id_fkey,
    ADD CONSTRAINT artifact_fetch_requests_node_id_fkey FOREIGN KEY (node_id) REFERENCES nodes(id) ON DELETE CASCADE;
ALTER TABLE cache_operation_node_attempts DROP CONSTRAINT cache_operation_node_attempts_scope_id_operation_id_node_i_fkey,
    ADD CONSTRAINT cache_operation_node_attempts_scope_id_operation_id_node_i_fkey FOREIGN KEY (scope_id, operation_id, node_id) REFERENCES cache_operation_nodes(scope_id, operation_id, node_id) ON DELETE CASCADE;
ALTER TABLE cache_operation_nodes DROP CONSTRAINT cache_operation_nodes_scope_id_node_id_fkey,
    ADD CONSTRAINT cache_operation_nodes_scope_id_node_id_fkey FOREIGN KEY (scope_id, node_id) REFERENCES nodes(scope_id, id) ON DELETE CASCADE;
ALTER TABLE cache_operation_node_targets DROP CONSTRAINT cache_operation_node_targets_scope_id_operation_id_node_id_fkey,
    ADD CONSTRAINT cache_operation_node_targets_scope_id_operation_id_node_id_fkey FOREIGN KEY (scope_id, operation_id, node_id) REFERENCES cache_operation_nodes(scope_id, operation_id, node_id) ON DELETE CASCADE;
ALTER TABLE cache_operation_target_results DROP CONSTRAINT cache_operation_target_resul_scope_id_operation_id_node_i_fkey1,
    ADD CONSTRAINT cache_operation_target_resul_scope_id_operation_id_node_i_fkey1 FOREIGN KEY (scope_id, operation_id, node_id, attempt) REFERENCES cache_operation_node_attempts(scope_id, operation_id, node_id, attempt) ON DELETE CASCADE;
ALTER TABLE cache_operation_target_results DROP CONSTRAINT cache_operation_target_result_scope_id_operation_id_node_i_fkey,
    ADD CONSTRAINT cache_operation_target_result_scope_id_operation_id_node_i_fkey FOREIGN KEY (scope_id, operation_id, node_id, target_ordinal) REFERENCES cache_operation_node_targets(scope_id, operation_id, node_id, target_ordinal) ON DELETE CASCADE;
ALTER TABLE cc_coordination_actions DROP CONSTRAINT cc_coordination_actions_tenant_scope_id_state_id_fkey,
    ADD CONSTRAINT cc_coordination_actions_tenant_scope_id_state_id_fkey FOREIGN KEY (tenant_scope_id, state_id) REFERENCES cc_coordination_states(tenant_scope_id, id) ON DELETE CASCADE;
ALTER TABLE cc_coordination_facts DROP CONSTRAINT cc_coordination_facts_tenant_scope_id_node_id_fkey,
    ADD CONSTRAINT cc_coordination_facts_tenant_scope_id_node_id_fkey FOREIGN KEY (tenant_scope_id, node_id) REFERENCES nodes(scope_id, id) ON DELETE CASCADE;
ALTER TABLE cc_coordination_releases DROP CONSTRAINT cc_coordination_releases_tenant_scope_id_action_id_fkey,
    ADD CONSTRAINT cc_coordination_releases_tenant_scope_id_action_id_fkey FOREIGN KEY (tenant_scope_id, action_id) REFERENCES cc_coordination_actions(tenant_scope_id, id) ON DELETE CASCADE;
ALTER TABLE cc_coordination_releases DROP CONSTRAINT cc_coordination_releases_tenant_scope_id_state_id_fkey,
    ADD CONSTRAINT cc_coordination_releases_tenant_scope_id_state_id_fkey FOREIGN KEY (tenant_scope_id, state_id) REFERENCES cc_coordination_states(tenant_scope_id, id) ON DELETE CASCADE;
ALTER TABLE cc_coordination_setting_targets DROP CONSTRAINT cc_coordination_setting_targets_tenant_scope_id_node_id_fkey,
    ADD CONSTRAINT cc_coordination_setting_targets_tenant_scope_id_node_id_fkey FOREIGN KEY (tenant_scope_id, node_id) REFERENCES nodes(scope_id, id) ON DELETE CASCADE;
ALTER TABLE cc_coordination_states DROP CONSTRAINT cc_coordination_states_tenant_scope_id_last_fact_id_fkey,
    ADD CONSTRAINT cc_coordination_states_tenant_scope_id_last_fact_id_fkey FOREIGN KEY (tenant_scope_id, last_fact_id) REFERENCES cc_coordination_facts(tenant_scope_id, id) ON DELETE CASCADE;
ALTER TABLE deployment_domain_event_fanout_receipts DROP CONSTRAINT deployment_domain_event_fanout_receipts_source_id_fkey,
    ADD CONSTRAINT deployment_domain_event_fanout_receipts_source_id_fkey FOREIGN KEY (source_id) REFERENCES deployment_domain_event_source_outbox(id) ON DELETE CASCADE;
ALTER TABLE deployment_domain_event_source_outbox DROP CONSTRAINT deployment_domain_event_source_outbo_deployment_id_attempt_fkey,
    ADD CONSTRAINT deployment_domain_event_source_outbo_deployment_id_attempt_fkey FOREIGN KEY (deployment_id, attempt) REFERENCES node_deployments(id, attempt) ON DELETE CASCADE;
ALTER TABLE deployment_domain_event_source_outbox DROP CONSTRAINT deployment_domain_event_source_outbox_node_id_fkey,
    ADD CONSTRAINT deployment_domain_event_source_outbox_node_id_fkey FOREIGN KEY (node_id) REFERENCES nodes(id) ON DELETE CASCADE;
ALTER TABLE deployment_status_events DROP CONSTRAINT deployment_status_events_deployment_id_attempt_fkey,
    ADD CONSTRAINT deployment_status_events_deployment_id_attempt_fkey FOREIGN KEY (deployment_id, attempt) REFERENCES node_deployments(id, attempt) ON DELETE CASCADE;
ALTER TABLE edge_command_outbox DROP CONSTRAINT edge_command_outbox_deployment_id_deployment_attempt_fkey,
    ADD CONSTRAINT edge_command_outbox_deployment_id_deployment_attempt_fkey FOREIGN KEY (deployment_id, deployment_attempt) REFERENCES node_deployments(id, attempt) ON DELETE CASCADE;
ALTER TABLE edge_command_outbox DROP CONSTRAINT edge_command_outbox_node_id_fkey,
    ADD CONSTRAINT edge_command_outbox_node_id_fkey FOREIGN KEY (node_id) REFERENCES nodes(id) ON DELETE CASCADE;
ALTER TABLE edge_target_snapshot_identities DROP CONSTRAINT edge_target_snapshot_identiti_tenant_scope_id_source_line__fkey,
    ADD CONSTRAINT edge_target_snapshot_identiti_tenant_scope_id_source_line__fkey FOREIGN KEY (tenant_scope_id, source_line_group_id, source_revision, endpoint_id) REFERENCES node_line_endpoints(tenant_scope_id, line_group_id, config_revision, id) ON DELETE CASCADE;
ALTER TABLE edge_target_snapshot_identities DROP CONSTRAINT edge_target_snapshot_identities_tenant_scope_id_node_id_fkey,
    ADD CONSTRAINT edge_target_snapshot_identities_tenant_scope_id_node_id_fkey FOREIGN KEY (tenant_scope_id, node_id) REFERENCES nodes(scope_id, id) ON DELETE CASCADE;
ALTER TABLE edge_target_snapshot_nodes DROP CONSTRAINT edge_target_snapshot_nodes_tenant_scope_id_node_id_fkey,
    ADD CONSTRAINT edge_target_snapshot_nodes_tenant_scope_id_node_id_fkey FOREIGN KEY (tenant_scope_id, node_id) REFERENCES nodes(scope_id, id) ON DELETE CASCADE;
ALTER TABLE error_page_scope_override_items DROP CONSTRAINT error_page_scope_override_items_override_id_revision_fkey,
    ADD CONSTRAINT error_page_scope_override_items_override_id_revision_fkey FOREIGN KEY (override_id, revision) REFERENCES error_page_scope_override_revisions(override_id, revision) ON DELETE CASCADE;
ALTER TABLE error_page_scope_override_revisions DROP CONSTRAINT error_page_scope_override_revisions_override_id_fkey,
    ADD CONSTRAINT error_page_scope_override_revisions_override_id_fkey FOREIGN KEY (override_id) REFERENCES error_page_scope_overrides(id) ON DELETE CASCADE;
ALTER TABLE error_page_scope_overrides DROP CONSTRAINT error_page_scope_overrides_target_node_id_fkey,
    ADD CONSTRAINT error_page_scope_overrides_target_node_id_fkey FOREIGN KEY (target_node_id) REFERENCES nodes(id) ON DELETE CASCADE;
ALTER TABLE firewall_command_outbox DROP CONSTRAINT firewall_command_outbox_tenant_scope_id_node_id_fkey,
    ADD CONSTRAINT firewall_command_outbox_tenant_scope_id_node_id_fkey FOREIGN KEY (tenant_scope_id, node_id) REFERENCES nodes(scope_id, id) ON DELETE CASCADE;
ALTER TABLE ja4_block_edge_receipt_queue_158 DROP CONSTRAINT ja4_block_edge_receipt_queue_158_tenant_scope_id_node_id_fkey,
    ADD CONSTRAINT ja4_block_edge_receipt_queue_158_tenant_scope_id_node_id_fkey FOREIGN KEY (tenant_scope_id, node_id) REFERENCES nodes(scope_id, id) ON DELETE CASCADE;
ALTER TABLE l4_line_switch_drain_plans DROP CONSTRAINT l4_line_switch_drain_plans_configuration_scope_id_node_id_fkey,
    ADD CONSTRAINT l4_line_switch_drain_plans_configuration_scope_id_node_id_fkey FOREIGN KEY (configuration_scope_id, node_id) REFERENCES nodes(scope_id, id) ON DELETE CASCADE;
ALTER TABLE l4_node_drain_counters DROP CONSTRAINT l4_node_drain_counters_configuration_scope_id_node_id_fkey,
    ADD CONSTRAINT l4_node_drain_counters_configuration_scope_id_node_id_fkey FOREIGN KEY (configuration_scope_id, node_id) REFERENCES nodes(scope_id, id) ON DELETE CASCADE;
ALTER TABLE node_artifact_encryption_keys DROP CONSTRAINT node_artifact_encryption_keys_authorization_id_node_id_fkey,
    ADD CONSTRAINT node_artifact_encryption_keys_authorization_id_node_id_fkey FOREIGN KEY (authorization_id, node_id) REFERENCES node_identity_authorizations(id, node_id) ON DELETE CASCADE;
ALTER TABLE node_artifact_encryption_keys DROP CONSTRAINT node_artifact_encryption_keys_node_id_fkey,
    ADD CONSTRAINT node_artifact_encryption_keys_node_id_fkey FOREIGN KEY (node_id) REFERENCES nodes(id) ON DELETE CASCADE;
ALTER TABLE node_auto_disable_usage DROP CONSTRAINT node_auto_disable_usage_node_id_fkey,
    ADD CONSTRAINT node_auto_disable_usage_node_id_fkey FOREIGN KEY (node_id) REFERENCES nodes(id) ON DELETE CASCADE;
ALTER TABLE node_certificate_events DROP CONSTRAINT node_certificate_events_certificate_id_node_id_fkey,
    ADD CONSTRAINT node_certificate_events_certificate_id_node_id_fkey FOREIGN KEY (certificate_id, node_id) REFERENCES node_certificates(id, node_id) ON DELETE CASCADE;
ALTER TABLE node_certificate_events DROP CONSTRAINT node_certificate_events_related_certificate_id_node_id_fkey,
    ADD CONSTRAINT node_certificate_events_related_certificate_id_node_id_fkey FOREIGN KEY (related_certificate_id, node_id) REFERENCES node_certificates(id, node_id) ON DELETE CASCADE;
ALTER TABLE node_certificate_renewal_requests DROP CONSTRAINT node_certificate_renewal_current_fk,
    ADD CONSTRAINT node_certificate_renewal_current_fk FOREIGN KEY (current_certificate_id, node_id) REFERENCES node_certificates(id, node_id) ON DELETE CASCADE;
ALTER TABLE node_certificate_renewal_requests DROP CONSTRAINT node_certificate_renewal_issued_fk,
    ADD CONSTRAINT node_certificate_renewal_issued_fk FOREIGN KEY (issued_certificate_id, node_id) REFERENCES node_certificates(id, node_id) ON DELETE CASCADE;
ALTER TABLE node_certificate_renewal_requests DROP CONSTRAINT node_certificate_renewal_requests_node_id_fkey,
    ADD CONSTRAINT node_certificate_renewal_requests_node_id_fkey FOREIGN KEY (node_id) REFERENCES nodes(id) ON DELETE CASCADE;
ALTER TABLE node_certificate_renewal_requests DROP CONSTRAINT node_certificate_renewals_owner_node_fk,
    ADD CONSTRAINT node_certificate_renewals_owner_node_fk FOREIGN KEY (owner_scope_id, node_id) REFERENCES nodes(scope_id, id) ON DELETE CASCADE;
ALTER TABLE node_certificate_revocations DROP CONSTRAINT node_certificate_revocations_certificate_id_node_id_fkey,
    ADD CONSTRAINT node_certificate_revocations_certificate_id_node_id_fkey FOREIGN KEY (certificate_id, node_id) REFERENCES node_certificates(id, node_id) ON DELETE CASCADE;
ALTER TABLE node_certificate_revocations DROP CONSTRAINT node_certificate_revocations_owner_node_fk,
    ADD CONSTRAINT node_certificate_revocations_owner_node_fk FOREIGN KEY (owner_scope_id, node_id) REFERENCES nodes(scope_id, id) ON DELETE CASCADE;
ALTER TABLE node_certificates DROP CONSTRAINT node_certificates_enrollment_authorization_id_node_id_fkey,
    ADD CONSTRAINT node_certificates_enrollment_authorization_id_node_id_fkey FOREIGN KEY (enrollment_authorization_id, node_id) REFERENCES node_identity_authorizations(id, node_id) ON DELETE CASCADE;
ALTER TABLE node_certificates DROP CONSTRAINT node_certificates_node_id_fkey,
    ADD CONSTRAINT node_certificates_node_id_fkey FOREIGN KEY (node_id) REFERENCES nodes(id) ON DELETE CASCADE;
ALTER TABLE node_certificates DROP CONSTRAINT node_certificates_owner_node_fk,
    ADD CONSTRAINT node_certificates_owner_node_fk FOREIGN KEY (owner_scope_id, node_id) REFERENCES nodes(scope_id, id) ON DELETE CASCADE;
ALTER TABLE node_certificates DROP CONSTRAINT node_certificates_renewal_request_id_node_id_fkey,
    ADD CONSTRAINT node_certificates_renewal_request_id_node_id_fkey FOREIGN KEY (renewal_request_id, node_id) REFERENCES node_certificate_renewal_requests(request_id, node_id) ON DELETE CASCADE;
ALTER TABLE node_certificates DROP CONSTRAINT node_certificates_replaces_certificate_id_node_id_fkey,
    ADD CONSTRAINT node_certificates_replaces_certificate_id_node_id_fkey FOREIGN KEY (replaces_certificate_id, node_id) REFERENCES node_certificates(id, node_id) ON DELETE CASCADE;
ALTER TABLE node_config_reconciliations DROP CONSTRAINT node_config_reconciliations_node_id_fkey,
    ADD CONSTRAINT node_config_reconciliations_node_id_fkey FOREIGN KEY (node_id) REFERENCES nodes(id) ON DELETE CASCADE;
ALTER TABLE node_config_reconciliations DROP CONSTRAINT node_config_reconciliations_source_deployment_id_source_de_fkey,
    ADD CONSTRAINT node_config_reconciliations_source_deployment_id_source_de_fkey FOREIGN KEY (source_deployment_id, source_deployment_attempt) REFERENCES node_deployments(id, attempt) ON DELETE CASCADE;
ALTER TABLE node_config_state DROP CONSTRAINT node_config_state_node_id_fkey,
    ADD CONSTRAINT node_config_state_node_id_fkey FOREIGN KEY (node_id) REFERENCES nodes(id) ON DELETE CASCADE;
ALTER TABLE node_config_state DROP CONSTRAINT node_config_state_reconciliation_source_fk,
    ADD CONSTRAINT node_config_state_reconciliation_source_fk FOREIGN KEY (reconciliation_deployment_id, reconciliation_deployment_attempt) REFERENCES node_deployments(id, attempt) ON DELETE CASCADE;
ALTER TABLE node_deployment_artifacts DROP CONSTRAINT node_deployment_artifacts_deployment_id_deployment_attempt_fkey,
    ADD CONSTRAINT node_deployment_artifacts_deployment_id_deployment_attempt_fkey FOREIGN KEY (deployment_id, deployment_attempt, config_version_id) REFERENCES node_deployments(id, attempt, config_version_id) ON DELETE CASCADE;
ALTER TABLE node_deployments DROP CONSTRAINT node_deployments_node_id_fkey,
    ADD CONSTRAINT node_deployments_node_id_fkey FOREIGN KEY (node_id) REFERENCES nodes(id) ON DELETE CASCADE;
ALTER TABLE node_enrollment_authorizations DROP CONSTRAINT node_enrollment_authorizations_token_id_node_id_purpose_fkey,
    ADD CONSTRAINT node_enrollment_authorizations_token_id_node_id_purpose_fkey FOREIGN KEY (token_id, node_id, purpose) REFERENCES node_enrollment_tokens(id, node_id, purpose) ON DELETE CASCADE;
ALTER TABLE node_enrollment_tokens DROP CONSTRAINT node_enrollment_tokens_node_id_fkey,
    ADD CONSTRAINT node_enrollment_tokens_node_id_fkey FOREIGN KEY (node_id) REFERENCES nodes(id) ON DELETE CASCADE;
ALTER TABLE node_gateway_port_transition_command_outbox DROP CONSTRAINT node_gateway_port_transition_command_outbox_node_id_fkey,
    ADD CONSTRAINT node_gateway_port_transition_command_outbox_node_id_fkey FOREIGN KEY (node_id) REFERENCES nodes(id) ON DELETE CASCADE;
ALTER TABLE node_gateway_port_transition_command_outbox DROP CONSTRAINT node_gateway_port_transition_command_outbox_transition_id_fkey,
    ADD CONSTRAINT node_gateway_port_transition_command_outbox_transition_id_fkey FOREIGN KEY (transition_id) REFERENCES node_gateway_port_transitions(id) ON DELETE CASCADE;
ALTER TABLE node_gateway_port_transitions DROP CONSTRAINT node_gateway_port_transitions_node_id_fkey,
    ADD CONSTRAINT node_gateway_port_transitions_node_id_fkey FOREIGN KEY (node_id) REFERENCES nodes(id) ON DELETE CASCADE;
ALTER TABLE node_gateway_port_transition_status_events DROP CONSTRAINT node_gateway_port_transition_status_events_node_id_fkey,
    ADD CONSTRAINT node_gateway_port_transition_status_events_node_id_fkey FOREIGN KEY (node_id) REFERENCES nodes(id) ON DELETE CASCADE;
ALTER TABLE node_gateway_port_transition_status_events DROP CONSTRAINT node_gateway_port_transition_status_events_transition_id_fkey,
    ADD CONSTRAINT node_gateway_port_transition_status_events_transition_id_fkey FOREIGN KEY (transition_id) REFERENCES node_gateway_port_transitions(id) ON DELETE CASCADE;
ALTER TABLE node_identity_authorizations DROP CONSTRAINT node_identity_authorizations_certificate_fk,
    ADD CONSTRAINT node_identity_authorizations_certificate_fk FOREIGN KEY (issued_certificate_id, node_id) REFERENCES node_certificates(id, node_id) ON DELETE CASCADE;
ALTER TABLE node_identity_authorizations DROP CONSTRAINT node_identity_authorizations_id_node_id_fkey,
    ADD CONSTRAINT node_identity_authorizations_id_node_id_fkey FOREIGN KEY (id, node_id) REFERENCES node_enrollment_authorizations(id, node_id) ON DELETE CASCADE;
ALTER TABLE node_identity_authorizations DROP CONSTRAINT node_identity_authorizations_token_id_node_id_purpose_fkey,
    ADD CONSTRAINT node_identity_authorizations_token_id_node_id_purpose_fkey FOREIGN KEY (token_id, node_id, purpose) REFERENCES node_enrollment_tokens(id, node_id, purpose) ON DELETE CASCADE;
ALTER TABLE node_identity_state DROP CONSTRAINT node_identity_state_active_artifact_key_fk,
    ADD CONSTRAINT node_identity_state_active_artifact_key_fk FOREIGN KEY (active_artifact_key_id, node_id) REFERENCES node_artifact_encryption_keys(id, node_id) ON DELETE CASCADE;
ALTER TABLE node_identity_state DROP CONSTRAINT node_identity_state_node_id_fkey,
    ADD CONSTRAINT node_identity_state_node_id_fkey FOREIGN KEY (node_id) REFERENCES nodes(id) ON DELETE CASCADE;
ALTER TABLE node_isolation_alert_events DROP CONSTRAINT node_isolation_alert_events_scope_id_node_id_fkey,
    ADD CONSTRAINT node_isolation_alert_events_scope_id_node_id_fkey FOREIGN KEY (scope_id, node_id) REFERENCES node_isolation_states(scope_id, node_id) ON DELETE CASCADE;
ALTER TABLE node_isolation_reports DROP CONSTRAINT node_isolation_reports_scope_id_node_id_fkey,
    ADD CONSTRAINT node_isolation_reports_scope_id_node_id_fkey FOREIGN KEY (scope_id, node_id) REFERENCES node_isolation_states(scope_id, node_id) ON DELETE CASCADE;
ALTER TABLE node_isolation_states DROP CONSTRAINT node_isolation_states_node_id_fkey,
    ADD CONSTRAINT node_isolation_states_node_id_fkey FOREIGN KEY (node_id) REFERENCES nodes(id) ON DELETE CASCADE;
ALTER TABLE node_isolation_states DROP CONSTRAINT node_isolation_states_scope_id_node_id_fkey,
    ADD CONSTRAINT node_isolation_states_scope_id_node_id_fkey FOREIGN KEY (scope_id, node_id) REFERENCES nodes(scope_id, id) ON DELETE CASCADE;
ALTER TABLE node_line_endpoint_health DROP CONSTRAINT node_line_endpoint_health_tenant_scope_id_line_group_id_co_fkey,
    ADD CONSTRAINT node_line_endpoint_health_tenant_scope_id_line_group_id_co_fkey FOREIGN KEY (tenant_scope_id, line_group_id, config_revision, endpoint_id) REFERENCES node_line_endpoints(tenant_scope_id, line_group_id, config_revision, id) ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED;
ALTER TABLE node_line_endpoints DROP CONSTRAINT node_line_endpoints_node_scope_fk,
    ADD CONSTRAINT node_line_endpoints_node_scope_fk FOREIGN KEY (tenant_scope_id, node_id) REFERENCES nodes(scope_id, id) ON DELETE CASCADE;
ALTER TABLE node_metric_samples DROP CONSTRAINT node_metric_samples_node_id_fkey,
    ADD CONSTRAINT node_metric_samples_node_id_fkey FOREIGN KEY (node_id) REFERENCES nodes(id) ON DELETE CASCADE;
ALTER TABLE node_monitoring_command_outbox DROP CONSTRAINT node_monitoring_command_outbox_node_id_fkey,
    ADD CONSTRAINT node_monitoring_command_outbox_node_id_fkey FOREIGN KEY (node_id) REFERENCES nodes(id) ON DELETE CASCADE;
ALTER TABLE node_monitoring_overrides DROP CONSTRAINT node_monitoring_overrides_node_id_fkey,
    ADD CONSTRAINT node_monitoring_overrides_node_id_fkey FOREIGN KEY (node_id) REFERENCES nodes(id) ON DELETE CASCADE;
ALTER TABLE node_monitoring_overrides DROP CONSTRAINT node_monitoring_overrides_scope_id_node_id_fkey,
    ADD CONSTRAINT node_monitoring_overrides_scope_id_node_id_fkey FOREIGN KEY (scope_id, node_id) REFERENCES nodes(scope_id, id) ON DELETE CASCADE;
ALTER TABLE node_network_inventory_reports DROP CONSTRAINT node_network_inventory_reports_certificate_id_fkey,
    ADD CONSTRAINT node_network_inventory_reports_certificate_id_fkey FOREIGN KEY (certificate_id) REFERENCES node_certificates(id) ON DELETE CASCADE;
ALTER TABLE node_network_inventory_reports DROP CONSTRAINT node_network_inventory_reports_node_id_fkey,
    ADD CONSTRAINT node_network_inventory_reports_node_id_fkey FOREIGN KEY (node_id) REFERENCES nodes(id) ON DELETE CASCADE;
ALTER TABLE node_presence DROP CONSTRAINT node_presence_node_id_fkey,
    ADD CONSTRAINT node_presence_node_id_fkey FOREIGN KEY (node_id) REFERENCES nodes(id) ON DELETE CASCADE;
ALTER TABLE node_serving_events DROP CONSTRAINT node_serving_events_node_id_fkey,
    ADD CONSTRAINT node_serving_events_node_id_fkey FOREIGN KEY (node_id) REFERENCES nodes(id) ON DELETE CASCADE;
ALTER TABLE node_serving_holds DROP CONSTRAINT node_serving_holds_node_id_fkey,
    ADD CONSTRAINT node_serving_holds_node_id_fkey FOREIGN KEY (node_id) REFERENCES nodes(id) ON DELETE CASCADE;
ALTER TABLE node_session_capabilities DROP CONSTRAINT node_session_capabilities_artifact_key_id_fkey,
    ADD CONSTRAINT node_session_capabilities_artifact_key_id_fkey FOREIGN KEY (artifact_key_id) REFERENCES node_artifact_encryption_keys(id) ON DELETE CASCADE;
ALTER TABLE node_session_capabilities DROP CONSTRAINT node_session_capabilities_certificate_id_node_id_fkey,
    ADD CONSTRAINT node_session_capabilities_certificate_id_node_id_fkey FOREIGN KEY (certificate_id, node_id) REFERENCES node_certificates(id, node_id) ON DELETE CASCADE;
ALTER TABLE node_session_capabilities DROP CONSTRAINT node_session_capabilities_node_id_fkey,
    ADD CONSTRAINT node_session_capabilities_node_id_fkey FOREIGN KEY (node_id) REFERENCES nodes(id) ON DELETE CASCADE;
ALTER TABLE node_traffic_policies DROP CONSTRAINT node_traffic_policies_node_id_fkey,
    ADD CONSTRAINT node_traffic_policies_node_id_fkey FOREIGN KEY (node_id) REFERENCES nodes(id) ON DELETE CASCADE;
ALTER TABLE node_traffic_policies DROP CONSTRAINT node_traffic_policies_scope_id_node_id_fkey,
    ADD CONSTRAINT node_traffic_policies_scope_id_node_id_fkey FOREIGN KEY (scope_id, node_id) REFERENCES nodes(scope_id, id) ON DELETE CASCADE;
ALTER TABLE node_traffic_policy_evaluations DROP CONSTRAINT node_traffic_policy_evaluations_scope_id_node_id_fkey,
    ADD CONSTRAINT node_traffic_policy_evaluations_scope_id_node_id_fkey FOREIGN KEY (scope_id, node_id) REFERENCES node_traffic_policies(scope_id, node_id) ON DELETE CASCADE;
ALTER TABLE node_traffic_sync_tasks DROP CONSTRAINT node_traffic_sync_tasks_evaluation_id_scope_id_node_id_fkey,
    ADD CONSTRAINT node_traffic_sync_tasks_evaluation_id_scope_id_node_id_fkey FOREIGN KEY (evaluation_id, scope_id, node_id) REFERENCES node_traffic_policy_evaluations(id, scope_id, node_id) ON DELETE CASCADE;
ALTER TABLE node_traffic_sync_tasks DROP CONSTRAINT node_traffic_sync_tasks_scope_id_node_id_fkey,
    ADD CONSTRAINT node_traffic_sync_tasks_scope_id_node_id_fkey FOREIGN KEY (scope_id, node_id) REFERENCES nodes(scope_id, id) ON DELETE CASCADE;
ALTER TABLE package_monitor_config_installations_114 DROP CONSTRAINT package_monitor_config_installations_114_node_id_fkey,
    ADD CONSTRAINT package_monitor_config_installations_114_node_id_fkey FOREIGN KEY (node_id) REFERENCES nodes(id) ON DELETE CASCADE;
ALTER TABLE security_policy_activation_recovery_pending_095 DROP CONSTRAINT security_policy_activation_re_deployment_id_deployment_att_fkey,
    ADD CONSTRAINT security_policy_activation_re_deployment_id_deployment_att_fkey FOREIGN KEY (deployment_id, deployment_attempt) REFERENCES node_deployments(id, attempt) ON DELETE CASCADE;
ALTER TABLE security_policy_activation_recovery_pending_095 DROP CONSTRAINT security_policy_activation_recovery_pending_095_outbox_id_fkey,
    ADD CONSTRAINT security_policy_activation_recovery_pending_095_outbox_id_fkey FOREIGN KEY (outbox_id) REFERENCES edge_command_outbox(id) ON DELETE CASCADE;
ALTER TABLE security_policy_activation_recovery_proofs_095 DROP CONSTRAINT security_policy_activation_re_candidate_id_node_id_generat_fkey,
    ADD CONSTRAINT security_policy_activation_re_candidate_id_node_id_generat_fkey FOREIGN KEY (candidate_id, node_id, generation) REFERENCES security_policy_activation_recovery_pending_095(candidate_id, node_id, generation) ON DELETE CASCADE;
ALTER TABLE security_policy_activation_recovery_proofs_095 DROP CONSTRAINT security_policy_activation_recovery_proofs_status_event_id_fkey,
    ADD CONSTRAINT security_policy_activation_recovery_proofs_status_event_id_fkey FOREIGN KEY (status_event_id) REFERENCES deployment_status_events(id) ON DELETE CASCADE;
ALTER TABLE security_policy_publication_targets DROP CONSTRAINT security_policy_publication_target_tenant_scope_id_node_id_fkey,
    ADD CONSTRAINT security_policy_publication_target_tenant_scope_id_node_id_fkey FOREIGN KEY (tenant_scope_id, node_id) REFERENCES nodes(scope_id, id) ON DELETE CASCADE;
ALTER TABLE site_protocol_node_results DROP CONSTRAINT site_protocol_node_results_node_id_fkey,
    ADD CONSTRAINT site_protocol_node_results_node_id_fkey FOREIGN KEY (node_id) REFERENCES nodes(id) ON DELETE CASCADE;

-- Protection triggers: DELETE is split into its own trigger gated by the purge
-- predicate; INSERT / UPDATE / TRUNCATE keep the original trigger unchanged.
DROP TRIGGER acme_http01_overlay_deployment_events_immutable ON acme_http01_overlay_deployment_events;
CREATE TRIGGER acme_http01_overlay_deployment_events_immutable BEFORE UPDATE ON acme_http01_overlay_deployment_events FOR EACH ROW EXECUTE FUNCTION protect_acme_http01_overlay_fact();
CREATE TRIGGER acme_http01_overlay_deployment_events_immutable_del BEFORE DELETE ON acme_http01_overlay_deployment_events FOR EACH ROW
    WHEN (NOT node_purge_in_progress()) EXECUTE FUNCTION protect_acme_http01_overlay_fact();
DROP TRIGGER acme_http01_overlay_deployments_immutable ON acme_http01_overlay_deployments;
CREATE TRIGGER acme_http01_overlay_deployments_immutable BEFORE UPDATE ON acme_http01_overlay_deployments FOR EACH ROW EXECUTE FUNCTION protect_acme_http01_overlay_fact();
CREATE TRIGGER acme_http01_overlay_deployments_immutable_del BEFORE DELETE ON acme_http01_overlay_deployments FOR EACH ROW
    WHEN (NOT node_purge_permits(OLD.node_id)) EXECUTE FUNCTION protect_acme_http01_overlay_fact();
DROP TRIGGER acme_http01_overlay_outbox_immutable ON acme_http01_overlay_outbox;
CREATE TRIGGER acme_http01_overlay_outbox_immutable BEFORE UPDATE ON acme_http01_overlay_outbox FOR EACH ROW EXECUTE FUNCTION protect_acme_http01_overlay_fact();
CREATE TRIGGER acme_http01_overlay_outbox_immutable_del BEFORE DELETE ON acme_http01_overlay_outbox FOR EACH ROW
    WHEN (NOT node_purge_permits(OLD.node_id)) EXECUTE FUNCTION protect_acme_http01_overlay_fact();
DROP TRIGGER acme_http01_overlay_outbox_attempts_immutable ON acme_http01_overlay_outbox_attempts;
CREATE TRIGGER acme_http01_overlay_outbox_attempts_immutable BEFORE UPDATE ON acme_http01_overlay_outbox_attempts FOR EACH ROW EXECUTE FUNCTION protect_acme_http01_overlay_fact();
CREATE TRIGGER acme_http01_overlay_outbox_attempts_immutable_del BEFORE DELETE ON acme_http01_overlay_outbox_attempts FOR EACH ROW
    WHEN (NOT node_purge_in_progress()) EXECUTE FUNCTION protect_acme_http01_overlay_fact();
DROP TRIGGER acme_http01_overlay_outbox_states_protected ON acme_http01_overlay_outbox_states;
CREATE TRIGGER acme_http01_overlay_outbox_states_protected BEFORE UPDATE ON acme_http01_overlay_outbox_states FOR EACH ROW EXECUTE FUNCTION protect_acme_http01_overlay_outbox_state();
CREATE TRIGGER acme_http01_overlay_outbox_states_protected_del BEFORE DELETE ON acme_http01_overlay_outbox_states FOR EACH ROW
    WHEN (NOT node_purge_in_progress()) EXECUTE FUNCTION protect_acme_http01_overlay_outbox_state();
DROP TRIGGER acme_http01_overlay_targets_immutable ON acme_http01_overlay_targets;
CREATE TRIGGER acme_http01_overlay_targets_immutable BEFORE UPDATE ON acme_http01_overlay_targets FOR EACH ROW EXECUTE FUNCTION protect_acme_http01_overlay_fact();
CREATE TRIGGER acme_http01_overlay_targets_immutable_del BEFORE DELETE ON acme_http01_overlay_targets FOR EACH ROW
    WHEN (NOT node_purge_permits(OLD.node_id)) EXECUTE FUNCTION protect_acme_http01_overlay_fact();
DROP TRIGGER cache_operation_node_attempts_integrity ON cache_operation_node_attempts;
CREATE CONSTRAINT TRIGGER cache_operation_node_attempts_integrity AFTER INSERT OR UPDATE ON cache_operation_node_attempts DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION validate_cache_operation_integrity();
CREATE CONSTRAINT TRIGGER cache_operation_node_attempts_integrity_del AFTER DELETE ON cache_operation_node_attempts DEFERRABLE INITIALLY DEFERRED FOR EACH ROW
    WHEN (NOT node_purge_permits(OLD.node_id)) EXECUTE FUNCTION validate_cache_operation_integrity();
DROP TRIGGER cache_operation_node_attempts_protected ON cache_operation_node_attempts;
CREATE TRIGGER cache_operation_node_attempts_protected BEFORE UPDATE ON cache_operation_node_attempts FOR EACH ROW EXECUTE FUNCTION protect_cache_operation_attempt();
CREATE TRIGGER cache_operation_node_attempts_protected_del BEFORE DELETE ON cache_operation_node_attempts FOR EACH ROW
    WHEN (NOT node_purge_permits(OLD.node_id)) EXECUTE FUNCTION protect_cache_operation_attempt();
DROP TRIGGER cache_operation_nodes_integrity ON cache_operation_nodes;
CREATE CONSTRAINT TRIGGER cache_operation_nodes_integrity AFTER INSERT OR UPDATE ON cache_operation_nodes DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION validate_cache_operation_integrity();
CREATE CONSTRAINT TRIGGER cache_operation_nodes_integrity_del AFTER DELETE ON cache_operation_nodes DEFERRABLE INITIALLY DEFERRED FOR EACH ROW
    WHEN (NOT node_purge_permits(OLD.node_id)) EXECUTE FUNCTION validate_cache_operation_integrity();
DROP TRIGGER cache_operation_nodes_no_delete ON cache_operation_nodes;
CREATE TRIGGER cache_operation_nodes_no_delete BEFORE DELETE ON cache_operation_nodes FOR EACH ROW
    WHEN (NOT node_purge_permits(OLD.node_id)) EXECUTE FUNCTION prevent_cache_projection_delete();
DROP TRIGGER cache_operation_node_targets_integrity ON cache_operation_node_targets;
CREATE CONSTRAINT TRIGGER cache_operation_node_targets_integrity AFTER INSERT OR UPDATE ON cache_operation_node_targets DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION validate_cache_operation_integrity();
CREATE CONSTRAINT TRIGGER cache_operation_node_targets_integrity_del AFTER DELETE ON cache_operation_node_targets DEFERRABLE INITIALLY DEFERRED FOR EACH ROW
    WHEN (NOT node_purge_permits(OLD.node_id)) EXECUTE FUNCTION validate_cache_operation_integrity();
DROP TRIGGER cache_operation_node_targets_no_delete ON cache_operation_node_targets;
CREATE TRIGGER cache_operation_node_targets_no_delete BEFORE DELETE ON cache_operation_node_targets FOR EACH ROW
    WHEN (NOT node_purge_permits(OLD.node_id)) EXECUTE FUNCTION prevent_cache_projection_delete();
DROP TRIGGER cache_operation_target_results_append_only ON cache_operation_target_results;
CREATE TRIGGER cache_operation_target_results_append_only BEFORE UPDATE ON cache_operation_target_results FOR EACH ROW EXECUTE FUNCTION prevent_cache_append_only_mutation();
CREATE TRIGGER cache_operation_target_results_append_only_del BEFORE DELETE ON cache_operation_target_results FOR EACH ROW
    WHEN (NOT node_purge_permits(OLD.node_id)) EXECUTE FUNCTION prevent_cache_append_only_mutation();
DROP TRIGGER cache_operation_target_results_integrity ON cache_operation_target_results;
CREATE CONSTRAINT TRIGGER cache_operation_target_results_integrity AFTER INSERT OR UPDATE ON cache_operation_target_results DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION validate_cache_operation_integrity();
CREATE CONSTRAINT TRIGGER cache_operation_target_results_integrity_del AFTER DELETE ON cache_operation_target_results DEFERRABLE INITIALLY DEFERRED FOR EACH ROW
    WHEN (NOT node_purge_permits(OLD.node_id)) EXECUTE FUNCTION validate_cache_operation_integrity();
DROP TRIGGER cc_coordination_actions_protected_127 ON cc_coordination_actions;
CREATE TRIGGER cc_coordination_actions_protected_127 BEFORE UPDATE ON cc_coordination_actions FOR EACH ROW EXECUTE FUNCTION protect_cc_coordination_action_127();
CREATE TRIGGER cc_coordination_actions_protected_127_del BEFORE DELETE ON cc_coordination_actions FOR EACH ROW
    WHEN (NOT node_purge_in_progress()) EXECUTE FUNCTION protect_cc_coordination_action_127();
DROP TRIGGER cc_coordination_facts_immutable_127 ON cc_coordination_facts;
CREATE TRIGGER cc_coordination_facts_immutable_127 BEFORE UPDATE ON cc_coordination_facts FOR EACH ROW EXECUTE FUNCTION protect_cc_coordination_immutable_127();
CREATE TRIGGER cc_coordination_facts_immutable_127_del BEFORE DELETE ON cc_coordination_facts FOR EACH ROW
    WHEN (NOT node_purge_permits(OLD.node_id)) EXECUTE FUNCTION protect_cc_coordination_immutable_127();
DROP TRIGGER cc_coordination_releases_protected_127 ON cc_coordination_releases;
CREATE TRIGGER cc_coordination_releases_protected_127 BEFORE UPDATE ON cc_coordination_releases FOR EACH ROW EXECUTE FUNCTION protect_cc_coordination_release_127();
CREATE TRIGGER cc_coordination_releases_protected_127_del BEFORE DELETE ON cc_coordination_releases FOR EACH ROW
    WHEN (NOT node_purge_in_progress()) EXECUTE FUNCTION protect_cc_coordination_release_127();
DROP TRIGGER cc_coordination_targets_immutable_127 ON cc_coordination_setting_targets;
CREATE TRIGGER cc_coordination_targets_immutable_127 BEFORE UPDATE ON cc_coordination_setting_targets FOR EACH ROW EXECUTE FUNCTION protect_cc_coordination_immutable_127();
CREATE TRIGGER cc_coordination_targets_immutable_127_del BEFORE DELETE ON cc_coordination_setting_targets FOR EACH ROW
    WHEN (NOT node_purge_permits(OLD.node_id)) EXECUTE FUNCTION protect_cc_coordination_immutable_127();
DROP TRIGGER cc_coordination_states_protected_127 ON cc_coordination_states;
CREATE TRIGGER cc_coordination_states_protected_127 BEFORE UPDATE ON cc_coordination_states FOR EACH ROW EXECUTE FUNCTION protect_cc_coordination_state_127();
CREATE TRIGGER cc_coordination_states_protected_127_del BEFORE DELETE ON cc_coordination_states FOR EACH ROW
    WHEN (NOT node_purge_in_progress()) EXECUTE FUNCTION protect_cc_coordination_state_127();
DROP TRIGGER deployment_domain_event_fanout_receipt_guard_189 ON deployment_domain_event_fanout_receipts;
CREATE TRIGGER deployment_domain_event_fanout_receipt_guard_189 BEFORE INSERT OR UPDATE ON deployment_domain_event_fanout_receipts FOR EACH ROW EXECUTE FUNCTION validate_deployment_domain_event_fanout_receipt_189();
CREATE TRIGGER deployment_domain_event_fanout_receipt_guard_189_del BEFORE DELETE ON deployment_domain_event_fanout_receipts FOR EACH ROW
    WHEN (NOT node_purge_in_progress()) EXECUTE FUNCTION validate_deployment_domain_event_fanout_receipt_189();
DROP TRIGGER deployment_domain_event_source_outbox_append_only ON deployment_domain_event_source_outbox;
CREATE TRIGGER deployment_domain_event_source_outbox_append_only BEFORE INSERT OR UPDATE ON deployment_domain_event_source_outbox FOR EACH ROW EXECUTE FUNCTION validate_deployment_domain_event_source_outbox();
CREATE TRIGGER deployment_domain_event_source_outbox_append_only_del BEFORE DELETE ON deployment_domain_event_source_outbox FOR EACH ROW
    WHEN (NOT node_purge_permits(OLD.node_id)) EXECUTE FUNCTION validate_deployment_domain_event_source_outbox();
DROP TRIGGER deployment_status_events_append_only ON deployment_status_events;
CREATE TRIGGER deployment_status_events_append_only BEFORE UPDATE ON deployment_status_events FOR EACH ROW EXECUTE FUNCTION prevent_deployment_status_event_mutation();
CREATE TRIGGER deployment_status_events_append_only_del BEFORE DELETE ON deployment_status_events FOR EACH ROW
    WHEN (NOT node_purge_in_progress()) EXECUTE FUNCTION prevent_deployment_status_event_mutation();
DROP TRIGGER edge_target_snapshot_identities_immutable_173 ON edge_target_snapshot_identities;
CREATE TRIGGER edge_target_snapshot_identities_immutable_173 BEFORE INSERT OR UPDATE ON edge_target_snapshot_identities FOR EACH ROW EXECUTE FUNCTION protect_edge_target_snapshot_identity_173();
CREATE TRIGGER edge_target_snapshot_identities_immutable_173_del BEFORE DELETE ON edge_target_snapshot_identities FOR EACH ROW
    WHEN (NOT node_purge_permits(OLD.node_id)) EXECUTE FUNCTION protect_edge_target_snapshot_identity_173();
DROP TRIGGER edge_target_snapshot_nodes_complete_074 ON edge_target_snapshot_nodes;
CREATE CONSTRAINT TRIGGER edge_target_snapshot_nodes_complete_074 AFTER INSERT OR UPDATE ON edge_target_snapshot_nodes DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION assert_edge_target_snapshot_complete_074();
CREATE CONSTRAINT TRIGGER edge_target_snapshot_nodes_complete_074_del AFTER DELETE ON edge_target_snapshot_nodes DEFERRABLE INITIALLY DEFERRED FOR EACH ROW
    WHEN (NOT node_purge_permits(OLD.node_id)) EXECUTE FUNCTION assert_edge_target_snapshot_complete_074();
DROP TRIGGER edge_target_snapshot_nodes_immutable_074 ON edge_target_snapshot_nodes;
CREATE TRIGGER edge_target_snapshot_nodes_immutable_074 BEFORE INSERT OR UPDATE ON edge_target_snapshot_nodes FOR EACH ROW EXECUTE FUNCTION protect_edge_target_snapshot_nodes_074();
CREATE TRIGGER edge_target_snapshot_nodes_immutable_074_del BEFORE DELETE ON edge_target_snapshot_nodes FOR EACH ROW
    WHEN (NOT node_purge_permits(OLD.node_id)) EXECUTE FUNCTION protect_edge_target_snapshot_nodes_074();
DROP TRIGGER error_page_scope_override_items_append_only_220 ON error_page_scope_override_items;
CREATE TRIGGER error_page_scope_override_items_append_only_220 BEFORE UPDATE OR TRUNCATE ON error_page_scope_override_items FOR EACH STATEMENT EXECUTE FUNCTION protect_error_page_scope_overrides_220();
CREATE TRIGGER error_page_scope_override_items_append_only_220_del BEFORE DELETE ON error_page_scope_override_items FOR EACH STATEMENT
    WHEN (NOT node_purge_in_progress()) EXECUTE FUNCTION protect_error_page_scope_overrides_220();
DROP TRIGGER error_page_scope_override_revisions_append_only_220 ON error_page_scope_override_revisions;
CREATE TRIGGER error_page_scope_override_revisions_append_only_220 BEFORE UPDATE OR TRUNCATE ON error_page_scope_override_revisions FOR EACH STATEMENT EXECUTE FUNCTION protect_error_page_scope_overrides_220();
CREATE TRIGGER error_page_scope_override_revisions_append_only_220_del BEFORE DELETE ON error_page_scope_override_revisions FOR EACH STATEMENT
    WHEN (NOT node_purge_in_progress()) EXECUTE FUNCTION protect_error_page_scope_overrides_220();
DROP TRIGGER error_page_scope_overrides_append_only_220 ON error_page_scope_overrides;
CREATE TRIGGER error_page_scope_overrides_append_only_220 BEFORE UPDATE OR TRUNCATE ON error_page_scope_overrides FOR EACH STATEMENT EXECUTE FUNCTION protect_error_page_scope_overrides_220();
CREATE TRIGGER error_page_scope_overrides_append_only_220_del BEFORE DELETE ON error_page_scope_overrides FOR EACH STATEMENT
    WHEN (NOT node_purge_in_progress()) EXECUTE FUNCTION protect_error_page_scope_overrides_220();
DROP TRIGGER firewall_command_outbox_mutation ON firewall_command_outbox;
CREATE TRIGGER firewall_command_outbox_mutation BEFORE UPDATE ON firewall_command_outbox FOR EACH ROW EXECUTE FUNCTION protect_firewall_command_outbox_mutation();
CREATE TRIGGER firewall_command_outbox_mutation_del BEFORE DELETE ON firewall_command_outbox FOR EACH ROW
    WHEN (NOT node_purge_permits(OLD.node_id)) EXECUTE FUNCTION protect_firewall_command_outbox_mutation();
DROP TRIGGER ja4_block_edge_receipt_guard_158 ON ja4_block_edge_receipt_queue_158;
CREATE TRIGGER ja4_block_edge_receipt_guard_158 BEFORE UPDATE ON ja4_block_edge_receipt_queue_158 FOR EACH ROW EXECUTE FUNCTION guard_ja4_block_edge_receipt_158();
CREATE TRIGGER ja4_block_edge_receipt_guard_158_del BEFORE DELETE ON ja4_block_edge_receipt_queue_158 FOR EACH ROW
    WHEN (NOT node_purge_permits(OLD.node_id)) EXECUTE FUNCTION guard_ja4_block_edge_receipt_158();
DROP TRIGGER l4_line_switch_drain_plans_protected_139 ON l4_line_switch_drain_plans;
CREATE TRIGGER l4_line_switch_drain_plans_protected_139 BEFORE UPDATE ON l4_line_switch_drain_plans FOR EACH ROW EXECUTE FUNCTION protect_l4_line_switch_drain_plan_139();
CREATE TRIGGER l4_line_switch_drain_plans_protected_139_del BEFORE DELETE ON l4_line_switch_drain_plans FOR EACH ROW
    WHEN (NOT node_purge_permits(OLD.node_id)) EXECUTE FUNCTION protect_l4_line_switch_drain_plan_139();
DROP TRIGGER l4_node_drain_counters_protected_139 ON l4_node_drain_counters;
CREATE TRIGGER l4_node_drain_counters_protected_139 BEFORE UPDATE ON l4_node_drain_counters FOR EACH ROW EXECUTE FUNCTION protect_l4_node_drain_counter_139();
CREATE TRIGGER l4_node_drain_counters_protected_139_del BEFORE DELETE ON l4_node_drain_counters FOR EACH ROW
    WHEN (NOT node_purge_permits(OLD.node_id)) EXECUTE FUNCTION protect_l4_node_drain_counter_139();
DROP TRIGGER node_artifact_encryption_keys_protected ON node_artifact_encryption_keys;
CREATE TRIGGER node_artifact_encryption_keys_protected BEFORE UPDATE ON node_artifact_encryption_keys FOR EACH ROW EXECUTE FUNCTION protect_node_artifact_encryption_key();
CREATE TRIGGER node_artifact_encryption_keys_protected_del BEFORE DELETE ON node_artifact_encryption_keys FOR EACH ROW
    WHEN (NOT node_purge_permits(OLD.node_id)) EXECUTE FUNCTION protect_node_artifact_encryption_key();
DROP TRIGGER node_certificate_events_append_only ON node_certificate_events;
CREATE TRIGGER node_certificate_events_append_only BEFORE UPDATE ON node_certificate_events FOR EACH ROW EXECUTE FUNCTION prevent_node_certificate_event_mutation();
CREATE TRIGGER node_certificate_events_append_only_del BEFORE DELETE ON node_certificate_events FOR EACH ROW
    WHEN (NOT node_purge_permits(OLD.node_id)) EXECUTE FUNCTION prevent_node_certificate_event_mutation();
DROP TRIGGER node_certificate_renewals_protected ON node_certificate_renewal_requests;
CREATE TRIGGER node_certificate_renewals_protected BEFORE UPDATE ON node_certificate_renewal_requests FOR EACH ROW EXECUTE FUNCTION protect_node_certificate_renewal();
CREATE TRIGGER node_certificate_renewals_protected_del BEFORE DELETE ON node_certificate_renewal_requests FOR EACH ROW
    WHEN (NOT node_purge_permits(OLD.node_id)) EXECUTE FUNCTION protect_node_certificate_renewal();
DROP TRIGGER node_certificate_revocations_append_only ON node_certificate_revocations;
CREATE TRIGGER node_certificate_revocations_append_only BEFORE UPDATE ON node_certificate_revocations FOR EACH ROW EXECUTE FUNCTION prevent_node_certificate_revocation_mutation();
CREATE TRIGGER node_certificate_revocations_append_only_del BEFORE DELETE ON node_certificate_revocations FOR EACH ROW
    WHEN (NOT node_purge_permits(OLD.node_id)) EXECUTE FUNCTION prevent_node_certificate_revocation_mutation();
DROP TRIGGER node_certificates_protected ON node_certificates;
CREATE TRIGGER node_certificates_protected BEFORE UPDATE ON node_certificates FOR EACH ROW EXECUTE FUNCTION protect_node_certificate();
CREATE TRIGGER node_certificates_protected_del BEFORE DELETE ON node_certificates FOR EACH ROW
    WHEN (NOT node_purge_permits(OLD.node_id)) EXECUTE FUNCTION protect_node_certificate();
DROP TRIGGER node_config_reconciliations_append_only ON node_config_reconciliations;
CREATE TRIGGER node_config_reconciliations_append_only BEFORE UPDATE ON node_config_reconciliations FOR EACH ROW EXECUTE FUNCTION prevent_node_config_reconciliation_mutation();
CREATE TRIGGER node_config_reconciliations_append_only_del BEFORE DELETE ON node_config_reconciliations FOR EACH ROW
    WHEN (NOT node_purge_permits(OLD.node_id)) EXECUTE FUNCTION prevent_node_config_reconciliation_mutation();
DROP TRIGGER node_deployment_artifacts_immutable ON node_deployment_artifacts;
CREATE TRIGGER node_deployment_artifacts_immutable BEFORE UPDATE ON node_deployment_artifacts FOR EACH ROW EXECUTE FUNCTION prevent_node_deployment_artifact_mutation();
CREATE TRIGGER node_deployment_artifacts_immutable_del BEFORE DELETE ON node_deployment_artifacts FOR EACH ROW
    WHEN (NOT node_purge_in_progress()) EXECUTE FUNCTION prevent_node_deployment_artifact_mutation();
DROP TRIGGER node_identity_authorizations_protected ON node_identity_authorizations;
CREATE TRIGGER node_identity_authorizations_protected BEFORE UPDATE ON node_identity_authorizations FOR EACH ROW EXECUTE FUNCTION protect_node_identity_authorization();
CREATE TRIGGER node_identity_authorizations_protected_del BEFORE DELETE ON node_identity_authorizations FOR EACH ROW
    WHEN (NOT node_purge_permits(OLD.node_id)) EXECUTE FUNCTION protect_node_identity_authorization();
DROP TRIGGER node_identity_revision_monotonic ON node_identity_state;
CREATE TRIGGER node_identity_revision_monotonic BEFORE UPDATE ON node_identity_state FOR EACH ROW EXECUTE FUNCTION protect_node_identity_revision();
CREATE TRIGGER node_identity_revision_monotonic_del BEFORE DELETE ON node_identity_state FOR EACH ROW
    WHEN (NOT node_purge_permits(OLD.node_id)) EXECUTE FUNCTION protect_node_identity_revision();
DROP TRIGGER node_isolation_alert_events_immutable_182 ON node_isolation_alert_events;
CREATE TRIGGER node_isolation_alert_events_immutable_182 BEFORE UPDATE ON node_isolation_alert_events FOR EACH ROW EXECUTE FUNCTION reject_node_isolation_evidence_mutation_182();
CREATE TRIGGER node_isolation_alert_events_immutable_182_del BEFORE DELETE ON node_isolation_alert_events FOR EACH ROW
    WHEN (NOT node_purge_permits(OLD.node_id)) EXECUTE FUNCTION reject_node_isolation_evidence_mutation_182();
DROP TRIGGER node_isolation_reports_immutable_182 ON node_isolation_reports;
CREATE TRIGGER node_isolation_reports_immutable_182 BEFORE UPDATE ON node_isolation_reports FOR EACH ROW EXECUTE FUNCTION reject_node_isolation_evidence_mutation_182();
CREATE TRIGGER node_isolation_reports_immutable_182_del BEFORE DELETE ON node_isolation_reports FOR EACH ROW
    WHEN (NOT node_purge_permits(OLD.node_id)) EXECUTE FUNCTION reject_node_isolation_evidence_mutation_182();
DROP TRIGGER node_line_endpoint_health_monotonic ON node_line_endpoint_health;
CREATE TRIGGER node_line_endpoint_health_monotonic BEFORE INSERT OR UPDATE ON node_line_endpoint_health FOR EACH ROW EXECUTE FUNCTION protect_node_line_endpoint_health();
CREATE TRIGGER node_line_endpoint_health_monotonic_del BEFORE DELETE ON node_line_endpoint_health FOR EACH ROW
    WHEN (NOT node_purge_in_progress()) EXECUTE FUNCTION protect_node_line_endpoint_health();
DROP TRIGGER node_line_endpoints_immutable ON node_line_endpoints;
CREATE TRIGGER node_line_endpoints_immutable BEFORE INSERT OR UPDATE ON node_line_endpoints FOR EACH ROW EXECUTE FUNCTION protect_node_line_endpoint();
CREATE TRIGGER node_line_endpoints_immutable_del BEFORE DELETE ON node_line_endpoints FOR EACH ROW
    WHEN (NOT node_purge_permits(OLD.node_id)) EXECUTE FUNCTION protect_node_line_endpoint();
DROP TRIGGER node_metric_samples_immutable_150 ON node_metric_samples;
CREATE TRIGGER node_metric_samples_immutable_150 BEFORE UPDATE OR TRUNCATE ON node_metric_samples FOR EACH STATEMENT EXECUTE FUNCTION protect_node_metric_sample_150();
CREATE TRIGGER node_metric_samples_immutable_150_del BEFORE DELETE ON node_metric_samples FOR EACH STATEMENT
    WHEN (NOT node_purge_in_progress()) EXECUTE FUNCTION protect_node_metric_sample_150();
DROP TRIGGER node_monitoring_command_outbox_append_only ON node_monitoring_command_outbox;
CREATE TRIGGER node_monitoring_command_outbox_append_only BEFORE INSERT OR UPDATE ON node_monitoring_command_outbox FOR EACH ROW EXECUTE FUNCTION protect_node_monitoring_command_outbox();
CREATE TRIGGER node_monitoring_command_outbox_append_only_del BEFORE DELETE ON node_monitoring_command_outbox FOR EACH ROW
    WHEN (NOT node_purge_permits(OLD.node_id)) EXECUTE FUNCTION protect_node_monitoring_command_outbox();
DROP TRIGGER node_monitoring_overrides_protect_279 ON node_monitoring_overrides;
CREATE TRIGGER node_monitoring_overrides_protect_279 BEFORE INSERT OR UPDATE ON node_monitoring_overrides FOR EACH ROW EXECUTE FUNCTION protect_node_monitoring_override_279();
CREATE TRIGGER node_monitoring_overrides_protect_279_del BEFORE DELETE ON node_monitoring_overrides FOR EACH ROW
    WHEN (NOT node_purge_permits(OLD.node_id)) EXECUTE FUNCTION protect_node_monitoring_override_279();
DROP TRIGGER node_network_inventory_immutable_271 ON node_network_inventory_reports;
CREATE TRIGGER node_network_inventory_immutable_271 BEFORE UPDATE OR TRUNCATE ON node_network_inventory_reports FOR EACH STATEMENT EXECUTE FUNCTION protect_node_network_inventory_271();
CREATE TRIGGER node_network_inventory_immutable_271_del BEFORE DELETE ON node_network_inventory_reports FOR EACH STATEMENT
    WHEN (NOT node_purge_in_progress()) EXECUTE FUNCTION protect_node_network_inventory_271();
DROP TRIGGER node_serving_events_append_only_280 ON node_serving_events;
CREATE TRIGGER node_serving_events_append_only_280 BEFORE UPDATE ON node_serving_events FOR EACH ROW EXECUTE FUNCTION protect_node_serving_event_280();
CREATE TRIGGER node_serving_events_append_only_280_del BEFORE DELETE ON node_serving_events FOR EACH ROW
    WHEN (NOT node_purge_permits(OLD.node_id)) EXECUTE FUNCTION protect_node_serving_event_280();
DROP TRIGGER node_serving_holds_protect_280 ON node_serving_holds;
CREATE TRIGGER node_serving_holds_protect_280 BEFORE INSERT OR UPDATE ON node_serving_holds FOR EACH ROW EXECUTE FUNCTION protect_node_serving_hold_280();
CREATE TRIGGER node_serving_holds_protect_280_del BEFORE DELETE ON node_serving_holds FOR EACH ROW
    WHEN (NOT node_purge_permits(OLD.node_id)) EXECUTE FUNCTION protect_node_serving_hold_280();
DROP TRIGGER node_session_capabilities_immutable_277 ON node_session_capabilities;
CREATE TRIGGER node_session_capabilities_immutable_277 BEFORE UPDATE ON node_session_capabilities FOR EACH ROW EXECUTE FUNCTION protect_node_session_capabilities_277();
CREATE TRIGGER node_session_capabilities_immutable_277_del BEFORE DELETE ON node_session_capabilities FOR EACH ROW
    WHEN (NOT node_purge_permits(OLD.node_id)) EXECUTE FUNCTION protect_node_session_capabilities_277();
DROP TRIGGER node_traffic_policy_evaluations_immutable_181 ON node_traffic_policy_evaluations;
CREATE TRIGGER node_traffic_policy_evaluations_immutable_181 BEFORE UPDATE ON node_traffic_policy_evaluations FOR EACH ROW EXECUTE FUNCTION reject_node_traffic_evidence_mutation_181();
CREATE TRIGGER node_traffic_policy_evaluations_immutable_181_del BEFORE DELETE ON node_traffic_policy_evaluations FOR EACH ROW
    WHEN (NOT node_purge_permits(OLD.node_id)) EXECUTE FUNCTION reject_node_traffic_evidence_mutation_181();
DROP TRIGGER package_monitor_config_installations_immutable_114 ON package_monitor_config_installations_114;
CREATE TRIGGER package_monitor_config_installations_immutable_114 BEFORE UPDATE ON package_monitor_config_installations_114 FOR EACH ROW EXECUTE FUNCTION guard_package_monitor_metric_authority_114();
CREATE TRIGGER package_monitor_config_installations_immutable_114_del BEFORE DELETE ON package_monitor_config_installations_114 FOR EACH ROW
    WHEN (NOT node_purge_permits(OLD.node_id)) EXECUTE FUNCTION guard_package_monitor_metric_authority_114();
DROP TRIGGER security_policy_activation_recovery_pending_immutable_095 ON security_policy_activation_recovery_pending_095;
CREATE TRIGGER security_policy_activation_recovery_pending_immutable_095 BEFORE UPDATE ON security_policy_activation_recovery_pending_095 FOR EACH ROW EXECUTE FUNCTION prevent_security_policy_activation_recovery_fact_mutation_095();
CREATE TRIGGER security_policy_activation_recovery_pending_immutable_095_del BEFORE DELETE ON security_policy_activation_recovery_pending_095 FOR EACH ROW
    WHEN (NOT node_purge_permits(OLD.node_id)) EXECUTE FUNCTION prevent_security_policy_activation_recovery_fact_mutation_095();
DROP TRIGGER security_policy_activation_recovery_proofs_immutable_095 ON security_policy_activation_recovery_proofs_095;
CREATE TRIGGER security_policy_activation_recovery_proofs_immutable_095 BEFORE UPDATE ON security_policy_activation_recovery_proofs_095 FOR EACH ROW EXECUTE FUNCTION prevent_security_policy_activation_recovery_fact_mutation_095();
CREATE TRIGGER security_policy_activation_recovery_proofs_immutable_095_del BEFORE DELETE ON security_policy_activation_recovery_proofs_095 FOR EACH ROW
    WHEN (NOT node_purge_permits(OLD.node_id)) EXECUTE FUNCTION prevent_security_policy_activation_recovery_fact_mutation_095();
DROP TRIGGER security_policy_publication_targets_protected ON security_policy_publication_targets;
CREATE TRIGGER security_policy_publication_targets_protected BEFORE UPDATE ON security_policy_publication_targets FOR EACH ROW EXECUTE FUNCTION protect_security_policy_publication_target();
CREATE TRIGGER security_policy_publication_targets_protected_del BEFORE DELETE ON security_policy_publication_targets FOR EACH ROW
    WHEN (NOT node_purge_permits(OLD.node_id)) EXECUTE FUNCTION protect_security_policy_publication_target();
DROP TRIGGER site_protocol_node_results_guard_136 ON site_protocol_node_results;
CREATE TRIGGER site_protocol_node_results_guard_136 BEFORE UPDATE ON site_protocol_node_results FOR EACH ROW EXECUTE FUNCTION guard_site_protocol_node_result_136();
CREATE TRIGGER site_protocol_node_results_guard_136_del BEFORE DELETE ON site_protocol_node_results FOR EACH ROW
    WHEN (NOT node_purge_permits(OLD.node_id)) EXECUTE FUNCTION guard_site_protocol_node_result_136();

CREATE TRIGGER node_line_endpoints_purge_guard_284 BEFORE DELETE ON node_line_endpoints
    FOR EACH ROW EXECUTE FUNCTION guard_node_line_endpoint_purge_284();

REVOKE ALL ON FUNCTION guard_node_line_endpoint_purge_284() FROM PUBLIC;
REVOKE ALL ON node_purged_ids FROM PUBLIC;
GRANT SELECT, INSERT ON node_purged_ids TO cdnca_control_app, cdnca_control_runtime;

-- Post-condition: every foreign key reaching nodes (directly or through
-- node-owned rows) cascades, except the L2 membership business reference.
DO $migration_284_check$
DECLARE
    offending text;
BEGIN
    WITH RECURSIVE closure(relation) AS (
        SELECT conrelid FROM pg_constraint
        WHERE contype = 'f' AND confrelid = (current_schema() || '.nodes')::regclass
        UNION
        SELECT constraint_row.conrelid FROM pg_constraint constraint_row
        JOIN closure ON constraint_row.confrelid = closure.relation
        WHERE constraint_row.contype = 'f'
    )
    SELECT string_agg(conrelid::regclass::text || '.' || conname, ', ') INTO offending
    FROM pg_constraint
    WHERE contype = 'f' AND confdeltype <> 'c'
      AND conrelid IN (SELECT relation FROM closure)
      AND (confrelid IN (SELECT relation FROM closure) OR confrelid = (current_schema() || '.nodes')::regclass)
      AND conname <> 'l2_topology_nodes_tenant_scope_id_node_id_fkey';
    IF offending IS NOT NULL THEN
        RAISE EXCEPTION 'migration 284 left non-cascading node foreign keys: %', offending USING ERRCODE='P2841';
    END IF;
    -- Every DELETE guard on those tables is gated by the purge predicate.
    WITH RECURSIVE closure(relation) AS (
        SELECT conrelid FROM pg_constraint
        WHERE contype = 'f' AND confrelid = (current_schema() || '.nodes')::regclass
        UNION
        SELECT constraint_row.conrelid FROM pg_constraint constraint_row
        JOIN closure ON constraint_row.confrelid = closure.relation
        WHERE constraint_row.contype = 'f'
    )
    SELECT string_agg(tgrelid::regclass::text || '.' || tgname, ', ') INTO offending
    FROM pg_trigger
    WHERE NOT tgisinternal AND (tgtype & 8) <> 0 AND tgrelid IN (SELECT relation FROM closure)
      AND tgname <> 'node_line_endpoints_purge_guard_284'
      AND (tgqual IS NULL OR (tgtype & (4 | 16)) <> 0);
    IF offending IS NOT NULL THEN
        RAISE EXCEPTION 'migration 284 left ungated node DELETE guards: %', offending USING ERRCODE='P2842';
    END IF;
END;
$migration_284_check$;
