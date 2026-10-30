LOCK TABLE acme_http01_overlay_outbox_attempts,
           acme_http01_overlay_outbox_states,
           acme_http01_overlay_outbox,
           acme_http01_overlay_deployment_events,
           acme_http01_overlay_deployments,
           acme_http01_overlay_targets,
           acme_http01_overlay_token_facts,
           acme_http01_overlay_versions,
           acme_http01_overlay_publications,
           acme_http01_overlay_states
IN ACCESS EXCLUSIVE MODE;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM acme_http01_overlay_states)
       OR EXISTS (SELECT 1 FROM acme_http01_overlay_publications)
       OR EXISTS (SELECT 1 FROM acme_http01_overlay_versions)
       OR EXISTS (SELECT 1 FROM acme_http01_overlay_token_facts)
       OR EXISTS (SELECT 1 FROM acme_http01_overlay_targets)
       OR EXISTS (SELECT 1 FROM acme_http01_overlay_deployments)
       OR EXISTS (SELECT 1 FROM acme_http01_overlay_deployment_events)
       OR EXISTS (SELECT 1 FROM acme_http01_overlay_outbox)
       OR EXISTS (SELECT 1 FROM acme_http01_overlay_outbox_states)
       OR EXISTS (SELECT 1 FROM acme_http01_overlay_outbox_attempts) THEN
        RAISE EXCEPTION 'cannot roll back ACME HTTP-01 overlay while facts exist' USING ERRCODE = 'P0001';
    END IF;
END;
$$;

DROP TABLE acme_http01_overlay_outbox_attempts;
DROP TABLE acme_http01_overlay_outbox_states;
DROP TABLE acme_http01_overlay_outbox;
DROP TABLE acme_http01_overlay_deployment_events;
DROP TABLE acme_http01_overlay_deployments;
DROP TABLE acme_http01_overlay_targets;
DROP TABLE acme_http01_overlay_token_facts;
DROP TABLE acme_http01_overlay_versions;
DROP TABLE acme_http01_overlay_publications;
DROP TABLE acme_http01_overlay_states;

DROP FUNCTION protect_acme_http01_overlay_outbox_state();
DROP FUNCTION assert_acme_http01_overlay_outbox_projection();
DROP FUNCTION protect_acme_http01_overlay_state();
DROP FUNCTION validate_acme_http01_overlay_outbox_attempt();
DROP FUNCTION validate_acme_http01_overlay_deployment_event();
DROP FUNCTION validate_acme_http01_overlay_token();
DROP FUNCTION assert_acme_http01_overlay_publication_complete();
DROP FUNCTION validate_acme_http01_overlay_publication();
DROP FUNCTION protect_acme_http01_overlay_fact();
