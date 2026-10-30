LOCK TABLE schema_migrations, acme_http01_node_challenges, acme_http01_node_overlay_generations
    IN ACCESS EXCLUSIVE MODE;

DO $migration_337_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 337 OR
       (SELECT max(version) FROM schema_migrations) <> 337 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=337 AND
        migration_id='337_acme_http01_node_generations' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 337 down requires the exact verified migration head' USING ERRCODE='P3377';
    END IF;
    -- A published challenge or generation may still be served by a node:
    -- dropping the facts would lose what must be withdrawn.
    IF EXISTS (SELECT 1 FROM acme_http01_node_challenges) OR
       EXISTS (SELECT 1 FROM acme_http01_node_overlay_generations) THEN
        RAISE EXCEPTION 'migration 337 down refuses to drop recorded HTTP-01 node overlay facts' USING ERRCODE='P3378';
    END IF;
END;
$migration_337_down$;

DROP TABLE acme_http01_node_overlay_deliveries;
DROP TABLE acme_http01_node_overlay_states;
DROP TABLE acme_http01_node_overlay_generation_tokens;
DROP TABLE acme_http01_node_overlay_generations;
DROP TABLE acme_http01_node_challenge_targets;
DROP TABLE acme_http01_node_challenges;
DROP FUNCTION guard_acme_http01_node_overlay_delivery_337();
DROP FUNCTION guard_acme_http01_node_overlay_state_337();
DROP FUNCTION validate_acme_http01_node_generation_337();
DROP FUNCTION acme_http01_node_generation_digest_337(uuid);
DROP FUNCTION validate_acme_http01_node_challenge_337();
DROP FUNCTION guard_acme_http01_node_challenge_337();
DROP FUNCTION acme_http01_node_append_only_337();
