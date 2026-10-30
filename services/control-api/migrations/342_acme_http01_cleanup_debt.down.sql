LOCK TABLE schema_migrations, acme_http01_node_overlay_generations, acme_http01_site_overlay_states,
    acme_http01_node_overlay_cleanup_debts, acme_http01_overlay_backfill_sites IN ACCESS EXCLUSIVE MODE;

DO $migration_342_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 342 OR
       (SELECT max(version) FROM schema_migrations) <> 342 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=342 AND
        migration_id='342_acme_http01_cleanup_debt' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 342 down requires the exact verified migration head' USING ERRCODE='P3429';
    END IF;
    -- ADR-0003 Up/Down 门禁: dropping epochs, debts, coverage or backfill marks
    -- would lose what nodes still owe.
    IF EXISTS (SELECT 1 FROM acme_http01_site_overlay_epochs) OR
       EXISTS (SELECT 1 FROM acme_http01_node_overlay_cleanup_debts) OR
       EXISTS (SELECT 1 FROM acme_http01_node_overlay_generation_coverages) OR
       EXISTS (SELECT 1 FROM acme_http01_overlay_backfill_sites) OR
       EXISTS (SELECT 1 FROM acme_http01_overlay_backfill_nodes) OR
       EXISTS (SELECT 1 FROM acme_http01_node_overlay_generations WHERE purpose <> 'apply') THEN
        RAISE EXCEPTION 'migration 342 down refuses to drop recorded HTTP-01 epoch, debt or coverage facts'
            USING ERRCODE='P0001';
    END IF;
END;
$migration_342_down$;

DROP TRIGGER acme_http01_node_challenges_epoch_342 ON acme_http01_node_challenges;
DROP TRIGGER acme_http01_node_overlay_generations_validate_342 ON acme_http01_node_overlay_generations;
DROP TRIGGER acme_http01_node_overlay_generations_validate_342_node ON acme_http01_node_overlay_generations;
DROP VIEW acme_http01_node_overlay_cleanup_debt_states;
DROP TABLE acme_http01_overlay_backfill_quarantines;
DROP TABLE acme_http01_overlay_backfill_nodes;
DROP TABLE acme_http01_overlay_backfill_sites;
DROP TABLE acme_http01_node_overlay_generation_coverages;
DROP TABLE acme_http01_site_overlay_epoch_releases;
DROP TABLE acme_http01_node_overlay_cleanup_debt_events;
DROP TABLE acme_http01_node_overlay_cleanup_debts;
DROP TABLE acme_http01_site_overlay_version_tokens;
DROP TABLE acme_http01_node_challenge_epochs;
-- States, epochs and versions reference each other: drop them together.
DROP TABLE acme_http01_site_overlay_states, acme_http01_site_overlay_versions,
    acme_http01_site_overlay_epoch_members, acme_http01_site_overlay_epochs;
ALTER TABLE acme_http01_node_overlay_generations
    DROP CONSTRAINT acme_http01_node_overlay_generations_purpose_342,
    DROP COLUMN non_serving_proof_sha256,
    DROP COLUMN cleanup_debt_coverage_count,
    DROP COLUMN required_coverage_count,
    DROP COLUMN purpose;
DROP FUNCTION acme_http01_backfill_063();
DROP FUNCTION validate_acme_http01_challenge_epoch_342();
DROP FUNCTION guard_acme_http01_backfill_node_342();
DROP FUNCTION guard_acme_http01_cleanup_debt_event_342();
DROP FUNCTION validate_acme_http01_cleanup_debt_opened_342();
DROP FUNCTION guard_acme_http01_cleanup_debt_342();
DROP FUNCTION validate_acme_http01_site_version_members_342();
DROP FUNCTION validate_acme_http01_generation_coverage_342();
DROP FUNCTION validate_acme_http01_node_coverage_342();
DROP FUNCTION assert_acme_http01_node_coverage_342(uuid);
DROP FUNCTION validate_acme_http01_site_overlay_version_342();
DROP FUNCTION guard_acme_http01_site_overlay_version_342();
DROP FUNCTION validate_acme_http01_site_overlay_epoch_342();
DROP FUNCTION guard_acme_http01_site_overlay_epoch_release_342();
DROP FUNCTION guard_acme_http01_site_overlay_epoch_member_342();
DROP FUNCTION guard_acme_http01_site_overlay_epoch_342();
DROP FUNCTION guard_acme_http01_site_overlay_state_342();
DROP FUNCTION guard_acme_http01_overlay_fact_342();
DROP FUNCTION acme_http01_overlay_append_only_342();
DROP FUNCTION acme_http01_site_version_healthy(uuid);
DROP FUNCTION acme_http01_gated_sites();
DROP FUNCTION acme_http01_site_node_serving_blocked(uuid, uuid, uuid);
DROP FUNCTION acme_http01_backfill_063_digest(uuid, uuid);
DROP FUNCTION acme_http01_non_serving_proof(uuid, text, bigint);
DROP FUNCTION acme_http01_node_set_digest(uuid[]);
DROP FUNCTION acme_http01_site_version_digest(uuid);
DROP FUNCTION acme_http01_site_token_set_digest(uuid, text[]);
DROP FUNCTION acme_http01_site_candidate_nodes(uuid, uuid);
