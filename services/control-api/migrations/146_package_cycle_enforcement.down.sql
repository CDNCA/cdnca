LOCK TABLE schema_migrations, package_cycle_enforcement_heads, package_cycle_enforcement_claims,
    package_cycle_enforcement_transitions, package_cycle_enforcement_overrides,
    package_cycle_usage_adjustments IN ACCESS EXCLUSIVE MODE;

DO $migration_146$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 146 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 146 OR EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE migration_id IS NULL OR migration_id = '' OR
              checksum_sha256 IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
              down_checksum_sha256 IS NULL OR down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR
              integrity_state IS DISTINCT FROM 'verified' OR
              metadata_recorded_at IS NULL OR applied_at IS NULL
    ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version = 146 AND migration_id = '146_package_cycle_enforcement' AND
              integrity_state = 'verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
    ) THEN
        RAISE EXCEPTION 'migration 146 rollback requires the exact verified 146 head'
            USING ERRCODE = 'P1460';
    END IF;
    IF EXISTS (SELECT 1 FROM package_cycle_enforcement_heads) OR
       EXISTS (SELECT 1 FROM package_cycle_enforcement_claims) OR
       EXISTS (SELECT 1 FROM package_cycle_enforcement_transitions) OR
       EXISTS (SELECT 1 FROM package_cycle_enforcement_overrides) OR
       EXISTS (SELECT 1 FROM package_cycle_usage_adjustments) THEN
        RAISE EXCEPTION 'migration 146 rollback would discard package cycle enforcement facts'
            USING ERRCODE = 'P1467';
    END IF;
END;
$migration_146$;

DROP TRIGGER package_cycle_adjustments_no_truncate_146 ON package_cycle_usage_adjustments;
DROP TRIGGER package_cycle_overrides_no_truncate_146 ON package_cycle_enforcement_overrides;
DROP TRIGGER package_cycle_transitions_no_truncate_146 ON package_cycle_enforcement_transitions;
DROP TRIGGER package_cycle_claims_no_truncate_146 ON package_cycle_enforcement_claims;
DROP TRIGGER package_cycle_heads_no_truncate_146 ON package_cycle_enforcement_heads;
DROP FUNCTION prevent_package_cycle_truncate_146();
DROP TRIGGER package_cycle_adjustments_append_only_146 ON package_cycle_usage_adjustments;
DROP TRIGGER package_cycle_overrides_append_only_146 ON package_cycle_enforcement_overrides;
DROP TRIGGER package_cycle_transitions_append_only_146 ON package_cycle_enforcement_transitions;
DROP FUNCTION protect_package_cycle_fact_146();
DROP FUNCTION package_cycle_claim_single_winner_146(text,integer,interval);

DROP TABLE package_cycle_usage_adjustments;
DROP TABLE package_cycle_enforcement_overrides;
DROP TABLE package_cycle_enforcement_transitions;
DROP TABLE package_cycle_enforcement_claims;
DROP TABLE package_cycle_enforcement_heads;
DROP FUNCTION valid_package_cycle_operations_146(text[]);
