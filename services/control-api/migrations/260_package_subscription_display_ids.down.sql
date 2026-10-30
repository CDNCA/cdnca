-- Application rollback must retain this additive migration so published IDs remain stable.
-- Schema rollback removes the mapping; a later reapply assigns IDs from created_at,id again.
LOCK TABLE schema_migrations, package_subscriptions, package_subscription_display_ids IN ACCESS EXCLUSIVE MODE;

DO $migration_260_down_head$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 260 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 260 OR
       NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version = 260 AND migration_id = '260_package_subscription_display_ids' AND
              integrity_state = 'verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR
       NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version = 259 AND migration_id = '259_certificate_defaults_runtime_grants' AND
              checksum_sha256 = 'd1bbefc1a232c015f3d4e072b528eb1f6202bdd5e43a7b4f4a544e3720105a65' AND
              down_checksum_sha256 = 'ce7378be178001203d55cdf7d7babf8a673fb1020904ace759f79b9313d64273' AND
              integrity_state = 'verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 260 rollback requires the exact verified 260 release head'
            USING ERRCODE = 'P2602';
    END IF;
END;
$migration_260_down_head$;

DROP TRIGGER package_subscriptions_assign_display_id_260 ON package_subscriptions;
DROP FUNCTION assign_package_subscription_display_id_260();
DROP TABLE package_subscription_display_ids;
DROP FUNCTION protect_package_subscription_display_ids_260();
