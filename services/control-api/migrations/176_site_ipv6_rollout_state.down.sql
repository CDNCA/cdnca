LOCK TABLE schema_migrations,site_ipv6_rollout_targets,config_versions,sites IN ACCESS EXCLUSIVE MODE;

DO $migration_176_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations)<>176 OR
       (SELECT min(version) FROM schema_migrations)<>1 OR
       (SELECT max(version) FROM schema_migrations)<>176 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version=176 AND migration_id='176_site_ipv6_rollout_state' AND
              checksum_sha256='51843578ad26276dd4d5ebca731f304f86fa8b572ad46b8fd9cf2eb09263a689' AND integrity_state='verified' AND
              metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
    ) THEN
        RAISE EXCEPTION 'migration 176 rollback requires the exact verified 176 head' USING ERRCODE='P1762';
    END IF;
    IF EXISTS (
        SELECT 1 FROM sites
        WHERE ipv6_enabled IS DISTINCT FROM true OR ipv6_runtime_state IS DISTINCT FROM 'active' OR
              ipv6_runtime_source_revision IS DISTINCT FROM 0
    ) THEN
        RAISE EXCEPTION 'migration 176 rollback would discard non-default IPv6 desired or runtime facts'
            USING ERRCODE='P1763';
    END IF;
END;
$migration_176_down$;

DROP TRIGGER site_ipv6_rollout_targets_no_truncate_176 ON site_ipv6_rollout_targets;
DROP TRIGGER site_ipv6_rollout_targets_immutable_176 ON site_ipv6_rollout_targets;
DROP INDEX site_ipv6_rollout_targets_site_idx;
DROP TABLE site_ipv6_rollout_targets;
DROP FUNCTION prevent_site_ipv6_rollout_target_mutation_176();

ALTER TABLE sites
    DROP COLUMN ipv6_runtime_source_revision,
    DROP COLUMN ipv6_runtime_state,
    DROP COLUMN ipv6_enabled;

ALTER TABLE config_versions
    DROP CONSTRAINT config_versions_id_scope_unique_176;
