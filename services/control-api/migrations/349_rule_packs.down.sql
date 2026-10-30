LOCK TABLE schema_migrations, rule_packs, site_security_mounts IN ACCESS EXCLUSIVE MODE;

DO $migration_349_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 349 OR
       (SELECT max(version) FROM schema_migrations) <> 349 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=349 AND
        migration_id='349_rule_packs' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 349 down requires the exact verified migration head' USING ERRCODE='P3491';
    END IF;
    -- Published site mounts may already be in site objects on nodes; the
    -- operator disables the packs and republishes the sites first.
    IF EXISTS (SELECT 1 FROM site_security_mounts) OR EXISTS (SELECT 1 FROM rule_packs) THEN
        RAISE EXCEPTION 'migration 349 rollback would discard rule packs or published site mounts' USING ERRCODE='P3491';
    END IF;
END;
$migration_349_down$;

DROP TABLE rule_pack_site_mount_artifacts;
DROP TABLE site_security_mounts;
DROP TABLE rule_pack_enablements;
ALTER TABLE rule_packs DROP CONSTRAINT rule_packs_current_version_349;
DROP TABLE rule_pack_artifacts;
DROP TABLE rule_packs;
