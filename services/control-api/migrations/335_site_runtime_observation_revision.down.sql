LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;
LOCK TABLE sites, edge_configuration_scopes IN SHARE ROW EXCLUSIVE MODE;

DO $migration_335_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 335 OR
       (SELECT max(version) FROM schema_migrations) <> 335 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=335 AND
        migration_id='335_site_runtime_observation_revision' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 335 down requires the exact verified migration head' USING ERRCODE='P3351';
    END IF;
END;
$migration_335_down$;

DROP TRIGGER sites_bump_edge_configuration_revision ON sites;
CREATE TRIGGER sites_bump_edge_configuration_revision
AFTER INSERT OR UPDATE OR DELETE ON sites
FOR EACH ROW EXECUTE FUNCTION bump_edge_configuration_scope_revision();

DROP FUNCTION bump_edge_configuration_site_revision_335();
