LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;
LOCK TABLE sites, edge_configuration_scopes IN SHARE ROW EXCLUSIVE MODE;

DO $migration_335_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 334 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 334 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=334 AND
        migration_id='334_l4_port_range' AND
        checksum_sha256='8797397e3bb1dfcaebf69422f8ac5dbce8a8e86ccfcabc27f937096c8c5dcbaa' AND
        down_checksum_sha256='a9ff06178c9f888ccd237f73769851bd68bc1ba0e97d1cc1c107216df2965303' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR checksum_sha256 IS NULL OR
        down_checksum_sha256 IS NULL OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR NOT EXISTS (
        SELECT 1 FROM pg_trigger WHERE tgrelid='sites'::regclass AND
        tgname='sites_bump_edge_configuration_revision' AND
        tgfoid='bump_edge_configuration_scope_revision()'::regprocedure AND NOT tgisinternal
       ) OR to_regprocedure('bump_edge_configuration_site_revision_335()') IS NOT NULL THEN
        RAISE EXCEPTION 'migration 335 requires the exact verified 334 release head and 021''s sites revision trigger'
            USING ERRCODE='P3350';
    END IF;
END;
$migration_335_up$;

-- r136: ipv6_runtime_state / ipv6_runtime_source_revision are what the nodes
-- reported (edgedeployment/site_ipv6_projection.go writes them, and
-- updated_at, when a rollout ends); no compiler reads them (edgepublish
-- loadSiteFacts reads the desired ipv6_enabled only). Advancing the scope's
-- source_revision for them invalidated configuration candidates for nothing:
-- a security activation could never promote (store.go CAS source_revision =
-- candidate - 1). An update that changes nothing but these columns no longer
-- advances it; insert, delete and any other column change still do.
CREATE FUNCTION bump_edge_configuration_site_revision_335()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'UPDATE' AND
       to_jsonb(NEW) - ARRAY['ipv6_runtime_state','ipv6_runtime_source_revision','updated_at'] =
       to_jsonb(OLD) - ARRAY['ipv6_runtime_state','ipv6_runtime_source_revision','updated_at'] THEN
        RETURN NULL;
    END IF;
    PERFORM advance_edge_configuration_scope_revision(
        CASE WHEN TG_OP = 'DELETE' THEN OLD.scope_id ELSE NEW.scope_id END
    );
    RETURN NULL;
END;
$$;

DROP TRIGGER sites_bump_edge_configuration_revision ON sites;
CREATE TRIGGER sites_bump_edge_configuration_revision
AFTER INSERT OR UPDATE OR DELETE ON sites
FOR EACH ROW EXECUTE FUNCTION bump_edge_configuration_site_revision_335();
