LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;

DO $migration_295_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 294 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 294 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=294 AND
        migration_id='294_drop_runtime_patch_policy' AND
        checksum_sha256='437c67e61f9d74a93e7f4c1523c685d029cd4882fa49e8dc965b5d842afda106' AND
        down_checksum_sha256='f87374d506b5f14723289d5b48d081bae8dfd6182504fa717f6e8c3b63482bf0' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR checksum_sha256 IS NULL OR
        down_checksum_sha256 IS NULL OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR to_regclass(current_schema() || '.config_version_telemetry_site_bindings') IS NOT NULL THEN
        RAISE EXCEPTION 'migration 295 requires the exact verified 294 release head' USING ERRCODE='P2950';
    END IF;
END;
$migration_295_up$;

-- A site runtime v2 release carries its telemetry identity (each site's
-- package subscription) only inside the node-encrypted bundle, so node
-- authorization cannot read it from the config version. The publication
-- records it here, in the same transaction and from the same facts: one row
-- per site of the version, the subscription NULL when the site has none.
-- Config-source v1 versions carry it in their canonical snapshot and have no
-- rows. Rows never change.
CREATE TABLE config_version_telemetry_site_bindings (
    config_version_id uuid NOT NULL REFERENCES config_versions(id) ON DELETE RESTRICT,
    site_id uuid NOT NULL CHECK (site_id <> '00000000-0000-0000-0000-000000000000'::uuid),
    package_subscription_id uuid
        CHECK (package_subscription_id IS DISTINCT FROM '00000000-0000-0000-0000-000000000000'::uuid),
    PRIMARY KEY (config_version_id, site_id)
);

CREATE FUNCTION protect_config_version_telemetry_site_bindings_295() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'config version telemetry site bindings are immutable' USING ERRCODE='P2951';
END;
$$;
CREATE TRIGGER config_version_telemetry_site_bindings_295_immutable
BEFORE UPDATE OR DELETE ON config_version_telemetry_site_bindings
FOR EACH ROW EXECUTE FUNCTION protect_config_version_telemetry_site_bindings_295();
CREATE TRIGGER config_version_telemetry_site_bindings_295_no_truncate
BEFORE TRUNCATE ON config_version_telemetry_site_bindings
FOR EACH STATEMENT EXECUTE FUNCTION protect_config_version_telemetry_site_bindings_295();

REVOKE ALL ON config_version_telemetry_site_bindings FROM PUBLIC;
REVOKE ALL ON FUNCTION protect_config_version_telemetry_site_bindings_295() FROM PUBLIC;
DO $$ BEGIN
    IF EXISTS(SELECT 1 FROM pg_roles WHERE rolname='cdnca_control_app') THEN
        GRANT SELECT,INSERT ON config_version_telemetry_site_bindings TO cdnca_control_app;
    END IF;
END $$;
