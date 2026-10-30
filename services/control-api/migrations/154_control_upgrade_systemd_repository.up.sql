LOCK TABLE schema_migrations,control_installation_entitlement IN ACCESS EXCLUSIVE MODE;

DO $migration_154$
BEGIN
    IF (SELECT count(*) FROM schema_migrations)<>153 OR
       (SELECT min(version) FROM schema_migrations)<>1 OR
       (SELECT max(version) FROM schema_migrations)<>153 OR EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE migration_id IS NULL OR migration_id='' OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
              down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR integrity_state IS DISTINCT FROM 'verified' OR
              metadata_recorded_at IS NULL OR applied_at IS NULL
    ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version=153 AND migration_id='153_node_revocation_checkpoint' AND
              checksum_sha256='625a59e7f6be7ebe73877550e87ac230f7fb118aeb8e69243553fe16574d1fbf' AND
              down_checksum_sha256='837e31ebeb2aa9cb3cf11e3bf58666f50b01fa7eefa29e5cfd8e80a05ec2c87b' AND
              integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
    ) OR to_regclass('control_upgrade_systemd_repository_154') IS NOT NULL OR
         to_regprocedure('guard_control_upgrade_systemd_repository_154()') IS NOT NULL OR
         to_regprocedure('prevent_control_upgrade_systemd_repository_truncate_154()') IS NOT NULL THEN
        RAISE EXCEPTION 'migration 154 requires the exact verified 153 release head'
            USING ERRCODE='P1540';
    END IF;
END;
$migration_154$;

CREATE TABLE control_upgrade_systemd_repository_154 (
    installation_id text NOT NULL REFERENCES control_installation_entitlement(installation_id) ON DELETE RESTRICT,
    operation text NOT NULL CHECK(operation='control-upgrade'),
    revision bigint NOT NULL CHECK(revision>0),
    plan_id text NOT NULL CHECK(plan_id ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'),
    publication_revision bigint NOT NULL CHECK(publication_revision>0),
    bundle_bytes bytea NOT NULL CHECK(octet_length(bundle_bytes) BETWEEN 1 AND 1048576),
    bundle_sha256 bytea NOT NULL CHECK(octet_length(bundle_sha256)=32),
    snapshot_bytes bytea NOT NULL CHECK(octet_length(snapshot_bytes) BETWEEN 1 AND 2097152),
    snapshot_sha256 bytea NOT NULL CHECK(octet_length(snapshot_sha256)=32),
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp() CHECK(isfinite(created_at)),
    updated_at timestamptz NOT NULL DEFAULT transaction_timestamp() CHECK(isfinite(updated_at)),
    PRIMARY KEY(installation_id,operation),
    CHECK(snapshot_sha256=sha256(snapshot_bytes)),
    CHECK(bundle_sha256=sha256(bundle_bytes))
);

CREATE FUNCTION guard_control_upgrade_systemd_repository_154()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP='DELETE' THEN
        RAISE EXCEPTION 'control upgrade systemd repository cannot be deleted or truncated'
            USING ERRCODE='P1541';
    END IF;
    IF TG_OP='INSERT' AND NEW.revision<>1 THEN
        RAISE EXCEPTION 'control upgrade systemd repository must begin at revision one'
            USING ERRCODE='P1541';
    END IF;
    IF TG_OP='UPDATE' AND (
        NEW.revision<>OLD.revision+1 OR
        NEW.installation_id IS DISTINCT FROM OLD.installation_id OR
        NEW.operation IS DISTINCT FROM OLD.operation OR
        NEW.publication_revision<OLD.publication_revision
    ) THEN
        RAISE EXCEPTION 'control upgrade systemd repository binding or revision is invalid'
            USING ERRCODE='P1541';
    END IF;
    IF TG_OP='UPDATE' AND NEW.publication_revision<>OLD.publication_revision AND
       NEW.bundle_sha256=OLD.bundle_sha256 THEN
        RAISE EXCEPTION 'control upgrade publication revision cannot change without a new bundle'
            USING ERRCODE='P1541';
    END IF;
    IF TG_OP='UPDATE' AND NEW.publication_revision=OLD.publication_revision AND (
        NEW.plan_id IS DISTINCT FROM OLD.plan_id OR NEW.bundle_sha256 IS DISTINCT FROM OLD.bundle_sha256
    ) THEN
        RAISE EXCEPTION 'control upgrade publication binding cannot change at the same revision'
            USING ERRCODE='P1541';
    END IF;
    NEW.updated_at:=transaction_timestamp();
    RETURN NEW;
END;
$$;

CREATE FUNCTION prevent_control_upgrade_systemd_repository_truncate_154()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'control upgrade systemd repository cannot be deleted or truncated'
        USING ERRCODE='P1541';
END;
$$;

CREATE TRIGGER control_upgrade_systemd_repository_guard_154
BEFORE INSERT OR UPDATE OR DELETE ON control_upgrade_systemd_repository_154
FOR EACH ROW EXECUTE FUNCTION guard_control_upgrade_systemd_repository_154();

CREATE TRIGGER control_upgrade_systemd_repository_truncate_154
BEFORE TRUNCATE ON control_upgrade_systemd_repository_154
FOR EACH STATEMENT EXECUTE FUNCTION prevent_control_upgrade_systemd_repository_truncate_154();

REVOKE ALL ON control_upgrade_systemd_repository_154 FROM PUBLIC;
REVOKE ALL ON FUNCTION guard_control_upgrade_systemd_repository_154() FROM PUBLIC;
REVOKE ALL ON FUNCTION prevent_control_upgrade_systemd_repository_truncate_154() FROM PUBLIC;
