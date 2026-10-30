LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;

DO $migration_417_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 416 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 416 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=416 AND
        migration_id='416_site_facts_republication' AND
        checksum_sha256='c5a3dcbacd0c13c1f2ac83e987e67c31bb97138d284f2cf625a370147165cb9c' AND
        down_checksum_sha256='e5a9f277dc0be1e0b9531665eb5855c80ef15b3b9154ee6a23a3f34260ceab51' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR to_regclass(current_schema() || '.rule_pack_mount_suspensions') IS NOT NULL THEN
        RAISE EXCEPTION 'migration 417 requires the exact verified 416 release head' USING ERRCODE='P4170';
    END IF;
END;
$migration_417_up$;

-- 417（r136 pack-suspend，占位 = 集成头 416 + 1，合入时改号）。A site's
-- published rule pack mount that the site's new CRS profile no longer covers
-- is suspended in the same transaction as the profile change (主会话 10-20):
-- it leaves site_security_mounts.security (so the profile takes effect with
-- the automatic publication) and is kept here, mount exactly as published,
-- until the profile covers it again (restored in the same transaction) or
-- the site publishes its mounts without it. The artifact cannot be deleted
-- while a suspension refers to it.
--   reason: out_of_profile (the only one for now);
--   crs_profile: the profile it was suspended under ('' = no managed WAF).
CREATE TABLE rule_pack_mount_suspensions (
    site_id uuid NOT NULL REFERENCES site_security_mounts(site_id) ON DELETE CASCADE,
    pack_id text NOT NULL,
    version text NOT NULL,
    sha256 text NOT NULL CHECK (sha256 ~ '^[0-9a-f]{64}$'),
    mount jsonb NOT NULL CHECK (jsonb_typeof(mount) = 'object'),
    reason text NOT NULL CHECK (reason IN ('out_of_profile')),
    crs_profile text NOT NULL CHECK (length(crs_profile) <= 160),
    detail text NOT NULL CHECK (length(detail) <= 1000),
    suspended_by_user_id uuid NOT NULL REFERENCES users(id),
    suspended_at timestamptz NOT NULL CHECK (isfinite(suspended_at)),
    PRIMARY KEY (site_id, pack_id),
    FOREIGN KEY (pack_id, version) REFERENCES rule_pack_artifacts(pack_id, version) ON DELETE RESTRICT
);
CREATE INDEX rule_pack_mount_suspensions_artifact_417 ON rule_pack_mount_suspensions (pack_id, version);

REVOKE ALL ON rule_pack_mount_suspensions FROM PUBLIC;
GRANT SELECT, INSERT, UPDATE, DELETE ON rule_pack_mount_suspensions TO cdnca_control_app;
GRANT SELECT ON rule_pack_mount_suspensions TO cdnca_control_runtime;
