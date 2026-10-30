LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;

DO $migration_381_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 380 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 380 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=380 AND
        migration_id='380_identity_login_throttle' AND
        checksum_sha256='fa85be1e51b1875460ace14fa67c04708bbdb93e1303293093e2d720a22a0bbb' AND
        down_checksum_sha256='b831845b02649a0fbda537fd44526bf2369611fcbfdc3e83e60a6cff7b8f19f8' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR to_regclass(current_schema() || '.platform_admin_access_policy') IS NOT NULL THEN
        RAISE EXCEPTION 'migration 381 requires the exact verified 380 release head' USING ERRCODE='P3810';
    END IF;
END;
$migration_381_up$;

-- r136 ge-account (placeholder number 381, guard on the 380 head; renumbered
-- on merge): platform administration access allowlist (GoEdge comparison G8,
-- missing item 4). When enabled, platform-scope sign-in, refresh and every
-- platform-scope session request must come from one of the addresses or
-- CIDR prefixes; loopback is always allowed. Saving requires the saving
-- administrator's own address to stay allowed; the root-local CLI
-- `control-api admin-access-allowlist disable` is the recovery path.
CREATE TABLE platform_admin_access_policy (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    revision bigint NOT NULL CHECK (revision > 0),
    enabled boolean NOT NULL,
    allowlist text[] NOT NULL CHECK (cardinality(allowlist) <= 64 AND array_position(allowlist, NULL) IS NULL),
    updated_by_user_id uuid REFERENCES users(id) ON DELETE SET NULL,
    updated_at timestamptz NOT NULL CHECK (isfinite(updated_at)),
    CHECK (NOT enabled OR cardinality(allowlist) > 0)
);

REVOKE ALL ON platform_admin_access_policy FROM PUBLIC;
GRANT SELECT, INSERT, UPDATE ON platform_admin_access_policy TO cdnca_control_app;
