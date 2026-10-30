LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;

DO $migration_382_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 381 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 381 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=381 AND
        migration_id='381_platform_admin_access_policy' AND
        checksum_sha256='74a45f990ac91fdd3b7b250dc52b2a0fc51afb1e61666cb5ba99d30553cf7949' AND
        down_checksum_sha256='812b0c1d762bb61c46284d719c14a81fc46100321fe7a864565f894d6ff73cf9' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR to_regclass(current_schema() || '.identity_session_regions') IS NOT NULL THEN
        RAISE EXCEPTION 'migration 382 requires the exact verified 381 release head' USING ERRCODE='P3820';
    END IF;
END;
$migration_382_up$;

-- r136 ge-account (placeholder number 382, guard on the 381 head; renumbered
-- on merge): session region binding (GoEdge comparison G8, missing item 3).
-- One row per sign-in session family: the region (country, or country and
-- province from the IP intelligence library) the family was last verified
-- in. A request from another region is refused with session_region_changed
-- until the user re-enters the password; challenged_region remembers the
-- region already announced so the challenge is audited once.
CREATE TABLE identity_session_regions (
    family_id uuid PRIMARY KEY,
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    region text NOT NULL CHECK (char_length(region) BETWEEN 2 AND 32),
    source_ip text NOT NULL CHECK (char_length(source_ip) <= 45),
    challenged_region text CHECK (challenged_region IS NULL OR char_length(challenged_region) BETWEEN 2 AND 32),
    updated_at timestamptz NOT NULL CHECK (isfinite(updated_at))
);
CREATE INDEX identity_session_regions_user_382_idx ON identity_session_regions (user_id);

REVOKE ALL ON identity_session_regions FROM PUBLIC;
GRANT SELECT, INSERT, UPDATE, DELETE ON identity_session_regions TO cdnca_control_app;
