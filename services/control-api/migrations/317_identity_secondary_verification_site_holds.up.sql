LOCK TABLE schema_migrations, sites, identity_user_secondary_verification IN ACCESS EXCLUSIVE MODE;

DO $migration_317_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 316 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 316 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=316 AND
        migration_id='316_l4_toa' AND
        checksum_sha256='18e4b00b627ff5367dfcfbcff59af5b8dae21dbcd26820eaa53c94c103bc87e3' AND
        down_checksum_sha256='3afc4e8e5fdee2bc7953d7659e1df6526adfcb4e1645184dc691600298123ec0' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR to_regclass(current_schema() || '.identity_secondary_verification_site_holds') IS NOT NULL THEN
        RAISE EXCEPTION 'migration 317 requires the exact verified 316 release head' USING ERRCODE='P3170';
    END IF;
END;
$migration_317_up$;

-- FX57: an overdue secondary verification stops the user's sites. A hold row
-- records exactly what the control plane changed on one site (disabled it,
-- locked it, or both), so releasing it after the reverification restores only
-- that change and leaves sites stopped or locked for other reasons untouched.
CREATE TABLE identity_secondary_verification_site_holds (
    site_id uuid NOT NULL REFERENCES sites(id) ON DELETE RESTRICT,
    held_at timestamptz NOT NULL CHECK (isfinite(held_at)),
    scope_id uuid NOT NULL,
    user_id uuid NOT NULL,
    request_revision bigint NOT NULL CHECK (request_revision > 0),
    disabled_site boolean NOT NULL,
    locked_site boolean NOT NULL,
    released_at timestamptz CHECK (released_at IS NULL OR isfinite(released_at) AND released_at >= held_at),
    PRIMARY KEY (site_id, held_at),
    FOREIGN KEY (scope_id,user_id) REFERENCES identity_user_secondary_verification(scope_id,user_id) ON DELETE RESTRICT,
    CHECK (disabled_site OR locked_site)
);

CREATE UNIQUE INDEX identity_secondary_verification_site_holds_open_317_idx
    ON identity_secondary_verification_site_holds (site_id) WHERE released_at IS NULL;
CREATE INDEX identity_secondary_verification_site_holds_request_317_idx
    ON identity_secondary_verification_site_holds (scope_id, user_id) WHERE released_at IS NULL;

REVOKE ALL ON identity_secondary_verification_site_holds FROM PUBLIC;
GRANT SELECT, INSERT, UPDATE ON identity_secondary_verification_site_holds TO cdnca_control_app, cdnca_control_runtime;
