LOCK TABLE schema_migrations, edge_system_republication_heads, edge_system_republication_attempts,
    edge_system_revision_segments IN ACCESS EXCLUSIVE MODE;

DO $migration_383_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 382 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 382 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=382 AND
        migration_id='382_identity_session_regions' AND
        checksum_sha256='954763dd743b2b7876e9e2793a9cdec31ca796cc468906fb6e68f45ccae9b62f' AND
        down_checksum_sha256='4bc1a91c144927ae77b7f07cc57c7e416a2c44696ebe1e68a11082cb0ce51282' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR to_regclass(current_schema() || '.account_suspension_site_holds') IS NOT NULL THEN
        RAISE EXCEPTION 'migration 383 requires the exact verified 382 release head' USING ERRCODE='P3830';
    END IF;
END;
$migration_383_up$;

-- r136 ge-account (placeholder number 383, guard on the 382 head; renumbered
-- on merge): a disabled or deleted user, a suspended membership or a
-- suspended/closed tenant stops serving its sites (GoEdge comparison G8,
-- unverified item "disabled tenant's sites still delivered"). Before 383 the
-- edge publication filtered only site and package state, so a disabled
-- tenant kept serving. The worker disables each serving site of such an
-- owner, records a hold, and republishes the scope at once under the new
-- system trigger account_suspension; when the owner is active again it
-- re-enables only the sites it held (and only while they are still in the
-- state it left them in) and republishes again.
CREATE TABLE account_suspension_site_holds (
    site_id uuid NOT NULL REFERENCES sites(id) ON DELETE RESTRICT,
    held_at timestamptz NOT NULL CHECK (isfinite(held_at)),
    scope_id uuid NOT NULL,
    owner_user_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    reason text NOT NULL CHECK (reason IN ('user_disabled','membership_suspended','tenant_suspended')),
    released_at timestamptz CHECK (released_at IS NULL OR isfinite(released_at) AND released_at >= held_at),
    PRIMARY KEY (site_id, held_at)
);
CREATE UNIQUE INDEX account_suspension_site_holds_open_383_idx
    ON account_suspension_site_holds (site_id) WHERE released_at IS NULL;
CREATE INDEX account_suspension_site_holds_owner_383_idx
    ON account_suspension_site_holds (scope_id, owner_user_id) WHERE released_at IS NULL;

ALTER TABLE edge_system_republication_heads
    DROP CONSTRAINT edge_system_republication_heads_triggers_check,
    ADD CONSTRAINT edge_system_republication_heads_triggers_check CHECK (cardinality(triggers) BETWEEN 1 AND 11 AND
        triggers <@ ARRAY['node_capability', 'traffic_enforcement', 'line_group', 'node_sync', 'domain_ownership',
            'secondary_verification', 'rule_catalog', 'challenge_delivery', 'module_entitlement',
            'theme_activation', 'account_suspension']::text[]);
ALTER TABLE edge_system_republication_attempts
    DROP CONSTRAINT edge_system_republication_attempts_triggers_check,
    ADD CONSTRAINT edge_system_republication_attempts_triggers_check CHECK (cardinality(triggers) BETWEEN 1 AND 11);
ALTER TABLE edge_system_revision_segments
    DROP CONSTRAINT edge_system_revision_segments_source_check,
    ADD CONSTRAINT edge_system_revision_segments_source_check CHECK (source IN ('node_capability', 'traffic_enforcement',
        'line_group', 'node_sync', 'domain_ownership', 'secondary_verification', 'rule_catalog', 'challenge_delivery',
        'module_entitlement', 'account_suspension'));

REVOKE ALL ON account_suspension_site_holds FROM PUBLIC;
GRANT SELECT, INSERT, UPDATE ON account_suspension_site_holds TO cdnca_control_app, cdnca_control_runtime;
