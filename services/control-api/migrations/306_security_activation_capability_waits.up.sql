LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;

DO $migration_306_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 305 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 305 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=305 AND
        migration_id='305_identity_secondary_verification' AND
        checksum_sha256='cb591779e5c8b35acff239ac4a5dec44caaaff5e005169d0bfab6ac22184009d' AND
        down_checksum_sha256='ca8f58f22cf5f18c7b4b3607bb00a70c3d891906a3e0635d1e4d6517925220d3' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR checksum_sha256 IS NULL OR
        down_checksum_sha256 IS NULL OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR to_regclass(current_schema() || '.security_activation_capability_waits') IS NOT NULL THEN
        RAISE EXCEPTION 'migration 306 requires the exact verified 305 release head' USING ERRCODE='P3060';
    END IF;
END;
$migration_306_up$;

-- A security activation refused because target nodes predate a gated CC
-- capability (CC v4 counting keys, v3 proof of work) waits here; the
-- activation worker starts it again once every target node's latest session
-- declares the capability ("能力提升自动重新发布"). One waiting row per site
-- and policy kind: a newer refusal replaces it, any started activation of
-- the site and kind supersedes it.
CREATE TABLE security_activation_capability_waits (
    id uuid PRIMARY KEY,
    tenant_scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE CASCADE,
    site_id uuid NOT NULL,
    policy_id uuid NOT NULL,
    policy_kind text NOT NULL CHECK (policy_kind IN ('waf', 'cc', 'acl')),
    policy_version bigint NOT NULL CHECK (policy_version >= 1),
    expected_binding_revision bigint NOT NULL CHECK (expected_binding_revision >= 0),
    expected_active_policy_version bigint NOT NULL CHECK (expected_active_policy_version >= 0),
    target_node_ids uuid[] NOT NULL CHECK (cardinality(target_node_ids) BETWEEN 1 AND 10000),
    canary_size integer NOT NULL CHECK (canary_size >= 1 AND canary_size <= cardinality(target_node_ids)),
    compatible_challenge boolean NOT NULL DEFAULT false,
    actor_user_id uuid NOT NULL,
    actor_scope_id uuid NOT NULL,
    actor_scope_kind text NOT NULL CHECK (actor_scope_kind IN ('tenant', 'platform')),
    capability integer NOT NULL CHECK (capability > 0),
    required_api_version integer NOT NULL CHECK (required_api_version > 0),
    blocking_node_ids uuid[] NOT NULL CHECK (cardinality(blocking_node_ids) >= 1),
    status text NOT NULL DEFAULT 'waiting' CHECK (status IN ('waiting', 'resumed', 'superseded', 'failed')),
    resumed_candidate_id uuid,
    last_error text CHECK (last_error IS NULL OR length(last_error) <= 64),
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    CHECK ((status = 'resumed') = (resumed_candidate_id IS NOT NULL))
);
CREATE UNIQUE INDEX security_activation_capability_waits_waiting_306_idx
    ON security_activation_capability_waits(tenant_scope_id, site_id, policy_kind) WHERE status = 'waiting';
CREATE INDEX security_activation_capability_waits_poll_306_idx
    ON security_activation_capability_waits(updated_at, id) WHERE status = 'waiting';

REVOKE ALL ON security_activation_capability_waits FROM PUBLIC;
GRANT SELECT, INSERT, UPDATE ON security_activation_capability_waits TO cdnca_control_app, cdnca_control_runtime;
