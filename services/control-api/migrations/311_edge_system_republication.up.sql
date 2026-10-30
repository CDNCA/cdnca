LOCK TABLE schema_migrations, edge_automatic_publication_requests IN ACCESS EXCLUSIVE MODE;

DO $migration_311_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 310 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 310 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=310 AND
        migration_id='310_notification_native_sms' AND
        checksum_sha256='806aed64663a810fb3040f78582215f1a58baca11ddf7f5698617f4bf3cdae9c' AND
        down_checksum_sha256='5fe79fcecbdc45214ec6931c86778f6a5ca55f88e7f2b0db004bea6652d9e512' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR checksum_sha256 IS NULL OR
        down_checksum_sha256 IS NULL OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) THEN
        RAISE EXCEPTION 'migration 311 requires the exact verified 310 release head' USING ERRCODE='P3110';
    END IF;
END;
$migration_311_up$;

-- An automatic scope whose node gained a capability republishes through its
-- own policy (source_kind node_capability).
ALTER TABLE edge_automatic_publication_requests
    DROP CONSTRAINT edge_automatic_publication_requests_source_kind_check,
    DROP CONSTRAINT edge_automatic_publication_requests_operation_check,
    DROP CONSTRAINT edge_automatic_publication_requests_reason_check,
    DROP CONSTRAINT edge_automatic_publication_requests_check,
    DROP CONSTRAINT edge_automatic_publication_l4_intent_presence_092;

ALTER TABLE edge_automatic_publication_requests
    ADD CONSTRAINT edge_automatic_publication_requests_source_kind_check
        CHECK (source_kind IN ('site', 'l4', 'line_group', 'node_sync', 'node_capability')),
    ADD CONSTRAINT edge_automatic_publication_requests_operation_check CHECK (operation IN (
        'site.create', 'site.update', 'site.origin.update', 'site.delete',
        'site.batch.enable', 'site.batch.disable', 'site.batch.delete',
        'stream.create', 'stream.update', 'stream.delete',
        'line_group.nodes_changed', 'node.sync_retry', 'node.capabilities_changed')),
    ADD CONSTRAINT edge_automatic_publication_requests_reason_check
        CHECK (reason IN ('resource_mutation', 'node_set_changed', 'sync_retry', 'capability_changed')),
    ADD CONSTRAINT edge_automatic_publication_requests_check CHECK (
        (source_kind = 'site' AND permission_name = 'sites.manage' AND reason = 'resource_mutation' AND (
            operation IN ('site.batch.enable', 'site.batch.disable', 'site.batch.delete') AND source_resource_id IS NULL OR
            operation IN ('site.create', 'site.update', 'site.origin.update', 'site.delete') AND source_resource_id IS NOT NULL
        )) OR
        (source_kind = 'l4' AND permission_name = 'streams.manage' AND reason = 'resource_mutation' AND
         operation IN ('stream.create', 'stream.update', 'stream.delete') AND source_resource_id IS NOT NULL) OR
        (source_kind = 'line_group' AND permission_name = 'sites.manage' AND reason = 'node_set_changed' AND
         operation = 'line_group.nodes_changed' AND source_resource_id IS NOT NULL) OR
        (source_kind = 'node_sync' AND permission_name = 'sites.manage' AND reason = 'sync_retry' AND
         operation = 'node.sync_retry' AND source_resource_id IS NOT NULL) OR
        (source_kind = 'node_capability' AND permission_name = 'sites.manage' AND reason = 'capability_changed' AND
         operation = 'node.capabilities_changed' AND source_resource_id IS NOT NULL)
    ),
    ADD CONSTRAINT edge_automatic_publication_l4_intent_presence_092 CHECK (
        (source_kind IN ('site', 'line_group', 'node_sync', 'node_capability') AND publish_intent_id IS NULL) OR
        (source_kind = 'l4' AND publish_intent_id IS NOT NULL)
    );

-- System republication: one debounced head per tenant scope. It republishes
-- only what the scope last published (or last asked to publish and was refused
-- for node capability), never a tenant edit made since.
CREATE TABLE edge_system_republication_heads (
    scope_id uuid PRIMARY KEY REFERENCES access_scopes(id) ON DELETE RESTRICT,
    generation bigint NOT NULL CHECK (generation > 0),
    state text NOT NULL CHECK (state IN ('pending', 'leased', 'idle')),
    triggers text[] NOT NULL CHECK (cardinality(triggers) BETWEEN 1 AND 5 AND
        triggers <@ ARRAY['node_capability', 'traffic_enforcement', 'line_group', 'node_sync', 'domain_ownership']::text[]),
    due_at timestamptz NOT NULL,
    attempt integer NOT NULL CHECK (attempt BETWEEN 0 AND 8),
    lease_owner text CHECK (lease_owner IS NULL OR char_length(lease_owner) BETWEEN 1 AND 128),
    lease_token uuid,
    lease_expires_at timestamptz,
    claimed_generation bigint CHECK (claimed_generation IS NULL OR claimed_generation BETWEEN 1 AND generation),
    excluded_node_ids uuid[] NOT NULL DEFAULT '{}' CHECK (cardinality(excluded_node_ids) <= 10000),
    last_outcome text CHECK (last_outcome IS NULL OR last_outcome IN (
        'published', 'unchanged', 'blocked_unpublished_changes', 'no_baseline', 'no_capable_target',
        'automatic_scope', 'retry', 'failed')),
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    CHECK ((state = 'leased') = (lease_owner IS NOT NULL AND lease_token IS NOT NULL AND
        lease_expires_at IS NOT NULL AND claimed_generation IS NOT NULL))
);

CREATE INDEX edge_system_republication_heads_due_idx
    ON edge_system_republication_heads (due_at, scope_id) WHERE state IN ('pending', 'leased');
CREATE INDEX edge_system_republication_heads_excluded_idx
    ON edge_system_republication_heads USING gin (excluded_node_ids);

-- Each attempt's result, with the nodes refused for capability (the
-- publication record's "rejected nodes" list).
CREATE TABLE edge_system_republication_attempts (
    id uuid PRIMARY KEY,
    scope_id uuid NOT NULL REFERENCES edge_system_republication_heads(scope_id) ON DELETE RESTRICT,
    generation bigint NOT NULL CHECK (generation > 0),
    attempt integer NOT NULL CHECK (attempt BETWEEN 1 AND 8),
    triggers text[] NOT NULL CHECK (cardinality(triggers) BETWEEN 1 AND 5),
    outcome text NOT NULL CHECK (outcome IN (
        'published', 'unchanged', 'blocked_unpublished_changes', 'no_baseline', 'no_capable_target',
        'automatic_scope', 'retry', 'failed')),
    baseline_source_revision bigint CHECK (baseline_source_revision IS NULL OR baseline_source_revision > 0),
    source_revision bigint CHECK (source_revision IS NULL OR source_revision > 0),
    publication_id uuid REFERENCES edge_config_publications(id) ON DELETE RESTRICT,
    node_ids uuid[] NOT NULL DEFAULT '{}' CHECK (cardinality(node_ids) <= 10000),
    refused_nodes jsonb NOT NULL DEFAULT '[]'::jsonb CHECK (jsonb_typeof(refused_nodes) = 'array'),
    error_class text CHECK (error_class IS NULL OR char_length(error_class) BETWEEN 1 AND 256),
    occurred_at timestamptz NOT NULL,
    CHECK ((outcome = 'published') = (publication_id IS NOT NULL))
);

CREATE INDEX edge_system_republication_attempts_scope_idx
    ON edge_system_republication_attempts (scope_id, occurred_at DESC, id DESC);

-- Source revision advances made by a system writer (traffic enforcement, line
-- group node set, sync retry, domain ownership claim, system republication). A scope is clean when
-- these segments chain from its baseline revision to its current revision;
-- any other advance is a tenant edit that has not been published.
CREATE TABLE edge_system_revision_segments (
    scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE RESTRICT,
    from_revision bigint NOT NULL CHECK (from_revision > 0),
    to_revision bigint NOT NULL,
    source text NOT NULL CHECK (source IN ('node_capability', 'traffic_enforcement', 'line_group', 'node_sync',
        'domain_ownership')),
    recorded_at timestamptz NOT NULL,
    PRIMARY KEY (scope_id, from_revision),
    CHECK (to_revision > from_revision)
);

-- A publication the tenant (or its automatic policy) asked for and the
-- control plane refused because a target node lacked a gated capability. It
-- is the scope's baseline while it is newer than the last publication; its
-- actor stays accountable for the system republication that delivers it.
CREATE TABLE edge_capability_publication_holds (
    scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE RESTRICT,
    source_revision bigint NOT NULL CHECK (source_revision > 0),
    actor_user_id uuid NOT NULL,
    actor_scope_id uuid NOT NULL,
    requested_node_ids uuid[] NOT NULL CHECK (cardinality(requested_node_ids) BETWEEN 1 AND 10000),
    refused_node_ids uuid[] NOT NULL CHECK (cardinality(refused_node_ids) BETWEEN 1 AND 10000),
    refused_at timestamptz NOT NULL,
    PRIMARY KEY (scope_id, source_revision),
    FOREIGN KEY (actor_scope_id, actor_user_id) REFERENCES memberships(scope_id, user_id) ON DELETE RESTRICT
);

CREATE INDEX edge_capability_publication_holds_refused_idx
    ON edge_capability_publication_holds USING gin (refused_node_ids);

-- The capability set the watcher last acted on per node.
CREATE TABLE edge_node_capability_marks (
    node_id uuid PRIMARY KEY REFERENCES nodes(id) ON DELETE CASCADE,
    session_epoch bigint NOT NULL CHECK (session_epoch > 0),
    capabilities_sha256 bytea NOT NULL CHECK (octet_length(capabilities_sha256) = 32),
    observed_at timestamptz NOT NULL
);

REVOKE ALL ON edge_system_republication_heads, edge_system_republication_attempts,
    edge_system_revision_segments, edge_capability_publication_holds, edge_node_capability_marks FROM PUBLIC;
GRANT SELECT, INSERT, UPDATE ON edge_system_republication_heads TO cdnca_control_app, cdnca_control_runtime;
GRANT SELECT, INSERT ON edge_system_republication_attempts TO cdnca_control_app, cdnca_control_runtime;
GRANT SELECT, INSERT ON edge_system_revision_segments TO cdnca_control_app, cdnca_control_runtime;
GRANT SELECT, INSERT, UPDATE ON edge_capability_publication_holds TO cdnca_control_app, cdnca_control_runtime;
GRANT SELECT, INSERT, UPDATE ON edge_node_capability_marks TO cdnca_control_app, cdnca_control_runtime;
