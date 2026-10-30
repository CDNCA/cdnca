LOCK TABLE schema_migrations, edge_automatic_publication_requests, edge_system_republication_heads,
    edge_system_republication_attempts, edge_system_revision_segments IN ACCESS EXCLUSIVE MODE;

DO $migration_343_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 342 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 342 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=342 AND
        migration_id='342_acme_http01_cleanup_debt' AND
        checksum_sha256='7d99900ceb9f9955c3fef1589c16a0f0d427db3c40e2af207229d9b0a12d9520' AND
        down_checksum_sha256='36dae24e16005edbcf884290fe51558bb1ad99cc26f1c8aca3a02153fde4145b' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR checksum_sha256 IS NULL OR
        down_checksum_sha256 IS NULL OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR (SELECT count(*) FROM pg_constraint WHERE connamespace=current_schema()::regnamespace AND conname IN (
        'edge_system_republication_heads_triggers_check', 'edge_system_republication_attempts_triggers_check',
        'edge_system_revision_segments_source_check', 'edge_automatic_publication_requests_source_kind_check',
        'edge_automatic_publication_requests_operation_check', 'edge_automatic_publication_requests_reason_check',
        'edge_automatic_publication_requests_check', 'edge_automatic_publication_l4_intent_presence_092')) <> 8
       OR to_regclass(current_schema() || '.edge_challenge_redeliveries') IS NOT NULL THEN
        RAISE EXCEPTION 'migration 343 requires the exact verified 342 release head' USING ERRCODE='P3430';
    END IF;
END;
$migration_343_up$;

-- r136 challenge-redeliver: a node that joins a scope's targets, or comes
-- back online / out of isolation, without the JS challenge policy (and key)
-- a site of the scope is bound to gets it redelivered by the control plane.
-- One row per (scope, node, policy version): the redelivery's state, its
-- attempts (bounded, with backoff) and the secret rollout of the current
-- attempt. A confirmed delivery (the node's healthy receipt) republishes the
-- scope with trigger challenge_delivery. A row lives while the node needs the
-- policy (the redeliverer deletes it otherwise); the secret rollout and the
-- republication keep the audit trail.
CREATE TABLE edge_challenge_redeliveries (
    scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE RESTRICT,
    node_id uuid NOT NULL REFERENCES nodes(id) ON DELETE RESTRICT,
    policy_id uuid NOT NULL,
    policy_version bigint NOT NULL CHECK (policy_version > 0),
    site_id uuid NOT NULL,
    origin_config_version_id uuid NOT NULL,
    state text NOT NULL CHECK (state IN ('pending', 'delivering', 'delivered', 'failed')),
    attempt integer NOT NULL CHECK (attempt BETWEEN 0 AND 8),
    session_epoch bigint NOT NULL CHECK (session_epoch >= 0),
    due_at timestamptz NOT NULL,
    rollout_id uuid,
    deadline_at timestamptz,
    last_error text CHECK (last_error IS NULL OR char_length(last_error) BETWEEN 1 AND 256),
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    delivered_at timestamptz,
    PRIMARY KEY (scope_id, node_id, policy_id, policy_version),
    CONSTRAINT edge_challenge_redeliveries_state_343_check CHECK (
        (state = 'pending' AND rollout_id IS NULL AND deadline_at IS NULL AND delivered_at IS NULL) OR
        (state = 'delivering' AND rollout_id IS NOT NULL AND deadline_at IS NOT NULL AND attempt > 0 AND
         delivered_at IS NULL) OR
        (state = 'delivered' AND rollout_id IS NOT NULL AND delivered_at IS NOT NULL) OR
        (state = 'failed' AND last_error IS NOT NULL AND delivered_at IS NULL)
    )
);
CREATE INDEX edge_challenge_redeliveries_due_343_idx ON edge_challenge_redeliveries (due_at, scope_id, node_id)
    WHERE state = 'pending';
CREATE INDEX edge_challenge_redeliveries_delivering_343_idx ON edge_challenge_redeliveries (deadline_at, scope_id, node_id)
    WHERE state = 'delivering';
REVOKE ALL ON edge_challenge_redeliveries FROM PUBLIC;
GRANT SELECT, INSERT, UPDATE, DELETE ON edge_challenge_redeliveries TO cdnca_control_app, cdnca_control_runtime;

-- Trigger challenge_delivery: manual scopes through the system channel,
-- automatic scopes through their own policy (source_kind challenge_delivery,
-- the redelivered node as the source resource).
ALTER TABLE edge_system_republication_heads
    DROP CONSTRAINT edge_system_republication_heads_triggers_check,
    ADD CONSTRAINT edge_system_republication_heads_triggers_check CHECK (cardinality(triggers) BETWEEN 1 AND 8 AND
        triggers <@ ARRAY['node_capability', 'traffic_enforcement', 'line_group', 'node_sync', 'domain_ownership',
            'secondary_verification', 'rule_catalog', 'challenge_delivery']::text[]);
ALTER TABLE edge_system_republication_attempts
    DROP CONSTRAINT edge_system_republication_attempts_triggers_check,
    ADD CONSTRAINT edge_system_republication_attempts_triggers_check CHECK (cardinality(triggers) BETWEEN 1 AND 8);
ALTER TABLE edge_system_revision_segments
    DROP CONSTRAINT edge_system_revision_segments_source_check,
    ADD CONSTRAINT edge_system_revision_segments_source_check CHECK (source IN ('node_capability', 'traffic_enforcement',
        'line_group', 'node_sync', 'domain_ownership', 'secondary_verification', 'rule_catalog', 'challenge_delivery'));

ALTER TABLE edge_automatic_publication_requests
    DROP CONSTRAINT edge_automatic_publication_requests_source_kind_check,
    DROP CONSTRAINT edge_automatic_publication_requests_operation_check,
    DROP CONSTRAINT edge_automatic_publication_requests_reason_check,
    DROP CONSTRAINT edge_automatic_publication_requests_check,
    DROP CONSTRAINT edge_automatic_publication_l4_intent_presence_092;

ALTER TABLE edge_automatic_publication_requests
    ADD CONSTRAINT edge_automatic_publication_requests_source_kind_check
        CHECK (source_kind IN ('site', 'l4', 'line_group', 'node_sync', 'node_capability', 'rule_catalog',
            'challenge_delivery')),
    ADD CONSTRAINT edge_automatic_publication_requests_operation_check CHECK (operation IN (
        'site.create', 'site.update', 'site.origin.update', 'site.delete',
        'site.batch.enable', 'site.batch.disable', 'site.batch.delete',
        'stream.create', 'stream.update', 'stream.delete',
        'line_group.nodes_changed', 'node.sync_retry', 'node.capabilities_changed', 'security_rule_catalog.updated',
        'node.challenge_delivered')),
    ADD CONSTRAINT edge_automatic_publication_requests_reason_check
        CHECK (reason IN ('resource_mutation', 'node_set_changed', 'sync_retry', 'capability_changed', 'catalog_changed',
            'challenge_delivered')),
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
         operation = 'node.capabilities_changed' AND source_resource_id IS NOT NULL) OR
        (source_kind = 'rule_catalog' AND permission_name = 'sites.manage' AND reason = 'catalog_changed' AND
         operation = 'security_rule_catalog.updated' AND source_resource_id IS NOT NULL) OR
        (source_kind = 'challenge_delivery' AND permission_name = 'sites.manage' AND reason = 'challenge_delivered' AND
         operation = 'node.challenge_delivered' AND source_resource_id IS NOT NULL)
    ),
    ADD CONSTRAINT edge_automatic_publication_l4_intent_presence_092 CHECK (
        (source_kind IN ('site', 'line_group', 'node_sync', 'node_capability', 'rule_catalog', 'challenge_delivery') AND
         publish_intent_id IS NULL) OR
        (source_kind = 'l4' AND publish_intent_id IS NOT NULL)
    );
