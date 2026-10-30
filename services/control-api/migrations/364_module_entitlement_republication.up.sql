LOCK TABLE schema_migrations, edge_automatic_publication_requests, edge_system_republication_heads,
    edge_system_republication_attempts, edge_system_revision_segments IN ACCESS EXCLUSIVE MODE;

DO $migration_364_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 363 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 363 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=363 AND
        migration_id='363_rule_pack_protection' AND
        checksum_sha256='bcd1e0d6d738e783d8ed0690f8ffd9adb4f07674d888e56e06047cb1ba4482fd' AND
        down_checksum_sha256='b0491dacc3291c7dbc954dadbfdd366ab30a213133c5f6a7b5fe51290d74db3e' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR to_regclass(current_schema() || '.edge_module_publication_holds') IS NOT NULL OR
       to_regclass(current_schema() || '.edge_module_grant_marks') IS NOT NULL THEN
        RAISE EXCEPTION 'migration 364 requires the exact verified 363 release head' USING ERRCODE='P3640';
    END IF;
END;
$migration_364_up$;

-- r136 default-modules (placeholder number; renumbered on merge): a module,
-- pack or theme the lease stops granting leaves the scopes whose latest
-- publication uses it "pending republication" (ADR 0007 §4.3/§9: the control
-- plane never silently rewrites a site's rules); the page shows it. Granting
-- the module again republishes those scopes through the system channel
-- (trigger module_entitlement).
--
-- One row per (scope, module): the scope's latest publication
-- (source_revision) uses a module the lease no longer grants. The row is
-- deleted when the module is granted again (the scope is then republished)
-- or when the scope's next publication passes the module gate.
CREATE TABLE edge_module_publication_holds (
    scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE RESTRICT,
    module_code text NOT NULL CHECK (char_length(module_code) <= 128 AND
        module_code ~ '^(module|pack|theme)\.[a-z][a-z0-9_-]*(\.[a-z][a-z0-9_-]*)*$'),
    source_revision bigint NOT NULL CHECK (source_revision > 0),
    held_at timestamptz NOT NULL,
    PRIMARY KEY (scope_id, module_code)
);
CREATE INDEX edge_module_publication_holds_module_364_idx ON edge_module_publication_holds (module_code, scope_id);

-- The module codes the watcher last acted on (the verified lease's grant).
CREATE TABLE edge_module_grant_marks (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    module_codes text[] NOT NULL CHECK (cardinality(module_codes) <= 256),
    observed_at timestamptz NOT NULL
);

REVOKE ALL ON edge_module_publication_holds, edge_module_grant_marks FROM PUBLIC;
GRANT SELECT, INSERT, UPDATE, DELETE ON edge_module_publication_holds TO cdnca_control_app, cdnca_control_runtime;
GRANT SELECT, INSERT, UPDATE ON edge_module_grant_marks TO cdnca_control_app, cdnca_control_runtime;

-- Trigger module_entitlement: manual scopes through the system channel,
-- automatic scopes through their own policy (source_kind module_entitlement).
ALTER TABLE edge_system_republication_heads
    DROP CONSTRAINT edge_system_republication_heads_triggers_check,
    ADD CONSTRAINT edge_system_republication_heads_triggers_check CHECK (cardinality(triggers) BETWEEN 1 AND 9 AND
        triggers <@ ARRAY['node_capability', 'traffic_enforcement', 'line_group', 'node_sync', 'domain_ownership',
            'secondary_verification', 'rule_catalog', 'challenge_delivery', 'module_entitlement']::text[]);
ALTER TABLE edge_system_republication_attempts
    DROP CONSTRAINT edge_system_republication_attempts_triggers_check,
    ADD CONSTRAINT edge_system_republication_attempts_triggers_check CHECK (cardinality(triggers) BETWEEN 1 AND 9);
ALTER TABLE edge_system_revision_segments
    DROP CONSTRAINT edge_system_revision_segments_source_check,
    ADD CONSTRAINT edge_system_revision_segments_source_check CHECK (source IN ('node_capability', 'traffic_enforcement',
        'line_group', 'node_sync', 'domain_ownership', 'secondary_verification', 'rule_catalog', 'challenge_delivery',
        'module_entitlement'));

ALTER TABLE edge_automatic_publication_requests
    DROP CONSTRAINT edge_automatic_publication_requests_source_kind_check,
    DROP CONSTRAINT edge_automatic_publication_requests_operation_check,
    DROP CONSTRAINT edge_automatic_publication_requests_reason_check,
    DROP CONSTRAINT edge_automatic_publication_requests_check,
    DROP CONSTRAINT edge_automatic_publication_l4_intent_presence_092;

ALTER TABLE edge_automatic_publication_requests
    ADD CONSTRAINT edge_automatic_publication_requests_source_kind_check
        CHECK (source_kind IN ('site', 'l4', 'line_group', 'node_sync', 'node_capability', 'rule_catalog',
            'challenge_delivery', 'module_entitlement')),
    ADD CONSTRAINT edge_automatic_publication_requests_operation_check CHECK (operation IN (
        'site.create', 'site.update', 'site.origin.update', 'site.delete',
        'site.batch.enable', 'site.batch.disable', 'site.batch.delete',
        'stream.create', 'stream.update', 'stream.delete',
        'line_group.nodes_changed', 'node.sync_retry', 'node.capabilities_changed', 'security_rule_catalog.updated',
        'node.challenge_delivered', 'entitlement.modules_granted')),
    ADD CONSTRAINT edge_automatic_publication_requests_reason_check
        CHECK (reason IN ('resource_mutation', 'node_set_changed', 'sync_retry', 'capability_changed', 'catalog_changed',
            'challenge_delivered', 'entitlement_changed')),
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
         operation = 'node.challenge_delivered' AND source_resource_id IS NOT NULL) OR
        (source_kind = 'module_entitlement' AND permission_name = 'sites.manage' AND reason = 'entitlement_changed' AND
         operation = 'entitlement.modules_granted' AND source_resource_id IS NOT NULL)
    ),
    ADD CONSTRAINT edge_automatic_publication_l4_intent_presence_092 CHECK (
        (source_kind IN ('site', 'line_group', 'node_sync', 'node_capability', 'rule_catalog', 'challenge_delivery',
            'module_entitlement') AND publish_intent_id IS NULL) OR
        (source_kind = 'l4' AND publish_intent_id IS NOT NULL)
    );
