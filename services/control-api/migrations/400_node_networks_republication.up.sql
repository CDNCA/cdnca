LOCK TABLE schema_migrations, edge_automatic_publication_requests, edge_system_republication_heads,
    edge_system_republication_attempts, edge_system_revision_segments IN ACCESS EXCLUSIVE MODE;

DO $migration_400_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 399 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 399 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=399 AND
        migration_id='399_security_activation_v2_root' AND
        checksum_sha256='10ed624dec56751600ff30cc869a5c2215845bb6b3e6770a7e8165e4a9d37b7e' AND
        down_checksum_sha256='a8885fa8fb4679ce1dd62dfc0a414d48d6c64a0620471dda00f8e32b2fb9399f' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR to_regclass(current_schema() || '.edge_node_network_marks') IS NOT NULL THEN
        RAISE EXCEPTION 'migration 400 requires the exact verified 399 release head' USING ERRCODE='P4000';
    END IF;
END;
$migration_400_up$;

-- 400 (r136 f3-node-networks, placeholder number: integration head 397 + 1,
-- renumbered on merge). A new node, a changed IPv4/IPv6 or a secondary IP
-- added or removed changes system.ddos.node_networks (the node to node DDoS
-- exemption) of every publication compiled afterwards; scopes already
-- published keep the old addresses until their next publication, so nodes
-- may ban each other. New system trigger node_networks, queued due at once
-- for every scope whose latest release carries other node networks: manual
-- scopes through the system channel, automatic scopes through their policy
-- (source_kind node_networks). Each check extends the latest one (383 for
-- the system channel, 364 for automatic requests) by one value.
-- The node networks the watcher last acted on (sha256 of the canonical
-- list): a sweep queues republications only when they change.
CREATE TABLE edge_node_network_marks (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    networks_sha256 bytea NOT NULL CHECK (octet_length(networks_sha256) = 32),
    network_count integer NOT NULL CHECK (network_count >= 0),
    observed_at timestamptz NOT NULL CHECK (isfinite(observed_at))
);
REVOKE ALL ON edge_node_network_marks FROM PUBLIC;
GRANT SELECT, INSERT, UPDATE ON edge_node_network_marks TO cdnca_control_app, cdnca_control_runtime;

ALTER TABLE edge_system_republication_heads
    DROP CONSTRAINT edge_system_republication_heads_triggers_check,
    ADD CONSTRAINT edge_system_republication_heads_triggers_check CHECK (cardinality(triggers) BETWEEN 1 AND 12 AND
        triggers <@ ARRAY['node_capability', 'traffic_enforcement', 'line_group', 'node_sync', 'domain_ownership',
            'secondary_verification', 'rule_catalog', 'challenge_delivery', 'module_entitlement',
            'theme_activation', 'account_suspension', 'node_networks']::text[]);
ALTER TABLE edge_system_republication_attempts
    DROP CONSTRAINT edge_system_republication_attempts_triggers_check,
    ADD CONSTRAINT edge_system_republication_attempts_triggers_check CHECK (cardinality(triggers) BETWEEN 1 AND 12);
ALTER TABLE edge_system_revision_segments
    DROP CONSTRAINT edge_system_revision_segments_source_check,
    ADD CONSTRAINT edge_system_revision_segments_source_check CHECK (source IN ('node_capability', 'traffic_enforcement',
        'line_group', 'node_sync', 'domain_ownership', 'secondary_verification', 'rule_catalog', 'challenge_delivery',
        'module_entitlement', 'account_suspension', 'node_networks'));

ALTER TABLE edge_automatic_publication_requests
    DROP CONSTRAINT edge_automatic_publication_requests_source_kind_check,
    DROP CONSTRAINT edge_automatic_publication_requests_operation_check,
    DROP CONSTRAINT edge_automatic_publication_requests_reason_check,
    DROP CONSTRAINT edge_automatic_publication_requests_check,
    DROP CONSTRAINT edge_automatic_publication_l4_intent_presence_092;

ALTER TABLE edge_automatic_publication_requests
    ADD CONSTRAINT edge_automatic_publication_requests_source_kind_check
        CHECK (source_kind IN ('site', 'l4', 'line_group', 'node_sync', 'node_capability', 'rule_catalog',
            'challenge_delivery', 'module_entitlement', 'node_networks')),
    ADD CONSTRAINT edge_automatic_publication_requests_operation_check CHECK (operation IN (
        'site.create', 'site.update', 'site.origin.update', 'site.delete',
        'site.batch.enable', 'site.batch.disable', 'site.batch.delete',
        'stream.create', 'stream.update', 'stream.delete',
        'line_group.nodes_changed', 'node.sync_retry', 'node.capabilities_changed', 'security_rule_catalog.updated',
        'node.challenge_delivered', 'entitlement.modules_granted', 'node.networks_changed')),
    ADD CONSTRAINT edge_automatic_publication_requests_reason_check
        CHECK (reason IN ('resource_mutation', 'node_set_changed', 'sync_retry', 'capability_changed', 'catalog_changed',
            'challenge_delivered', 'entitlement_changed', 'node_networks_changed')),
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
         operation = 'entitlement.modules_granted' AND source_resource_id IS NOT NULL) OR
        (source_kind = 'node_networks' AND permission_name = 'sites.manage' AND reason = 'node_networks_changed' AND
         operation = 'node.networks_changed' AND source_resource_id IS NOT NULL)
    ),
    ADD CONSTRAINT edge_automatic_publication_l4_intent_presence_092 CHECK (
        (source_kind IN ('site', 'line_group', 'node_sync', 'node_capability', 'rule_catalog', 'challenge_delivery',
            'module_entitlement', 'node_networks') AND publish_intent_id IS NULL) OR
        (source_kind = 'l4' AND publish_intent_id IS NOT NULL)
    );
