LOCK TABLE schema_migrations, edge_automatic_publication_requests, edge_system_republication_heads,
    edge_system_republication_attempts, edge_system_revision_segments IN ACCESS EXCLUSIVE MODE;

DO $migration_339_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 339 OR
       (SELECT max(version) FROM schema_migrations) <> 339 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=339 AND
        migration_id='339_security_rule_catalog_republication' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 339 down requires the exact verified migration head' USING ERRCODE='P3391';
    END IF;
    -- Requests, attempts and segments are durable facts; the narrower checks cannot hold them.
    IF EXISTS (SELECT 1 FROM edge_automatic_publication_requests WHERE source_kind = 'rule_catalog') OR
       EXISTS (SELECT 1 FROM edge_system_republication_heads
        WHERE 'rule_catalog' = ANY(triggers) OR cardinality(triggers) > 6) OR
       EXISTS (SELECT 1 FROM edge_system_republication_attempts
        WHERE 'rule_catalog' = ANY(triggers) OR cardinality(triggers) > 6) OR
       EXISTS (SELECT 1 FROM edge_system_revision_segments WHERE source = 'rule_catalog') THEN
        RAISE EXCEPTION 'migration 339 rollback would orphan rule catalog republication facts' USING ERRCODE='P3391';
    END IF;
END;
$migration_339_down$;

ALTER TABLE edge_system_republication_heads
    DROP CONSTRAINT edge_system_republication_heads_triggers_check,
    ADD CONSTRAINT edge_system_republication_heads_triggers_check CHECK (cardinality(triggers) BETWEEN 1 AND 6 AND
        triggers <@ ARRAY['node_capability', 'traffic_enforcement', 'line_group', 'node_sync', 'domain_ownership',
            'secondary_verification']::text[]);
ALTER TABLE edge_system_republication_attempts
    DROP CONSTRAINT edge_system_republication_attempts_triggers_check,
    ADD CONSTRAINT edge_system_republication_attempts_triggers_check CHECK (cardinality(triggers) BETWEEN 1 AND 6);
ALTER TABLE edge_system_revision_segments
    DROP CONSTRAINT edge_system_revision_segments_source_check,
    ADD CONSTRAINT edge_system_revision_segments_source_check CHECK (source IN ('node_capability', 'traffic_enforcement',
        'line_group', 'node_sync', 'domain_ownership', 'secondary_verification'));

ALTER TABLE edge_automatic_publication_requests
    DROP CONSTRAINT edge_automatic_publication_l4_intent_presence_092,
    DROP CONSTRAINT edge_automatic_publication_requests_check,
    DROP CONSTRAINT edge_automatic_publication_requests_reason_check,
    DROP CONSTRAINT edge_automatic_publication_requests_operation_check,
    DROP CONSTRAINT edge_automatic_publication_requests_source_kind_check;

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
