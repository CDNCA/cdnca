LOCK TABLE schema_migrations, edge_automatic_publication_requests IN ACCESS EXCLUSIVE MODE;

DO $migration_311_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 311 OR
       (SELECT max(version) FROM schema_migrations) <> 311 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=311 AND
        migration_id='311_edge_system_republication' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 311 down requires the exact verified migration head' USING ERRCODE='P3111';
    END IF;
    -- Republication attempts, segments and holds are durable facts.
    IF EXISTS (SELECT 1 FROM edge_automatic_publication_requests WHERE source_kind = 'node_capability') OR
       EXISTS (SELECT 1 FROM edge_system_republication_heads) OR
       EXISTS (SELECT 1 FROM edge_system_revision_segments) OR
       EXISTS (SELECT 1 FROM edge_capability_publication_holds) THEN
        RAISE EXCEPTION 'migration 311 rollback would orphan system republication facts' USING ERRCODE='P3111';
    END IF;
END;
$migration_311_down$;

DROP TABLE edge_node_capability_marks;
DROP TABLE edge_capability_publication_holds;
DROP TABLE edge_system_revision_segments;
DROP TABLE edge_system_republication_attempts;
DROP TABLE edge_system_republication_heads;

ALTER TABLE edge_automatic_publication_requests
    DROP CONSTRAINT edge_automatic_publication_l4_intent_presence_092,
    DROP CONSTRAINT edge_automatic_publication_requests_check,
    DROP CONSTRAINT edge_automatic_publication_requests_reason_check,
    DROP CONSTRAINT edge_automatic_publication_requests_operation_check,
    DROP CONSTRAINT edge_automatic_publication_requests_source_kind_check;

ALTER TABLE edge_automatic_publication_requests
    ADD CONSTRAINT edge_automatic_publication_requests_source_kind_check
        CHECK (source_kind IN ('site', 'l4', 'line_group', 'node_sync')),
    ADD CONSTRAINT edge_automatic_publication_requests_operation_check CHECK (operation IN (
        'site.create', 'site.update', 'site.origin.update', 'site.delete',
        'site.batch.enable', 'site.batch.disable', 'site.batch.delete',
        'stream.create', 'stream.update', 'stream.delete',
        'line_group.nodes_changed', 'node.sync_retry')),
    ADD CONSTRAINT edge_automatic_publication_requests_reason_check
        CHECK (reason IN ('resource_mutation', 'node_set_changed', 'sync_retry')),
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
         operation = 'node.sync_retry' AND source_resource_id IS NOT NULL)
    ),
    ADD CONSTRAINT edge_automatic_publication_l4_intent_presence_092 CHECK (
        (source_kind IN ('site', 'line_group', 'node_sync') AND publish_intent_id IS NULL) OR
        (source_kind = 'l4' AND publish_intent_id IS NOT NULL)
    );
