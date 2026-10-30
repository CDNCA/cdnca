LOCK TABLE schema_migrations, edge_automatic_publication_requests, node_serving_holds, node_serving_events
IN ACCESS EXCLUSIVE MODE;

DO $migration_301_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 301 OR
       (SELECT max(version) FROM schema_migrations) <> 301 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=301 AND
        migration_id='301_line_group_publication_sync_hold' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 301 down requires the exact verified migration head' USING ERRCODE='P3011';
    END IF;
    -- Requests and holds are durable facts; the 300 constraints cannot describe them.
    IF EXISTS (SELECT 1 FROM edge_automatic_publication_requests WHERE source_kind IN ('line_group', 'node_sync')) OR
       EXISTS (SELECT 1 FROM node_serving_holds WHERE source = 'config_sync') OR
       EXISTS (SELECT 1 FROM node_serving_events WHERE source = 'config_sync') THEN
        RAISE EXCEPTION 'migration 301 rollback would orphan line-group, sync-retry or config-sync facts'
            USING ERRCODE='P3011';
    END IF;
END;
$migration_301_down$;

ALTER TABLE node_serving_events DROP CONSTRAINT node_serving_events_source_check,
    ADD CONSTRAINT node_serving_events_source_check CHECK (source IN ('availability_monitor', 'auto_disable'));
ALTER TABLE node_serving_holds DROP CONSTRAINT node_serving_holds_source_check,
    ADD CONSTRAINT node_serving_holds_source_check CHECK (source IN ('availability_monitor', 'auto_disable'));

ALTER TABLE edge_automatic_publication_requests
    DROP CONSTRAINT edge_automatic_publication_l4_intent_presence_092,
    DROP CONSTRAINT edge_automatic_publication_requests_check,
    DROP CONSTRAINT edge_automatic_publication_requests_reason_check,
    DROP CONSTRAINT edge_automatic_publication_requests_operation_check,
    DROP CONSTRAINT edge_automatic_publication_requests_source_kind_check;

ALTER TABLE edge_automatic_publication_requests
    ADD CONSTRAINT edge_automatic_publication_requests_source_kind_check CHECK (source_kind IN ('site', 'l4')),
    ADD CONSTRAINT edge_automatic_publication_requests_operation_check CHECK (operation IN (
        'site.create', 'site.update', 'site.origin.update', 'site.delete',
        'site.batch.enable', 'site.batch.disable', 'site.batch.delete',
        'stream.create', 'stream.update', 'stream.delete')),
    ADD CONSTRAINT edge_automatic_publication_requests_reason_check CHECK (reason = 'resource_mutation'),
    ADD CONSTRAINT edge_automatic_publication_requests_check CHECK (
        (source_kind = 'site' AND permission_name = 'sites.manage' AND (
            operation IN ('site.batch.enable', 'site.batch.disable', 'site.batch.delete') AND source_resource_id IS NULL OR
            operation IN ('site.create', 'site.update', 'site.origin.update', 'site.delete') AND source_resource_id IS NOT NULL
        )) OR
        (source_kind = 'l4' AND permission_name = 'streams.manage' AND
         operation IN ('stream.create', 'stream.update', 'stream.delete') AND source_resource_id IS NOT NULL)
    ),
    ADD CONSTRAINT edge_automatic_publication_l4_intent_presence_092 CHECK (
        (source_kind = 'site' AND publish_intent_id IS NULL) OR
        (source_kind = 'l4' AND publish_intent_id IS NOT NULL)
    );
