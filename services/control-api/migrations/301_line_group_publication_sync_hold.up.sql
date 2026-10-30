LOCK TABLE schema_migrations, edge_automatic_publication_requests, node_serving_holds, node_serving_events
IN ACCESS EXCLUSIVE MODE;

DO $migration_301_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 300 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 300 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=300 AND
        migration_id='300_l4_new_connection_rate' AND
        checksum_sha256='57c497adfbc4c2bc9d1cf87c872332bc6d919614dc33132868fe8a00cdbef250' AND
        down_checksum_sha256='fb2987d6d82d8db1c8e19607d71fbbdfc872e88d7575a0fbdcc9a2604d9a279a' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR checksum_sha256 IS NULL OR
        down_checksum_sha256 IS NULL OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR to_regclass(current_schema() || '.node_line_endpoint_serving') IS NULL THEN
        RAISE EXCEPTION 'migration 301 requires the exact verified 300 release head' USING ERRCODE='P3010';
    END IF;
END;
$migration_301_up$;

-- FX02: a line group whose node set changes republishes every automatic scope
-- that uses it (source_kind line_group). NF04: a node held for failed
-- configuration sync gets a republish of its scope after 30 minutes
-- (source_kind node_sync). Neither carries an L4 publish intent.
ALTER TABLE edge_automatic_publication_requests
    DROP CONSTRAINT edge_automatic_publication_requests_source_kind_check,
    DROP CONSTRAINT edge_automatic_publication_requests_operation_check,
    DROP CONSTRAINT edge_automatic_publication_requests_reason_check,
    DROP CONSTRAINT edge_automatic_publication_requests_check,
    DROP CONSTRAINT edge_automatic_publication_l4_intent_presence_092;

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

-- NF04: nodes whose configuration sync failed leave customer DNS through the
-- same node_line_endpoint_serving view (280) as the other system holds.
ALTER TABLE node_serving_holds DROP CONSTRAINT node_serving_holds_source_check,
    ADD CONSTRAINT node_serving_holds_source_check
        CHECK (source IN ('availability_monitor', 'auto_disable', 'config_sync'));
ALTER TABLE node_serving_events DROP CONSTRAINT node_serving_events_source_check,
    ADD CONSTRAINT node_serving_events_source_check
        CHECK (source IN ('availability_monitor', 'auto_disable', 'config_sync'));
