LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;

DO $migration_280_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 280 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 280 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=280 AND
        migration_id='280_node_serving_holds' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 280 down requires the exact verified migration head' USING ERRCODE='P2800';
    END IF;
    -- Dropping an active hold would silently put a failed node back into DNS,
    -- and retarget facts record values already published to providers.
    IF EXISTS (SELECT 1 FROM node_serving_holds WHERE held) OR
       EXISTS (SELECT 1 FROM dns_cname_retargets) THEN
        RAISE EXCEPTION 'migration 280 down refuses to discard serving holds or DNS retargets' USING ERRCODE='P2803';
    END IF;
END;
$migration_280_down$;

DROP VIEW node_line_endpoint_serving;
DROP TABLE dns_cname_retargets;
DROP TABLE node_serving_events;
DROP TABLE node_serving_holds;
DROP FUNCTION protect_dns_cname_retarget_280();
DROP FUNCTION protect_node_serving_event_280();
DROP FUNCTION protect_node_serving_hold_280();
