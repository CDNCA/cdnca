-- 508（r136 l4-traffic）回退：open 的转发超额停服事实是恢复转发的唯一依据，存在时拒绝回退。
LOCK TABLE schema_migrations, package_traffic_stream_suspensions IN ACCESS EXCLUSIVE MODE;

DO $migration_508_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 508 OR
       (SELECT max(version) FROM schema_migrations) <> 508 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=508 AND
        migration_id='508_package_traffic_stream_suspensions' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 508 down requires the exact verified migration head' USING ERRCODE='P5082';
    END IF;
    IF EXISTS (SELECT 1 FROM package_traffic_stream_suspensions WHERE recovered_at IS NULL) THEN
        RAISE EXCEPTION 'migration 508 rollback would strand traffic-suspended streams' USING ERRCODE='P5083';
    END IF;
END;
$migration_508_down$;

DROP TRIGGER package_traffic_stream_suspensions_close_once_508 ON package_traffic_stream_suspensions;
DROP TABLE package_traffic_stream_suspensions;
DROP FUNCTION protect_package_traffic_stream_suspension_508();
