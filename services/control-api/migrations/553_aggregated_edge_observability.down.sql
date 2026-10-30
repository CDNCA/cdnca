-- 553（fix-aephase1）回退：删自有节点组轮次表与拨测设置列（拨测回到 GET、无自定义头、3/3）。
LOCK TABLE schema_migrations, site_supply_cdn_configs IN ACCESS EXCLUSIVE MODE;

DO $migration_553_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 553 OR
       (SELECT max(version) FROM schema_migrations) <> 553 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=553 AND
        migration_id='553_aggregated_edge_observability' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 553 down requires the exact verified migration head' USING ERRCODE='P5531';
    END IF;
END;
$migration_553_down$;

ALTER TABLE site_supply_cdn_configs DROP COLUMN health_method, DROP COLUMN health_headers,
    DROP COLUMN failure_threshold, DROP COLUMN recovery_threshold;
DROP TABLE aggregated_edge_local_rounds;
