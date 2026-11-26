-- 691 回退：删当前权益解析函数与改套餐发布标记。旧版 control-api 不读它们（回到读初购快照）。
LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;

DO $migration_691_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 691 OR
       (SELECT max(version) FROM schema_migrations) <> 691 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=691 AND
        migration_id='691_package_change_current_entitlement' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 691 down requires the exact verified migration head' USING ERRCODE='P6911';
    END IF;
END;
$migration_691_down$;

DROP TABLE package_entitlement_republication_marks;
DROP FUNCTION package_subscription_current_product_snapshot(uuid,timestamptz);
DROP FUNCTION package_subscription_current_product_id(uuid,timestamptz);
