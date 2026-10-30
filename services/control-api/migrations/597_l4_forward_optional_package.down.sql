LOCK TABLE schema_migrations, l4_forwards IN ACCESS EXCLUSIVE MODE;

DO $migration_597_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 597 OR
       (SELECT max(version) FROM schema_migrations) <> 597 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=597 AND
        migration_id='597_l4_forward_optional_package' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 597 down requires the exact verified migration head' USING ERRCODE='P5971';
    END IF;
    -- 无套餐的转发（含已删除行）无法补回套餐，回到 596 前须先由运维处理。
    IF EXISTS (SELECT 1 FROM l4_forwards WHERE package_subscription_id IS NULL) THEN
        RAISE EXCEPTION 'migration 597 down refuses L4 forwards without a package subscription' USING ERRCODE='P5972';
    END IF;
END;
$migration_597_down$;

ALTER TABLE l4_forwards ALTER COLUMN package_subscription_id SET NOT NULL;
