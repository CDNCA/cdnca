-- 548 回滚：去掉升级包折扣类别与用户组目标。
-- 已发布的升级包折扣或带用户组的折扣是运营可见的事实，回滚会把用户组折扣悄悄放宽成全体、
-- 让升级包折扣违反旧约束，此时拒绝回滚。
LOCK TABLE schema_migrations, promotion_policy_versions, promotion_policy_product_targets,
    promotion_policy_user_group_targets IN ACCESS EXCLUSIVE MODE;

DO $migration_548_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 548 OR
       (SELECT max(version) FROM schema_migrations) <> 548 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=548 AND
        migration_id='548_promotion_addon_user_groups' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 548 down requires the exact verified migration head' USING ERRCODE='P5482';
    END IF;
    IF EXISTS (SELECT 1 FROM promotion_policy_versions WHERE product_kind='package_addon') OR
       EXISTS (SELECT 1 FROM promotion_policy_user_group_targets) THEN
        RAISE EXCEPTION 'migration 548 rollback would discard addon or user group discounts' USING ERRCODE='P5483';
    END IF;
END;
$migration_548_down$;

DROP TABLE promotion_policy_user_group_targets;
DROP FUNCTION assert_promotion_user_group_target_548();

CREATE OR REPLACE FUNCTION assert_promotion_policy_target()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE target_kind text;
BEGIN
    SELECT product_kind INTO target_kind
    FROM promotion_policy_versions
    WHERE policy_id = NEW.policy_id AND revision = NEW.policy_revision;
    IF target_kind = 'package_subscription' AND NOT EXISTS (
        SELECT 1 FROM package_product_versions WHERE product_id = NEW.product_id
    ) THEN
        RAISE EXCEPTION 'promotion package target does not exist';
    ELSIF target_kind = 'traffic_package' AND NOT EXISTS (
        SELECT 1 FROM traffic_package_product_snapshots WHERE product_id = NEW.product_id
    ) THEN
        RAISE EXCEPTION 'promotion traffic package target does not exist';
    ELSIF target_kind IS NULL THEN
        RAISE EXCEPTION 'promotion policy version does not exist';
    END IF;
    RETURN NEW;
END;
$$;

ALTER TABLE promotion_policy_versions DROP CONSTRAINT promotion_policy_versions_addon_shape_548;
ALTER TABLE promotion_policy_versions DROP CONSTRAINT promotion_policy_versions_product_kind_check;
ALTER TABLE promotion_policy_versions ADD CONSTRAINT promotion_policy_versions_product_kind_check
    CHECK (product_kind IN ('package_subscription', 'traffic_package'));
