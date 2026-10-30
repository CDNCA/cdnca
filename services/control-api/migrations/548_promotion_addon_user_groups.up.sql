-- 548（fix-pkgmkt，用户 10-27「按照竞品的做」）：折扣按竞品补两项。
-- ① 生效类别加「升级包」（product_kind='package_addon'）：目标是 package_addon_products。升级包购买不走
--    报价/预留（升级包单在 549 的 package_addon_orders，与 package_orders 分开），所以只允许自动折扣、
--    只用于购买、不能续费同价；报价表 promotion_quotes 的 product_kind 约束不动，升级包永远进不了报价。
-- ② 生效用户组：promotion_policy_user_group_targets（按版本追加，空 = 所有用户）。组是平台级
--    identity_user_groups，成员以 user_id 为主键（一个用户最多一个组），所以按「下单用户」匹配，
--    与租户目标同时存在时两者都要命中。不加外键：组可删除（135 只拦有成员的组），删后折扣不再
--    匹配任何人，而不是悄悄放宽成全体；插入时校验组存在。
--    报价复核函数 reprice_promotion_quote_policies 不复核用户组（成员可变；续费同价快照不应因退组失效），
--    与券码一样只在报价时判定（internal/promotion quote_store.go）。
-- 前驱 547（node_ip_location_resolution），守卫钉 547 校验和。
LOCK TABLE schema_migrations, promotion_policies, promotion_policy_versions, promotion_policy_product_targets
    IN ACCESS EXCLUSIVE MODE;

DO $migration_548_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 547 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 547 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=547 AND
        migration_id='547_node_ip_location_resolution' AND
        checksum_sha256='965d0aeec3e1d2f3c700ee775f2503dd711e1be03df397e6a1898d91a2ed8eed' AND
        down_checksum_sha256='63a505680163337f7c7e8ddd210170911eaeebea8091e79e71eb7f402af80925' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR to_regclass('promotion_policy_user_group_targets') IS NOT NULL THEN
        RAISE EXCEPTION 'migration 548 requires the exact verified 547 release head' USING ERRCODE='P5480';
    END IF;
END;
$migration_548_up$;

ALTER TABLE promotion_policy_versions DROP CONSTRAINT promotion_policy_versions_product_kind_check;
ALTER TABLE promotion_policy_versions ADD CONSTRAINT promotion_policy_versions_product_kind_check
    CHECK (product_kind IN ('package_subscription', 'traffic_package', 'package_addon'));
ALTER TABLE promotion_policy_versions ADD CONSTRAINT promotion_policy_versions_addon_shape_548
    CHECK (product_kind <> 'package_addon' OR (use_purchase AND NOT use_renewal AND NOT renewal_same_price));

CREATE OR REPLACE FUNCTION assert_promotion_policy_target()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE target_kind text;
DECLARE coupon text;
BEGIN
    SELECT version.product_kind, policy.coupon_code INTO target_kind, coupon
    FROM promotion_policy_versions version
    JOIN promotion_policies policy ON policy.id = version.policy_id
    WHERE version.policy_id = NEW.policy_id AND version.revision = NEW.policy_revision;
    IF target_kind = 'package_subscription' AND NOT EXISTS (
        SELECT 1 FROM package_product_versions WHERE product_id = NEW.product_id
    ) THEN
        RAISE EXCEPTION 'promotion package target does not exist';
    ELSIF target_kind = 'traffic_package' AND NOT EXISTS (
        SELECT 1 FROM traffic_package_product_snapshots WHERE product_id = NEW.product_id
    ) THEN
        RAISE EXCEPTION 'promotion traffic package target does not exist';
    ELSIF target_kind = 'package_addon' AND (coupon IS NOT NULL OR NOT EXISTS (
        SELECT 1 FROM package_addon_products WHERE id = NEW.product_id AND deleted_at IS NULL
    )) THEN
        RAISE EXCEPTION 'promotion addon target must be an existing addon of an automatic discount';
    ELSIF target_kind IS NULL THEN
        RAISE EXCEPTION 'promotion policy version does not exist';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TABLE promotion_policy_user_group_targets (
    policy_id uuid NOT NULL,
    policy_revision bigint NOT NULL,
    user_group_id uuid NOT NULL,
    PRIMARY KEY (policy_id, policy_revision, user_group_id),
    FOREIGN KEY (policy_id, policy_revision)
        REFERENCES promotion_policy_versions(policy_id, revision) ON DELETE RESTRICT
);
CREATE INDEX promotion_policy_user_group_targets_group_idx
    ON promotion_policy_user_group_targets (user_group_id, policy_id, policy_revision);

CREATE FUNCTION assert_promotion_user_group_target_548()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM identity_user_groups WHERE id = NEW.user_group_id) THEN
        RAISE EXCEPTION 'promotion user group target does not exist' USING ERRCODE='P5481';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER promotion_user_group_targets_validate_548
BEFORE INSERT ON promotion_policy_user_group_targets
FOR EACH ROW EXECUTE FUNCTION assert_promotion_user_group_target_548();
CREATE TRIGGER promotion_policy_user_group_targets_append_only
BEFORE UPDATE OR DELETE ON promotion_policy_user_group_targets
FOR EACH ROW EXECUTE FUNCTION prevent_promotion_append_mutation();
CREATE TRIGGER promotion_policy_user_group_targets_no_truncate
BEFORE TRUNCATE ON promotion_policy_user_group_targets
FOR EACH STATEMENT EXECUTE FUNCTION prevent_promotion_append_mutation();

DO $$ BEGIN
    IF EXISTS(SELECT 1 FROM pg_roles WHERE rolname='cdnca_control_app') THEN
        GRANT SELECT, INSERT ON promotion_policy_user_group_targets TO cdnca_control_app;
    END IF;
END $$;
