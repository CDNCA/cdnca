LOCK TABLE schema_migrations, package_subscriptions IN ACCESS EXCLUSIVE MODE;

DO $migration_261_down_head$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 261 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 261 OR
       NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version = 261 AND migration_id = '261_package_sold_administration' AND
              integrity_state = 'verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR
       NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version = 260 AND migration_id = '260_package_subscription_display_ids' AND
              checksum_sha256 = 'd9fd515f0e4685b7d179d5ae53e9ecec5ead34de925ae52c34622b6cfe7fee67' AND
              down_checksum_sha256 = '09960d3bfa44d0aa4660c8c686d53882664d8eb46e37e8782dcfeaebf2af05a1' AND
              integrity_state = 'verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 261 rollback requires the exact verified 261 release head'
            USING ERRCODE = 'P2612';
    END IF;
END;
$migration_261_down_head$;

LOCK TABLE package_subscriptions,package_subscription_versions,package_subscription_entitlement_versions IN SHARE ROW EXCLUSIVE MODE;
DO $$ BEGIN IF EXISTS(SELECT 1 FROM package_sold_write_requests) OR EXISTS(SELECT 1 FROM package_subscription_versions WHERE operation LIKE 'admin_%') THEN
 RAISE EXCEPTION 'sold package administrative history requires forward recovery'; END IF; END $$;
DROP TABLE package_sold_publications;
DROP TABLE package_sold_write_requests;
CREATE OR REPLACE FUNCTION protect_package_subscription_snapshot()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.id IS DISTINCT FROM OLD.id
       OR NEW.tenant_scope_id IS DISTINCT FROM OLD.tenant_scope_id
       OR NEW.product_id IS DISTINCT FROM OLD.product_id
       OR NEW.product_revision IS DISTINCT FROM OLD.product_revision
       OR NEW.product_snapshot IS DISTINCT FROM OLD.product_snapshot
       OR NEW.site_limit IS DISTINCT FROM OLD.site_limit
       OR NEW.domain_limit IS DISTINCT FROM OLD.domain_limit
       OR NEW.node_limit IS DISTINCT FROM OLD.node_limit
       OR NEW.traffic_limit_bytes IS DISTINCT FROM OLD.traffic_limit_bytes
       OR NEW.starts_at IS DISTINCT FROM OLD.starts_at
       OR NEW.timezone IS DISTINCT FROM OLD.timezone
       OR NEW.cycle_kind IS DISTINCT FROM OLD.cycle_kind
       OR NEW.custom_cycle_days IS DISTINCT FROM OLD.custom_cycle_days
       OR NEW.tcp_factor_numerator IS DISTINCT FROM OLD.tcp_factor_numerator
       OR NEW.tcp_factor_denominator IS DISTINCT FROM OLD.tcp_factor_denominator
       OR NEW.created_by_user_id IS DISTINCT FROM OLD.created_by_user_id
       OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
        RAISE EXCEPTION 'package subscription snapshot is immutable';
    END IF;
    IF OLD.lifecycle_status = 'cancelled' THEN
        RAISE EXCEPTION 'cancelled package subscription is immutable';
    END IF;
    IF NEW.revision <> OLD.revision + 1 THEN
        RAISE EXCEPTION 'package subscription revision must advance by one';
    END IF;
    IF NEW.updated_at < OLD.updated_at THEN
        RAISE EXCEPTION 'package subscription updated_at cannot move backwards';
    END IF;
    IF NEW.lifecycle_status = 'active' THEN
        IF NEW.ends_at < OLD.ends_at OR NEW.cancelled_at IS NOT NULL THEN
            RAISE EXCEPTION 'active package subscription renewal must strictly extend ends_at';
        END IF;
    ELSIF NEW.lifecycle_status = 'cancelled' THEN
        IF NEW.ends_at IS DISTINCT FROM OLD.ends_at
           OR NEW.cancelled_at IS DISTINCT FROM NEW.updated_at
           OR NEW.cancelled_at < OLD.updated_at THEN
            RAISE EXCEPTION 'package subscription cancellation facts are invalid';
        END IF;
    ELSE
        RAISE EXCEPTION 'invalid package subscription lifecycle transition';
    END IF;
    RETURN NEW;
END;
$$;
CREATE OR REPLACE FUNCTION assert_package_subscription_revision_fact()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE fact_operation text;
BEGIN
    SELECT operation INTO fact_operation
    FROM package_subscription_versions
    WHERE subscription_id = NEW.id AND revision = NEW.revision;
    IF fact_operation IS NULL
       OR (NEW.lifecycle_status = 'cancelled' AND fact_operation <> 'cancel')
       OR (NEW.lifecycle_status = 'active' AND NEW.ends_at > OLD.ends_at AND fact_operation <> 'renew')
       OR (NEW.lifecycle_status = 'active' AND NEW.ends_at = OLD.ends_at
           AND fact_operation NOT IN ('upgrade', 'downgrade')) THEN
        RAISE EXCEPTION 'package subscription revision requires matching version fact';
    END IF;
    RETURN NULL;
END;
$$;
ALTER TABLE package_subscriptions DROP COLUMN admin_enabled,DROP COLUMN deleted_at;
ALTER TABLE package_subscription_versions DROP CONSTRAINT package_subscription_versions_operation_check,DROP CONSTRAINT package_subscription_versions_commerce_shape;
ALTER TABLE package_subscription_versions ADD CONSTRAINT package_subscription_versions_operation_check CHECK(operation IN ('open','renew','cancel','upgrade','downgrade')),
 ADD CONSTRAINT package_subscription_versions_commerce_shape CHECK(
 (operation IN ('open','cancel') AND order_id IS NULL AND entitlement_revision IS NULL)
 OR (operation='renew' AND ((order_id IS NULL AND entitlement_revision IS NULL) OR (order_id IS NOT NULL AND entitlement_revision IS NOT NULL)))
 OR (operation IN ('upgrade','downgrade') AND order_id IS NOT NULL AND entitlement_revision IS NOT NULL));
ALTER TABLE package_subscription_entitlement_versions DROP CONSTRAINT package_entitlement_operation_261_check,DROP CONSTRAINT package_entitlement_source_order_261_check;
ALTER TABLE package_subscription_entitlement_versions ADD CONSTRAINT package_entitlement_operation_140_check CHECK(operation IN ('migration_backfill','manual_open','purchase','renew','upgrade','downgrade','refund','void')),
 ADD CONSTRAINT package_entitlement_source_order_140_check CHECK((operation IN ('migration_backfill','manual_open'))=(source_order_id IS NULL));
