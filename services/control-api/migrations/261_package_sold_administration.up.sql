LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;

DO $migration_261_up_head$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 260 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 260 OR
       NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version = 260 AND migration_id = '260_package_subscription_display_ids' AND
              checksum_sha256 = 'd9fd515f0e4685b7d179d5ae53e9ecec5ead34de925ae52c34622b6cfe7fee67' AND
              down_checksum_sha256 = '09960d3bfa44d0aa4660c8c686d53882664d8eb46e37e8782dcfeaebf2af05a1' AND
              integrity_state = 'verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 261 requires the exact verified 260 release head'
            USING ERRCODE = 'P2610';
    END IF;
END;
$migration_261_up_head$;

LOCK TABLE package_subscriptions,package_subscription_versions,package_subscription_entitlement_versions IN SHARE ROW EXCLUSIVE MODE;
ALTER TABLE package_subscriptions ADD COLUMN admin_enabled boolean NOT NULL DEFAULT true,
 ADD COLUMN deleted_at timestamptz;
ALTER TABLE package_subscription_versions DROP CONSTRAINT package_subscription_versions_operation_check,
 DROP CONSTRAINT package_subscription_versions_commerce_shape;
ALTER TABLE package_subscription_versions ADD CONSTRAINT package_subscription_versions_operation_check
 CHECK(operation IN ('open','renew','cancel','upgrade','downgrade','admin_edit','admin_enable','admin_disable','admin_delete')),
 ADD CONSTRAINT package_subscription_versions_commerce_shape CHECK(
 (operation IN ('open','cancel','admin_edit','admin_enable','admin_disable','admin_delete') AND order_id IS NULL AND entitlement_revision IS NULL)
 OR (operation='renew' AND ((order_id IS NULL AND entitlement_revision IS NULL) OR (order_id IS NOT NULL AND entitlement_revision IS NOT NULL)))
 OR (operation IN ('upgrade','downgrade') AND order_id IS NOT NULL AND entitlement_revision IS NOT NULL));
ALTER TABLE package_subscription_entitlement_versions DROP CONSTRAINT package_entitlement_operation_140_check,
 DROP CONSTRAINT package_entitlement_source_order_140_check;
ALTER TABLE package_subscription_entitlement_versions ADD CONSTRAINT package_entitlement_operation_261_check
 CHECK(operation IN ('migration_backfill','manual_open','admin_edit','purchase','renew','upgrade','downgrade','refund','void')),
 ADD CONSTRAINT package_entitlement_source_order_261_check CHECK(
 (operation IN ('migration_backfill','manual_open','admin_edit'))=(source_order_id IS NULL));
CREATE TABLE package_sold_write_requests (
 actor_scope_id uuid NOT NULL REFERENCES access_scopes(id), actor_user_id uuid NOT NULL REFERENCES users(id),
 idempotency_key text NOT NULL CHECK(length(idempotency_key) BETWEEN 1 AND 128),
 request_digest bytea NOT NULL CHECK(octet_length(request_digest)=32),
 response_body jsonb NOT NULL CHECK(jsonb_typeof(response_body)='object'),
 created_at timestamptz NOT NULL,
 PRIMARY KEY(actor_scope_id,actor_user_id,idempotency_key));
CREATE TABLE package_sold_publications (
 subscription_id uuid NOT NULL REFERENCES package_subscriptions(id),
 publication_id uuid NOT NULL REFERENCES edge_config_publications(id),
 rollout_id uuid NOT NULL,
 tenant_scope_id uuid NOT NULL REFERENCES access_scopes(id),
 created_at timestamptz NOT NULL,
 PRIMARY KEY(subscription_id,publication_id));
CREATE TRIGGER package_sold_write_requests_immutable BEFORE UPDATE OR DELETE ON package_sold_write_requests
 FOR EACH ROW EXECUTE FUNCTION prevent_package_commerce_fact_mutation();
CREATE TRIGGER package_sold_publications_immutable BEFORE UPDATE OR DELETE ON package_sold_publications
 FOR EACH ROW EXECUTE FUNCTION prevent_package_commerce_fact_mutation();
CREATE OR REPLACE FUNCTION protect_package_subscription_snapshot() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE admin_operation text;
BEGIN
 SELECT operation INTO admin_operation FROM package_subscription_versions WHERE subscription_id=NEW.id AND revision=NEW.revision;
 IF admin_operation IN ('admin_edit','admin_enable','admin_disable','admin_delete') THEN
  IF OLD.deleted_at IS NOT NULL OR OLD.lifecycle_status<>'active' OR NEW.revision<>OLD.revision+1 OR NEW.updated_at<OLD.updated_at
   OR NEW.id<>OLD.id OR NEW.tenant_scope_id<>OLD.tenant_scope_id OR NEW.product_id<>OLD.product_id OR NEW.product_revision<>OLD.product_revision
   OR NEW.site_limit<>OLD.site_limit OR NEW.node_limit<>OLD.node_limit OR NEW.starts_at<>OLD.starts_at OR NEW.timezone<>OLD.timezone
   OR NEW.cycle_kind<>OLD.cycle_kind OR NEW.custom_cycle_days<>OLD.custom_cycle_days
   OR NEW.tcp_factor_numerator<>OLD.tcp_factor_numerator OR NEW.tcp_factor_denominator<>OLD.tcp_factor_denominator
   OR NEW.created_by_user_id<>OLD.created_by_user_id OR NEW.created_at<>OLD.created_at OR NEW.lifecycle_status<>OLD.lifecycle_status
   OR NEW.cancelled_at IS DISTINCT FROM OLD.cancelled_at THEN
    RAISE EXCEPTION 'invalid sold package administrative transition';
  END IF;
  IF NOT EXISTS(SELECT 1 FROM package_subscription_versions v WHERE v.subscription_id=NEW.id AND v.revision=NEW.revision
    AND (v.snapshot#>>'{sold,enabled}')::boolean=NEW.admin_enabled
    AND (v.snapshot#>>'{sold,deleted}')::boolean=(NEW.deleted_at IS NOT NULL)
    AND (v.snapshot#>>'{sold,ends_at}')::timestamptz=NEW.ends_at
    AND v.created_by_user_id=NEW.updated_by_user_id AND v.created_at=NEW.updated_at) THEN
    RAISE EXCEPTION 'sold package administrative snapshot does not match current row';
  END IF;
  IF admin_operation='admin_edit' THEN
   IF NOT EXISTS(SELECT 1 FROM package_subscription_versions v WHERE v.subscription_id=NEW.id AND v.revision=NEW.revision
    AND NEW.product_snapshot->'spec' @> (v.snapshot#>'{sold,config}')
    AND NEW.product_snapshot->>'name'=v.snapshot#>>'{sold,config,name}'
    AND NEW.domain_limit=(v.snapshot#>>'{sold,config,limits,domains}')::bigint
    AND NEW.traffic_limit_bytes=(v.snapshot#>>'{sold,config,limits,monthly_traffic_bytes}')::bigint) THEN
    RAISE EXCEPTION 'sold package config does not match administrative snapshot'; END IF;
   IF NEW.admin_enabled<>OLD.admin_enabled OR NEW.deleted_at IS DISTINCT FROM OLD.deleted_at THEN RAISE EXCEPTION 'edit cannot change package status'; END IF;
  ELSIF NEW.product_snapshot<>OLD.product_snapshot OR NEW.domain_limit<>OLD.domain_limit OR NEW.traffic_limit_bytes<>OLD.traffic_limit_bytes OR NEW.ends_at<>OLD.ends_at THEN
   RAISE EXCEPTION 'status change cannot edit package snapshot';
  END IF;
  IF (admin_operation='admin_enable' AND (NOT NEW.admin_enabled OR NEW.deleted_at IS NOT NULL))
   OR (admin_operation='admin_disable' AND (NEW.admin_enabled OR NEW.deleted_at IS NOT NULL))
   OR (admin_operation='admin_delete' AND (NEW.admin_enabled OR NEW.deleted_at IS DISTINCT FROM NEW.updated_at)) THEN
   RAISE EXCEPTION 'invalid sold package status';
  END IF;
  RETURN NEW;
 END IF;
 IF NEW.admin_enabled IS DISTINCT FROM OLD.admin_enabled OR NEW.deleted_at IS DISTINCT FROM OLD.deleted_at OR OLD.deleted_at IS NOT NULL THEN
  RAISE EXCEPTION 'sold package status requires administrative version';
 END IF;

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
CREATE OR REPLACE FUNCTION assert_package_subscription_revision_fact() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE fact_operation text;
BEGIN
    SELECT operation INTO fact_operation
    FROM package_subscription_versions
    WHERE subscription_id = NEW.id AND revision = NEW.revision;
    IF fact_operation IN ('admin_edit','admin_enable','admin_disable','admin_delete') THEN RETURN NULL; END IF;
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
GRANT SELECT,INSERT ON package_sold_write_requests,package_sold_publications TO cdnca_control_app;
