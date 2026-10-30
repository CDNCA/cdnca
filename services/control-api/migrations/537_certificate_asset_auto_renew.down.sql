-- 537 回滚：恢复 103 的认领触发器（读订单 auto_renew），去掉资产层自动续签。
-- 用户已通过开关改过自动续签时拒绝回滚（回滚会丢失这些设置）。
LOCK TABLE schema_migrations, certificate_assets, certificate_orders, acme_renewal_claim_facts,
    certificate_asset_write_requests IN ACCESS EXCLUSIVE MODE;

DO $migration_537_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 537 OR
       (SELECT max(version) FROM schema_migrations) <> 537 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=537 AND
        migration_id='537_certificate_asset_auto_renew' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 537 down requires the exact verified migration head' USING ERRCODE='P5371';
    END IF;
    IF EXISTS (SELECT 1 FROM certificate_asset_write_requests WHERE operation='certificate.auto_renew.update') THEN
        RAISE EXCEPTION 'migration 537 rollback would drop certificate auto-renew changes' USING ERRCODE='P5372';
    END IF;
END;
$migration_537_down$;

CREATE OR REPLACE FUNCTION validate_acme_renewal_claim_fact_048()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    source_order certificate_orders%ROWTYPE;
    previous acme_renewal_claim_facts%ROWTYPE;
    renewal_order certificate_orders%ROWTYPE;
    database_now timestamptz := statement_timestamp();
BEGIN
    SELECT * INTO source_order
    FROM certificate_orders
    WHERE scope_id = NEW.tenant_scope_id AND id = NEW.source_order_id
    FOR UPDATE;
    IF source_order.id IS NULL
       OR NOT source_order.auto_renew
       OR source_order.status NOT IN ('active', 'renewal_due')
       OR source_order.created_by_user_id IS DISTINCT FROM NEW.actor_user_id
       OR NOT acme_runtime_actor_is_active_048(NEW.tenant_scope_id, NEW.actor_user_id)
       OR NEW.occurred_at < database_now - interval '5 minutes'
       OR NEW.occurred_at > database_now + interval '1 minute' THEN
        RAISE EXCEPTION 'ACME renewal claim source or actor is invalid' USING ERRCODE = 'P0001';
    END IF;

    IF NEW.revision = 1 THEN
        IF NEW.event_type <> 'claim_created' OR NEW.status <> 'active'
           OR NEW.fence_token IS DISTINCT FROM NEW.lease_token
           OR NEW.lease_expires_at <= database_now THEN
            RAISE EXCEPTION 'invalid initial ACME renewal claim' USING ERRCODE = 'P0001';
        END IF;
        RETURN NEW;
    END IF;

    SELECT * INTO previous
    FROM acme_renewal_claim_facts
    WHERE tenant_scope_id = NEW.tenant_scope_id
      AND source_order_id = NEW.source_order_id
      AND revision = NEW.revision - 1;
    IF NOT FOUND OR NEW.occurred_at < previous.occurred_at THEN
        RAISE EXCEPTION 'ACME renewal claim revision is not contiguous'
            USING ERRCODE = 'P0001';
    END IF;

    IF previous.status = 'completed' THEN
        IF NEW.event_type <> 'claim_reopened' OR NEW.status <> 'active'
           OR NEW.fence_token IS DISTINCT FROM NEW.lease_token
           OR NEW.lease_expires_at <= database_now
           OR NEW.reopened_from_order_id IS NULL THEN
            RAISE EXCEPTION 'invalid ACME renewal claim reopen' USING ERRCODE = 'P0001';
        END IF;
        SELECT * INTO renewal_order
        FROM certificate_orders
        WHERE scope_id = NEW.tenant_scope_id AND id = NEW.reopened_from_order_id;
        IF renewal_order.id IS NULL
           OR renewal_order.status IS DISTINCT FROM 'failed'
           OR renewal_order.renewal_of_order_id IS DISTINCT FROM NEW.source_order_id
           OR renewal_order.created_by_user_id IS DISTINCT FROM NEW.actor_user_id
           OR previous.renewal_order_id IS DISTINCT FROM NEW.reopened_from_order_id THEN
            RAISE EXCEPTION 'claim_reopened event must bind the exact failed child'
                USING ERRCODE = 'P0001';
        END IF;
        RETURN NEW;
    END IF;

    IF NEW.event_type = 'lease_taken_over' THEN
        IF NEW.status <> 'active'
           OR NEW.fence_token IS DISTINCT FROM NEW.lease_token
           OR NEW.lease_token IS NOT DISTINCT FROM previous.lease_token
           OR NEW.lease_expires_at <= database_now
           OR NOT (
               (previous.status = 'active' AND previous.lease_expires_at <= database_now)
               OR (previous.status = 'retry_wait' AND previous.next_attempt_at <= database_now)
           ) THEN
            RAISE EXCEPTION 'invalid ACME renewal lease takeover' USING ERRCODE = 'P0001';
        END IF;
        RETURN NEW;
    END IF;

    IF previous.status <> 'active' OR previous.lease_expires_at <= database_now
       OR NEW.fence_token IS DISTINCT FROM previous.lease_token THEN
        RAISE EXCEPTION 'ACME renewal claim lease fence rejected the event'
            USING ERRCODE = 'P0001';
    END IF;
    IF NEW.event_type = 'retry_scheduled' THEN
        IF NEW.status <> 'retry_wait' THEN
            RAISE EXCEPTION 'invalid ACME renewal retry event' USING ERRCODE = 'P0001';
        END IF;
        RETURN NEW;
    END IF;
    IF NEW.event_type = 'completed' AND NEW.status = 'completed' THEN
        SELECT * INTO renewal_order
        FROM certificate_orders
        WHERE scope_id = NEW.tenant_scope_id AND id = NEW.renewal_order_id;
        IF renewal_order.id IS NULL
           OR renewal_order.renewal_of_order_id IS DISTINCT FROM NEW.source_order_id
           OR renewal_order.status IS DISTINCT FROM 'pending'
           OR renewal_order.dns_provider_id IS DISTINCT FROM source_order.dns_provider_id
           OR renewal_order.domains IS DISTINCT FROM source_order.domains
           OR renewal_order.challenge_type IS DISTINCT FROM source_order.challenge_type
           OR renewal_order.auto_renew IS DISTINCT FROM source_order.auto_renew
           OR renewal_order.created_by_user_id IS DISTINCT FROM NEW.actor_user_id THEN
            RAISE EXCEPTION 'ACME renewal claim result is not a child order'
                USING ERRCODE = 'P0001';
        END IF;
        RETURN NEW;
    END IF;
    RAISE EXCEPTION 'invalid ACME renewal claim event' USING ERRCODE = 'P0001';
END;
$$;

REVOKE ALL ON FUNCTION validate_acme_renewal_claim_fact_048() FROM PUBLIC;

DROP FUNCTION certificate_asset_auto_renew_537(uuid, uuid);
ALTER TABLE certificate_asset_write_requests
    DROP CONSTRAINT certificate_asset_write_requests_operation_check;
ALTER TABLE certificate_asset_write_requests
    ADD CONSTRAINT certificate_asset_write_requests_operation_check CHECK (operation IN (
        'certificate.asset.import', 'certificate.asset.activate', 'certificate.asset.revoke',
        'certificate.asset.delete', 'certificate.asset.bind', 'certificate.asset.unbind',
        'certificate.asset.rewrap'
    ));
ALTER TABLE certificate_assets DROP CONSTRAINT certificate_assets_auto_renew_acme_537_check;
ALTER TABLE certificate_assets DROP COLUMN auto_renew;
