-- 537（fix-autorenew，用户 10-27 要求证书列表"自动续签"可直接点击开关）：
-- 续签意愿从下单快照（certificate_orders.auto_renew，048 定为不可变）移到证书资产层
-- certificate_assets.auto_renew，可经 PATCH /v1/certificate-assets/{id}/auto-renew 修改。
-- 订单 auto_renew 仍不可变，只作下单时快照；续签调度与续签认领触发器改读资产层。
-- 前驱 536（node_peer_probe_log），守卫钉 536 校验和。
LOCK TABLE schema_migrations, certificate_assets, certificate_orders, acme_renewal_claim_facts,
    certificate_asset_write_requests IN ACCESS EXCLUSIVE MODE;

DO $migration_537_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 536 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 536 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=536 AND
        migration_id='536_node_peer_probe_log' AND
        checksum_sha256='152e7d6a488e17b06487cc1ec9910c1e8d1b8b0566747c5ca4241e447307a23a' AND
        down_checksum_sha256='a64a8b01e9a896f753c78e9627f144b223371c9e931e82938f1ed5b34fdd453e' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR EXISTS (
        SELECT 1 FROM information_schema.columns WHERE table_schema=current_schema()
          AND table_name='certificate_assets' AND column_name='auto_renew'
       ) THEN
        RAISE EXCEPTION 'migration 537 requires the exact verified 536 release head' USING ERRCODE='P5370';
    END IF;
END;
$migration_537_up$;

-- 手动上传的证书没有 ACME 订单，不能自动续签。
ALTER TABLE certificate_assets ADD COLUMN auto_renew boolean NOT NULL DEFAULT false;
ALTER TABLE certificate_assets ADD CONSTRAINT certificate_assets_auto_renew_acme_537_check
    CHECK (source = 'acme' OR NOT auto_renew);

-- 存量：按签发该资产的最近一张订单的 auto_renew 回填（不推进 revision，不算用户修改）。
ALTER TABLE certificate_assets DISABLE TRIGGER certificate_assets_protect;
ALTER TABLE certificate_assets DISABLE TRIGGER certificate_assets_actor_target_085;
UPDATE certificate_assets asset SET auto_renew = true
WHERE asset.source = 'acme' AND asset.deleted_at IS NULL AND (
    SELECT cert_order.auto_renew FROM certificate_orders cert_order
    WHERE cert_order.scope_id = asset.tenant_scope_id AND cert_order.issued_asset_id = asset.id
    ORDER BY cert_order.created_at DESC, cert_order.id DESC LIMIT 1
) IS TRUE;
ALTER TABLE certificate_assets ENABLE TRIGGER certificate_assets_actor_target_085;
ALTER TABLE certificate_assets ENABLE TRIGGER certificate_assets_protect;

-- 修改自动续签走幂等写请求。
ALTER TABLE certificate_asset_write_requests
    DROP CONSTRAINT certificate_asset_write_requests_operation_check;
ALTER TABLE certificate_asset_write_requests
    ADD CONSTRAINT certificate_asset_write_requests_operation_check CHECK (operation IN (
        'certificate.asset.import', 'certificate.asset.activate', 'certificate.asset.revoke',
        'certificate.asset.delete', 'certificate.asset.bind', 'certificate.asset.unbind',
        'certificate.asset.rewrap', 'certificate.auto_renew.update'
    ));

-- 资产当前是否自动续签（未删除的 ACME 资产且已开启）。调度器与认领触发器共用。
CREATE FUNCTION certificate_asset_auto_renew_537(scope_id uuid, asset_id uuid)
RETURNS boolean LANGUAGE sql STABLE SET search_path FROM CURRENT AS $$
    SELECT COALESCE((SELECT asset.auto_renew FROM certificate_assets asset
        WHERE asset.tenant_scope_id = $1 AND asset.id = $2 AND asset.deleted_at IS NULL), false)
$$;

-- 续签认领：源订单可续以资产层设置为准；续签子订单必为自动续签。
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
       OR source_order.issued_asset_id IS NULL
       OR NOT certificate_asset_auto_renew_537(source_order.scope_id, source_order.issued_asset_id)
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
           OR NOT renewal_order.auto_renew
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
