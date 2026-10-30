-- 552（fix-certops，用户 10-27；占位，合入时由主会话改号；前驱暂钉 546_ticket_notification_choices）：
-- 证书禁用/启用（按竞品 证书管理 > 更多 > 禁用/启用）。
-- certificate_assets.disabled：禁用的证书不能新绑定网站（服务层拒绝 + 本迁移触发器兜底）、不参与自动续签
--   （certificate_asset_auto_renew_537 加条件，调度器与续签认领触发器共用）；仍被网站绑定时不能禁用（先解绑）。
--   默认 false，存量全部保持启用；列名取 disabled 使 551 之前的幂等回放（JSON 无该字段）解码为启用。
-- 写请求操作加 certificate.asset.enable / certificate.asset.disable（幂等，与自动续签同一套 write_requests）。
LOCK TABLE schema_migrations, certificate_assets, certificate_asset_write_requests, certificate_site_binding_facts
    IN ACCESS EXCLUSIVE MODE;

DO $migration_551_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 550 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 550 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=550 AND
        migration_id='550_cname_zone_random_allocation' AND
        checksum_sha256='dc3f3042d9503ed6babb536562c921ef4cb9337e1086acf665d8282d99f57182' AND
        down_checksum_sha256='41cdc2838f64157b69ad9f9bda0967610c98a6ce8e99dee36f33dc3570b9311c' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR EXISTS (
        SELECT 1 FROM information_schema.columns WHERE table_schema=current_schema()
          AND table_name='certificate_assets' AND column_name='disabled'
       ) THEN
        RAISE EXCEPTION 'migration 551 requires the exact verified 550 release head' USING ERRCODE='P5510';
    END IF;
END;
$migration_551_up$;

ALTER TABLE certificate_assets ADD COLUMN disabled boolean NOT NULL DEFAULT false;

ALTER TABLE certificate_asset_write_requests
    DROP CONSTRAINT certificate_asset_write_requests_operation_check;
ALTER TABLE certificate_asset_write_requests
    ADD CONSTRAINT certificate_asset_write_requests_operation_check CHECK (operation IN (
        'certificate.asset.import', 'certificate.asset.activate', 'certificate.asset.revoke',
        'certificate.asset.delete', 'certificate.asset.bind', 'certificate.asset.unbind',
        'certificate.asset.rewrap', 'certificate.auto_renew.update',
        'certificate.asset.enable', 'certificate.asset.disable'
    ));

-- 禁用的证书不自动续签（调度器 dnsacme/store.go 与续签认领触发器都调用本函数）。
CREATE OR REPLACE FUNCTION certificate_asset_auto_renew_537(scope_id uuid, asset_id uuid)
RETURNS boolean LANGUAGE sql STABLE SET search_path FROM CURRENT AS $$
    SELECT COALESCE((SELECT asset.auto_renew AND NOT asset.disabled FROM certificate_assets asset
        WHERE asset.tenant_scope_id = $1 AND asset.id = $2 AND asset.deleted_at IS NULL), false)
$$;

-- 当前被网站绑定的证书。
CREATE FUNCTION certificate_asset_bound_551(scope_id uuid, asset_id uuid)
RETURNS boolean LANGUAGE sql STABLE SET search_path FROM CURRENT AS $$
    SELECT EXISTS (
        SELECT 1 FROM (
            SELECT DISTINCT ON (fact.site_id) fact.action, fact.asset_id
            FROM certificate_site_binding_facts fact
            WHERE fact.tenant_scope_id = $1
            ORDER BY fact.site_id, fact.sequence DESC
        ) current_binding
        WHERE current_binding.action = 'bind' AND current_binding.asset_id = $2
    )
$$;

-- 兜底：禁用的证书不能新绑定；仍被绑定的证书不能禁用。
CREATE FUNCTION validate_certificate_asset_disabled_551() RETURNS trigger
LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
BEGIN
    IF TG_TABLE_NAME = 'certificate_assets' THEN
        IF NEW.disabled AND NOT OLD.disabled AND
           certificate_asset_bound_551(NEW.tenant_scope_id, NEW.id) THEN
            RAISE EXCEPTION 'bound certificate asset cannot be disabled' USING ERRCODE='P5511';
        END IF;
        RETURN NEW;
    END IF;
    IF NEW.action = 'bind' AND EXISTS (
        SELECT 1 FROM certificate_assets asset
        WHERE asset.tenant_scope_id = NEW.tenant_scope_id AND asset.id = NEW.asset_id AND asset.disabled
    ) THEN
        RAISE EXCEPTION 'disabled certificate asset cannot be bound' USING ERRCODE='P5512';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER certificate_assets_disabled_551 BEFORE UPDATE OF disabled ON certificate_assets
FOR EACH ROW EXECUTE FUNCTION validate_certificate_asset_disabled_551();
CREATE TRIGGER certificate_site_binding_facts_disabled_551 BEFORE INSERT ON certificate_site_binding_facts
FOR EACH ROW EXECUTE FUNCTION validate_certificate_asset_disabled_551();

-- certificate_asset_bound_551 在触发器里以应用角色调用，保留默认 EXECUTE（与 537 函数一致）。
REVOKE ALL ON FUNCTION validate_certificate_asset_disabled_551() FROM PUBLIC;
