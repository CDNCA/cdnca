-- 551 回滚：去掉证书禁用。已有禁用的证书或禁用/启用写请求时拒绝回滚（回滚会悄悄把禁用的证书恢复成可用）。
LOCK TABLE schema_migrations, certificate_assets, certificate_asset_write_requests, certificate_site_binding_facts
    IN ACCESS EXCLUSIVE MODE;

DO $migration_551_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 551 OR
       (SELECT max(version) FROM schema_migrations) <> 551 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=551 AND
        migration_id='551_certificate_asset_disabled' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 551 down requires the exact verified migration head' USING ERRCODE='P5513';
    END IF;
    IF EXISTS (SELECT 1 FROM certificate_assets WHERE disabled) OR
       EXISTS (SELECT 1 FROM certificate_asset_write_requests
               WHERE operation IN ('certificate.asset.enable', 'certificate.asset.disable')) THEN
        RAISE EXCEPTION 'migration 551 rollback would drop certificate disable state' USING ERRCODE='P5514';
    END IF;
END;
$migration_551_down$;

DROP TRIGGER certificate_site_binding_facts_disabled_551 ON certificate_site_binding_facts;
DROP TRIGGER certificate_assets_disabled_551 ON certificate_assets;
DROP FUNCTION validate_certificate_asset_disabled_551();
DROP FUNCTION certificate_asset_bound_551(uuid, uuid);

CREATE OR REPLACE FUNCTION certificate_asset_auto_renew_537(scope_id uuid, asset_id uuid)
RETURNS boolean LANGUAGE sql STABLE SET search_path FROM CURRENT AS $$
    SELECT COALESCE((SELECT asset.auto_renew FROM certificate_assets asset
        WHERE asset.tenant_scope_id = $1 AND asset.id = $2 AND asset.deleted_at IS NULL), false)
$$;

ALTER TABLE certificate_asset_write_requests
    DROP CONSTRAINT certificate_asset_write_requests_operation_check;
ALTER TABLE certificate_asset_write_requests
    ADD CONSTRAINT certificate_asset_write_requests_operation_check CHECK (operation IN (
        'certificate.asset.import', 'certificate.asset.activate', 'certificate.asset.revoke',
        'certificate.asset.delete', 'certificate.asset.bind', 'certificate.asset.unbind',
        'certificate.asset.rewrap', 'certificate.auto_renew.update'
    ));

ALTER TABLE certificate_assets DROP COLUMN disabled;
