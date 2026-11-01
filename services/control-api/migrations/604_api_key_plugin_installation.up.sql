-- 604（plugapi-S2，调度预留 control 604；前驱 S1 的 603 dns_records_manage_permission，合入顺序 S1 → S2）：
-- API 密钥可选绑定一个插件安装（插件身份，ADR 0007 §3.2）。
--   plugin_installation_authorization_id / plugin_installation_id / plugin_id 三列同空或同非空；
--   绑定只能在创建时写入、之后不可改；创建时安装必须是本租户 enabled 的安装，installation_id/plugin_id 与 head 一致。
--   安装停用/卸载后不改密钥行：鉴权时实时校验 head.status='enabled'（internal/apikey AuthenticateWithKeyID），
--   新请求立即 401，恢复安装后密钥重新可用；吊销密钥仍走原生命周期。
-- 前驱：603（dns_records_manage_permission，plugapi-S1）。
LOCK TABLE schema_migrations, api_keys, plugin_installation_heads IN ACCESS EXCLUSIVE MODE;

DO $migration_604_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 603 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 603 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=603 AND
        migration_id='603_dns_records_manage_permission' AND
        checksum_sha256='3e520ea363b24824a25b2239569ea6b9c06f09eab8f58ef69f6c31e280a31ccd' AND
        down_checksum_sha256='606bf2c9d0e06fdeb283c0a26a35d451929bbcfa768d11689d9428ec39a10550' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name='api_keys' AND column_name='plugin_installation_authorization_id'
       ) THEN
        RAISE EXCEPTION 'migration 604 requires the exact verified 603 release head' USING ERRCODE='P6040';
    END IF;
END;
$migration_604_up$;

ALTER TABLE api_keys
    ADD COLUMN plugin_installation_authorization_id uuid,
    ADD COLUMN plugin_installation_id uuid,
    ADD COLUMN plugin_id text,
    ADD CONSTRAINT api_keys_plugin_installation_shape_604
        CHECK ((plugin_installation_authorization_id IS NULL AND plugin_installation_id IS NULL AND plugin_id IS NULL) OR
               (plugin_installation_authorization_id IS NOT NULL AND plugin_installation_id IS NOT NULL AND
                plugin_id IS NOT NULL)),
    ADD CONSTRAINT api_keys_plugin_installation_604_fk
        FOREIGN KEY (scope_id, plugin_installation_authorization_id)
        REFERENCES plugin_installation_heads(tenant_scope_id, authorization_id) ON DELETE RESTRICT;

CREATE INDEX api_keys_plugin_installation_604_idx
    ON api_keys(scope_id, plugin_installation_authorization_id)
    WHERE plugin_installation_authorization_id IS NOT NULL;

CREATE FUNCTION validate_api_key_plugin_installation_604()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    head_installation_id uuid;
    head_plugin_id text;
    head_status text;
BEGIN
    IF TG_OP = 'UPDATE' THEN
        IF ROW(NEW.plugin_installation_authorization_id, NEW.plugin_installation_id, NEW.plugin_id) IS DISTINCT FROM
           ROW(OLD.plugin_installation_authorization_id, OLD.plugin_installation_id, OLD.plugin_id) THEN
            RAISE EXCEPTION 'API key plugin installation binding is immutable' USING ERRCODE='P6041';
        END IF;
        RETURN NEW;
    END IF;
    IF NEW.plugin_installation_authorization_id IS NULL THEN
        RETURN NEW;
    END IF;
    SELECT head.installation_id, head.plugin_id, head.status
    INTO head_installation_id, head_plugin_id, head_status
    FROM plugin_installation_heads head
    WHERE head.tenant_scope_id=NEW.scope_id AND head.authorization_id=NEW.plugin_installation_authorization_id
    FOR SHARE;
    IF NOT FOUND OR head_status IS DISTINCT FROM 'enabled' OR
       head_installation_id IS DISTINCT FROM NEW.plugin_installation_id OR
       head_plugin_id IS DISTINCT FROM NEW.plugin_id THEN
        RAISE EXCEPTION 'API key plugin binding is not an enabled installation of this tenant' USING ERRCODE='P6042';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER api_keys_plugin_installation_604
BEFORE INSERT OR UPDATE ON api_keys
FOR EACH ROW EXECUTE FUNCTION validate_api_key_plugin_installation_604();

REVOKE ALL ON FUNCTION validate_api_key_plugin_installation_604() FROM PUBLIC;
