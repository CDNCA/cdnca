-- 604 回滚：去掉 API 密钥的插件安装绑定。已有绑定安装的密钥时拒绝回滚（不静默把插件身份变成普通用户密钥）。
LOCK TABLE schema_migrations, api_keys IN ACCESS EXCLUSIVE MODE;

DO $migration_604_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 604 OR
       (SELECT max(version) FROM schema_migrations) <> 604 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=604 AND
        migration_id='604_api_key_plugin_installation' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 604 down requires the exact verified migration head' USING ERRCODE='P6043';
    END IF;
    IF EXISTS (SELECT 1 FROM api_keys WHERE plugin_installation_authorization_id IS NOT NULL) THEN
        RAISE EXCEPTION 'migration 604 down refuses API keys bound to a plugin installation' USING ERRCODE='P6044';
    END IF;
END;
$migration_604_down$;

DROP TRIGGER api_keys_plugin_installation_604 ON api_keys;
DROP FUNCTION validate_api_key_plugin_installation_604();
DROP INDEX api_keys_plugin_installation_604_idx;
ALTER TABLE api_keys
    DROP CONSTRAINT api_keys_plugin_installation_604_fk,
    DROP CONSTRAINT api_keys_plugin_installation_shape_604,
    DROP COLUMN plugin_id,
    DROP COLUMN plugin_installation_id,
    DROP COLUMN plugin_installation_authorization_id;
