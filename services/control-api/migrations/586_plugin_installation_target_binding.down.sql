-- 586 回滚：去掉插件类型与目标绑定唯一约束。
LOCK TABLE schema_migrations, plugin_installation_heads IN ACCESS EXCLUSIVE MODE;

DO $migration_586_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 586 OR
       (SELECT max(version) FROM schema_migrations) <> 586 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=586 AND
        migration_id='586_plugin_installation_target_binding' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 586 down requires the exact verified migration head' USING ERRCODE='P5863';
    END IF;
END;
$migration_586_down$;

DROP TRIGGER plugin_installation_heads_entrypoint_586 ON plugin_installation_heads;
DROP FUNCTION validate_plugin_installation_entrypoint_586();
DROP INDEX plugin_installation_heads_authorization_586_uk;
ALTER TABLE plugin_installation_heads DROP CONSTRAINT plugin_installation_heads_entrypoint_586_check;
ALTER TABLE plugin_installation_heads DROP COLUMN entrypoint_type;
