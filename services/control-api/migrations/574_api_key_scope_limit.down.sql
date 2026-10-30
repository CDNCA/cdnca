-- 574 回滚：scopes 上限恢复 32。已有超过 32 个权限的密钥时拒绝回滚（不静默截断权限）。
LOCK TABLE schema_migrations, api_keys IN ACCESS EXCLUSIVE MODE;

DO $migration_574_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 574 OR
       (SELECT max(version) FROM schema_migrations) <> 574 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=574 AND
        migration_id='574_api_key_scope_limit' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 574 down requires the exact verified migration head' USING ERRCODE='P5741';
    END IF;
    IF EXISTS (SELECT 1 FROM api_keys WHERE cardinality(scopes) > 32) THEN
        RAISE EXCEPTION 'migration 574 down refuses API keys with more than 32 scopes' USING ERRCODE='P5742';
    END IF;
END;
$migration_574_down$;

ALTER TABLE api_keys
    DROP CONSTRAINT api_keys_scopes_check,
    ADD CONSTRAINT api_keys_scopes_check CHECK (cardinality(scopes) BETWEEN 1 AND 32);
