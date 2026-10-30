-- 568 回滚：删掉外部验证码本地防重放表。旧版本只依赖服务商侧的一次性校验。
LOCK TABLE schema_migrations, account_login_captcha_replay_568 IN ACCESS EXCLUSIVE MODE;

DO $migration_568_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 568 OR
       (SELECT max(version) FROM schema_migrations) <> 568 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=568 AND
        migration_id='568_account_login_captcha_replay' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 568 down requires the exact verified migration head' USING ERRCODE='P5681';
    END IF;
END;
$migration_568_down$;

DROP TABLE account_login_captcha_replay_568;
