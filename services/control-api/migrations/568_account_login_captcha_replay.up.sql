-- 568（fix-smallfu，主会话 10-28 预留占位）：主控 OTP 登录外部验证码（腾讯 / 极验 v4）本地防重放。
-- 每行是"服务商 + 一次性票据（腾讯 ticket、极验 lot_number）"的 HMAC 摘要，不存票据原文；
-- 同一票据在 expires_at 前第二次用于新建登录挑战一律拒绝（internal/accountloginchallenge captcha_replay.go）。
-- 过期行可被同一摘要覆盖，并在写事务提交后按批有界删除。
-- 前驱：集成头 554（node_bandwidth_alerts）；本分支头 552。合入时由主会话改号连号并改钉前驱
-- （count/max 与 migration_id、两个校验和换成当时的头）。
LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;

DO $migration_568_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 567 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 567 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=567 AND
        migration_id='567_certificate_failure_reason' AND
        checksum_sha256='c56b6376f0fcbf45514391183d30991b2f58cdcf653aa15cfaf117dcedd0a2f7' AND
        down_checksum_sha256='57fc4a9409606e27bad433b61cd9388d69a0bc86ea39d9b3db3fc8c12eaacf3d' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR to_regclass('account_login_captcha_replay_568') IS NOT NULL THEN
        RAISE EXCEPTION 'migration 568 requires the exact verified 567 release head' USING ERRCODE='P5680';
    END IF;
END;
$migration_568_up$;

CREATE TABLE account_login_captcha_replay_568 (
    token_digest bytea PRIMARY KEY CHECK (octet_length(token_digest) = 32),
    provider text NOT NULL CHECK (provider IN ('tencent', 'geetest_v4')),
    used_at timestamptz NOT NULL CHECK (isfinite(used_at)),
    expires_at timestamptz NOT NULL CHECK (isfinite(expires_at) AND expires_at > used_at)
);

CREATE INDEX account_login_captcha_replay_expiry_568 ON account_login_captcha_replay_568(expires_at);

REVOKE ALL ON account_login_captcha_replay_568 FROM PUBLIC;
