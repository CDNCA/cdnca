-- 683（前驱 682_registration_username_required）。
-- 内置图形验证码改为绑定浏览器：取图时下发 HttpOnly cookie（cdnca_captcha_bind），库里只存它的
-- 键控摘要 binding_digest（与 answer_digest 同一把 HMAC 密钥，32 字节）；消费时要求 cookie 摘要一致。
-- 来源 IP（source_ip）照旧记录，只用于按 IP 限流取图，不再是消费条件：主控前面套 CDN 且未配回源鉴权时，
-- 取图和提交的来源 IP 是不同的边缘节点。升级前已签发、没有 binding_digest 的图形码直接视为无效
-- （有效期 5 分钟，用户换一张即可）。错误码：头检查 P6830；down 头检查 P6831。
LOCK TABLE schema_migrations, identity_login_captchas IN ACCESS EXCLUSIVE MODE;

DO $migration_683_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 682 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 682 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=682 AND
        migration_id='682_registration_username_required' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR EXISTS (
        SELECT 1 FROM information_schema.columns WHERE table_schema=current_schema() AND
            table_name='identity_login_captchas' AND column_name='binding_digest'
       ) THEN
        RAISE EXCEPTION 'migration 683 requires the exact verified 682 release head' USING ERRCODE='P6830';
    END IF;
END;
$migration_683_up$;

ALTER TABLE identity_login_captchas
    ADD COLUMN binding_digest bytea,
    ADD CONSTRAINT identity_login_captchas_binding_683_check CHECK (
        binding_digest IS NULL OR octet_length(binding_digest) = 32
    );
