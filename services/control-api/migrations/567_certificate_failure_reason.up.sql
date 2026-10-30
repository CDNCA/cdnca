-- 567（fix-cfl-a2，竞品 10-27 第 10 条“修复证书签发原因显示不完整”；占位，前驱钉本分支 568，合入时由主会话改号与改钉）。
-- 申请记录的“失败原因”此前只有分类码（failure_code / outbox last_error_code），CA 返回的具体原因只进日志。
-- 新增 CA 原因文本：acmeworker.PublicReason 生成（只取 ACME problem detail，URL/邮箱/令牌已替换，无控制字符，≤512 字符）。
--   certificate_orders.failure_reason：订单失败时与 failure_code 同时写入；签发成功清空。
--   dns_acme_outbox.last_error_reason：重试中的最近一次原因，与 last_error_code 同生同灭。
LOCK TABLE schema_migrations, certificate_orders, dns_acme_outbox IN ACCESS EXCLUSIVE MODE;

DO $migration_567_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 566 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 566 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=566 AND
        migration_id='566_cache_ban_history_retention' AND
        checksum_sha256='08732a075b749f1f5f20cf5bc352e0de8f8e78812b110ed999ccb11208fa5e1a' AND
        down_checksum_sha256='4e712c16cb69fcf830a9503eec1cfccf85c934146beaf1b54beb69120b5e9c5c' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR EXISTS (SELECT 1 FROM information_schema.columns
           WHERE table_schema = current_schema() AND table_name = 'certificate_orders' AND column_name = 'failure_reason') THEN
        RAISE EXCEPTION 'migration 567 requires the exact verified 568 head' USING ERRCODE='P5670';
    END IF;
END;
$migration_567_up$;

ALTER TABLE certificate_orders
    ADD COLUMN failure_reason text CHECK (failure_reason IS NULL OR (
        char_length(failure_reason) BETWEEN 1 AND 512 AND failure_reason = btrim(failure_reason) AND
        failure_reason !~ '[[:cntrl:]]')),
    ADD CONSTRAINT certificate_orders_failure_reason_567 CHECK (failure_reason IS NULL OR failure_code IS NOT NULL);

ALTER TABLE dns_acme_outbox
    ADD COLUMN last_error_reason text CHECK (last_error_reason IS NULL OR (
        char_length(last_error_reason) BETWEEN 1 AND 512 AND last_error_reason = btrim(last_error_reason) AND
        last_error_reason !~ '[[:cntrl:]]')),
    ADD CONSTRAINT dns_acme_outbox_last_error_reason_567 CHECK (last_error_reason IS NULL OR last_error_code IS NOT NULL);
