-- 554（fix-codexd2，L08）：主控用量上报的持久投递状态。
-- 每个安装一行：已分配的最大序号（跨重启/时钟回拨单调），以及尚未被授权端确认的那一份报文
-- （固定序号、幂等键、租约序号与签名后的完整 JSON 字节）。重启后先按原字节重发，确认后才分配下一轮；
-- 只有授权端明确拒收（租约未知、序号已占用、幂等冲突）才终结 pending（internal/entitlementsync usage_state.go）。
-- 私钥不进本表。
-- 前驱：本分支头 546（ticket_notification_choices）。547–553 由并行任务占用，合入时守卫改钉 553
-- （count/max 改 553，migration_id 与两个校验和换成 553 的）。
LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;

DO $migration_552_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 551 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 551 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=551 AND
        migration_id='551_certificate_asset_disabled' AND
        checksum_sha256='0584ec0c0f862722d02c643ed15053dd81f8f88f460e9980a3a7b1c51ec4bbf0' AND
        down_checksum_sha256='c7c56bc5bf3c16b34aad054867fdbb4b4905726b657a93672023dfd5be19efd5' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR to_regclass('control_usage_report_state') IS NOT NULL THEN
        RAISE EXCEPTION 'migration 552 requires the exact verified 551 release head' USING ERRCODE='P5520';
    END IF;
END;
$migration_552_up$;

CREATE TABLE control_usage_report_state (
    installation_id uuid PRIMARY KEY,
    last_sequence bigint NOT NULL CHECK (last_sequence >= 0),
    pending_sequence bigint,
    pending_request_id text,
    pending_lease_serial bigint,
    pending_body bytea,
    pending_created_at timestamptz,
    updated_at timestamptz NOT NULL CHECK (isfinite(updated_at)),
    -- pending 各列同有同无；pending 一定是最后分配的那个序号（不越过未确认的报文分配新序号）。
    CONSTRAINT control_usage_report_state_pending_whole CHECK (
        (pending_sequence IS NULL AND pending_request_id IS NULL AND pending_lease_serial IS NULL AND
         pending_body IS NULL AND pending_created_at IS NULL) OR
        (pending_sequence = last_sequence AND pending_sequence > 0 AND pending_lease_serial > 0 AND
         pending_request_id ~ '^control-usage-[0-9a-f-]{36}-[0-9]{1,19}$' AND
         octet_length(pending_body) BETWEEN 2 AND 65536 AND isfinite(pending_created_at)))
);

REVOKE ALL ON control_usage_report_state FROM PUBLIC;
GRANT SELECT, INSERT, UPDATE ON control_usage_report_state TO cdnca_control_app, cdnca_control_runtime;
