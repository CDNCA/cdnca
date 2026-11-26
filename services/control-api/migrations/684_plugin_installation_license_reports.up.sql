-- 684（前驱 683_login_captcha_binding）。
-- 插件安装生命周期回执（确认安装/升级/暂停/恢复/卸载）向授权端回报的送达确认。本机写入提交后再回报授权端；
-- 回报失败时本机状态照旧生效，回执留在「未送达」里，由后台、详情读取时按 to_revision 顺序原样补报
-- （同一回执的签名请求逐字节相同，授权端按幂等键回放，不会记两次）。
-- - 只追加：一行即授权端已签收该回执；lifecycle_revision 是授权端签名回执里的授权修订号，NULL 表示迁移前的回执
-- （见下方回填）。
-- - 回填：30 天前的旧回执视为已送达（授权端只收 30 天内的新回执）；近 30 天的留作未送达，升级后补报一次——
-- 已送达的由授权端按幂等键回放签收，未送达的（如 1132 那次暂停）补上。
-- - 补报退避：后台每轮每个授权只取最早一条未签收回执；这条补报失败时只给它记失败
-- 次数与下次尝试时间，按次数单独退避，其他授权照常补报；到期的按上次尝试时间轮转（没试过的在前）。
-- 签收后该授权的下一条回执没有退避记录，立即可补。写操作与打开详情仍立即补报，不看退避。
-- 错误码：头检查 P6840；只追加 P6841；down 头检查 P6842。
LOCK TABLE schema_migrations, plugin_installation_receipts IN ACCESS EXCLUSIVE MODE;

DO $migration_684_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 683 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 683 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=683 AND
        migration_id='683_login_captcha_binding' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR to_regclass('plugin_installation_license_reports') IS NOT NULL THEN
        RAISE EXCEPTION 'migration 684 requires the exact verified 683 release head' USING ERRCODE='P6840';
    END IF;
END;
$migration_684_up$;

CREATE TABLE plugin_installation_license_reports (
    receipt_id uuid PRIMARY KEY REFERENCES plugin_installation_receipts(id) ON DELETE RESTRICT,
    lifecycle_revision bigint CHECK (lifecycle_revision IS NULL OR lifecycle_revision > 0),
    reported_at timestamptz NOT NULL
);

CREATE FUNCTION protect_plugin_installation_license_report_684()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'plugin installation license reports are append-only' USING ERRCODE = 'P6841';
END;
$$;

CREATE TRIGGER plugin_installation_license_reports_append_only_684
BEFORE UPDATE OR DELETE ON plugin_installation_license_reports
FOR EACH ROW EXECUTE FUNCTION protect_plugin_installation_license_report_684();

CREATE TABLE plugin_installation_license_report_attempts (
    receipt_id uuid PRIMARY KEY REFERENCES plugin_installation_receipts(id) ON DELETE RESTRICT,
    failures integer NOT NULL CHECK (failures > 0),
    last_attempted_at timestamptz NOT NULL,
    next_attempt_at timestamptz NOT NULL CHECK (next_attempt_at >= last_attempted_at)
);

INSERT INTO plugin_installation_license_reports(receipt_id, lifecycle_revision, reported_at)
SELECT receipt.id, NULL, receipt.occurred_at FROM plugin_installation_receipts receipt
WHERE receipt.occurred_at < transaction_timestamp() - interval '30 days';

REVOKE ALL ON plugin_installation_license_reports FROM PUBLIC;
REVOKE ALL ON plugin_installation_license_report_attempts FROM PUBLIC;
