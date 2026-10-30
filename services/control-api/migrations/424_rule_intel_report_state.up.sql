LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;

DO $migration_424_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 423 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 423 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=423 AND
        migration_id='423_waf_adapt' AND
        checksum_sha256='a96f39b3ce63fc7fb8325e530bef43bd58526c006db914409cd1960ad2fbbe7c' AND
        down_checksum_sha256='938c271f6d5053acf34337408443fbd02d3077aac719f48c9c3f5d8d08acb2ba' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR to_regclass(current_schema() || '.rule_intel_report_state') IS NOT NULL THEN
        RAISE EXCEPTION 'migration 424 requires the exact verified 423 release head' USING ERRCODE='P4240';
    END IF;
END;
$migration_424_up$;

-- 416（r136 ri-08，占位号：合入时改为预留的 420）。主控 → 授权端规则情报上报
-- （ADR 0011 §4.3，cdnca.rule-intel-report/v1）的状态行：每安装一行，记最近一份
-- 报告（已脱敏的正文，用于同一身份重试）、序号、投递状态与授权端收据计数。
-- 超限（体积/条数/每天次数）只记状态顺延，不截断。开关在平台“其他设置”
-- rule_intel_contribution（默认开）。
CREATE TABLE rule_intel_report_state (
    installation_id uuid PRIMARY KEY,
    sequence bigint NOT NULL CHECK (sequence > 0),
    request_id text NOT NULL CHECK (char_length(request_id) BETWEEN 1 AND 128),
    observed_at timestamptz NOT NULL CHECK (isfinite(observed_at)),
    report jsonb NOT NULL CHECK (jsonb_typeof(report) = 'object'),
    report_digest bytea NOT NULL CHECK (octet_length(report_digest) = 32),
    report_bytes bigint NOT NULL CHECK (report_bytes >= 0),
    section_counts jsonb NOT NULL CHECK (jsonb_typeof(section_counts) = 'object'),
    status text NOT NULL CHECK (status IN ('pending', 'sent', 'failed', 'deferred_too_large',
        'deferred_rate_limited', 'disabled')),
    sent_at timestamptz CHECK (sent_at IS NULL OR isfinite(sent_at)),
    sent_day bigint NOT NULL DEFAULT 0 CHECK (sent_day >= 0),
    sent_today smallint NOT NULL DEFAULT 0 CHECK (sent_today BETWEEN 0 AND 32),
    attempts integer NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    next_attempt_at timestamptz NOT NULL CHECK (isfinite(next_attempt_at)),
    receipt_id uuid,
    accepted bigint NOT NULL DEFAULT 0 CHECK (accepted >= 0),
    blocked bigint NOT NULL DEFAULT 0 CHECK (blocked >= 0),
    dropped bigint NOT NULL DEFAULT 0 CHECK (dropped >= 0),
    fragments bigint NOT NULL DEFAULT 0 CHECK (fragments >= 0),
    local_dropped bigint NOT NULL DEFAULT 0 CHECK (local_dropped >= 0),
    last_error text NOT NULL DEFAULT '' CHECK (char_length(last_error) <= 200),
    updated_at timestamptz NOT NULL CHECK (isfinite(updated_at)),
    -- sent_at/receipt_id 是当前这份报告的送达记录（prepare 新报告时清空）；顺延、关闭、汇总失败不动它。
    CHECK (status <> 'sent' OR (sent_at IS NOT NULL AND receipt_id IS NOT NULL))
);

REVOKE ALL ON rule_intel_report_state FROM PUBLIC;
GRANT SELECT, INSERT, UPDATE ON rule_intel_report_state TO cdnca_control_app, cdnca_control_runtime;
