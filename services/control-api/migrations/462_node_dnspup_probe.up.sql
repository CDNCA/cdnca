LOCK TABLE schema_migrations, notification_event_policies, notification_templates, probe_dnspup_write_requests
    IN ACCESS EXCLUSIVE MODE;

DO $migration_462_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 461 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 461 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=461 AND
        migration_id='461_ban_list_truncation' AND
        checksum_sha256='382e5e63754dcd34c767fb8654ac7620ca60e0481a506bf69474562c2863e6a6' AND
        down_checksum_sha256='79e1d9f8840b9a0e79f16b11fce133c62b39ddc379beb42b1e172492e7d2380b' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR to_regclass(current_schema() || '.node_dnspup_probe_settings') IS NOT NULL OR EXISTS (
        SELECT 1 FROM notification_event_policies WHERE event_type IN ('node.dnspup.unreachable',
            'node.dnspup.recovered', 'probe.dnspup.balance_low', 'probe.dnspup.balance_exhausted')
       ) THEN
        RAISE EXCEPTION 'migration 462 requires the exact verified 461 release head' USING ERRCODE='P4620';
    END IF;
END;
$migration_462_up$;

-- 462（r136 probe-node；占位，预留 462，合入时改号）。
-- Node availability monitoring from dnspup checkpoints (用户 10-22 22:25):
-- with module.probe.dnspup active, every published node IP:port is probed
-- (tcping) from the selected monitoring groups' checkpoints.
--
-- 1. node_dnspup_probe_settings: one row. interval_seconds 0 (off) / 60 /
--    300 (default) / 900; groups and points_per_group pick the checkpoints
--    (default telecom, unicom, mobile × 3); a round fails when more than
--    failure_percent of the answering checkpoints failed, the node's dnspup
--    verdict turns failing after failure_rounds failed rounds and back after
--    recovery_rounds good ones. low_balance: remaining monthly dnspup
--    requests under which the interval triples (budget_state low) and the
--    managers are told; none left (exhausted) stops dnspup node probing.
-- 2. node_dnspup_probe_results: one row per probed IP and round (the
--    availability log), kept 8 days.
-- 3. node_dnspup_probe_states: the node's dnspup verdict. The availability
--    monitor only removes a node from serving when the local probe (failed
--    or stale reports) and a fresh failing dnspup verdict agree; dnspup
--    alone only alerts; no fresh verdict (off, exhausted, paused) falls back
--    to the local probe alone.
-- 4. Notifications node.dnspup.unreachable / node.dnspup.recovered (nodes.manage)
--    and probe.dnspup.balance_low / probe.dnspup.balance_exhausted
--    (system.probe_dnspup.manage).
-- No data is migrated (BATCH-PLUGIN section 9: fresh install).

CREATE TABLE node_dnspup_probe_settings (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    interval_seconds integer NOT NULL DEFAULT 300 CHECK (interval_seconds IN (0, 60, 300, 900)),
    groups text[] NOT NULL DEFAULT ARRAY['telecom', 'unicom', 'mobile'] CHECK (
        cardinality(groups) BETWEEN 1 AND 5 AND groups <@ ARRAY['domestic', 'telecom', 'unicom', 'mobile', 'overseas']),
    points_per_group integer NOT NULL DEFAULT 3 CHECK (points_per_group BETWEEN 1 AND 20),
    failure_percent integer NOT NULL DEFAULT 50 CHECK (failure_percent BETWEEN 1 AND 99),
    failure_rounds integer NOT NULL DEFAULT 3 CHECK (failure_rounds BETWEEN 1 AND 10),
    recovery_rounds integer NOT NULL DEFAULT 1 CHECK (recovery_rounds BETWEEN 1 AND 10),
    low_balance bigint NOT NULL DEFAULT 1000 CHECK (low_balance BETWEEN 0 AND 1000000000),
    budget_state text NOT NULL DEFAULT 'normal' CHECK (budget_state IN ('normal', 'low', 'exhausted')),
    budget_sequence bigint NOT NULL DEFAULT 0 CHECK (budget_sequence >= 0),
    budget_checked_at timestamptz,
    revision bigint NOT NULL DEFAULT 0 CHECK (revision >= 0),
    updated_by_user_id uuid REFERENCES users(id) ON DELETE SET NULL,
    updated_at timestamptz NOT NULL
);
INSERT INTO node_dnspup_probe_settings(singleton, updated_at) VALUES (true, CURRENT_TIMESTAMP);

CREATE TABLE node_dnspup_probe_results (
    node_id uuid NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
    address inet NOT NULL,
    port integer NOT NULL CHECK (port BETWEEN 1 AND 65535),
    observed_at timestamptz NOT NULL CHECK (isfinite(observed_at)),
    total_checks integer NOT NULL CHECK (total_checks BETWEEN 0 AND 100),
    failed_checks integer NOT NULL CHECK (failed_checks BETWEEN 0 AND total_checks),
    failed boolean NOT NULL,
    checkpoints jsonb NOT NULL CHECK (jsonb_typeof(checkpoints) = 'array'),
    PRIMARY KEY (node_id, observed_at, address, port)
);

CREATE TABLE node_dnspup_probe_states (
    node_id uuid PRIMARY KEY REFERENCES nodes(id) ON DELETE CASCADE,
    consecutive_failed integer NOT NULL DEFAULT 0 CHECK (consecutive_failed >= 0),
    consecutive_ok integer NOT NULL DEFAULT 0 CHECK (consecutive_ok >= 0),
    failing boolean NOT NULL DEFAULT false,
    observed_at timestamptz NOT NULL,
    -- The verdict counts for the availability monitor until fresh_until
    -- (two effective rounds + 60 s); afterwards the local probe decides alone.
    fresh_until timestamptz NOT NULL,
    alert_revision bigint NOT NULL DEFAULT 0 CHECK (alert_revision >= 0),
    updated_at timestamptz NOT NULL
);

ALTER TABLE probe_dnspup_write_requests DROP CONSTRAINT probe_dnspup_write_requests_operation_check,
    ADD CONSTRAINT probe_dnspup_write_requests_operation_462_ck CHECK (operation IN ('settings', 'test', 'node_settings'));

INSERT INTO notification_event_policies(
    event_type, enabled, sms_enabled, email_enabled, repeat_count, interval_hours, supported,
    default_email, default_sms, updated_at
) VALUES
    ('node.dnspup.unreachable', true, true, true, 1, 24, true, true, false, now()),
    ('node.dnspup.recovered', true, true, true, 1, 24, true, true, false, now()),
    ('probe.dnspup.balance_low', true, true, true, 1, 24, true, true, false, now()),
    ('probe.dnspup.balance_exhausted', true, true, true, 1, 24, true, true, false, now());

INSERT INTO notification_templates(template_id, version, channel, subject, body, variables, created_at) VALUES
    ('node.dnspup.unreachable.zh-cn', 1, 'sms', '',
     '节点{{.node_name}}（{{.node_ip}}）dnspup 拨测连续失败（{{.failed}}/{{.total}} 个检测点），本机探测正常时不停调度。',
     ARRAY['node_name','node_ip','failed','total'], '2026-10-22 00:00:00+00'),
    ('node.dnspup.unreachable.zh-cn', 1, 'email', 'dnspup 拨测节点不可达：{{.node_name}}',
     '节点 {{.node_name}}（{{.node_ip}}）在 {{.occurred_at}}（UTC）被 dnspup 运营商检测点连续判定不可达（本轮 {{.failed}}/{{.total}} 个检测点失败）。本机探测也失败时节点才会暂停解析；仅 dnspup 失败时只告警。',
     ARRAY['node_name','node_ip','failed','total','occurred_at'], '2026-10-22 00:00:00+00'),
    ('node.dnspup.recovered.zh-cn', 1, 'sms', '',
     '节点{{.node_name}}（{{.node_ip}}）dnspup 拨测已恢复。',
     ARRAY['node_name','node_ip'], '2026-10-22 00:00:00+00'),
    ('node.dnspup.recovered.zh-cn', 1, 'email', 'dnspup 拨测节点已恢复：{{.node_name}}',
     '节点 {{.node_name}}（{{.node_ip}}）在 {{.occurred_at}}（UTC）dnspup 运营商检测点拨测已恢复。',
     ARRAY['node_name','node_ip','occurred_at'], '2026-10-22 00:00:00+00'),
    ('probe.dnspup.balance_low.zh-cn', 1, 'sms', '',
     'dnspup 本月剩余 {{.remaining}} 次，低于预警线 {{.threshold}}，节点拨测已降频，请到 dnspup 充值：{{.link}}',
     ARRAY['remaining','threshold','link'], '2026-10-22 00:00:00+00'),
    ('probe.dnspup.balance_low.zh-cn', 1, 'email', 'dnspup 额度不足，节点拨测已降频',
     'dnspup 本月剩余 {{.remaining}} 次，低于预警线 {{.threshold}}。节点可用性拨测已自动降频。点数请到 dnspup 充值，设置见 {{.link}}。',
     ARRAY['remaining','threshold','link'], '2026-10-22 00:00:00+00'),
    ('probe.dnspup.balance_exhausted.zh-cn', 1, 'sms', '',
     'dnspup 本月额度已用完，节点拨测已停止并回落本机探测，请到 dnspup 充值：{{.link}}',
     ARRAY['link'], '2026-10-22 00:00:00+00'),
    ('probe.dnspup.balance_exhausted.zh-cn', 1, 'email', 'dnspup 额度已用完，节点拨测已停止',
     'dnspup 本月额度已用完，节点可用性拨测已停止，改由节点本机探测判定（不会因缺少拨测数据判节点离线），告警照常。点数请到 dnspup 充值，设置见 {{.link}}。',
     ARRAY['link'], '2026-10-22 00:00:00+00');

REVOKE ALL ON node_dnspup_probe_settings, node_dnspup_probe_results, node_dnspup_probe_states FROM PUBLIC;
GRANT SELECT, UPDATE ON node_dnspup_probe_settings TO cdnca_control_app, cdnca_control_runtime;
GRANT SELECT, INSERT, DELETE ON node_dnspup_probe_results TO cdnca_control_app, cdnca_control_runtime;
GRANT SELECT, INSERT, UPDATE, DELETE ON node_dnspup_probe_states TO cdnca_control_app, cdnca_control_runtime;
