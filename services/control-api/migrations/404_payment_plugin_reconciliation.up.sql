LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;

DO $migration_404_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 403 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 403 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=403 AND
        migration_id='403_autodefense_store' AND
        checksum_sha256='6cb9d7920a2c62b80d46757bf7405048634dff6aecd73a29f4c6b9f083267ff4' AND
        down_checksum_sha256='2cd498c92848d8b174315148fd867686e27da3b01f6512c1e8285bb0166d26ed' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM notification_event_policies
        WHERE event_type IN ('payment.reconcile.mismatch', 'payment.plugin.alert')
       ) THEN
        RAISE EXCEPTION 'migration 404 requires the exact verified 403 release head' USING ERRCODE='P4040';
    END IF;
END;
$migration_404_up$;

-- 404（r136 pay-recon，BACKLOG-1035b A7；合入时改号，占位 410）。
-- Daily reconciliation of third-party payment plugin channels: once per
-- (channel, UTC day) control-api pulls the plugin's day statement
-- (reconcile action) and compares it with the recharge orders it credited
-- through that channel. Differences are kept per run:
--   remote_only  the statement lists a payment control-api did not credit
--                (a missed notification is first queried and credited the
--                same way as compensation: resolution = credited)
--   local_only   control-api credited an order the statement does not list
--   mismatch     both sides have the order but amount or trade number differ
CREATE TABLE payment_reconcile_runs (
    channel_id uuid NOT NULL REFERENCES payment_channels(id) ON DELETE RESTRICT,
    day date NOT NULL,
    state text NOT NULL CHECK (state IN ('running', 'matched', 'mismatched', 'failed')),
    attempt integer NOT NULL CHECK (attempt BETWEEN 1 AND 5),
    lease_until timestamptz CHECK (lease_until IS NULL OR isfinite(lease_until)),
    statement_count integer NOT NULL DEFAULT 0 CHECK (statement_count >= 0),
    local_count integer NOT NULL DEFAULT 0 CHECK (local_count >= 0),
    mismatch_count integer NOT NULL DEFAULT 0 CHECK (mismatch_count >= 0),
    error_code text NOT NULL DEFAULT '' CHECK (error_code ~ '^[a-z_]{0,64}$'),
    started_at timestamptz NOT NULL CHECK (isfinite(started_at)),
    finished_at timestamptz CHECK (finished_at IS NULL OR (isfinite(finished_at) AND finished_at >= started_at)),
    PRIMARY KEY (channel_id, day),
    CHECK ((state = 'running') = (lease_until IS NOT NULL)),
    CHECK ((state = 'running') = (finished_at IS NULL)),
    CHECK ((state = 'failed') = (error_code <> '')),
    CHECK (state <> 'matched' OR mismatch_count = 0),
    CHECK (state <> 'mismatched' OR mismatch_count > 0)
);
CREATE INDEX payment_reconcile_runs_day_404_idx ON payment_reconcile_runs (day DESC, channel_id);

CREATE TABLE payment_reconcile_mismatches (
    id uuid PRIMARY KEY,
    channel_id uuid NOT NULL,
    day date NOT NULL,
    kind text NOT NULL CHECK (kind IN ('remote_only', 'local_only', 'mismatch')),
    order_ref text NOT NULL CHECK (order_ref ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'),
    order_id uuid REFERENCES recharge_orders_v1(id) ON DELETE RESTRICT,
    local_trade_no text CHECK (local_trade_no IS NULL OR local_trade_no ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'),
    remote_trade_no text CHECK (remote_trade_no IS NULL OR remote_trade_no ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'),
    local_amount_minor bigint CHECK (local_amount_minor IS NULL OR local_amount_minor >= 0),
    remote_amount_minor bigint CHECK (remote_amount_minor IS NULL OR remote_amount_minor >= 0),
    resolution text NOT NULL DEFAULT '' CHECK (resolution IN ('', 'credited')),
    created_at timestamptz NOT NULL CHECK (isfinite(created_at)),
    FOREIGN KEY (channel_id, day) REFERENCES payment_reconcile_runs(channel_id, day) ON DELETE RESTRICT,
    UNIQUE (channel_id, day, kind, order_ref),
    CHECK (kind = 'remote_only' OR (order_id IS NOT NULL AND local_amount_minor IS NOT NULL)),
    CHECK (kind = 'local_only' OR remote_amount_minor IS NOT NULL),
    CHECK (resolution = '' OR kind = 'remote_only')
);

REVOKE ALL ON payment_reconcile_runs, payment_reconcile_mismatches FROM PUBLIC;
GRANT SELECT, INSERT, UPDATE ON payment_reconcile_runs TO cdnca_control_app, cdnca_control_runtime;
GRANT SELECT, INSERT ON payment_reconcile_mismatches TO cdnca_control_app, cdnca_control_runtime;

-- Notification center (platform operations events, to platform members
-- holding billing.payment_channels.manage): a day with differences, and a
-- payment plugin claim control-api refused (plugin.provider.payment_alert).
INSERT INTO notification_event_policies(
    event_type, enabled, sms_enabled, email_enabled, repeat_count, interval_hours, supported,
    default_email, default_sms, updated_at
) VALUES
    ('payment.reconcile.mismatch', true, true, true, 1, 24, true, true, false, now()),
    ('payment.plugin.alert', true, true, true, 1, 24, true, true, false, now());

INSERT INTO notification_templates(template_id, version, channel, subject, body, variables, created_at) VALUES
    ('payment.reconcile.mismatch.zh-cn', 1, 'sms', '',
     '收款通道{{.channel_name}}{{.day}}对账有差异：漏单{{.remote_only}}笔、对方无记录{{.local_only}}笔、金额或单号不符{{.mismatch}}笔，请登录后台核对。',
     ARRAY['channel_name','day','remote_only','local_only','mismatch'], '2026-10-19 00:00:00+00'),
    ('payment.reconcile.mismatch.zh-cn', 1, 'email', '支付对账差异：{{.channel_name}} {{.day}}',
     '收款通道 {{.channel_name}} 在 {{.day}}（UTC）的对账结果与支付插件账单不一致：对方已收款但本地未入账 {{.remote_only}} 笔（已到账的会自动补单）、本地已入账但对方无记录 {{.local_only}} 笔、金额或交易号不符 {{.mismatch}} 笔。请到“收款通道 > 对账结果”核对明细。',
     ARRAY['channel_name','day','remote_only','local_only','mismatch'], '2026-10-19 00:00:00+00'),
    ('payment.plugin.alert.zh-cn', 1, 'sms', '',
     '告警：支付插件{{.plugin_id}}上报的订单{{.order_id}}支付结果未通过核验({{.reason_code}})，未入账。',
     ARRAY['plugin_id','order_id','reason_code'], '2026-10-19 00:00:00+00'),
    ('payment.plugin.alert.zh-cn', 1, 'email', '支付插件告警：{{.plugin_id}}',
     '支付插件 {{.plugin_id}} 上报订单 {{.order_id}} 已支付，但主控核验未通过（原因：{{.reason_code}}），该笔未入账。若频繁出现，请检查插件版本或停用该插件。',
     ARRAY['plugin_id','order_id','reason_code'], '2026-10-19 00:00:00+00');
