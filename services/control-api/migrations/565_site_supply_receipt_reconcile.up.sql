LOCK TABLE schema_migrations, site_supply_leaf_sites, notification_event_policies, notification_templates IN ACCESS EXCLUSIVE MODE;

DO $migration_565_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 564 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 564 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=564 AND
        migration_id='564_deployment_status_error_codes' AND
        checksum_sha256='a83d5a322db203f7ba87f45c9220b9604370dd9478cdd1e109f9dddc53d60eb4' AND
        down_checksum_sha256='28c2e6f74650c037c95cdb007b76246dede2570e60181835c588374f88c58cf8' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR EXISTS (
        SELECT 1 FROM notification_event_policies WHERE event_type = 'market.supply.receipt_unconfirmed'
       ) THEN
        RAISE EXCEPTION 'migration 565 requires the exact verified 564 release head' USING ERRCODE='P5650';
    END IF;
END;
$migration_565_up$;

-- 565（fix-cfgflow2 §2，占位，合入时由主会话改号与改钉前驱）。
-- 订阅下发“待确认”后台对账：外发 commit 前把叶子回执行置为 committing 并记下本次 revision/digest
-- （pending_*），回执写成功就转 applied 并清掉；写失败时行停在 committing，worker（internal/marketsubscribe
-- reconcile.go）过宽限期后以同版本同内容向该叶子补发 commit（叶子按 market-<site>-<revision> 幂等，不重复建站），
-- 成功写回 applied；失败按 next_reconcile_at 退避，达到上限转 inconsistent 并通知持 marketplace.purchase 的平台成员。
ALTER TABLE site_supply_leaf_sites DROP CONSTRAINT site_supply_leaf_sites_state_check;
ALTER TABLE site_supply_leaf_sites ADD CONSTRAINT site_supply_leaf_sites_state_565 CHECK (
    state IN ('pending', 'committing', 'applied', 'failed', 'inconsistent'));
ALTER TABLE site_supply_leaf_sites
    ADD COLUMN pending_revision bigint NOT NULL DEFAULT 0 CHECK (pending_revision >= 0),
    ADD COLUMN pending_digest text NOT NULL DEFAULT '' CHECK (pending_digest = '' OR pending_digest ~ '^[0-9a-f]{64}$'),
    ADD COLUMN reconcile_attempts integer NOT NULL DEFAULT 0 CHECK (reconcile_attempts BETWEEN 0 AND 100),
    ADD COLUMN next_reconcile_at timestamptz;
ALTER TABLE site_supply_leaf_sites ADD CONSTRAINT site_supply_leaf_sites_committing_565 CHECK (
    (state = 'committing') = (pending_revision > 0 AND pending_digest <> '' AND next_reconcile_at IS NOT NULL));
CREATE INDEX site_supply_leaf_sites_reconcile_565_idx ON site_supply_leaf_sites (next_reconcile_at)
    WHERE state = 'committing';

INSERT INTO notification_event_policies(
    event_type, enabled, sms_enabled, email_enabled, repeat_count, interval_hours, supported,
    default_email, default_sms, updated_at
) VALUES ('market.supply.receipt_unconfirmed', true, true, true, 1, 1, true, true, false, now());

INSERT INTO notification_templates(template_id, version, channel, subject, body, variables, created_at) VALUES
    ('market.supply.receipt_unconfirmed.zh-cn', 1, 'sms', '',
     '网站{{.domain}}在市场供货{{.supply}}的第{{.revision}}版配置多次对账仍未确认：{{.reason}}，请到节点市场处理。',
     ARRAY['domain','supply','revision','reason'], '2026-10-27 00:00:00+00'),
    ('market.supply.receipt_unconfirmed.zh-cn', 1, 'email', '市场订阅配置未能确认',
     '网站 {{.domain}} 下发到市场供货 {{.supply}} 的第 {{.revision}} 版配置，叶子已响应但结果多次对账仍未确认，已标记为不一致。原因：{{.reason}}。请在节点市场页面对该网站重新下发，或联系供货方核对。',
     ARRAY['domain','supply','revision','reason'], '2026-10-27 00:00:00+00');
