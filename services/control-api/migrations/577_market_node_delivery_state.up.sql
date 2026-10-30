-- 577（fix-mktsiteconf7，占位号，合入时由主会话按集成头顺延并改钉前驱；前驱暂钉本分支的 589_region_catalog_geo_codes）。
-- ①叶子回源鉴权凭据送达的构建失败计数落表（原在进程内存，重启清零）：每个租户作用域一行，记最新发布修订的
--   失败次数、最后失败时间与原因；新修订重新计，成功发起即删行。上限沿用系统重新发布 8 次（Go 侧判断）。
-- ②订阅方对已应用的每个叶子定期调用 supply.site_status，记下“送达节点”状态：
--   node_state ''（未应用/不跟踪）/ delivering（已应用，送达节点中）/ effective（已在节点生效）/ failed（部分失败），
--   node_reason/node_detail 为原因码与细节，next_node_check_at 为下次核对时间（退避），node_check_attempts 为未得出结论的次数。
-- ③通知事件 market.supply.node_delivery_failed（叶子节点送达失败或长时间未生效）+ zh-cn 短信/邮件模板。
-- 用户 10-17：1.0.35 为初始版本、上线全部重装，不做旧版兼容。
LOCK TABLE schema_migrations, site_supply_leaf_sites, notification_event_policies, notification_templates IN ACCESS EXCLUSIVE MODE;

DO $migration_577_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 576 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 576 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=576 AND
        migration_id='576_region_catalog_geo_codes' AND
        checksum_sha256='a1bf4f310b89eaeffd95bf6e6b0f29e54719c3107191b8739b140d75a9c6c81b' AND
        down_checksum_sha256='d21cf9dd984999c6e4e23c301e62593682703914319ef2bff59028d668fed8d4' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR EXISTS (
        SELECT 1 FROM notification_event_policies WHERE event_type = 'market.supply.node_delivery_failed'
       ) THEN
        RAISE EXCEPTION 'migration 577 requires the exact verified 576 release head' USING ERRCODE='P5770';
    END IF;
END;
$migration_577_up$;

CREATE TABLE origin_auth_delivery_build_failures (
    tenant_scope_id uuid PRIMARY KEY REFERENCES access_scopes(id) ON DELETE CASCADE,
    revision bigint NOT NULL CHECK (revision > 0),
    attempts integer NOT NULL CHECK (attempts BETWEEN 1 AND 100),
    last_failed_at timestamptz NOT NULL,
    reason text NOT NULL CHECK (reason IN ('credential_unreadable', 'publication_invalid', 'node_rejected', 'delivery_unavailable'))
);

ALTER TABLE site_supply_leaf_sites
    ADD COLUMN node_state text NOT NULL DEFAULT '' CHECK (node_state IN ('', 'delivering', 'effective', 'failed')),
    ADD COLUMN node_reason text NOT NULL DEFAULT '' CHECK (node_reason = '' OR node_reason ~ '^[a-z0-9_]{1,64}$'),
    ADD COLUMN node_detail text NOT NULL DEFAULT '' CHECK (char_length(node_detail) <= 500),
    ADD COLUMN node_check_attempts integer NOT NULL DEFAULT 0 CHECK (node_check_attempts BETWEEN 0 AND 100),
    ADD COLUMN node_checked_at timestamptz,
    ADD COLUMN next_node_check_at timestamptz;
-- 只有已应用的叶子跟踪送达；送达中必有下次核对时间，结论（生效/失败）不再排期。
ALTER TABLE site_supply_leaf_sites ADD CONSTRAINT site_supply_leaf_sites_node_state_577 CHECK (
    (node_state = '' OR state = 'applied') AND
    (node_state = 'delivering') = (next_node_check_at IS NOT NULL));
CREATE INDEX site_supply_leaf_sites_node_check_577_idx ON site_supply_leaf_sites (next_node_check_at)
    WHERE node_state = 'delivering';

INSERT INTO notification_event_policies(
    event_type, enabled, sms_enabled, email_enabled, repeat_count, interval_hours, supported,
    default_email, default_sms, updated_at
) VALUES ('market.supply.node_delivery_failed', true, true, true, 1, 1, true, true, false, now());

INSERT INTO notification_templates(template_id, version, channel, subject, body, variables, created_at) VALUES
    ('market.supply.node_delivery_failed.zh-cn', 1, 'sms', '',
     '网站{{.domain}}在市场供货{{.supply}}的第{{.revision}}版配置未能在供货方节点生效：{{.reason}}，请到节点市场查看。',
     ARRAY['domain','supply','revision','reason'], '2026-10-28 00:00:00+00'),
    ('market.supply.node_delivery_failed.zh-cn', 1, 'email', '市场订阅配置未在节点生效',
     '网站 {{.domain}} 下发到市场供货 {{.supply}} 的第 {{.revision}} 版配置，供货方已应用，但未能在其节点生效（部分失败）。原因：{{.reason}}。请在节点市场页面查看该网站的下发结果，按原因处理后重新下发，或联系供货方。',
     ARRAY['domain','supply','revision','reason'], '2026-10-28 00:00:00+00');
