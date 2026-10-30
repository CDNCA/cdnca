LOCK TABLE schema_migrations, notification_event_policies, notification_templates IN ACCESS EXCLUSIVE MODE;

DO $migration_440_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 439 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 439 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=439 AND
        migration_id='439_market_complaint_notices' AND
        checksum_sha256='1165c0df8220c4b5e9c385bb2734f176ed8dbc7da4edfe8a8508482ded48e039' AND
        down_checksum_sha256='1a20978565668bb12c43091033ef38faf40f7ba5db8149ae0e7a1eb1bce0dae3' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR EXISTS (
        SELECT 1 FROM notification_event_policies WHERE event_type IN ('market.node.action', 'market.site.paused', 'market.site.resumed')
       ) OR to_regclass(current_schema() || '.market_node_action_queue') IS NOT NULL THEN
        RAISE EXCEPTION 'migration 440 requires the exact verified 439 release head' USING ERRCODE='P4400';
    END IF;
END;
$migration_440_up$;

-- 440（r136 ML-23/ML-24，ADR 0012 §19.3/§19.4；本地连号 431+1，合入时改号，前一版 431_market_supply_limits）。
--
-- 1. market_node_action_queue: the leaf's outbox of whole-node actions on
-- nodes of hidden market supply line groups. internal/autodefense writes it
-- in the ingest transaction (node_event of every source, and automatic
-- defence L4/L5 verdicts on market tenant sites with the tenant's market key
-- and site); internal/marketprobe signs and posts the unreported rows to the
-- market once a minute (cdnca.market.nodeaction/v1) and prunes them after a
-- day (the market refuses older actions). No client address is kept.
CREATE TABLE market_node_action_queue (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    node_id uuid NOT NULL,
    node_pool_ref text NOT NULL CHECK (char_length(node_pool_ref) BETWEEN 1 AND 128),
    occurred_at timestamptz NOT NULL,
    source text NOT NULL CHECK (source IN ('autodefense', 'ddos', 'l4guard', 'xdp')),
    kind text NOT NULL CHECK (kind ~ '^[a-z][a-z0-9_]{0,63}$'),
    level smallint NOT NULL CHECK (level BETWEEN 0 AND 5),
    count bigint NOT NULL CHECK (count BETWEEN 1 AND 1000000),
    market_key text CHECK (market_key ~ '^[0-9a-f]{24}$'),
    site_id uuid,
    created_at timestamptz NOT NULL,
    -- Claimed into one signed report (its report_id) before sending, so a
    -- retry after a lost answer resends the same report and the market drops
    -- it as a replay; reported_at once the market answered.
    report_id uuid,
    reported_at timestamptz,
    CHECK ((market_key IS NULL) = (site_id IS NULL)),
    CHECK (reported_at IS NULL OR report_id IS NOT NULL),
    CHECK (site_id IS NULL OR (source = 'autodefense' AND level >= 4))
);
CREATE INDEX market_node_action_queue_pending_idx ON market_node_action_queue (report_id, id) WHERE reported_at IS NULL;
CREATE INDEX market_node_action_queue_created_idx ON market_node_action_queue (created_at);
REVOKE ALL ON market_node_action_queue FROM PUBLIC;
GRANT SELECT, INSERT, UPDATE, DELETE ON market_node_action_queue TO cdnca_control_app, cdnca_control_runtime;

-- 2. Three more node market notices (430 seeded the first 14): a whole-node
-- action on a supply node (to every subscriber of every supply with it, no
-- site, no client), and a same-site pause / resume (owner with its leaf site,
-- suppliers with the downstream reference). Same delivery as 430: members
-- choose channels per event, email on by default, SMS off.
INSERT INTO notification_event_policies(
    event_type, enabled, sms_enabled, email_enabled, repeat_count, interval_hours, supported,
    default_email, default_sms, updated_at
) VALUES
    ('market.node.action', true, true, true, 1, 24, true, true, false, now()),
    ('market.site.paused', true, true, true, 1, 24, true, true, false, now()),
    ('market.site.resumed', true, true, true, 1, 24, true, true, false, now());

INSERT INTO notification_templates(template_id, version, channel, subject, body, variables, created_at) VALUES
    ('market.node.action.zh-cn', 1, 'sms', '', '节点市场供给{{.offer}}所在节点（{{.region}}/{{.carrier}}）{{.at}}发生整节点处置：{{.source}}/{{.event}}。', ARRAY['offer','region','carrier','source','event','at'], '2026-10-22 00:00:00+00'),
    ('market.node.action.zh-cn', 1, 'email', '节点市场：供给 {{.offer}} 的节点发生整节点处置', '你订阅的供给 {{.offer}} 中一个节点（地区 {{.region}}，运营商 {{.carrier}}）于 {{.at}} 发生整节点处置（{{.source}}/{{.event}}，如内核封禁、XDP 切换），该节点上的所有站点都可能受影响。同一节点同类处置每小时最多通知一次；不提供被攻击站点与客户端信息。', ARRAY['offer','region','carrier','source','event','at'], '2026-10-22 00:00:00+00'),
    ('market.site.paused.zh-cn', 1, 'sms', '', '节点市场供给{{.offer}}（订阅{{.subscription}}，下游{{.downstream}}）站点{{.site}}在池{{.pool}}上24小时内整节点处置{{.count}}次，已自动暂停调度。', ARRAY['offer','subscription','site','count','pool','downstream'], '2026-10-22 00:00:00+00'),
    ('market.site.paused.zh-cn', 1, 'email', '节点市场：站点 {{.site}} 在供给上已自动暂停', '供给 {{.offer}}（订阅 {{.subscription}}，下游编号 {{.downstream}}）的叶子站点 {{.site}} 在节点池 {{.pool}} 上 24 小时内触发整节点处置 {{.count}} 次，超过平台上限，已在这条供给上自动暂停调度；有备用供给的站点会切到备用供给。24 小时内次数回落后，可由开启自动暂停的供货商恢复。', ARRAY['offer','subscription','site','count','pool','downstream'], '2026-10-22 00:00:00+00'),
    ('market.site.resumed.zh-cn', 1, 'sms', '', '节点市场供给{{.offer}}（订阅{{.subscription}}，下游{{.downstream}}）站点{{.site}}在池{{.pool}}上已恢复调度（暂停时{{.count}}次）。', ARRAY['offer','subscription','site','count','pool','downstream'], '2026-10-22 00:00:00+00'),
    ('market.site.resumed.zh-cn', 1, 'email', '节点市场：站点 {{.site}} 已恢复调度', '供给 {{.offer}}（订阅 {{.subscription}}，下游编号 {{.downstream}}）的叶子站点 {{.site}} 在节点池 {{.pool}} 上的自动暂停（暂停时 24 小时内 {{.count}} 次）已解除，恢复调度，整节点处置次数从现在重新计算。', ARRAY['offer','subscription','site','count','pool','downstream'], '2026-10-22 00:00:00+00');
