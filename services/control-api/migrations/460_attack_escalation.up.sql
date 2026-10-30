LOCK TABLE schema_migrations, node_line_groups, package_products, sites, dns_cname_retargets,
    aggregated_edge_switch_events, edge_system_republication_heads, edge_system_republication_attempts,
    edge_system_revision_segments, notification_event_policies, notification_templates IN ACCESS EXCLUSIVE MODE;

DO $migration_460_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 459 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 459 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=459 AND
        migration_id='459_tenant_system_role_grants' AND
        checksum_sha256='c4772c854d5294193c6d91b858b5a3b76e4ca809baf8a20f8fbc2e5c966c20af' AND
        down_checksum_sha256='aa0701eeab00c053ac7f597ec7e54912917143dc87924a033367b167ac607547' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR to_regclass(current_schema() || '.escalate_package_policies') IS NOT NULL THEN
        RAISE EXCEPTION 'migration 460 requires the exact verified 459 release head' USING ERRCODE='P4600';
    END IF;
END;
$migration_460_up$;

-- 460（r136 esc-core，攻击自动升级 module.escalate；主会话预留 control 460，守卫指 459）。
-- 用户 10-22 18:40/19:00/19:10：A 普通线路组 → B 高防 → C 无限防或站长自己的 CF → D 黑洞。
-- A/B/C 由套餐所有者配置；线路组可标等级，上级授权给下级哪些线路组，下级只能在授权范围里挑。
-- 线路组表与套餐 spec 都有严格守卫（234 protect_node_line_group、090 spec 键集），所以等级、
-- 授权和 A/B/C 放在独立表里：A = 套餐 spec 的 node_group_id，这里只存 B/C。

-- 线路组等级。没有行 = 普通（normal）。只有线路组所在 scope 能标。
CREATE TABLE node_line_group_tiers (
    tenant_scope_id uuid NOT NULL,
    line_group_id uuid NOT NULL,
    tier text NOT NULL CHECK (tier IN ('normal', 'high_defense', 'unlimited')),
    updated_by_user_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    updated_at timestamptz NOT NULL CHECK (isfinite(updated_at)),
    PRIMARY KEY (tenant_scope_id, line_group_id),
    FOREIGN KEY (tenant_scope_id, line_group_id) REFERENCES node_line_groups(tenant_scope_id, id) ON DELETE RESTRICT
);

-- 线路组授权给下级。grantor 是线路组所有者，或持有 may_regrant 的有效授权（中间代理继续授权）。
-- 同一线路组每个下级只有一条有效授权，授权关系是一棵树（不会成环），撤销时递归撤下游。
-- 撤销只写 revoked_at，不删行。
CREATE TABLE node_line_group_grants (
    id uuid PRIMARY KEY,
    owner_scope_id uuid NOT NULL,
    line_group_id uuid NOT NULL,
    grantor_scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE RESTRICT,
    grantee_scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE RESTRICT,
    may_regrant boolean NOT NULL,
    created_by_user_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    created_at timestamptz NOT NULL CHECK (isfinite(created_at)),
    revoked_at timestamptz CHECK (revoked_at IS NULL OR (isfinite(revoked_at) AND revoked_at >= created_at)),
    revoked_by_user_id uuid REFERENCES users(id) ON DELETE RESTRICT,
    FOREIGN KEY (owner_scope_id, line_group_id) REFERENCES node_line_groups(tenant_scope_id, id) ON DELETE RESTRICT,
    CHECK (grantee_scope_id <> grantor_scope_id AND grantee_scope_id <> owner_scope_id),
    CHECK ((revoked_at IS NULL) = (revoked_by_user_id IS NULL))
);
CREATE UNIQUE INDEX node_line_group_grants_active_key
    ON node_line_group_grants (owner_scope_id, line_group_id, grantee_scope_id) WHERE revoked_at IS NULL;
CREATE INDEX node_line_group_grants_grantor_idx
    ON node_line_group_grants (owner_scope_id, line_group_id, grantor_scope_id) WHERE revoked_at IS NULL;

-- 某 scope 能否使用线路组：自己的，或持有有效授权（线路组未删除）。
CREATE FUNCTION scope_may_use_line_group_460(checked_scope uuid, group_owner uuid, group_id uuid)
RETURNS boolean LANGUAGE sql STABLE AS $$
    SELECT EXISTS (SELECT 1 FROM node_line_groups line_group
        WHERE line_group.tenant_scope_id = group_owner AND line_group.id = group_id AND line_group.deleted_at IS NULL)
    AND (checked_scope = group_owner OR EXISTS (SELECT 1 FROM node_line_group_grants grant_row
        WHERE grant_row.owner_scope_id = group_owner AND grant_row.line_group_id = group_id
          AND grant_row.grantee_scope_id = checked_scope AND grant_row.revoked_at IS NULL))
$$;

CREATE FUNCTION guard_node_line_group_grant_460() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'UPDATE' THEN
        IF ROW(NEW.id, NEW.owner_scope_id, NEW.line_group_id, NEW.grantor_scope_id, NEW.grantee_scope_id,
               NEW.may_regrant, NEW.created_by_user_id, NEW.created_at) IS DISTINCT FROM
           ROW(OLD.id, OLD.owner_scope_id, OLD.line_group_id, OLD.grantor_scope_id, OLD.grantee_scope_id,
               OLD.may_regrant, OLD.created_by_user_id, OLD.created_at) OR OLD.revoked_at IS NOT NULL THEN
            RAISE EXCEPTION 'line group grants only change by revocation' USING ERRCODE='P4602';
        END IF;
        RETURN NEW;
    END IF;
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'line group grants are kept' USING ERRCODE='P4602';
    END IF;
    IF NEW.revoked_at IS NOT NULL OR NOT EXISTS (SELECT 1 FROM node_line_groups line_group
        WHERE line_group.tenant_scope_id = NEW.owner_scope_id AND line_group.id = NEW.line_group_id
          AND line_group.deleted_at IS NULL) THEN
        RAISE EXCEPTION 'line group grant needs a live line group' USING ERRCODE='P4603';
    END IF;
    IF NEW.grantor_scope_id <> NEW.owner_scope_id AND NOT EXISTS (SELECT 1 FROM node_line_group_grants upstream
        WHERE upstream.owner_scope_id = NEW.owner_scope_id AND upstream.line_group_id = NEW.line_group_id
          AND upstream.grantee_scope_id = NEW.grantor_scope_id AND upstream.may_regrant AND upstream.revoked_at IS NULL) THEN
        RAISE EXCEPTION 'grantor may not grant this line group' USING ERRCODE='P4603';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER node_line_group_grants_guard_460
BEFORE INSERT OR UPDATE OR DELETE ON node_line_group_grants
FOR EACH ROW EXECUTE FUNCTION guard_node_line_group_grant_460();

-- 套餐的攻击自动升级策略（套餐所有者配置）。A = spec.node_group_id；B 须为高防组、C 须为无限防组，
-- 且是所有者可用的线路组。c_cloudflare：C 级允许改用站点已绑定且已同步的站长自己的 CF。
-- thresholds（Go 校验）：{"b"|"c"|"d": {"qps"|"bps": {"default","min","max"}}}，0 = 该指标不触发；
-- 站长只能在 [min,max] 内覆盖。
CREATE TABLE escalate_package_policies (
    product_id uuid PRIMARY KEY REFERENCES package_products(id) ON DELETE RESTRICT,
    owner_scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE RESTRICT,
    b_owner_scope_id uuid,
    b_line_group_id uuid,
    c_owner_scope_id uuid,
    c_line_group_id uuid,
    c_cloudflare boolean NOT NULL DEFAULT false,
    blackhole_enabled boolean NOT NULL DEFAULT true,
    thresholds jsonb NOT NULL CHECK (jsonb_typeof(thresholds) = 'object'),
    sustain_seconds integer NOT NULL CHECK (sustain_seconds BETWEEN 10 AND 3600),
    recover_permille integer NOT NULL CHECK (recover_permille BETWEEN 100 AND 900),
    min_dwell_seconds integer NOT NULL CHECK (min_dwell_seconds BETWEEN 60 AND 86400),
    revision bigint NOT NULL CHECK (revision > 0),
    updated_by_user_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    updated_at timestamptz NOT NULL CHECK (isfinite(updated_at)),
    FOREIGN KEY (b_owner_scope_id, b_line_group_id) REFERENCES node_line_groups(tenant_scope_id, id) ON DELETE RESTRICT,
    FOREIGN KEY (c_owner_scope_id, c_line_group_id) REFERENCES node_line_groups(tenant_scope_id, id) ON DELETE RESTRICT,
    CHECK ((b_owner_scope_id IS NULL) = (b_line_group_id IS NULL)),
    CHECK ((c_owner_scope_id IS NULL) = (c_line_group_id IS NULL)),
    CHECK (b_line_group_id IS NULL OR c_line_group_id IS NULL OR b_line_group_id <> c_line_group_id)
);
CREATE INDEX escalate_package_policies_b_idx ON escalate_package_policies (b_owner_scope_id, b_line_group_id)
    WHERE b_line_group_id IS NOT NULL;
CREATE INDEX escalate_package_policies_c_idx ON escalate_package_policies (c_owner_scope_id, c_line_group_id)
    WHERE c_line_group_id IS NOT NULL;

CREATE FUNCTION guard_escalate_package_policy_460() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.b_line_group_id IS NOT NULL AND (
        NOT scope_may_use_line_group_460(NEW.owner_scope_id, NEW.b_owner_scope_id, NEW.b_line_group_id) OR
        COALESCE((SELECT tier FROM node_line_group_tiers WHERE tenant_scope_id = NEW.b_owner_scope_id
            AND line_group_id = NEW.b_line_group_id), 'normal') <> 'high_defense') THEN
        RAISE EXCEPTION 'level B needs a usable high defense line group' USING ERRCODE='P4604';
    END IF;
    IF NEW.c_line_group_id IS NOT NULL AND (
        NOT scope_may_use_line_group_460(NEW.owner_scope_id, NEW.c_owner_scope_id, NEW.c_line_group_id) OR
        COALESCE((SELECT tier FROM node_line_group_tiers WHERE tenant_scope_id = NEW.c_owner_scope_id
            AND line_group_id = NEW.c_line_group_id), 'normal') <> 'unlimited') THEN
        RAISE EXCEPTION 'level C needs a usable unlimited line group' USING ERRCODE='P4605';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER escalate_package_policies_guard_460
BEFORE INSERT OR UPDATE ON escalate_package_policies
FOR EACH ROW EXECUTE FUNCTION guard_escalate_package_policy_460();

-- 站点设置：站长只能开关插件、在套餐范围内覆盖阈值（{"b"|"c"|"d": {"qps"|"bps": n}}）。
CREATE TABLE escalate_sites (
    tenant_scope_id uuid NOT NULL,
    site_id uuid NOT NULL,
    enabled boolean NOT NULL DEFAULT false,
    thresholds jsonb NOT NULL DEFAULT '{}' CHECK (jsonb_typeof(thresholds) = 'object'),
    revision bigint NOT NULL CHECK (revision > 0),
    updated_by_user_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    updated_at timestamptz NOT NULL CHECK (isfinite(updated_at)),
    PRIMARY KEY (tenant_scope_id, site_id),
    FOREIGN KEY (tenant_scope_id, site_id) REFERENCES sites(scope_id, id) ON DELETE CASCADE
);

-- 站点升级状态（worker 每 10 秒推进）。level：目标级别；applied_level：执行器已确认生效的级别
-- （B/C 切线需先发布到新线路组并确认；套餐模式 CNAME 未拆完或站长未改 CNAME 时 B 不生效，
-- pending_reason 标明）。over_since/under_since：持续超过/低于阈值的起点。locked_level：管理员锁定。
CREATE TABLE escalate_site_states (
    tenant_scope_id uuid NOT NULL,
    site_id uuid NOT NULL,
    level text NOT NULL CHECK (level IN ('A', 'B', 'C', 'D')),
    applied_level text NOT NULL CHECK (applied_level IN ('A', 'B', 'C', 'D')),
    c_via text NOT NULL DEFAULT '' CHECK (c_via IN ('', 'line_group', 'cloudflare')),
    pending_reason text NOT NULL DEFAULT '' CHECK (char_length(pending_reason) <= 64),
    entered_at timestamptz NOT NULL CHECK (isfinite(entered_at)),
    over_since timestamptz CHECK (over_since IS NULL OR isfinite(over_since)),
    under_since timestamptz CHECK (under_since IS NULL OR isfinite(under_since)),
    locked_level text CHECK (locked_level IS NULL OR locked_level IN ('A', 'B', 'C', 'D')),
    locked_by_user_id uuid REFERENCES users(id) ON DELETE RESTRICT,
    last_qps bigint NOT NULL DEFAULT 0 CHECK (last_qps >= 0),
    last_bps bigint NOT NULL DEFAULT 0 CHECK (last_bps >= 0),
    attacked boolean NOT NULL DEFAULT false,
    revision bigint NOT NULL CHECK (revision > 0),
    updated_at timestamptz NOT NULL CHECK (isfinite(updated_at)),
    PRIMARY KEY (tenant_scope_id, site_id),
    FOREIGN KEY (tenant_scope_id, site_id) REFERENCES sites(scope_id, id) ON DELETE CASCADE,
    CHECK ((locked_level IS NULL) = (locked_by_user_id IS NULL))
);
CREATE INDEX escalate_site_states_active_idx ON escalate_site_states (updated_at) WHERE level <> 'A' OR applied_level <> 'A';

-- 级别变化历史（只追加）。
CREATE TABLE escalate_events (
    id uuid PRIMARY KEY,
    tenant_scope_id uuid NOT NULL,
    site_id uuid NOT NULL,
    from_level text NOT NULL CHECK (from_level IN ('A', 'B', 'C', 'D')),
    to_level text NOT NULL CHECK (to_level IN ('A', 'B', 'C', 'D')),
    reason text NOT NULL CHECK (reason IN ('escalate', 'recover', 'lock', 'unlock', 'reset', 'applied', 'skipped',
        'apply_failed', 'plugin_off')),
    detail text NOT NULL DEFAULT '' CHECK (char_length(detail) <= 256),
    qps bigint NOT NULL DEFAULT 0 CHECK (qps >= 0),
    bps bigint NOT NULL DEFAULT 0 CHECK (bps >= 0),
    actor_user_id uuid REFERENCES users(id) ON DELETE RESTRICT,
    occurred_at timestamptz NOT NULL CHECK (isfinite(occurred_at)),
    FOREIGN KEY (tenant_scope_id, site_id) REFERENCES sites(scope_id, id) ON DELETE CASCADE
);
CREATE INDEX escalate_events_site_idx ON escalate_events (tenant_scope_id, site_id, occurred_at DESC);

-- S3 站点线路覆盖（执行器写，没有行 = 站点按原线路组承载与解析）。
-- line_group：DNS 正在/可以指向的覆盖组；next_group：另一个仍需承载的组——prepare_revision 非空时是
-- 正在准备的组（已请求发布，等该组节点都到 prepare_revision），为空时是 DNS 切走前的旧组（排空中）。
-- 两者都计入站点承载线路组（287/342 函数与 edgepublish/edgeautopublish/securityban/nodescheduler
-- 五处查询），所以高防组节点在 DNS 切过去之前就拿到站点配置；回切时先改 DNS 再删行。
-- dns_target：default=原线路组，line_group=覆盖组，cloudflare=聚合边缘线路已切到站长 CF，
-- blackhole=D 级（DNS 解析到 0.0.0.0、TTL 60，节点丢弃）。dns_changed_at 之后提交的 retarget 即确认。
CREATE TABLE escalate_site_routes (
    tenant_scope_id uuid NOT NULL,
    site_id uuid NOT NULL,
    line_owner_scope_id uuid,
    line_group_id uuid,
    next_owner_scope_id uuid,
    next_group_id uuid,
    prepare_revision bigint CHECK (prepare_revision IS NULL OR prepare_revision > 0),
    dns_target text NOT NULL CHECK (dns_target IN ('default', 'line_group', 'cloudflare', 'blackhole')),
    dns_changed_at timestamptz NOT NULL CHECK (isfinite(dns_changed_at)),
    blackhole_since timestamptz CHECK (blackhole_since IS NULL OR isfinite(blackhole_since)),
    updated_at timestamptz NOT NULL CHECK (isfinite(updated_at)),
    PRIMARY KEY (tenant_scope_id, site_id),
    FOREIGN KEY (tenant_scope_id, site_id) REFERENCES sites(scope_id, id) ON DELETE CASCADE,
    FOREIGN KEY (line_owner_scope_id, line_group_id) REFERENCES node_line_groups(tenant_scope_id, id) ON DELETE RESTRICT,
    FOREIGN KEY (next_owner_scope_id, next_group_id) REFERENCES node_line_groups(tenant_scope_id, id) ON DELETE RESTRICT,
    CHECK ((line_owner_scope_id IS NULL) = (line_group_id IS NULL)),
    CHECK ((next_owner_scope_id IS NULL) = (next_group_id IS NULL)),
    CHECK (prepare_revision IS NULL OR next_group_id IS NOT NULL),
    CHECK (dns_target <> 'line_group' OR line_group_id IS NOT NULL),
    CHECK ((dns_target = 'blackhole') = (blackhole_since IS NOT NULL))
);
CREATE INDEX escalate_site_routes_line_idx ON escalate_site_routes (line_group_id) WHERE line_group_id IS NOT NULL;
CREATE INDEX escalate_site_routes_next_idx ON escalate_site_routes (next_group_id) WHERE next_group_id IS NOT NULL;
CREATE INDEX escalate_site_routes_blackhole_idx ON escalate_site_routes (site_id) WHERE dns_target = 'blackhole';

-- D 级站点丢弃快照（cdnca.site-drop/v1，esc-node 定稿契约）每节点的下发与回执。
CREATE TABLE escalate_site_drop_node_states (
    node_id uuid PRIMARY KEY REFERENCES nodes(id) ON DELETE CASCADE,
    revision bigint NOT NULL CHECK (revision > 0),
    content_sha256 bytea NOT NULL CHECK (octet_length(content_sha256) = 32),
    list_sha256 bytea NOT NULL CHECK (octet_length(list_sha256) = 32),
    published_at timestamptz NOT NULL CHECK (isfinite(published_at)),
    applied_revision bigint NOT NULL DEFAULT 0 CHECK (applied_revision >= 0),
    applied boolean NOT NULL DEFAULT false,
    mode text NOT NULL DEFAULT '' CHECK (mode IN ('', 'xdp', 'nftables')),
    error_code text NOT NULL DEFAULT '' CHECK (error_code ~ '^([a-z][a-z0-9_]{0,63})?$'),
    rejected jsonb NOT NULL DEFAULT '[]' CHECK (jsonb_typeof(rejected) = 'array'),
    reported_at timestamptz CHECK (reported_at IS NULL OR isfinite(reported_at))
);

-- 站点 CNAME retarget：D 级 TTL 60（280 只允许 300）；覆盖组可以是平台线路组，
-- 外键改指线路组所在 scope（280 指 tenant_scope_id，平台组 retarget 插入会撞外键）。
DO $migration_460_retarget$
DECLARE
    old_fk text;
BEGIN
    SELECT conname INTO old_fk FROM pg_constraint
    WHERE conrelid = to_regclass(current_schema() || '.dns_cname_retargets') AND contype = 'f'
      AND confrelid = to_regclass(current_schema() || '.node_line_group_revisions');
    IF old_fk IS NULL THEN
        RAISE EXCEPTION 'migration 460: dns_cname_retargets lacks its line group revision foreign key' USING ERRCODE='P4600';
    END IF;
    EXECUTE format('ALTER TABLE dns_cname_retargets DROP CONSTRAINT %I', old_fk);
END;
$migration_460_retarget$;
ALTER TABLE dns_cname_retargets ADD COLUMN node_group_scope_id uuid;
ALTER TABLE dns_cname_retargets DISABLE TRIGGER dns_cname_retargets_protect_286;
UPDATE dns_cname_retargets SET node_group_scope_id = tenant_scope_id;
ALTER TABLE dns_cname_retargets ENABLE TRIGGER dns_cname_retargets_protect_286;
ALTER TABLE dns_cname_retargets
    ALTER COLUMN node_group_scope_id SET NOT NULL,
    ADD CONSTRAINT dns_cname_retargets_node_group_460_fkey FOREIGN KEY (node_group_scope_id, node_group_id, node_group_revision)
        REFERENCES node_line_group_revisions(tenant_scope_id, line_group_id, revision) ON DELETE RESTRICT,
    DROP CONSTRAINT dns_cname_retargets_ttl_check,
    ADD CONSTRAINT dns_cname_retargets_ttl_460_check CHECK (ttl IN (60, 300));

-- 升级到 B/C 先把站点发布到覆盖组节点：系统重新发布通道新增 trigger attack_escalation
-- （451 的约束扩展，cardinality 17 -> 18）。
ALTER TABLE edge_system_republication_heads
    DROP CONSTRAINT edge_system_republication_heads_triggers_check,
    ADD CONSTRAINT edge_system_republication_heads_triggers_check CHECK (cardinality(triggers) BETWEEN 1 AND 18 AND
        triggers <@ ARRAY['node_capability', 'traffic_enforcement', 'line_group', 'node_sync', 'domain_ownership',
            'secondary_verification', 'rule_catalog', 'challenge_delivery', 'module_entitlement',
            'theme_activation', 'account_suspension', 'node_networks', 'error_page_published',
            'origin_auth_published', 'origin_failover', 'market_limits', 'ip_list', 'attack_escalation']::text[]);
ALTER TABLE edge_system_republication_attempts
    DROP CONSTRAINT edge_system_republication_attempts_triggers_check,
    ADD CONSTRAINT edge_system_republication_attempts_triggers_check CHECK (cardinality(triggers) BETWEEN 1 AND 18);
ALTER TABLE edge_system_revision_segments
    DROP CONSTRAINT edge_system_revision_segments_source_check,
    ADD CONSTRAINT edge_system_revision_segments_source_check CHECK (source IN ('node_capability', 'traffic_enforcement',
        'line_group', 'node_sync', 'domain_ownership', 'secondary_verification', 'rule_catalog', 'challenge_delivery',
        'module_entitlement', 'account_suspension', 'node_networks', 'error_page_published', 'origin_auth_published',
        'origin_failover', 'market_limits', 'ip_list', 'attack_escalation'));

-- 进入 D 级（黑洞）通知站长（用户 10-22：站内信 / 邮件 / 短信，走通知中心）。
INSERT INTO notification_event_policies(
    event_type, enabled, sms_enabled, email_enabled, repeat_count, interval_hours, supported, default_email, default_sms, updated_at
) VALUES ('security.escalate.blackhole', true, true, true, 1, 1, true, true, true, now());
INSERT INTO notification_templates(template_id, version, channel, subject, body, variables, created_at) VALUES
    ('security.escalate.blackhole.zh-cn', 1, 'sms', '',
     '网站{{.domain}}遭受大流量攻击，已进入黑洞：解析指向0.0.0.0，访问暂时中断，攻击回落后自动恢复。',
     ARRAY['domain'], '2026-10-22 00:00:00+00'),
    ('security.escalate.blackhole.zh-cn', 1, 'email', '攻击自动升级：{{.domain}} 已进入黑洞',
     '网站 {{.domain}} 在 {{.occurred_at}} 因持续大流量攻击（全部节点合计 {{.qps}} 请求/秒、{{.bps}} bit/秒）升级到 D 级「黑洞」：域名解析指向 0.0.0.0（TTL 60 秒），节点丢弃该网站的残余流量，访问暂时中断。攻击持续低于阈值且停留期满后会自动逐级回切；也可以在控制台「攻击升级」查看状态与历史。',
     ARRAY['domain','occurred_at','qps','bps'], '2026-10-22 00:00:00+00');

-- 攻击触发的聚合边缘切换（C 级切站长 CF / 回切）原因码。
ALTER TABLE aggregated_edge_switch_events DROP CONSTRAINT aggregated_edge_switch_events_reason_420_check;
ALTER TABLE aggregated_edge_switch_events ADD CONSTRAINT aggregated_edge_switch_events_reason_460_check
    CHECK (reason IN ('failover', 'failback', 'quality', 'manual', 'unbind', 'bind', 'freeze', 'unfreeze',
        'all_unhealthy', 'current_unhealthy', 'origin_unhealthy', 'edge_all_unhealthy', 'recovered', 'attack_escalate'));

-- 承载判定加上站点线路覆盖（287 的平台节点分支、342 的 HTTP-01 候选节点）。
CREATE OR REPLACE FUNCTION tenant_carries_node_287(checked_tenant_scope_id uuid, checked_node_id uuid)
RETURNS boolean LANGUAGE sql STABLE AS $$
    SELECT EXISTS (
        SELECT 1 FROM nodes node
        WHERE node.id = checked_node_id AND node.admin_state <> 'retired' AND (
            node.scope_id = checked_tenant_scope_id OR (
                EXISTS (SELECT 1 FROM access_scopes scope WHERE scope.id = node.scope_id AND scope.kind = 'platform')
                AND (
                    EXISTS (SELECT 1 FROM node_config_state state
                        WHERE state.node_id = node.id AND state.configuration_scope_id = checked_tenant_scope_id)
                    OR EXISTS (
                        SELECT 1 FROM sites site
                        LEFT JOIN package_subscriptions subscription
                          ON subscription.tenant_scope_id = site.scope_id AND subscription.id = site.package_subscription_id
                         AND subscription.deleted_at IS NULL
                        LEFT JOIN escalate_site_routes route
                          ON route.tenant_scope_id = site.scope_id AND route.site_id = site.id
                        JOIN node_line_groups line_group ON line_group.deleted_at IS NULL
                         AND line_group.tenant_scope_id IN (node.scope_id, site.scope_id)
                         AND line_group.id IN (
                             site.node_group_id,
                             (subscription.product_snapshot->'spec'->>'node_group_id')::uuid,
                             (subscription.product_snapshot->'spec'->>'backup_node_group_id')::uuid,
                             route.line_group_id, route.next_group_id)
                        JOIN node_line_endpoint_serving endpoint
                          ON endpoint.tenant_scope_id = line_group.tenant_scope_id
                         AND endpoint.line_group_id = line_group.id
                         AND endpoint.config_revision = line_group.current_revision
                         AND endpoint.node_id = node.id
                        WHERE site.scope_id = checked_tenant_scope_id AND site.deleted_at IS NULL
                    )
                )
            )
        )
    )
$$;

CREATE OR REPLACE FUNCTION acme_http01_site_candidate_nodes(target_scope_id uuid, target_site_id uuid)
RETURNS SETOF uuid LANGUAGE sql STABLE AS $$
    SELECT DISTINCT endpoint.node_id FROM sites site
    LEFT JOIN package_subscriptions subscription ON subscription.tenant_scope_id=site.scope_id
     AND subscription.id=site.package_subscription_id AND subscription.deleted_at IS NULL
    LEFT JOIN escalate_site_routes route ON route.tenant_scope_id=site.scope_id AND route.site_id=site.id
    JOIN node_line_groups line_group ON line_group.deleted_at IS NULL AND line_group.id IN (
         site.node_group_id,
         (subscription.product_snapshot->'spec'->>'node_group_id')::uuid,
         (subscription.product_snapshot->'spec'->>'backup_node_group_id')::uuid,
         route.line_group_id, route.next_group_id)
    JOIN node_line_endpoints endpoint ON endpoint.tenant_scope_id=line_group.tenant_scope_id
     AND endpoint.line_group_id=line_group.id AND endpoint.config_revision=line_group.current_revision
     AND endpoint.enabled AND endpoint.node_id IS NOT NULL
    JOIN nodes node ON node.id=endpoint.node_id AND node.admin_state='active'
    JOIN access_scopes node_scope ON node_scope.id=node.scope_id
    WHERE site.scope_id=target_scope_id AND site.id=target_site_id
      AND line_group.tenant_scope_id IN (site.scope_id, node.scope_id)
      AND (node.scope_id=site.scope_id OR node_scope.kind='platform')
      AND NOT EXISTS (SELECT 1 FROM node_serving_holds hold WHERE hold.node_id=node.id AND hold.held)
$$;

DO $migration_460_path$
BEGIN
    EXECUTE format('ALTER FUNCTION %I.scope_may_use_line_group_460(uuid, uuid, uuid) SET search_path = pg_catalog, %I, pg_temp',
        current_schema(), current_schema());
    EXECUTE format('ALTER FUNCTION %I.guard_node_line_group_grant_460() SET search_path = pg_catalog, %I, pg_temp',
        current_schema(), current_schema());
    EXECUTE format('ALTER FUNCTION %I.guard_escalate_package_policy_460() SET search_path = pg_catalog, %I, pg_temp',
        current_schema(), current_schema());
    EXECUTE format('ALTER FUNCTION %I.tenant_carries_node_287(uuid, uuid) SET search_path = pg_catalog, %I, pg_temp',
        current_schema(), current_schema());
END;
$migration_460_path$;

REVOKE ALL ON node_line_group_tiers, node_line_group_grants, escalate_package_policies, escalate_sites,
    escalate_site_states, escalate_events, escalate_site_routes, escalate_site_drop_node_states FROM PUBLIC;
GRANT SELECT, INSERT, UPDATE ON node_line_group_tiers, node_line_group_grants, escalate_package_policies, escalate_sites,
    escalate_site_states, escalate_site_drop_node_states TO cdnca_control_app, cdnca_control_runtime;
GRANT SELECT, INSERT, UPDATE, DELETE ON escalate_site_routes TO cdnca_control_app, cdnca_control_runtime;
GRANT SELECT, INSERT ON escalate_events TO cdnca_control_app, cdnca_control_runtime;
GRANT EXECUTE ON FUNCTION scope_may_use_line_group_460(uuid, uuid, uuid) TO cdnca_control_app, cdnca_control_runtime;
