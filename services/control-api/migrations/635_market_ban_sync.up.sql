-- 635（订阅站点封禁名单经市场下发到订阅节点；前驱 634_market_stale_commit）：
--   买家（根订阅方）对只经市场订阅节点服务的站点加的封禁，以整份快照经 relay 发给供货叶子（supply.ban_sync，
--   libs/marketproto/bansync），叶子把它落到该订阅的叶子站点的封禁名单，由叶子现有的分发器发给订阅节点执行。
--   1. security_ban_entries.source 加 'market'：叶子按买家快照写的行。下发到节点时线上来源写成 manual（节点 agent
--      只认 waf/cc/manual/autodefense，来源只进节点日志），控制面与页面仍显示 market。
--   2. market_supply_ban_refs（叶子）：买家条目 → 叶子名单行。按（市场租户作用域, 买家站点, 买家条目 ID）唯一；
--      entry_created_at 是该映射最近一次建出名单行的时间，按租户限速；release_cause 记叶子因何解除：
--      buyer（买家解除）、subscription（订阅取消/暂停，订阅恢复后买家快照会重建），运营在叶子名单页手工解除的行
--      released_by 非空、release_cause 为空，之后买家再发同一条目一律拒收（released_by_supplier）。
--   3. market_supply_ban_sites（叶子）：每个市场站点最近应用的快照修订（比它旧的重放跳过）与按分钟计的消息数
--      （超过即整份拒收 ban_sync_rate_limited）。
--   4. site_supply_ban_deliveries（买家）：每个（站点, 供给, 叶子, 节点池）最近一次发出的快照修订与内容摘要、
--      叶子回执（接收的条目、拒收的条目与原因、节点进度）与下次发送时间。页面按它显示每条封禁的下发状态。
LOCK TABLE schema_migrations, security_ban_entries IN ACCESS EXCLUSIVE MODE;

DO $migration_635_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 634 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 634 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=634 AND
        migration_id='634_market_stale_commit' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR to_regclass(current_schema() || '.market_supply_site_revisions') IS NULL OR
          to_regclass(current_schema() || '.market_supply_ban_refs') IS NOT NULL THEN
        RAISE EXCEPTION 'migration 635 requires the exact verified 634 release head' USING ERRCODE='P6350';
    END IF;
END;
$migration_635_up$;

ALTER TABLE security_ban_entries DROP CONSTRAINT security_ban_entries_source_415;
ALTER TABLE security_ban_entries ADD CONSTRAINT security_ban_entries_source_635
    CHECK (source IN ('waf', 'cc', 'manual', 'autodefense', 'market'));

CREATE TABLE market_supply_ban_refs (
    tenant_scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE CASCADE,
    site_id uuid NOT NULL,
    ref uuid NOT NULL,
    leaf_site_id uuid NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
    entry_id uuid NOT NULL UNIQUE REFERENCES security_ban_entries(id) ON DELETE CASCADE,
    buyer_source text NOT NULL CHECK (buyer_source IN ('manual', 'cc', 'waf', 'autodefense')),
    entry_created_at timestamptz NOT NULL,
    release_cause text CHECK (release_cause IN ('buyer', 'subscription')),
    PRIMARY KEY (tenant_scope_id, site_id, ref)
);
CREATE INDEX market_supply_ban_refs_rate_635_idx ON market_supply_ban_refs (tenant_scope_id, entry_created_at);

CREATE TABLE market_supply_ban_sites (
    tenant_scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE CASCADE,
    site_id uuid NOT NULL,
    leaf_site_id uuid NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
    revision bigint NOT NULL CHECK (revision >= 1),
    window_start timestamptz NOT NULL,
    window_messages integer NOT NULL CHECK (window_messages >= 0),
    updated_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_scope_id, site_id)
);

CREATE TABLE site_supply_ban_deliveries (
    site_id uuid NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
    supply_id uuid NOT NULL REFERENCES site_supplies(id) ON DELETE CASCADE,
    leaf_member_id uuid NOT NULL,
    node_pool_ref text NOT NULL CHECK (char_length(node_pool_ref) BETWEEN 1 AND 128),
    leaf_site_id uuid NOT NULL,
    revision bigint NOT NULL CHECK (revision >= 1),
    digest text NOT NULL CHECK (digest ~ '^[0-9a-f]{64}$'),
    -- What the leaf answered for revision: sent (no answer yet), accepted, rejected
    -- (the whole snapshot, reason), unsupported (a leaf or market that predates bansync).
    state text NOT NULL CHECK (state IN ('sent', 'accepted', 'rejected', 'unsupported')),
    reason text NOT NULL DEFAULT '' CHECK (reason = '' OR reason ~ '^[a-z][a-z0-9_]{0,63}$'),
    detail text NOT NULL DEFAULT '' CHECK (char_length(detail) <= 500),
    -- The subscriber entries of the last accepted snapshot the leaf took, and those it refused.
    accepted_refs uuid[] NOT NULL DEFAULT '{}',
    refused jsonb NOT NULL DEFAULT '[]' CHECK (jsonb_typeof(refused) = 'array'),
    nodes jsonb NOT NULL DEFAULT '{}' CHECK (jsonb_typeof(nodes) = 'object'),
    attempts integer NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    sent_at timestamptz NOT NULL,
    answered_at timestamptz,
    next_at timestamptz NOT NULL,
    PRIMARY KEY (site_id, supply_id, leaf_member_id, node_pool_ref)
);
CREATE INDEX site_supply_ban_deliveries_next_635_idx ON site_supply_ban_deliveries (next_at);

REVOKE ALL ON market_supply_ban_refs, market_supply_ban_sites, site_supply_ban_deliveries FROM PUBLIC;
GRANT SELECT, INSERT, UPDATE, DELETE ON market_supply_ban_refs, market_supply_ban_sites, site_supply_ban_deliveries
    TO cdnca_control_app, cdnca_control_runtime;
