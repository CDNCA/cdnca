-- 641（独享订阅方的节点级设置；前驱 640_line_group_dnshub_batch_idempotency）：
-- 独享订阅方的节点级设置（四层转发、拒绝规则）经市场中继到卖家（docs/architecture/market-subscribed-nodes.md §9.4）。
--
--   卖家（叶子）侧：
--   1. market_supply_node_settings：每个市场租户（一个授权的隐藏租户）最近收下的整份快照与回执；key 是授权外部键
--      （marketsupply.Key），撤销扫描用它对最近一次授权同步；window_* 是每分钟快照数限流。
--   2. market_supply_node_streams：订阅方转发 ref → 隐藏租户名下的 l4_forwards 行。只有这里登记的转发才是
--      "来自订阅方"的，卖家页面据此标来源；订阅结束时按它删除。
--   3. market_supply_node_disables：卖家运营停用的订阅方转发/规则；之后的快照不能重新打开，直到运营恢复。
--   买家侧：
--   4. market_node_settings：本主控对一个市场供给（site_supplies）保存的独享节点设置文档与修订。
--   5. market_node_settings_deliveries：每个叶子/节点组最近一次发送与回执（拒收、下发进度），页面读它。
-- 只加表，不改已有表与数据。
LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;

DO $migration_641_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 640 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 640 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=640 AND
        migration_id='640_line_group_dnshub_batch_idempotency' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR to_regclass(current_schema() || '.l4_forwards') IS NULL OR
          to_regclass(current_schema() || '.site_supplies') IS NULL OR
          to_regclass(current_schema() || '.market_supply_node_settings') IS NOT NULL THEN
        RAISE EXCEPTION 'migration 641 requires the exact verified 640 release head' USING ERRCODE='P6410';
    END IF;
END;
$migration_641_up$;

CREATE TABLE market_supply_node_settings (
    tenant_scope_id uuid PRIMARY KEY REFERENCES access_scopes(id) ON DELETE CASCADE,
    market_key text NOT NULL CHECK (market_key ~ '^[0-9a-f]{24}$'),
    revision bigint NOT NULL CHECK (revision >= 1),
    digest text NOT NULL CHECK (digest ~ '^[0-9a-f]{64}$'),
    document jsonb NOT NULL CHECK (jsonb_typeof(document) = 'object'),
    refused jsonb NOT NULL DEFAULT '[]' CHECK (jsonb_typeof(refused) = 'array'),
    -- Set when the subscriber's settings were removed (subscription_ended / supply_paused).
    removed_at timestamptz,
    removed_reason text CHECK (removed_reason IS NULL OR removed_reason IN ('subscription_ended', 'supply_paused')),
    window_start timestamptz NOT NULL,
    window_messages integer NOT NULL CHECK (window_messages >= 0),
    updated_at timestamptz NOT NULL,
    CHECK ((removed_at IS NULL) = (removed_reason IS NULL))
);

CREATE TABLE market_supply_node_streams (
    tenant_scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE CASCADE,
    ref uuid NOT NULL,
    stream_id uuid NOT NULL UNIQUE,
    -- Digest of the forward fields last written: an unchanged forward is not written again.
    digest text NOT NULL CHECK (digest ~ '^[0-9a-f]{64}$'),
    PRIMARY KEY (tenant_scope_id, ref)
);

CREATE TABLE market_supply_node_disables (
    tenant_scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE CASCADE,
    kind text NOT NULL CHECK (kind IN ('stream', 'rule')),
    ref uuid NOT NULL,
    disabled_by_user_id uuid NOT NULL,
    disabled_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_scope_id, kind, ref)
);

CREATE TABLE market_node_settings (
    supply_id uuid PRIMARY KEY REFERENCES site_supplies(id) ON DELETE CASCADE,
    revision bigint NOT NULL CHECK (revision >= 1),
    document jsonb NOT NULL CHECK (jsonb_typeof(document) = 'object'),
    updated_by_user_id uuid NOT NULL,
    updated_at timestamptz NOT NULL
);

CREATE TABLE market_node_settings_deliveries (
    supply_id uuid NOT NULL REFERENCES market_node_settings(supply_id) ON DELETE CASCADE,
    leaf_member_id uuid NOT NULL,
    node_pool_ref text NOT NULL CHECK (char_length(node_pool_ref) BETWEEN 1 AND 128),
    revision bigint NOT NULL CHECK (revision >= 1),
    -- sent (no answer yet), accepted, rejected (the whole snapshot, reason), unsupported (an older leaf or market).
    state text NOT NULL CHECK (state IN ('sent', 'accepted', 'rejected', 'unsupported')),
    reason text NOT NULL DEFAULT '' CHECK (reason = '' OR reason ~ '^[a-z][a-z0-9_]{0,63}$'),
    refused jsonb NOT NULL DEFAULT '[]' CHECK (jsonb_typeof(refused) = 'array'),
    delivery jsonb NOT NULL DEFAULT '{}' CHECK (jsonb_typeof(delivery) = 'object'),
    attempts integer NOT NULL CHECK (attempts >= 1),
    sent_at timestamptz NOT NULL,
    answered_at timestamptz,
    next_at timestamptz NOT NULL,
    PRIMARY KEY (supply_id, leaf_member_id, node_pool_ref)
);
CREATE INDEX market_node_settings_deliveries_next_641_idx ON market_node_settings_deliveries (next_at);

REVOKE ALL ON market_supply_node_settings, market_supply_node_streams, market_supply_node_disables, market_node_settings, market_node_settings_deliveries FROM PUBLIC;
GRANT SELECT, INSERT, UPDATE, DELETE ON market_supply_node_settings, market_supply_node_streams, market_supply_node_disables, market_node_settings, market_node_settings_deliveries TO cdnca_control_app, cdnca_control_runtime;
