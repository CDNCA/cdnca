LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;

DO $migration_573_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 572 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 572 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=572 AND
        migration_id='572_aggregated_edge_migrate_restore' AND
        checksum_sha256='4b562a0e35cc7450eb0181d5c7e797eafe785fdef4fb1536ba62f44feadc9d67' AND
        down_checksum_sha256='e3cc084098d0f31afdd8667cd445ed535c8e381d7208b1db5578ba238c05d2d9' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR to_regclass(current_schema() || '.node_gateway_address_changes') IS NOT NULL OR
         to_regclass(current_schema() || '.node_gateway_address_change_nodes') IS NOT NULL THEN
        RAISE EXCEPTION 'migration 573 requires the exact verified 572 release head' USING ERRCODE='P5730';
    END IF;
END;
$migration_573_up$;

-- 573（fix-nodegw，占位：合入时由主会话改号并改钉前驱）。
-- 维护升级 → 节点设置「更换主控连接地址」：一次变更（新 Gateway 地址 HOST:PORT + SNI 名称，
-- 范围 all/region/nodes）与逐节点状态。主控为每个节点签 cdnca.gateway-address-change/v1
-- （节点 revision 递增）经网关下发；节点探测成功才切换。状态：
--   pending   待下发（已入表，尚未发布到网关流）
--   delivered 已下发，等节点回执
--   probing   节点正在用新地址做 mTLS 握手探测
--   switched  节点已用新地址连上并回报（由新地址会话上的回执确认）
--   failed    探测/写入失败或节点不支持（error_code），旧地址保持
--   superseded 同一节点被更新的一次变更取代
CREATE TABLE node_gateway_address_changes (
    id uuid PRIMARY KEY,
    scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE RESTRICT,
    address text NOT NULL CHECK (char_length(address) BETWEEN 3 AND 255 AND address = btrim(address)),
    server_name text NOT NULL CHECK (char_length(server_name) BETWEEN 1 AND 253 AND server_name = btrim(server_name)),
    target_kind text NOT NULL CHECK (target_kind IN ('all', 'region', 'nodes')),
    target_region text NOT NULL DEFAULT '' CHECK (char_length(target_region) <= 64 AND
        (target_kind = 'region') = (target_region <> '')),
    node_count integer NOT NULL CHECK (node_count > 0),
    request_id text NOT NULL CHECK (char_length(request_id) BETWEEN 1 AND 128),
    created_by_user_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    created_at timestamptz NOT NULL CHECK (isfinite(created_at))
);
CREATE INDEX node_gateway_address_changes_scope_created_idx ON node_gateway_address_changes (scope_id, created_at DESC, id);

-- 一个节点在 node_gateway_address_change_nodes 上始终最多一条非终态记录；revision 按节点单调递增，
-- 跨变更共用（node_gateway_address_node_revisions），所以节点永远不会接受旧的签名文档。
CREATE TABLE node_gateway_address_node_revisions (
    node_id uuid PRIMARY KEY REFERENCES nodes(id) ON DELETE CASCADE,
    revision bigint NOT NULL CHECK (revision > 0)
);

CREATE TABLE node_gateway_address_change_nodes (
    change_id uuid NOT NULL REFERENCES node_gateway_address_changes(id) ON DELETE CASCADE,
    node_id uuid NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
    revision bigint NOT NULL CHECK (revision > 0),
    state text NOT NULL DEFAULT 'pending'
        CHECK (state IN ('pending', 'delivered', 'probing', 'switched', 'failed', 'superseded')),
    error_code text NOT NULL DEFAULT '' CHECK (error_code ~ '^([a-z][a-z0-9_]{0,63})?$' AND
        (state = 'failed') = (error_code <> '')),
    document_sha256 bytea CHECK (document_sha256 IS NULL OR octet_length(document_sha256) = 32),
    attempts integer NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    active_address text NOT NULL DEFAULT '' CHECK (char_length(active_address) <= 255),
    published_at timestamptz CHECK (published_at IS NULL OR isfinite(published_at)),
    reported_at timestamptz CHECK (reported_at IS NULL OR isfinite(reported_at)),
    updated_at timestamptz NOT NULL CHECK (isfinite(updated_at)),
    PRIMARY KEY (change_id, node_id),
    UNIQUE (node_id, revision)
);
CREATE UNIQUE INDEX node_gateway_address_change_nodes_open_idx ON node_gateway_address_change_nodes (node_id)
    WHERE state IN ('pending', 'delivered', 'probing');
CREATE INDEX node_gateway_address_change_nodes_pending_idx ON node_gateway_address_change_nodes (updated_at)
    WHERE state IN ('pending', 'delivered');

REVOKE ALL ON node_gateway_address_changes, node_gateway_address_node_revisions,
    node_gateway_address_change_nodes FROM PUBLIC;
GRANT SELECT, INSERT ON node_gateway_address_changes TO cdnca_control_app, cdnca_control_runtime;
GRANT SELECT, INSERT, UPDATE ON node_gateway_address_node_revisions, node_gateway_address_change_nodes
    TO cdnca_control_app, cdnca_control_runtime;
