LOCK TABLE schema_migrations, agent_gateways IN ACCESS EXCLUSIVE MODE;

DO $migration_448_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 447 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 447 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=447 AND
        migration_id='447_agent_gateways' AND
        checksum_sha256='3441bdb3855cf1b57c07bb959eac937497c6737711925ccd60a31cf792ab2607' AND
        down_checksum_sha256='ef73ed3669c888610b958b794265b40744e53114bff66a6c7df2b1c6b30ebe4b' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR to_regclass(current_schema() || '.agent_gateway_trusted_ranges') IS NOT NULL THEN
        RAISE EXCEPTION 'migration 448 requires the exact verified 447 release head' USING ERRCODE='P4480';
    END IF;
END;
$migration_448_up$;

-- 448（r136 gw-impl4 GW-06/GW-07，占位号：合入时由主会话统一改号）。ADR 0013 §3.4/§4.4/§4.5：
-- 1. agent_gateway_trusted_ranges：可信 CDN 回源段（网关管理页编辑，ControlInternal
--    GetGatewaySettings 下发，网关整表热替换）。预置只有 Cloudflare（与
--    services/agent-gateway/trusted_proxies_cloudflare.txt 同源，绑定 CF-Connecting-IP）。
-- 2. agent_gateway_allowed_ips：每台独立网关的放行 IP（默认 = 绑定来源 IP，页面可增删）；
--    ControlInternal 远端监听与 nftables 集合都只读这一张表（bound/active 网关）。
-- 3. agent_gateway_entrypoints：管理员额外加的节点入口（如 CDN 的 443，传输 ws），
--    排在在线网关之后进节点端点列表。
-- 全新安装起点（兼容基线 1.0.35）；已绑定网关的 source_ip 搬进放行表。

CREATE TABLE agent_gateway_trusted_ranges (
    position integer PRIMARY KEY CHECK (position BETWEEN 1 AND 512),
    cidr cidr NOT NULL UNIQUE,
    header text NOT NULL CHECK (header ~ '^[A-Za-z0-9-]{1,64}$')
);

INSERT INTO agent_gateway_trusted_ranges(position, cidr, header) VALUES
    (1, '173.245.48.0/20', 'CF-Connecting-IP'),
    (2, '103.21.244.0/22', 'CF-Connecting-IP'),
    (3, '103.22.200.0/22', 'CF-Connecting-IP'),
    (4, '103.31.4.0/22', 'CF-Connecting-IP'),
    (5, '141.101.64.0/18', 'CF-Connecting-IP'),
    (6, '108.162.192.0/18', 'CF-Connecting-IP'),
    (7, '190.93.240.0/20', 'CF-Connecting-IP'),
    (8, '188.114.96.0/20', 'CF-Connecting-IP'),
    (9, '197.234.240.0/22', 'CF-Connecting-IP'),
    (10, '198.41.128.0/17', 'CF-Connecting-IP'),
    (11, '162.158.0.0/15', 'CF-Connecting-IP'),
    (12, '104.16.0.0/13', 'CF-Connecting-IP'),
    (13, '104.24.0.0/14', 'CF-Connecting-IP'),
    (14, '172.64.0.0/13', 'CF-Connecting-IP'),
    (15, '131.0.72.0/22', 'CF-Connecting-IP'),
    (16, '2400:cb00::/32', 'CF-Connecting-IP'),
    (17, '2606:4700::/32', 'CF-Connecting-IP'),
    (18, '2803:f800::/32', 'CF-Connecting-IP'),
    (19, '2405:b500::/32', 'CF-Connecting-IP'),
    (20, '2405:8100::/32', 'CF-Connecting-IP'),
    (21, '2a06:98c0::/29', 'CF-Connecting-IP'),
    (22, '2c0f:f248::/32', 'CF-Connecting-IP');

CREATE TABLE agent_gateway_allowed_ips (
    gateway_id uuid NOT NULL REFERENCES agent_gateways(id) ON DELETE CASCADE,
    ip inet NOT NULL CHECK (masklen(ip) = CASE family(ip) WHEN 4 THEN 32 ELSE 128 END),
    created_at timestamptz NOT NULL,
    PRIMARY KEY (gateway_id, ip)
);

INSERT INTO agent_gateway_allowed_ips(gateway_id, ip, created_at)
SELECT id, source_ip, COALESCE(bound_at, created_at) FROM agent_gateways
WHERE source_ip IS NOT NULL AND status <> 'deleted';

CREATE TABLE agent_gateway_entrypoints (
    position integer PRIMARY KEY CHECK (position BETWEEN 1 AND 16),
    address text NOT NULL UNIQUE CHECK (char_length(address) BETWEEN 3 AND 260),
    server_name text NOT NULL CHECK (char_length(server_name) BETWEEN 1 AND 253 AND server_name = lower(server_name)),
    transport text NOT NULL CHECK (transport IN ('grpc', 'ws')),
    tunnel_host text NOT NULL DEFAULT '' CHECK (char_length(tunnel_host) <= 253 AND tunnel_host = lower(tunnel_host)),
    CHECK (transport = 'ws' OR tunnel_host = '')
);
