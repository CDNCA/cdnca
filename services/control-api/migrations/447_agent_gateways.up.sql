LOCK TABLE schema_migrations, permissions, role_permissions, roles, access_scopes IN ACCESS EXCLUSIVE MODE;

DO $migration_447_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 446 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 446 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=446 AND
        migration_id='446_migrate_import' AND
        checksum_sha256='86a1e1d2c969e966fe9585564bbf0b8a230e0b6980a877c35be9c05002ca7725' AND
        down_checksum_sha256='43bfa7f0ddedd8969fd66278d46c31941fcb406b5fcef584217d33cba0dcbbb1' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR to_regclass(current_schema() || '.agent_gateways') IS NOT NULL
         OR EXISTS (SELECT 1 FROM permissions WHERE name = 'system.gateway.manage') THEN
        RAISE EXCEPTION 'migration 447 requires the exact verified 446 release head' USING ERRCODE='P4470';
    END IF;
END;
$migration_447_up$;

-- 447（r136 gw-impl2 GW-06/GW-08，占位号：合入时由主会话统一改号）。ADR 0013 §3.2–§3.4：
-- 1. agent_gateways：独立网关（gateway 模式安装、一次性令牌绑定）。同机网关（all 模式）
--    用安装器签的 spiffe://cdn-platform/gateway/control 证书，不在本表。
--    status：pending 待绑定 → bound 已签证书 → active 已上报就绪；disabled 停用（ControlInternal
--    拒绝，节点端点列表不再列出）；deleted 已删除（证书全部吊销，行保留供吊销判断与审计）。
--    host 是网关公网名（服务端证书 SAN），端口在绑定时由安装器上报（安装时已选定，ADR §3.5）；
--    source_ip 是绑定请求来源地址，主控 ControlInternal 远端监听只放行 bound/active 网关的该地址。
-- 2. agent_gateway_binding_tokens：每网关至多一枚，库里只存 SHA-256，1 小时有效、只能用一次。
-- 3. agent_gateway_certificates：主控签给网关的客户端证书（kind=client，URI SAN
--    spiffe://cdn-platform/gateway/<id>）与节点通道服务端证书（kind=server）；ControlInternal
--    按序列号+SHA-256 判定，吊销即拒。续签必须同一把公钥（public_key_sha256）。
-- 4. 权限 system.gateway.manage（平台 platform_owner）。
-- 全新安装起点（兼容基线 1.0.35），无数据迁移。

CREATE TABLE agent_gateways (
    id uuid PRIMARY KEY,
    name text NOT NULL CHECK (char_length(name) BETWEEN 1 AND 64 AND name = btrim(name)),
    host text NOT NULL CHECK (char_length(host) BETWEEN 1 AND 253 AND host = lower(host)),
    enrollment_port integer CHECK (enrollment_port IS NULL OR enrollment_port BETWEEN 1 AND 65535),
    agent_port integer CHECK (agent_port IS NULL OR agent_port BETWEEN 1 AND 65535),
    status text NOT NULL CHECK (status IN ('pending', 'bound', 'active', 'disabled', 'deleted')),
    version text NOT NULL DEFAULT '' CHECK (char_length(version) <= 64),
    -- source_ip: address the binding came from; the ControlInternal remote
    -- listener only accepts bound/active Gateways' addresses (GW-09).
    source_ip inet,
    created_by_user_id uuid REFERENCES users(id) ON DELETE SET NULL,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    bound_at timestamptz,
    ready_at timestamptz,
    CONSTRAINT agent_gateways_ports_447_ck CHECK (
        (enrollment_port IS NULL) = (agent_port IS NULL) AND
        (enrollment_port IS NULL OR enrollment_port <> agent_port) AND
        (bound_at IS NULL) = (enrollment_port IS NULL) AND
        (status <> 'pending' OR bound_at IS NULL) AND
        (status NOT IN ('bound', 'active', 'disabled') OR bound_at IS NOT NULL))
);
CREATE UNIQUE INDEX agent_gateways_name_447_uk ON agent_gateways (lower(name)) WHERE status <> 'deleted';

CREATE TABLE agent_gateway_binding_tokens (
    gateway_id uuid PRIMARY KEY REFERENCES agent_gateways(id) ON DELETE CASCADE,
    secret_sha256 bytea NOT NULL CHECK (octet_length(secret_sha256) = 32),
    expires_at timestamptz NOT NULL,
    used_at timestamptz,
    created_at timestamptz NOT NULL,
    CHECK (expires_at > created_at)
);

CREATE TABLE agent_gateway_certificates (
    serial_number text PRIMARY KEY CHECK (serial_number ~ '^[0-9a-f]{1,64}$'),
    gateway_id uuid NOT NULL REFERENCES agent_gateways(id) ON DELETE CASCADE,
    kind text NOT NULL CHECK (kind IN ('client', 'server')),
    certificate_sha256 bytea NOT NULL UNIQUE CHECK (octet_length(certificate_sha256) = 32),
    public_key_sha256 bytea NOT NULL CHECK (octet_length(public_key_sha256) = 32),
    certificate_pem text NOT NULL CHECK (char_length(certificate_pem) BETWEEN 1 AND 16384),
    not_before timestamptz NOT NULL,
    not_after timestamptz NOT NULL,
    revoked_at timestamptz,
    issued_at timestamptz NOT NULL,
    CHECK (not_after > not_before)
);
CREATE INDEX agent_gateway_certificates_gateway_447_idx ON agent_gateway_certificates (gateway_id, kind, not_after DESC);

INSERT INTO permissions(name, description)
VALUES ('system.gateway.manage', 'Manage Agent Gateways: add (binding token), disable, delete, entry points and trusted CDN ranges');

INSERT INTO role_permissions(role_id, permission_name)
SELECT role.id, 'system.gateway.manage'
FROM roles role
JOIN access_scopes scope ON scope.id = role.scope_id AND scope.kind = 'platform'
WHERE role.system_role AND role.name = 'platform_owner'
ON CONFLICT DO NOTHING;
