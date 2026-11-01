-- 608（r136 node-ssh-tab，主会话分配 control 608；集成头 604 之后 605 fw-default、606 autodefense-ux、607 fw-receipt。
--   merge-p40 已按 607 前驱重钉）：
-- 节点管理「SSH 连接」标签：
--   1. 权限码 nodes.ssh：浏览器内 SSH 终端。不授给任何角色，只有持 platform.admin 的平台管理员可用
--      （identity.Authorize 对 platform.admin 放行），也不进自定义角色目录（租户不能拿到）。
--   2. node_ssh_credentials：终端可选“记住”的登录凭据（每节点一条），密文由主控凭据密钥环加密，
--      绑定节点行；同时钉定主机公钥指纹，之后的连接必须匹配。
--   3. node_ssh_install_jobs.restrict_ssh：SSH 安装时勾选“仅允许主控 SSH”，装完对注册出的节点开启。
--   4. node_ssh_access：节点“仅允许主控 SSH”期望状态与下发/确认状态（节点侧 nft 表 inet cdnca_ssh_access，
--      与 cdnca_firewall、fail2ban 并存；应用后 5 分钟内未收到主控确认，节点自行撤销）。
--      下发经 ConnectResponse 32 / ConnectRequest 29，节点需声明能力 78 SSH_ACCESS。
LOCK TABLE schema_migrations, permissions, nodes, node_ssh_install_jobs IN ACCESS EXCLUSIVE MODE;

DO $migration_608_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 607 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 607 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=607 AND
        migration_id='607_firewall_action_default_receipt' AND
        checksum_sha256='a40fdc5eb96f3ca70f1c064ab35d78d4d4bf0b4c071a8f64a3428c7b2997ce16' AND
        down_checksum_sha256='ee42b0545cde05d061a1513a3de343167d7f8cbd2619853996dcc7c5886c00cd' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR EXISTS (SELECT 1 FROM permissions WHERE name = 'nodes.ssh') THEN
        RAISE EXCEPTION 'migration 608 requires the exact verified 607 release head' USING ERRCODE='P6080';
    END IF;
END;
$migration_608_up$;

INSERT INTO permissions(name, description) VALUES
    ('nodes.ssh', 'Open an interactive SSH terminal to a platform node from the console (platform administrators only)');

CREATE TABLE node_ssh_credentials (
    node_id uuid PRIMARY KEY REFERENCES nodes(id) ON DELETE CASCADE,
    scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE CASCADE,
    port integer NOT NULL CHECK (port BETWEEN 1 AND 65535),
    username text NOT NULL CHECK (username ~ '^[a-z_][a-z0-9_.-]{0,31}$'),
    auth_kind text NOT NULL CHECK (auth_kind IN ('password', 'private_key')),
    host_key_sha256 text NOT NULL CHECK (host_key_sha256 ~ '^SHA256:[A-Za-z0-9+/]{43}$'),
    credential_key_id text NOT NULL CHECK (credential_key_id <> ''),
    credential_ciphertext bytea NOT NULL CHECK (octet_length(credential_ciphertext) BETWEEN 1 AND 65536),
    saved_by_user_id uuid NOT NULL REFERENCES users(id),
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL
);
CREATE INDEX node_ssh_credentials_scope_608_idx ON node_ssh_credentials (scope_id);

ALTER TABLE node_ssh_install_jobs ADD COLUMN restrict_ssh boolean NOT NULL DEFAULT false;

CREATE TABLE node_ssh_access (
    node_id uuid PRIMARY KEY REFERENCES nodes(id) ON DELETE CASCADE,
    scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE CASCADE,
    enabled boolean NOT NULL,
    ssh_port integer NOT NULL CHECK (ssh_port BETWEEN 1 AND 65535),
    -- 主控出口地址（开启时从配置取的快照）与运营者额外白名单，均为规范 CIDR。
    controller_cidrs text[] NOT NULL CHECK (cardinality(controller_cidrs) <= 16),
    allow_cidrs text[] NOT NULL DEFAULT '{}' CHECK (cardinality(allow_cidrs) <= 64),
    revision bigint NOT NULL CHECK (revision > 0),
    -- pending：已下发待节点应用；applied：节点已应用、等主控确认；confirmed：主控确认 SSH 仍可达；
    -- reverted：节点 5 分钟内未获确认已自行撤销；failed：节点拒绝或应用失败。
    state text NOT NULL CHECK (state IN ('pending', 'applied', 'confirmed', 'reverted', 'failed')),
    failure_code text NOT NULL DEFAULT '' CHECK (failure_code ~ '^([a-z][a-z0-9_]{0,63})?$'),
    updated_by_user_id uuid REFERENCES users(id),
    applied_at timestamptz,
    confirmed_at timestamptz,
    -- 下发记账（主控 worker）：最近一次发给节点的修订号与操作（apply / confirm）及时间；
    -- 修订号前进或超过重发间隔即重发，回执与之对账。
    published_revision bigint NOT NULL DEFAULT 0 CHECK (published_revision >= 0),
    published_operation text NOT NULL DEFAULT '' CHECK (published_operation IN ('', 'apply', 'confirm')),
    published_at timestamptz,
    updated_at timestamptz NOT NULL,
    CHECK (NOT enabled OR cardinality(controller_cidrs) >= 1),
    CHECK (published_revision <= revision)
);
CREATE INDEX node_ssh_access_due_608_idx ON node_ssh_access (state, updated_at) WHERE state IN ('pending', 'applied');

REVOKE ALL ON node_ssh_credentials, node_ssh_access FROM PUBLIC;
GRANT SELECT, INSERT, UPDATE, DELETE ON node_ssh_credentials, node_ssh_access TO cdnca_control_app, cdnca_control_runtime;
