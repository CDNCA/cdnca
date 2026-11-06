-- 639（前驱 638_security_policy_batch_idempotency）：
-- 拨测插件 module.probe.dnspup 细化与统一出口（docs/architecture/probe-dnspup-unified.md）。
--   1. node_dnspup_probe_settings 加拨测类型、细化选点 selection、线路告警阈值、自动排障开关；
--   2. node_dnspup_probe_overrides：按节点或线路组覆盖拨测类型与选点；
--   3. probe_dnspup_purposes / probe_dnspup_usage：按用途的开关、月上限、频率与本月计量；
--   4. probe_dnspup_observations：节点以外的拨测结果（聚合边缘候选、排障），矩阵视图读它；
--   5. node_dnspup_line_alert_states + 事件 node.dnspup.line_unreachable / line_recovered；
--   6. 插件拨测接口：权限 probes.dnspup.request（授 tenant_owner，含新建租户触发器，同 603 模式），
--      probe_dnspup_settings 加插件限速，probe_dnspup_plugin_requests / probe_dnspup_plugin_usage；
--   7. probe_dnspup_write_requests.operation 加 purposes / overrides / diagnose。
LOCK TABLE schema_migrations, access_scopes, roles, role_permissions, permissions, custom_rbac_permission_catalog,
    notification_event_policies, notification_templates, probe_dnspup_settings, probe_dnspup_write_requests,
    node_dnspup_probe_settings IN ACCESS EXCLUSIVE MODE;

DO $migration_639_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 638 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 638 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=638 AND
        migration_id='638_security_policy_batch_idempotency' AND
        checksum_sha256='29eed0e1939f03ced6f1853921b4f5be5e047726e427fe3c0a5f72d4996f148c' AND
        down_checksum_sha256='c6b092c39067eb0866d2169ede92f9e56143ac6929628725b0f55650f7a3cf37' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR to_regclass(current_schema() || '.probe_dnspup_purposes') IS NOT NULL
         OR EXISTS (SELECT 1 FROM permissions WHERE name = 'probes.dnspup.request')
         OR EXISTS (SELECT 1 FROM notification_event_policies
                    WHERE event_type IN ('node.dnspup.line_unreachable', 'node.dnspup.line_recovered')) THEN
        RAISE EXCEPTION 'migration 639 requires the exact verified 638 release head' USING ERRCODE='P6390';
    END IF;
END;
$migration_639_up$;

ALTER TABLE node_dnspup_probe_settings
    ADD COLUMN probe_type text NOT NULL DEFAULT 'tcping' CHECK (probe_type IN ('tcping', 'ping', 'http')),
    ADD COLUMN selection jsonb CHECK (selection IS NULL OR jsonb_typeof(selection) = 'object'),
    ADD COLUMN line_alert_min_points integer NOT NULL DEFAULT 3 CHECK (line_alert_min_points BETWEEN 1 AND 20),
    ADD COLUMN line_alert_rounds integer NOT NULL DEFAULT 2 CHECK (line_alert_rounds BETWEEN 1 AND 10),
    ADD COLUMN auto_diagnose boolean NOT NULL DEFAULT true;

CREATE TABLE node_dnspup_probe_overrides (
    id uuid PRIMARY KEY,
    subject_kind text NOT NULL CHECK (subject_kind IN ('node', 'line_group')),
    node_id uuid REFERENCES nodes(id) ON DELETE CASCADE,
    tenant_scope_id uuid REFERENCES access_scopes(id) ON DELETE CASCADE,
    line_group_id uuid,
    probe_type text CHECK (probe_type IS NULL OR probe_type IN ('tcping', 'ping', 'http')),
    selection jsonb CHECK (selection IS NULL OR jsonb_typeof(selection) = 'object'),
    revision bigint NOT NULL DEFAULT 1 CHECK (revision >= 1),
    updated_by_user_id uuid REFERENCES users(id) ON DELETE SET NULL,
    updated_at timestamptz NOT NULL,
    CHECK (subject_kind = 'node' AND node_id IS NOT NULL AND tenant_scope_id IS NULL AND line_group_id IS NULL OR
           subject_kind = 'line_group' AND node_id IS NULL AND tenant_scope_id IS NOT NULL AND line_group_id IS NOT NULL),
    CHECK (probe_type IS NOT NULL OR selection IS NOT NULL)
);
CREATE UNIQUE INDEX node_dnspup_probe_overrides_node_639_uq ON node_dnspup_probe_overrides(node_id)
    WHERE subject_kind = 'node';
CREATE UNIQUE INDEX node_dnspup_probe_overrides_group_639_uq ON node_dnspup_probe_overrides(tenant_scope_id, line_group_id)
    WHERE subject_kind = 'line_group';

CREATE TABLE probe_dnspup_purposes (
    purpose text PRIMARY KEY CHECK (purpose IN ('node_availability', 'origin_failover', 'edge_health', 'plugin', 'diagnose')),
    enabled boolean NOT NULL DEFAULT true,
    monthly_cap bigint NOT NULL DEFAULT 0 CHECK (monthly_cap BETWEEN 0 AND 1000000000),
    -- 0: the runner's own interval; otherwise at least this many seconds between rounds.
    interval_seconds integer NOT NULL DEFAULT 0 CHECK (interval_seconds BETWEEN 0 AND 86400),
    updated_by_user_id uuid REFERENCES users(id) ON DELETE SET NULL,
    updated_at timestamptz NOT NULL
);
INSERT INTO probe_dnspup_purposes(purpose, monthly_cap, updated_at) VALUES
    ('node_availability', 0, now()), ('origin_failover', 0, now()), ('edge_health', 0, now()),
    ('plugin', 0, now()), ('diagnose', 300, now());

CREATE TABLE probe_dnspup_usage (
    month date NOT NULL CHECK (extract(day FROM month) = 1),
    purpose text NOT NULL REFERENCES probe_dnspup_purposes(purpose) ON DELETE CASCADE,
    requests bigint NOT NULL DEFAULT 0 CHECK (requests >= 0),
    PRIMARY KEY (month, purpose)
);

CREATE TABLE probe_dnspup_observations (
    id bigserial PRIMARY KEY,
    consumer text NOT NULL CHECK (consumer IN ('edge', 'diagnose')),
    subject text NOT NULL CHECK (length(subject) BETWEEN 1 AND 300),
    probe_type text NOT NULL CHECK (probe_type IN ('tcping', 'ping', 'http', 'https', 'dns', 'mtr')),
    observed_at timestamptz NOT NULL CHECK (isfinite(observed_at)),
    total_checks integer NOT NULL CHECK (total_checks BETWEEN 0 AND 100),
    failed_checks integer NOT NULL CHECK (failed_checks BETWEEN 0 AND total_checks),
    checkpoints jsonb NOT NULL CHECK (jsonb_typeof(checkpoints) = 'array')
);
CREATE INDEX probe_dnspup_observations_subject_639_idx ON probe_dnspup_observations(consumer, subject, observed_at);
CREATE INDEX probe_dnspup_observations_observed_639_idx ON probe_dnspup_observations(observed_at);

CREATE TABLE node_dnspup_line_alert_states (
    node_id uuid NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
    carrier text NOT NULL CHECK (carrier IN ('telecom', 'unicom', 'mobile', 'edu', 'bgp', 'other')),
    area text NOT NULL CHECK (length(area) BETWEEN 1 AND 16),
    consecutive_failed integer NOT NULL DEFAULT 0 CHECK (consecutive_failed >= 0),
    failing boolean NOT NULL DEFAULT false,
    failed_points integer NOT NULL DEFAULT 0 CHECK (failed_points >= 0),
    total_points integer NOT NULL DEFAULT 0 CHECK (total_points >= failed_points),
    top_failure text NOT NULL DEFAULT '' CHECK (top_failure IN ('', 'refused', 'timeout', 'reset', 'tls', 'http', 'dns', 'other')),
    alert_revision bigint NOT NULL DEFAULT 0 CHECK (alert_revision >= 0),
    updated_at timestamptz NOT NULL,
    PRIMARY KEY (node_id, carrier, area)
);

ALTER TABLE probe_dnspup_settings
    ADD COLUMN plugin_per_minute integer NOT NULL DEFAULT 60 CHECK (plugin_per_minute BETWEEN 1 AND 600),
    ADD COLUMN plugin_tenant_monthly bigint NOT NULL DEFAULT 20000 CHECK (plugin_tenant_monthly BETWEEN 0 AND 1000000000);

CREATE TABLE probe_dnspup_plugin_requests (
    id uuid PRIMARY KEY,
    origin text NOT NULL CHECK (origin IN ('plugin', 'admin', 'alert')),
    tenant_scope_id uuid REFERENCES access_scopes(id) ON DELETE CASCADE,
    installation_id uuid,
    api_key_id uuid,
    node_id uuid REFERENCES nodes(id) ON DELETE CASCADE,
    idempotency_key text NOT NULL CHECK (length(idempotency_key) BETWEEN 1 AND 128),
    request_digest_sha256 bytea NOT NULL CHECK (length(request_digest_sha256) = 32),
    request jsonb NOT NULL CHECK (jsonb_typeof(request) = 'object'),
    dnspup_request_id text NOT NULL DEFAULT '' CHECK (length(dnspup_request_id) <= 128),
    status text NOT NULL CHECK (status IN ('pending', 'completed', 'failed')),
    result jsonb CHECK (result IS NULL OR jsonb_typeof(result) = 'object'),
    error_code text NOT NULL DEFAULT '' CHECK (length(error_code) <= 64),
    created_at timestamptz NOT NULL,
    polled_at timestamptz,
    expires_at timestamptz NOT NULL,
    CHECK (origin = 'plugin' AND tenant_scope_id IS NOT NULL AND installation_id IS NOT NULL AND api_key_id IS NOT NULL OR
           origin <> 'plugin' AND installation_id IS NULL AND api_key_id IS NULL)
);
CREATE UNIQUE INDEX probe_dnspup_plugin_requests_idem_639_uq ON probe_dnspup_plugin_requests(installation_id, idempotency_key)
    WHERE origin = 'plugin';
CREATE INDEX probe_dnspup_plugin_requests_rate_639_idx ON probe_dnspup_plugin_requests(installation_id, created_at);
CREATE INDEX probe_dnspup_plugin_requests_expiry_639_idx ON probe_dnspup_plugin_requests(expires_at);
CREATE INDEX probe_dnspup_plugin_requests_node_639_idx ON probe_dnspup_plugin_requests(node_id, created_at)
    WHERE node_id IS NOT NULL;

CREATE TABLE probe_dnspup_plugin_usage (
    month date NOT NULL CHECK (extract(day FROM month) = 1),
    tenant_scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE CASCADE,
    installation_id uuid NOT NULL,
    requests bigint NOT NULL DEFAULT 0 CHECK (requests >= 0),
    PRIMARY KEY (month, tenant_scope_id, installation_id)
);

ALTER TABLE probe_dnspup_write_requests DROP CONSTRAINT probe_dnspup_write_requests_operation_462_ck,
    ADD CONSTRAINT probe_dnspup_write_requests_operation_639_ck
        CHECK (operation IN ('settings', 'test', 'node_settings', 'purposes', 'overrides', 'diagnose'));

INSERT INTO permissions(name, description) VALUES
    ('probes.dnspup.request', 'Run dnspup probes against public targets with the platform''s dnspup quota (plugin probe API; results go back to the caller only)');
INSERT INTO custom_rbac_permission_catalog(permission_name, step_up_required) VALUES ('probes.dnspup.request', false);

CREATE TABLE tenant_system_role_grant_additions_639 (
    role_id uuid NOT NULL,
    permission_name text NOT NULL,
    PRIMARY KEY (role_id, permission_name),
    CONSTRAINT tenant_system_role_grant_permission_fk_639
        FOREIGN KEY (role_id, permission_name)
        REFERENCES role_permissions(role_id, permission_name) ON DELETE CASCADE
);

WITH additions AS (
    INSERT INTO role_permissions(role_id, permission_name)
    SELECT role.id, 'probes.dnspup.request'
    FROM roles role
    JOIN access_scopes scope ON scope.id = role.scope_id AND scope.kind = 'tenant'
    WHERE role.system_role AND role.name = 'tenant_owner'
    ON CONFLICT DO NOTHING
    RETURNING role_id, permission_name
)
INSERT INTO tenant_system_role_grant_additions_639(role_id, permission_name)
SELECT role_id, permission_name FROM additions;

CREATE FUNCTION grant_tenant_probes_dnspup_request_639()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NOT NEW.system_role OR NEW.name <> 'tenant_owner' OR NOT EXISTS (
        SELECT 1 FROM access_scopes WHERE id = NEW.scope_id AND kind = 'tenant'
    ) THEN
        RETURN NEW;
    END IF;
    WITH additions AS (
        INSERT INTO role_permissions(role_id, permission_name)
        VALUES (NEW.id, 'probes.dnspup.request')
        ON CONFLICT DO NOTHING
        RETURNING role_id, permission_name
    )
    INSERT INTO tenant_system_role_grant_additions_639(role_id, permission_name)
    SELECT role_id, permission_name FROM additions;
    RETURN NEW;
END;
$$;

CREATE TRIGGER roles_tenant_probes_dnspup_request_639
AFTER INSERT ON roles
FOR EACH ROW EXECUTE FUNCTION grant_tenant_probes_dnspup_request_639();

REVOKE ALL ON FUNCTION grant_tenant_probes_dnspup_request_639() FROM PUBLIC;

INSERT INTO notification_event_policies(
    event_type, enabled, sms_enabled, email_enabled, repeat_count, interval_hours, supported,
    default_email, default_sms, updated_at
) VALUES
    ('node.dnspup.line_unreachable', true, true, true, 1, 24, true, true, false, now()),
    ('node.dnspup.line_recovered', true, true, true, 1, 24, true, true, false, now());

INSERT INTO notification_templates(template_id, version, channel, subject, body, variables, created_at) VALUES
    ('node.dnspup.line_unreachable.zh-cn', 1, 'sms', '',
     '节点{{.node_name}}（{{.node_ip}}）{{.line}} {{.failed}} 个点连续失败（主要故障：{{.failure}}）。',
     ARRAY['node_name','node_ip','line','failed','failure'], '2026-11-05 00:00:00+00'),
    ('node.dnspup.line_unreachable.zh-cn', 1, 'email', 'dnspup 线路拨测失败：{{.node_name}} {{.line}}',
     '节点 {{.node_name}}（{{.node_ip}}）在 {{.occurred_at}}（UTC）{{.line}} {{.failed}}/{{.total}} 个检测点连续失败，主要故障：{{.failure}}。这是诊断告警，不改变节点调度；详情见 {{.link}}。',
     ARRAY['node_name','node_ip','line','failed','total','failure','occurred_at','link'], '2026-11-05 00:00:00+00'),
    ('node.dnspup.line_recovered.zh-cn', 1, 'sms', '',
     '节点{{.node_name}}（{{.node_ip}}）{{.line}} 拨测已恢复。',
     ARRAY['node_name','node_ip','line'], '2026-11-05 00:00:00+00'),
    ('node.dnspup.line_recovered.zh-cn', 1, 'email', 'dnspup 线路拨测已恢复：{{.node_name}} {{.line}}',
     '节点 {{.node_name}}（{{.node_ip}}）在 {{.occurred_at}}（UTC）{{.line}} 拨测已恢复。',
     ARRAY['node_name','node_ip','line','occurred_at'], '2026-11-05 00:00:00+00');

REVOKE ALL ON node_dnspup_probe_overrides, probe_dnspup_purposes, probe_dnspup_usage, probe_dnspup_observations,
    node_dnspup_line_alert_states, probe_dnspup_plugin_requests, probe_dnspup_plugin_usage FROM PUBLIC;
GRANT SELECT, INSERT, UPDATE, DELETE ON node_dnspup_probe_overrides TO cdnca_control_app, cdnca_control_runtime;
GRANT SELECT, UPDATE ON probe_dnspup_purposes TO cdnca_control_app, cdnca_control_runtime;
GRANT SELECT, INSERT, UPDATE ON probe_dnspup_usage TO cdnca_control_app, cdnca_control_runtime;
GRANT SELECT, INSERT, DELETE ON probe_dnspup_observations TO cdnca_control_app, cdnca_control_runtime;
GRANT USAGE, SELECT ON SEQUENCE probe_dnspup_observations_id_seq TO cdnca_control_app, cdnca_control_runtime;
GRANT SELECT, INSERT, UPDATE, DELETE ON node_dnspup_line_alert_states TO cdnca_control_app, cdnca_control_runtime;
GRANT SELECT, INSERT, UPDATE, DELETE ON probe_dnspup_plugin_requests TO cdnca_control_app, cdnca_control_runtime;
GRANT SELECT, INSERT, UPDATE ON probe_dnspup_plugin_usage TO cdnca_control_app, cdnca_control_runtime;
