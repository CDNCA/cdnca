LOCK TABLE schema_migrations, notification_event_policies, notification_templates IN ACCESS EXCLUSIVE MODE;

DO $migration_428_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 427 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 427 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=427 AND
        migration_id='427_market_supply_line_groups' AND
        checksum_sha256='a108fd06c68a15675aace029e9a278e09c84a1569259d053ef4fcb316f9eb5aa' AND
        down_checksum_sha256='0e38dc6344858f9e661065ead129785f3d36da63f5be0177188ddbe0b3c5f784' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR to_regclass(current_schema() || '.probe_dnspup_settings') IS NOT NULL OR EXISTS (
        SELECT 1 FROM notification_event_policies WHERE event_type='probe.dnspup.degraded'
       ) THEN
        RAISE EXCEPTION 'migration 428 requires the exact verified 427 release head' USING ERRCODE='P4280';
    END IF;
END;
$migration_428_up$;

-- Official plugin module.probe.dnspup (用户 10-20 19:10): the platform's own
-- dnspup customer API key pair probes origins (origin failover) and supplies
-- (aggregated edge) from dnspup's checkpoints, a probe source next to the
-- tenant's nodes (MARKET_PROBE v3) and the control plane's direct probe.
--
-- 1. probe_dnspup_settings: one row. base_url (https; default dnspup's API),
--    api_key in clear, api_secret sealed with the control-api credential
--    keyring (secret_key_id + secret_ciphertext, plaintext bound to its
--    purpose), write-only; secret_fingerprint only says "set / replaced";
--    source_domain non-empty for a key bound to a server domain (requests
--    are signed). Source orders per consumer: origin_sources (node, dnspup,
--    controller) and edge_sources (node, dnspup); default "nodes first,
--    dnspup fills up, the control plane last".
-- 2. probe_dnspup_state: one row. Last account check (async capability,
--    monthly quota), the pause of a degraded source (quota / rate limit /
--    key refused / dnspup unavailable) with its reason, and the degrade
--    sequence (one alert per sequence).
-- 3. probe_dnspup_write_requests: idempotent settings / test writes.
-- 4. Permission system.probe_dnspup.manage (platform owner).
-- 5. Notification probe.dnspup.degraded (platform members holding the
--    permission): the source paused and probes fell back.
-- No data is migrated (BATCH-PLUGIN section 9: fresh install).

CREATE TABLE probe_dnspup_settings (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    enabled boolean NOT NULL DEFAULT false,
    base_url text NOT NULL DEFAULT 'https://api.dnspup.com' CHECK (char_length(base_url) BETWEEN 1 AND 2048),
    api_key text NOT NULL DEFAULT '' CHECK (char_length(api_key) <= 512),
    secret_key_id text CHECK (secret_key_id IS NULL OR char_length(secret_key_id) BETWEEN 1 AND 128),
    secret_ciphertext bytea CHECK (secret_ciphertext IS NULL OR octet_length(secret_ciphertext) BETWEEN 29 AND 4096),
    secret_fingerprint text NOT NULL DEFAULT '' CHECK (secret_fingerprint ~ '^([0-9a-f]{16})?$'),
    source_domain text NOT NULL DEFAULT '' CHECK (char_length(source_domain) <= 253 AND source_domain = lower(source_domain)),
    origin_sources text[] NOT NULL DEFAULT ARRAY['node', 'dnspup', 'controller'] CHECK (
        cardinality(origin_sources) BETWEEN 1 AND 3 AND origin_sources <@ ARRAY['node', 'dnspup', 'controller']),
    edge_sources text[] NOT NULL DEFAULT ARRAY['node', 'dnspup'] CHECK (
        cardinality(edge_sources) BETWEEN 1 AND 2 AND edge_sources <@ ARRAY['node', 'dnspup']),
    revision bigint NOT NULL DEFAULT 0 CHECK (revision >= 0),
    updated_by_user_id uuid REFERENCES users(id) ON DELETE SET NULL,
    updated_at timestamptz NOT NULL,
    CONSTRAINT probe_dnspup_settings_secret_428_ck CHECK (
        (secret_key_id IS NULL) = (secret_ciphertext IS NULL)
        AND (secret_ciphertext IS NULL) = (secret_fingerprint = '')),
    CONSTRAINT probe_dnspup_settings_enabled_428_ck CHECK (
        NOT enabled OR (api_key <> '' AND secret_ciphertext IS NOT NULL))
);
INSERT INTO probe_dnspup_settings(singleton, updated_at) VALUES (true, CURRENT_TIMESTAMP);

CREATE TABLE probe_dnspup_state (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    account_checked_at timestamptz,
    async_capable boolean NOT NULL DEFAULT false,
    monthly_limit bigint NOT NULL DEFAULT 0 CHECK (monthly_limit >= 0),
    monthly_used bigint NOT NULL DEFAULT 0 CHECK (monthly_used >= 0),
    account_error_code text NOT NULL DEFAULT '' CHECK (account_error_code ~ '^[a-z0-9_]{0,64}$'),
    paused_until timestamptz,
    pause_reason text NOT NULL DEFAULT '' CHECK (
        pause_reason IN ('', 'quota_exceeded', 'rate_limited', 'unauthorized', 'unavailable')),
    pause_code text NOT NULL DEFAULT '' CHECK (pause_code ~ '^[a-z0-9_]{0,64}$'),
    degrade_sequence bigint NOT NULL DEFAULT 0 CHECK (degrade_sequence >= 0),
    updated_at timestamptz NOT NULL,
    CONSTRAINT probe_dnspup_state_pause_428_ck CHECK ((paused_until IS NULL) = (pause_reason = ''))
);
INSERT INTO probe_dnspup_state(singleton, updated_at) VALUES (true, CURRENT_TIMESTAMP);

CREATE TABLE probe_dnspup_write_requests (
    actor_session_id uuid NOT NULL,
    idempotency_key text NOT NULL CHECK (idempotency_key ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$'),
    operation text NOT NULL CHECK (operation IN ('settings', 'test')),
    request_digest_sha256 bytea NOT NULL CHECK (octet_length(request_digest_sha256) = 32),
    response_body jsonb NOT NULL CHECK (jsonb_typeof(response_body) = 'object'),
    created_at timestamptz NOT NULL CHECK (isfinite(created_at)),
    PRIMARY KEY (actor_session_id, idempotency_key)
);

INSERT INTO permissions(name, description)
VALUES ('system.probe_dnspup.manage', 'Configure dnspup probing (dnspup customer API key pair and probe source order)');

INSERT INTO role_permissions(role_id, permission_name)
SELECT role.id, 'system.probe_dnspup.manage'
FROM roles role
JOIN access_scopes scope ON scope.id = role.scope_id AND scope.kind = 'platform'
WHERE role.system_role AND role.name = 'platform_owner'
ON CONFLICT DO NOTHING;

INSERT INTO notification_event_policies(
    event_type, enabled, sms_enabled, email_enabled, repeat_count, interval_hours, supported,
    default_email, default_sms, updated_at
) VALUES ('probe.dnspup.degraded', true, true, true, 1, 24, true, true, false, now());

INSERT INTO notification_templates(template_id, version, channel, subject, body, variables, created_at) VALUES
    ('probe.dnspup.degraded.zh-cn', 1, 'sms', '',
     'dnspup 拨测暂停：{{.reason_text}}（{{.code}}），{{.until}} 前改用其它拨测来源，请到后台处理：{{.link}}',
     ARRAY['reason_text','code','until','link'], '2026-10-20 00:00:00+00'),
    ('probe.dnspup.degraded.zh-cn', 1, 'email', 'dnspup 拨测已暂停',
     'dnspup 拨测来源已暂停：{{.reason_text}}（dnspup 错误码 {{.code}}）。{{.until}} 前源站与聚合边缘拨测改用节点与主控直拨。请打开 {{.link}} 检查 dnspup Key、额度与来源设置。',
     ARRAY['reason_text','code','until','link'], '2026-10-20 00:00:00+00');

REVOKE ALL ON probe_dnspup_settings, probe_dnspup_state, probe_dnspup_write_requests FROM PUBLIC;
GRANT SELECT, UPDATE ON probe_dnspup_settings, probe_dnspup_state TO cdnca_control_app, cdnca_control_runtime;
GRANT SELECT, INSERT ON probe_dnspup_write_requests TO cdnca_control_app, cdnca_control_runtime;
