LOCK TABLE schema_migrations, site_origin_pools, site_origins, edge_system_republication_heads,
    edge_system_republication_attempts, edge_system_revision_segments, notification_event_policies,
    notification_templates IN ACCESS EXCLUSIVE MODE;

DO $migration_418_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 417 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 417 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=417 AND
        migration_id='417_rule_pack_mount_suspensions' AND
        checksum_sha256='080ae0dd3d3c77faf5c4c98073f7e6b1e7bd01cbe47bcb2da895b74ec366d4ca' AND
        down_checksum_sha256='6d814a39ae6484c1691644cb8ab8978a46f11bfd08098101b40e256bc239405a' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) THEN
        RAISE EXCEPTION 'migration 418 requires the exact verified 417 release head' USING ERRCODE='P4180';
    END IF;
END;
$migration_418_up$;

-- 418 (r136 origin-failover, placeholder number: BATCH-PLUGIN 18 reserves
-- 422, renumbered on merge). Origins of a site's pool are ordered in levels
-- (0 = primary, 1 = backup 1, ...): the edge uses the lowest usable level
-- from the pool's active level on, a level only when every origin of the
-- levels before it is down. 1.0.35 is the first release: backup becomes
-- level 1 with no compatibility path.
ALTER TABLE site_origins
    ADD COLUMN level smallint NOT NULL DEFAULT 0 CHECK (level BETWEEN 0 AND 15);
UPDATE site_origins SET level = 1 WHERE backup;
-- the update queued the pool's deferred checks: run them before the next
-- ALTER of the table
SET CONSTRAINTS ALL IMMEDIATE;
SET CONSTRAINTS ALL DEFERRED;
ALTER TABLE site_origins DROP COLUMN backup;

-- failback_mode: after a higher level recovers, auto returns to it (after
-- the probe's debounce), manual waits for the user's "switch back".
-- health_check_path is what the control plane probes on every origin.
ALTER TABLE site_origin_pools
    ADD COLUMN failback_mode text NOT NULL DEFAULT 'auto' CHECK (failback_mode IN ('auto', 'manual')),
    ADD COLUMN health_check_path text NOT NULL DEFAULT '/'
        CHECK (health_check_path ~ '^/[A-Za-z0-9._~!$&''()*+,;=:@%/?-]{0,255}$');

-- A pool needs an enabled level 0 (primary) origin.
CREATE OR REPLACE FUNCTION validate_site_origin_pool(target_site_id uuid) RETURNS void
LANGUAGE plpgsql AS $$
DECLARE
    pool_failover smallint;
    origin_count integer;
    enabled_count integer;
    primary_count integer;
BEGIN
    IF NOT EXISTS (SELECT 1 FROM sites WHERE id = target_site_id) THEN
        RETURN;
    END IF;

    SELECT failover_tries
    INTO pool_failover
    FROM site_origin_pools
    WHERE site_id = target_site_id;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'site origin pool is required for site %', target_site_id
            USING ERRCODE = '23514';
    END IF;

    SELECT count(*), count(*) FILTER (WHERE enabled), count(*) FILTER (WHERE enabled AND level = 0)
    INTO origin_count, enabled_count, primary_count
    FROM site_origins
    WHERE site_id = target_site_id;

    IF origin_count < 1 OR origin_count > 32 OR enabled_count < 1 OR primary_count < 1 OR
       pool_failover > enabled_count THEN
        RAISE EXCEPTION 'site origin pool invariant failed for site %', target_site_id
            USING ERRCODE = '23514';
    END IF;
END;
$$;

-- The pool's active level (what the edge starts from), moved by the probe
-- runner (internal/originfailover) or the user's switch back. No row: 0.
-- failback_ready: manual mode, a higher level is healthy again.
CREATE TABLE site_origin_failover_states (
    site_id uuid PRIMARY KEY REFERENCES sites(id) ON DELETE CASCADE,
    active_level smallint NOT NULL CHECK (active_level BETWEEN 0 AND 15),
    failback_ready boolean NOT NULL DEFAULT false,
    sequence bigint NOT NULL DEFAULT 0 CHECK (sequence >= 0),
    switched_at timestamptz,
    checked_at timestamptz,
    -- the Idempotency-Key of the last manual switch back (its replay)
    failback_request_key text CHECK (char_length(failback_request_key) BETWEEN 1 AND 128),
    updated_at timestamptz NOT NULL
);

-- Each origin's probe state by address (a reordered pool keeps it):
-- consecutive outcomes debounce the status.
CREATE TABLE site_origin_probe_states (
    site_id uuid NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
    host text NOT NULL CHECK (char_length(host) BETWEEN 1 AND 253),
    port integer NOT NULL CHECK (port BETWEEN 1 AND 65535),
    status text NOT NULL CHECK (status IN ('healthy', 'unhealthy', 'unknown')),
    consecutive_failures integer NOT NULL DEFAULT 0 CHECK (consecutive_failures >= 0),
    consecutive_successes integer NOT NULL DEFAULT 0 CHECK (consecutive_successes >= 0),
    reason text NOT NULL DEFAULT '' CHECK (char_length(reason) <= 64),
    checked_at timestamptz NOT NULL,
    PRIMARY KEY (site_id, host, port)
);

REVOKE ALL ON site_origin_failover_states, site_origin_probe_states FROM PUBLIC;
GRANT SELECT, INSERT, UPDATE, DELETE ON site_origin_failover_states, site_origin_probe_states
    TO cdnca_control_app, cdnca_control_runtime;

-- A level change republishes the scope through the system channel
-- (trigger origin_failover; 417's checks extended, cardinality 14 -> 15).
ALTER TABLE edge_system_republication_heads
    DROP CONSTRAINT edge_system_republication_heads_triggers_check,
    ADD CONSTRAINT edge_system_republication_heads_triggers_check CHECK (cardinality(triggers) BETWEEN 1 AND 15 AND
        triggers <@ ARRAY['node_capability', 'traffic_enforcement', 'line_group', 'node_sync', 'domain_ownership',
            'secondary_verification', 'rule_catalog', 'challenge_delivery', 'module_entitlement',
            'theme_activation', 'account_suspension', 'node_networks', 'error_page_published',
            'origin_auth_published', 'origin_failover']::text[]);
ALTER TABLE edge_system_republication_attempts
    DROP CONSTRAINT edge_system_republication_attempts_triggers_check,
    ADD CONSTRAINT edge_system_republication_attempts_triggers_check CHECK (cardinality(triggers) BETWEEN 1 AND 15);
ALTER TABLE edge_system_revision_segments
    DROP CONSTRAINT edge_system_revision_segments_source_check,
    ADD CONSTRAINT edge_system_revision_segments_source_check CHECK (source IN ('node_capability', 'traffic_enforcement',
        'line_group', 'node_sync', 'domain_ownership', 'secondary_verification', 'rule_catalog', 'challenge_delivery',
        'module_entitlement', 'account_suspension', 'node_networks', 'error_page_published', 'origin_auth_published',
        'origin_failover'));

-- Notification center: a level switch, and (manual mode) a recovered higher
-- level that can be switched back to. The site owner is notified.
INSERT INTO notification_event_policies(
    event_type, enabled, sms_enabled, email_enabled, repeat_count, interval_hours, supported, default_email, updated_at
) VALUES ('site.origin.failover', true, true, true, 1, 1, true, true, now()),
         ('site.origin.recovered', true, true, true, 1, 1, true, true, now());

INSERT INTO notification_templates(template_id, version, channel, subject, body, variables, created_at) VALUES
    ('site.origin.failover.zh-cn', 1, 'sms', '',
     '网站{{.domain}}回源已从{{.from_level}}切换到{{.to_level}}：{{.reason}}。',
     ARRAY['domain','from_level','to_level','reason'], '2026-10-20 00:00:00+00'),
    ('site.origin.failover.zh-cn', 1, 'email', '回源切换：{{.domain}}',
     '网站 {{.domain}} 于 {{.switched_at}} 回源从 {{.from_level}} 切换到 {{.to_level}}，原因：{{.reason}}。回切方式：{{.failback_mode}}。请在控制台“网站设置 - 回源”查看各源站状态{{.action}}。',
     ARRAY['domain','switched_at','from_level','to_level','reason','failback_mode','action'], '2026-10-20 00:00:00+00'),
    ('site.origin.recovered.zh-cn', 1, 'sms', '',
     '网站{{.domain}}的{{.level}}已恢复，可在控制台手动切回。',
     ARRAY['domain','level'], '2026-10-20 00:00:00+00'),
    ('site.origin.recovered.zh-cn', 1, 'email', '源站已恢复，可手动切回：{{.domain}}',
     '网站 {{.domain}} 的 {{.level}} 于 {{.recovered_at}} 拨测恢复正常，当前仍在 {{.active_level}}（手动回切）。请在控制台“网站设置 - 回源”点击“切回主源”。',
     ARRAY['domain','recovered_at','level','active_level'], '2026-10-20 00:00:00+00');
