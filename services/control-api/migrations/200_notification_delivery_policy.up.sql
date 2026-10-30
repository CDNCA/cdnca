LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;

DO $migration_200$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 199 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 199 OR
       NOT EXISTS (SELECT 1 FROM schema_migrations WHERE version=199 AND migration_id='199_platform_system_settings_runtime_grants' AND checksum_sha256='e0f52bf3e1040cd31ab4a88d43604a72db0939dcc54ba743a6176b55740fdcf5' AND down_checksum_sha256='2b0f7cf1c085731c28ae47ac2d3f909e1fc61d56ecddd812c0142d4bc0cb5a65' AND integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL) THEN
        RAISE EXCEPTION 'migration 200 requires the exact verified 199 release head' USING ERRCODE='P2000';
    END IF;
END;
$migration_200$;

CREATE TABLE notification_delivery_policy (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    window_mode text NOT NULL CHECK (window_mode IN ('all_day', 'custom')),
    window_start_minute integer NOT NULL CHECK (window_start_minute BETWEEN 0 AND 1439),
    window_end_minute integer NOT NULL CHECK (window_end_minute BETWEEN 0 AND 1439),
    timezone text NOT NULL CHECK (length(timezone) BETWEEN 1 AND 64),
    revision bigint NOT NULL CHECK (revision >= 1),
    updated_at timestamptz NOT NULL
);

INSERT INTO notification_delivery_policy(singleton, window_mode, window_start_minute, window_end_minute, timezone, revision, updated_at)
VALUES (true, 'all_day', 0, 1439, 'Asia/Shanghai', 1, now());

CREATE TABLE notification_event_policies (
    event_type text PRIMARY KEY CHECK (event_type ~ '^[a-z][a-z0-9._-]{0,95}$'),
    enabled boolean NOT NULL,
    sms_enabled boolean NOT NULL,
    email_enabled boolean NOT NULL,
    repeat_count integer NOT NULL CHECK (repeat_count BETWEEN 1 AND 10),
    interval_hours integer NOT NULL CHECK (interval_hours BETWEEN 1 AND 168),
    supported boolean NOT NULL,
    updated_at timestamptz NOT NULL
);

INSERT INTO notification_event_policies(event_type, enabled, sms_enabled, email_enabled, repeat_count, interval_hours, supported, updated_at)
SELECT event_type, true, true, true, 1, 24, supported, now()
FROM (VALUES
    ('announcement.published', true),
    ('package.monitor.traffic.triggered', true),
    ('package.monitor.traffic.recovered', true),
    ('package.monitor.bandwidth.triggered', true),
    ('package.monitor.bandwidth.recovered', true),
    ('package.monitor.connections.triggered', true),
    ('package.monitor.connections.recovered', true),
    ('package.monitor.expiration.triggered', true),
    ('package.monitor.expiration.recovered', true),
    ('package.monitor.cc_rule_auto_switch', false),
    ('package.monitor.bandwidth_over_limit', false),
    ('package.monitor.connections_over_limit', false),
    ('certificate.expired', false),
    ('certificate.expiring', false),
    ('identity.secondary_verification', false)
) AS seed(event_type, supported);

DO $grant_notification_policy$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname='cdnca_control_app') THEN
        GRANT SELECT,INSERT,UPDATE ON notification_delivery_policy, notification_event_policies TO cdnca_control_app;
    END IF;
END;
$grant_notification_policy$;
