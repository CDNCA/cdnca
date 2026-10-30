LOCK TABLE schema_migrations, package_subscriptions, sites, notification_templates IN ACCESS EXCLUSIVE MODE;

DO $migration_299_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 298 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 298 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=298 AND
        migration_id='298_payment_channels' AND
        checksum_sha256='cb59bdfe8ad4b3e4f24c83f7ae98d3f443e2f77475c5518695a61e64c0fab155' AND
        down_checksum_sha256='f34e609b85ce1fd697586b4645c8fe17189af972a758b490fac9827bffe68513' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR checksum_sha256 IS NULL OR
        down_checksum_sha256 IS NULL OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR to_regclass(current_schema() || '.package_traffic_site_suspensions') IS NOT NULL OR
            to_regclass(current_schema() || '.package_traffic_enforcement_schedule') IS NOT NULL THEN
        RAISE EXCEPTION 'migration 299 requires the exact verified 298 release head' USING ERRCODE='P2990';
    END IF;
END;
$migration_299_up$;

-- Package traffic enforcement (FX25/FX52). A site moved to traffic_exceeded by
-- the package cycle head keeps one open suspension fact; only this fact lets
-- the enforcement recover the site, so sites stopped for any other reason are
-- never resumed by it.
CREATE TABLE package_traffic_site_suspensions (
    suspension_id uuid PRIMARY KEY,
    tenant_scope_id uuid NOT NULL,
    subscription_id uuid NOT NULL,
    site_id uuid NOT NULL REFERENCES sites(id) ON DELETE RESTRICT,
    period_key text NOT NULL CHECK (period_key = btrim(period_key) AND char_length(period_key) BETWEEN 1 AND 256),
    head_revision bigint NOT NULL CHECK (head_revision > 0),
    suspended_at timestamptz NOT NULL,
    recovered_at timestamptz,
    recovered_period_key text CHECK (
        recovered_period_key IS NULL OR
        (recovered_period_key = btrim(recovered_period_key) AND char_length(recovered_period_key) BETWEEN 1 AND 256)
    ),
    recovered_reason text CHECK (recovered_reason IS NULL OR recovered_reason IN (
        'new_cycle', 'within_limit', 'traffic_close_disabled', 'manual_override', 'detached'
    )),
    recovered_site_status text CHECK (recovered_site_status IS NULL OR recovered_site_status IN ('active', 'unchanged')),
    FOREIGN KEY (tenant_scope_id, subscription_id)
        REFERENCES package_subscriptions(tenant_scope_id, id) ON DELETE RESTRICT,
    CHECK ((recovered_at IS NULL) = (recovered_reason IS NULL) AND
           (recovered_at IS NULL) = (recovered_site_status IS NULL) AND
           (recovered_period_key IS NULL OR recovered_at IS NOT NULL)),
    CHECK (recovered_at IS NULL OR recovered_at >= suspended_at)
);

CREATE UNIQUE INDEX package_traffic_site_suspensions_open_299
    ON package_traffic_site_suspensions (site_id) WHERE recovered_at IS NULL;
CREATE INDEX package_traffic_site_suspensions_subscription_299
    ON package_traffic_site_suspensions (tenant_scope_id, subscription_id) WHERE recovered_at IS NULL;
CREATE INDEX package_traffic_site_suspensions_site_latest_299
    ON package_traffic_site_suspensions (site_id, suspended_at DESC, suspension_id DESC);

CREATE FUNCTION protect_package_traffic_site_suspension_299()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'UPDATE' AND OLD.recovered_at IS NULL AND NEW.recovered_at IS NOT NULL AND
       NEW.suspension_id = OLD.suspension_id AND NEW.tenant_scope_id = OLD.tenant_scope_id AND
       NEW.subscription_id = OLD.subscription_id AND NEW.site_id = OLD.site_id AND
       NEW.period_key = OLD.period_key AND NEW.head_revision = OLD.head_revision AND
       NEW.suspended_at = OLD.suspended_at THEN
        RETURN NEW;
    END IF;
    RAISE EXCEPTION 'package traffic site suspensions only close once' USING ERRCODE='P2991';
END;
$$;

CREATE TRIGGER package_traffic_site_suspensions_close_once_299
BEFORE UPDATE OR DELETE ON package_traffic_site_suspensions
FOR EACH ROW EXECUTE FUNCTION protect_package_traffic_site_suspension_299();

-- One row per subscription; replicas claim due rows with SKIP LOCKED, so a
-- subscription is evaluated by at most one replica per tick.
CREATE TABLE package_traffic_enforcement_schedule (
    tenant_scope_id uuid NOT NULL,
    subscription_id uuid NOT NULL,
    next_evaluation_at timestamptz NOT NULL,
    last_evaluated_at timestamptz,
    last_error text CHECK (last_error IS NULL OR last_error ~ '^[a-z0-9_]{1,64}$'),
    PRIMARY KEY (tenant_scope_id, subscription_id),
    FOREIGN KEY (tenant_scope_id, subscription_id)
        REFERENCES package_subscriptions(tenant_scope_id, id) ON DELETE RESTRICT
);

CREATE INDEX package_traffic_enforcement_schedule_due_299
    ON package_traffic_enforcement_schedule (next_evaluation_at, tenant_scope_id, subscription_id);

-- Delivered through the existing package.monitor.traffic.* event policies.
INSERT INTO notification_templates (template_id, version, channel, subject, body, variables, created_at) VALUES
    ('package.traffic.suspended.zh-cn', 1, 'sms', '',
     '套餐{{.subscription_id}}本周期流量{{.metric_value}}已超过上限{{.threshold_value}}（周期{{.period_key}}）。',
     ARRAY['subscription_id','metric_value','threshold_value','period_key'], '2026-10-17 00:00:00+00'),
    ('package.traffic.suspended.zh-cn', 1, 'email', '套餐流量已超限',
     '套餐{{.subscription_id}}在周期{{.period_key}}的流量已用{{.metric_value}}，超过上限{{.threshold_value}}。按平台设置，相关网站可能已停用，续费、升级或购买流量包后会自动恢复。',
     ARRAY['subscription_id','metric_value','threshold_value','period_key'], '2026-10-17 00:00:00+00'),
    ('package.traffic.recovered.zh-cn', 1, 'sms', '',
     '套餐{{.subscription_id}}流量已恢复可用，当前用量{{.metric_value}}，上限{{.threshold_value}}（周期{{.period_key}}）。',
     ARRAY['subscription_id','metric_value','threshold_value','period_key'], '2026-10-17 00:00:00+00'),
    ('package.traffic.recovered.zh-cn', 1, 'email', '套餐流量已恢复',
     '套餐{{.subscription_id}}在周期{{.period_key}}的流量已恢复可用，当前用量{{.metric_value}}，上限{{.threshold_value}}，相关网站已自动恢复。',
     ARRAY['subscription_id','metric_value','threshold_value','period_key'], '2026-10-17 00:00:00+00');

REVOKE ALL ON package_traffic_site_suspensions, package_traffic_enforcement_schedule FROM PUBLIC;
REVOKE ALL ON FUNCTION protect_package_traffic_site_suspension_299() FROM PUBLIC;
GRANT SELECT, INSERT, UPDATE ON package_traffic_site_suspensions TO cdnca_control_app, cdnca_control_runtime;
GRANT SELECT, INSERT, UPDATE ON package_traffic_enforcement_schedule TO cdnca_control_app, cdnca_control_runtime;
