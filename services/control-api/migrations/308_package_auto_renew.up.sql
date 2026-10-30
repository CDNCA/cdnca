LOCK TABLE schema_migrations, package_subscriptions, package_orders, notification_templates,
    notification_event_policies IN ACCESS EXCLUSIVE MODE;

DO $migration_308_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 307 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 307 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=307 AND
        migration_id='307_site_origin_keepalive' AND
        checksum_sha256='64af8a7720f0d553a0e63c6101c19729c6433a5df4996c67b1b3cbe95e9299b1' AND
        down_checksum_sha256='fe0466749f4fb83f1d655a053c65f86dda4aa33d38c51fd512ac84ca711e456a' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR checksum_sha256 IS NULL OR
        down_checksum_sha256 IS NULL OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR to_regclass(current_schema() || '.package_subscription_auto_renew_settings') IS NOT NULL OR
            EXISTS (SELECT 1 FROM notification_templates WHERE template_id LIKE 'package.auto_renew.%') THEN
        RAISE EXCEPTION 'migration 308 requires the exact verified 307 release head' USING ERRCODE='P3080';
    END IF;
END;
$migration_308_up$;

-- v6.1.0 #10 套餐自动续费. package_subscriptions rows are revision-guarded
-- snapshots, so the switch lives beside them. A missing row means "off".
CREATE TABLE package_subscription_auto_renew_settings (
    subscription_id uuid PRIMARY KEY,
    tenant_scope_id uuid NOT NULL,
    enabled boolean NOT NULL,
    period text NOT NULL CHECK (period IN ('month', 'quarter', 'year')),
    lead_hours integer NOT NULL CHECK (lead_hours BETWEEN 1 AND 720),
    revision bigint NOT NULL CHECK (revision > 0),
    updated_by_scope_id uuid NOT NULL,
    updated_by_user_id uuid NOT NULL,
    updated_at timestamptz NOT NULL,
    FOREIGN KEY (tenant_scope_id, subscription_id)
        REFERENCES package_subscriptions(tenant_scope_id, id) ON DELETE RESTRICT
);
CREATE INDEX package_subscription_auto_renew_enabled_308_idx
    ON package_subscription_auto_renew_settings (subscription_id) WHERE enabled;

-- One row per scheduled try. (subscription_id, ends_at, attempt_no) is the
-- idempotency key: a renewal moves ends_at, so a new term starts over at 1.
CREATE TABLE package_auto_renew_attempts (
    id uuid PRIMARY KEY,
    subscription_id uuid NOT NULL,
    tenant_scope_id uuid NOT NULL,
    ends_at timestamptz NOT NULL,
    attempt_no integer NOT NULL CHECK (attempt_no BETWEEN 1 AND 3),
    outcome text NOT NULL CHECK (outcome IN ('succeeded', 'failed')),
    failure_code text CHECK (failure_code IS NULL OR failure_code ~ '^[a-z][a-z0-9_]{0,63}$'),
    order_id uuid REFERENCES package_orders(id) ON DELETE RESTRICT,
    period text NOT NULL CHECK (period IN ('month', 'quarter', 'year')),
    created_at timestamptz NOT NULL,
    UNIQUE (subscription_id, ends_at, attempt_no),
    UNIQUE (order_id),
    CHECK ((outcome = 'succeeded') = (order_id IS NOT NULL)),
    CHECK ((outcome = 'failed') = (failure_code IS NOT NULL)),
    FOREIGN KEY (tenant_scope_id, subscription_id)
        REFERENCES package_subscriptions(tenant_scope_id, id) ON DELETE RESTRICT
);

CREATE FUNCTION prevent_package_auto_renew_attempt_mutation_308() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    RAISE EXCEPTION 'package auto-renew attempts are append-only';
END;
$$;
CREATE TRIGGER package_auto_renew_attempts_immutable_308
BEFORE UPDATE OR DELETE ON package_auto_renew_attempts
FOR EACH ROW EXECUTE FUNCTION prevent_package_auto_renew_attempt_mutation_308();

INSERT INTO notification_templates (template_id, version, channel, subject, body, variables, created_at) VALUES
    ('package.auto_renew.succeeded.zh-cn', 1, 'sms', '',
     '套餐{{.subscription_id}}已自动续费，扣款{{.amount}}元，有效期至{{.ends_at}}。',
     ARRAY['subscription_id','amount','ends_at'], '2026-10-17 00:00:00+00'),
    ('package.auto_renew.succeeded.zh-cn', 1, 'email', '套餐自动续费成功',
     '套餐{{.subscription_id}}已自动续费，账户余额扣款{{.amount}}元，新的有效期至{{.ends_at}}。',
     ARRAY['subscription_id','amount','ends_at'], '2026-10-17 00:00:00+00'),
    ('package.auto_renew.failed.zh-cn', 1, 'sms', '',
     '套餐{{.subscription_id}}自动续费失败（{{.reason}}），将于{{.ends_at}}到期，请及时处理。',
     ARRAY['subscription_id','reason','ends_at'], '2026-10-17 00:00:00+00'),
    ('package.auto_renew.failed.zh-cn', 1, 'email', '套餐自动续费失败',
     '套餐{{.subscription_id}}自动续费失败，原因：{{.reason}}。套餐将于{{.ends_at}}到期，请充值或手动续费。',
     ARRAY['subscription_id','reason','ends_at'], '2026-10-17 00:00:00+00');

INSERT INTO notification_event_policies(event_type, enabled, sms_enabled, email_enabled, repeat_count,
    interval_hours, supported, updated_at) VALUES
    ('package.auto_renew.succeeded', true, true, true, 1, 24, true, now()),
    ('package.auto_renew.failed', true, true, true, 1, 24, true, now());

GRANT SELECT, INSERT, UPDATE ON package_subscription_auto_renew_settings
    TO cdnca_control_app, cdnca_control_runtime;
GRANT SELECT, INSERT ON package_auto_renew_attempts TO cdnca_control_app, cdnca_control_runtime;
