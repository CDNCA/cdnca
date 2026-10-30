-- 508（r136 l4-traffic，用户 10-25 15:3x「四层流量和七层同口径扣套餐月流量，超额按同样规则处理」；
-- 派单号 506，merge-p7 改号为 508 接 507（原 493 接 492））。
-- 套餐流量超额停服对四层转发生效：转发 admin_status normal → traffic_exceeded（不再下发，节点撤监听），
-- 本表记一条 open 事实；只有本事实能让超额停服恢复转发，管理员手动设的状态（locked 等）不被它动。
LOCK TABLE schema_migrations, l4_forwards IN ACCESS EXCLUSIVE MODE;

DO $migration_508_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 507 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 507 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=507 AND
        migration_id='507_dns_reconcile_stream_anchor' AND
        checksum_sha256='20bf64648ec52edeab0e7680347d5d9def5b41fb9e3081cdd132e25527865f6a' AND
        down_checksum_sha256='d63e3d754b78657212894423824bf81faf05310a5f95565566a932480b99bd0b' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR to_regclass(current_schema() || '.package_traffic_stream_suspensions') IS NOT NULL THEN
        RAISE EXCEPTION 'migration 508 requires the exact verified 507 head' USING ERRCODE='P5080';
    END IF;
END;
$migration_508_up$;

CREATE TABLE package_traffic_stream_suspensions (
    suspension_id uuid PRIMARY KEY,
    tenant_scope_id uuid NOT NULL,
    subscription_id uuid NOT NULL,
    stream_id uuid NOT NULL REFERENCES l4_forwards(id) ON DELETE RESTRICT,
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
    recovered_stream_status text CHECK (recovered_stream_status IS NULL OR recovered_stream_status IN ('normal', 'unchanged')),
    FOREIGN KEY (tenant_scope_id, subscription_id)
        REFERENCES package_subscriptions(tenant_scope_id, id) ON DELETE RESTRICT,
    CHECK ((recovered_at IS NULL) = (recovered_reason IS NULL) AND
           (recovered_at IS NULL) = (recovered_stream_status IS NULL) AND
           (recovered_period_key IS NULL OR recovered_at IS NOT NULL)),
    CHECK (recovered_at IS NULL OR recovered_at >= suspended_at)
);

CREATE UNIQUE INDEX package_traffic_stream_suspensions_open_508
    ON package_traffic_stream_suspensions (stream_id) WHERE recovered_at IS NULL;
CREATE INDEX package_traffic_stream_suspensions_subscription_508
    ON package_traffic_stream_suspensions (tenant_scope_id, subscription_id) WHERE recovered_at IS NULL;

CREATE FUNCTION protect_package_traffic_stream_suspension_508()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'UPDATE' AND OLD.recovered_at IS NULL AND NEW.recovered_at IS NOT NULL AND
       NEW.suspension_id = OLD.suspension_id AND NEW.tenant_scope_id = OLD.tenant_scope_id AND
       NEW.subscription_id = OLD.subscription_id AND NEW.stream_id = OLD.stream_id AND
       NEW.period_key = OLD.period_key AND NEW.head_revision = OLD.head_revision AND
       NEW.suspended_at = OLD.suspended_at THEN
        RETURN NEW;
    END IF;
    RAISE EXCEPTION 'package traffic stream suspensions only close once' USING ERRCODE='P5081';
END;
$$;

CREATE TRIGGER package_traffic_stream_suspensions_close_once_508
BEFORE UPDATE OR DELETE ON package_traffic_stream_suspensions
FOR EACH ROW EXECUTE FUNCTION protect_package_traffic_stream_suspension_508();

REVOKE ALL ON FUNCTION protect_package_traffic_stream_suspension_508() FROM PUBLIC;
