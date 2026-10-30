LOCK TABLE memberships IN SHARE ROW EXCLUSIVE MODE;
LOCK TABLE package_subscriptions IN SHARE ROW EXCLUSIVE MODE;
LOCK TABLE package_subscription_state_versions IN SHARE ROW EXCLUSIVE MODE;
LOCK TABLE package_orders IN SHARE ROW EXCLUSIVE MODE;
LOCK TABLE package_order_fulfillments IN SHARE ROW EXCLUSIVE MODE;
LOCK TABLE notification_events IN SHARE ROW EXCLUSIVE MODE;
LOCK TABLE notification_templates IN SHARE ROW EXCLUSIVE MODE;
LOCK TABLE audit_events IN SHARE ROW EXCLUSIVE MODE;

CREATE UNIQUE INDEX package_subscription_state_versions_owner_exact_078
    ON package_subscription_state_versions (
        subscription_id, revision, tenant_scope_id, owner_user_id
    );

CREATE UNIQUE INDEX notification_events_monitor_exact_078
    ON notification_events (
        scope_id, id, recipient_user_id, source_event_id, event_type
    );

CREATE UNIQUE INDEX audit_events_package_monitor_identity_078
    ON audit_events (scope_id, action, resource_type, resource_id)
    WHERE action IN (
        'package_monitor.alert.observe_before',
        'package_monitor.alert.trigger',
        'package_monitor.alert.recover',
        'package_monitor.alert.suppress_stale',
        'package_monitor.evaluation.commit'
    );

CREATE FUNCTION package_monitor_template_sha256_078(
    template_body text,
    template_channel text,
    template_subject text,
    template_identifier text,
    template_variables text[],
    template_version bigint
)
RETURNS bytea
LANGUAGE sql
IMMUTABLE
STRICT
AS $$
    SELECT sha256(convert_to(format(
        '{"body":%s,"channel":%s,"subject":%s,"template_id":%s,"variables":%s,"version":%s}',
        to_json(template_body)::text,
        to_json(template_channel)::text,
        to_json(template_subject)::text,
        to_json(template_identifier)::text,
        to_json(template_variables)::text,
        template_version::text
    ), 'UTF8'));
$$;

INSERT INTO notification_templates (
    template_id, version, channel, subject, body, variables, created_at
) VALUES
    ('package.monitor.traffic.triggered.zh-cn', 1, 'sms', '',
     '套餐{{.subscription_id}}流量已达到{{.metric_value}}，阈值{{.threshold_value}}，周期{{.period_key}}。',
     ARRAY['subscription_id','metric_value','threshold_value','period_key'],
     '2026-07-28 00:00:00+00'),
    ('package.monitor.traffic.triggered.zh-cn', 1, 'email', '套餐流量阈值提醒',
     '套餐{{.subscription_id}}在周期{{.period_key}}的流量已达到{{.metric_value}}，触发阈值为{{.threshold_value}}。',
     ARRAY['subscription_id','metric_value','threshold_value','period_key'],
     '2026-07-28 00:00:00+00'),
    ('package.monitor.traffic.recovered.zh-cn', 1, 'sms', '',
     '套餐{{.subscription_id}}流量已恢复至{{.metric_value}}，恢复阈值{{.threshold_value}}，周期{{.period_key}}。',
     ARRAY['subscription_id','metric_value','threshold_value','period_key'],
     '2026-07-28 00:00:00+00'),
    ('package.monitor.traffic.recovered.zh-cn', 1, 'email', '套餐流量恢复通知',
     '套餐{{.subscription_id}}在周期{{.period_key}}的流量已恢复至{{.metric_value}}，恢复阈值为{{.threshold_value}}。',
     ARRAY['subscription_id','metric_value','threshold_value','period_key'],
     '2026-07-28 00:00:00+00'),
    ('package.monitor.bandwidth.triggered.zh-cn', 1, 'sms', '',
     '套餐{{.subscription_id}}带宽已达到{{.metric_value}}，阈值{{.threshold_value}}，周期{{.period_key}}。',
     ARRAY['subscription_id','metric_value','threshold_value','period_key'],
     '2026-07-28 00:00:00+00'),
    ('package.monitor.bandwidth.triggered.zh-cn', 1, 'email', '套餐带宽阈值提醒',
     '套餐{{.subscription_id}}在周期{{.period_key}}的带宽已达到{{.metric_value}}，触发阈值为{{.threshold_value}}。',
     ARRAY['subscription_id','metric_value','threshold_value','period_key'],
     '2026-07-28 00:00:00+00'),
    ('package.monitor.bandwidth.recovered.zh-cn', 1, 'sms', '',
     '套餐{{.subscription_id}}带宽已恢复至{{.metric_value}}，恢复阈值{{.threshold_value}}，周期{{.period_key}}。',
     ARRAY['subscription_id','metric_value','threshold_value','period_key'],
     '2026-07-28 00:00:00+00'),
    ('package.monitor.bandwidth.recovered.zh-cn', 1, 'email', '套餐带宽恢复通知',
     '套餐{{.subscription_id}}在周期{{.period_key}}的带宽已恢复至{{.metric_value}}，恢复阈值为{{.threshold_value}}。',
     ARRAY['subscription_id','metric_value','threshold_value','period_key'],
     '2026-07-28 00:00:00+00'),
    ('package.monitor.connections.triggered.zh-cn', 1, 'sms', '',
     '套餐{{.subscription_id}}连接数已达到{{.metric_value}}，阈值{{.threshold_value}}，周期{{.period_key}}。',
     ARRAY['subscription_id','metric_value','threshold_value','period_key'],
     '2026-07-28 00:00:00+00'),
    ('package.monitor.connections.triggered.zh-cn', 1, 'email', '套餐连接数阈值提醒',
     '套餐{{.subscription_id}}在周期{{.period_key}}的连接数已达到{{.metric_value}}，触发阈值为{{.threshold_value}}。',
     ARRAY['subscription_id','metric_value','threshold_value','period_key'],
     '2026-07-28 00:00:00+00'),
    ('package.monitor.connections.recovered.zh-cn', 1, 'sms', '',
     '套餐{{.subscription_id}}连接数已恢复至{{.metric_value}}，恢复阈值{{.threshold_value}}，周期{{.period_key}}。',
     ARRAY['subscription_id','metric_value','threshold_value','period_key'],
     '2026-07-28 00:00:00+00'),
    ('package.monitor.connections.recovered.zh-cn', 1, 'email', '套餐连接数恢复通知',
     '套餐{{.subscription_id}}在周期{{.period_key}}的连接数已恢复至{{.metric_value}}，恢复阈值为{{.threshold_value}}。',
     ARRAY['subscription_id','metric_value','threshold_value','period_key'],
     '2026-07-28 00:00:00+00'),
    ('package.monitor.expiration.triggered.zh-cn', 1, 'sms', '',
     '套餐{{.subscription_id}}将在{{.ends_at}}到期，提醒阈值{{.threshold_value}}，周期{{.period_key}}。',
     ARRAY['subscription_id','ends_at','threshold_value','period_key'],
     '2026-07-28 00:00:00+00'),
    ('package.monitor.expiration.triggered.zh-cn', 1, 'email', '套餐到期提醒',
     '套餐{{.subscription_id}}将在{{.ends_at}}到期，提醒阈值为{{.threshold_value}}，周期为{{.period_key}}。',
     ARRAY['subscription_id','ends_at','threshold_value','period_key'],
     '2026-07-28 00:00:00+00'),
    ('package.monitor.expiration.recovered.zh-cn', 1, 'sms', '',
     '套餐{{.subscription_id}}到期时间已更新为{{.ends_at}}，原阈值{{.threshold_value}}提醒已解除，周期{{.period_key}}。',
     ARRAY['subscription_id','ends_at','threshold_value','period_key'],
     '2026-07-28 00:00:00+00'),
    ('package.monitor.expiration.recovered.zh-cn', 1, 'email', '套餐到期提醒已解除',
     '套餐{{.subscription_id}}到期时间已更新为{{.ends_at}}，原阈值{{.threshold_value}}提醒已解除，周期为{{.period_key}}。',
     ARRAY['subscription_id','ends_at','threshold_value','period_key'],
     '2026-07-28 00:00:00+00');

CREATE TABLE package_monitor_subscription_owners (
    subscription_id uuid PRIMARY KEY,
    state_revision bigint NOT NULL CHECK (state_revision > 0),
    tenant_scope_id uuid NOT NULL,
    owner_user_id uuid NOT NULL,
    source_kind text NOT NULL CHECK (
        source_kind IN ('commerce_fulfillment', 'subscription_state')
    ),
    source_fulfillment_id uuid REFERENCES package_order_fulfillments(id) ON DELETE RESTRICT,
    migration_backfilled boolean NOT NULL DEFAULT false,
    created_at timestamptz NOT NULL CHECK (isfinite(created_at)),
    UNIQUE (subscription_id, tenant_scope_id, owner_user_id),
    FOREIGN KEY (
        subscription_id, state_revision, tenant_scope_id, owner_user_id
    ) REFERENCES package_subscription_state_versions (
        subscription_id, revision, tenant_scope_id, owner_user_id
    ) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_scope_id, owner_user_id)
        REFERENCES memberships(scope_id, user_id) ON DELETE RESTRICT,
    CHECK (
        (source_kind = 'commerce_fulfillment' AND source_fulfillment_id IS NOT NULL)
        OR (source_kind = 'subscription_state' AND source_fulfillment_id IS NULL)
    )
);

CREATE INDEX package_monitor_subscription_owners_tenant_user_078
    ON package_monitor_subscription_owners (
        tenant_scope_id, owner_user_id, subscription_id
    );

CREATE FUNCTION validate_package_monitor_owner_078()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    membership_status text;
    exact_proof_count bigint;
    total_proof_count bigint;
BEGIN
    SELECT membership.status
    INTO membership_status
    FROM memberships AS membership
    WHERE membership.scope_id = NEW.tenant_scope_id
      AND membership.user_id = NEW.owner_user_id
    FOR KEY SHARE;

    IF membership_status IS DISTINCT FROM 'active' THEN
        RAISE EXCEPTION 'package monitor owner must be an active tenant member'
            USING ERRCODE = '23514';
    END IF;

    IF EXISTS (
        SELECT 1
        FROM memberships AS platform_membership
        JOIN access_scopes AS platform_scope
          ON platform_scope.id = platform_membership.scope_id
         AND platform_scope.kind = 'platform'
        WHERE platform_membership.user_id = NEW.owner_user_id
    ) THEN
        RAISE EXCEPTION 'platform member cannot be a package monitor owner'
            USING ERRCODE = '23514';
    END IF;

    IF NEW.source_kind = 'commerce_fulfillment' THEN
        SELECT count(*) FILTER (WHERE
                   fulfillment.id = NEW.source_fulfillment_id
               AND fulfillment.tenant_scope_id = NEW.tenant_scope_id
               AND package_order.tenant_scope_id = NEW.tenant_scope_id
               AND package_order.user_id = NEW.owner_user_id
               AND (package_order.subscription_id IS NULL
                    OR package_order.subscription_id = NEW.subscription_id)
               AND package_order.product_kind = 'package_subscription'
               ),
               count(*)
        INTO exact_proof_count, total_proof_count
        FROM package_order_fulfillments AS fulfillment
        JOIN package_orders AS package_order ON package_order.id = fulfillment.order_id
        WHERE fulfillment.subscription_id = NEW.subscription_id
          AND fulfillment.subscription_revision = NEW.state_revision;
        IF exact_proof_count <> 1 OR total_proof_count <> 1 THEN
            RAISE EXCEPTION 'package monitor commerce owner proof is not exact'
                USING ERRCODE = '23514';
        END IF;
    ELSIF EXISTS (
        SELECT 1
        FROM package_order_fulfillments AS fulfillment
        WHERE fulfillment.subscription_id = NEW.subscription_id
    ) THEN
        RAISE EXCEPTION 'package monitor state owner cannot bypass commerce proof'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER package_monitor_subscription_owners_validate_078
BEFORE INSERT ON package_monitor_subscription_owners
FOR EACH ROW EXECUTE FUNCTION validate_package_monitor_owner_078();

WITH current_state AS (
    SELECT state.*
    FROM package_subscription_state_versions AS state
    JOIN package_subscriptions AS subscription
      ON subscription.id = state.subscription_id
     AND subscription.revision = state.revision
     AND subscription.tenant_scope_id = state.tenant_scope_id
     AND subscription.created_by_user_id = state.owner_user_id
    JOIN memberships AS membership
      ON membership.scope_id = state.tenant_scope_id
     AND membership.user_id = state.owner_user_id
     AND membership.status = 'active'
    WHERE state.lifecycle_status = 'active'
      AND NOT EXISTS (
          SELECT 1
          FROM memberships AS platform_membership
          JOIN access_scopes AS platform_scope
            ON platform_scope.id = platform_membership.scope_id
           AND platform_scope.kind = 'platform'
          WHERE platform_membership.user_id = state.owner_user_id
      )
), commerce_proof AS (
    SELECT state.subscription_id, state.revision, state.tenant_scope_id,
           state.owner_user_id, state.created_at,
           min(fulfillment.id::text)::uuid AS source_fulfillment_id
    FROM current_state AS state
    JOIN package_order_fulfillments AS fulfillment
      ON fulfillment.subscription_id = state.subscription_id
     AND fulfillment.subscription_revision = state.revision
     AND fulfillment.tenant_scope_id = state.tenant_scope_id
    JOIN package_orders AS package_order
      ON package_order.id = fulfillment.order_id
     AND package_order.tenant_scope_id = state.tenant_scope_id
     AND package_order.user_id = state.owner_user_id
     AND (package_order.subscription_id IS NULL
          OR package_order.subscription_id = state.subscription_id)
     AND package_order.product_kind = 'package_subscription'
    GROUP BY state.subscription_id, state.revision, state.tenant_scope_id,
             state.owner_user_id, state.created_at
    HAVING count(*) = 1
       AND (SELECT count(*)
            FROM package_order_fulfillments AS all_fulfillment
            WHERE all_fulfillment.subscription_id = state.subscription_id
              AND all_fulfillment.subscription_revision = state.revision) = 1
), legacy_proof AS (
    SELECT state.subscription_id, state.revision, state.tenant_scope_id,
           state.owner_user_id, state.created_at
    FROM current_state AS state
    WHERE NOT EXISTS (
        SELECT 1
        FROM package_order_fulfillments AS fulfillment
        WHERE fulfillment.subscription_id = state.subscription_id
    )
)
INSERT INTO package_monitor_subscription_owners (
    subscription_id, state_revision, tenant_scope_id, owner_user_id,
    source_kind, source_fulfillment_id, migration_backfilled, created_at
)
SELECT subscription_id, revision, tenant_scope_id, owner_user_id,
       'commerce_fulfillment', source_fulfillment_id, true, created_at
FROM commerce_proof
UNION ALL
SELECT subscription_id, revision, tenant_scope_id, owner_user_id,
       'subscription_state', NULL, true, created_at
FROM legacy_proof;

CREATE FUNCTION validate_package_monitor_owner_provenance_078()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.migration_backfilled THEN
        RAISE EXCEPTION 'package monitor migration provenance is reserved'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER package_monitor_subscription_owners_provenance_078
BEFORE INSERT ON package_monitor_subscription_owners
FOR EACH ROW EXECUTE FUNCTION validate_package_monitor_owner_provenance_078();

CREATE FUNCTION package_monitor_threshold_sha256_078(
    policy_identifier uuid,
    policy_revision bigint,
    policy_metric text,
    policy_trigger numeric,
    policy_recovery numeric,
    policy_stale_seconds bigint
)
RETURNS bytea
LANGUAGE sql
IMMUTABLE
AS $$
    SELECT sha256(convert_to(
        'policy_id=' || policy_identifier::text || E'\n' ||
        'revision=' || policy_revision::text || E'\n' ||
        'metric=' || policy_metric || E'\n' ||
        'trigger_value=' || policy_trigger::text || E'\n' ||
        'recovery_value=' || policy_recovery::text || E'\n' ||
        'stale_after_seconds=' || COALESCE(policy_stale_seconds::text, 'null'),
        'UTF8'
    ));
$$;

CREATE TABLE package_monitor_policy_versions (
    policy_id uuid NOT NULL,
    revision bigint NOT NULL CHECK (revision > 0),
    tenant_scope_id uuid NOT NULL,
    subscription_id uuid NOT NULL,
    owner_user_id uuid NOT NULL,
    metric text NOT NULL CHECK (
        metric IN ('traffic_bytes', 'bandwidth_bps', 'connections', 'expiration')
    ),
    trigger_value numeric(20,0) NOT NULL CHECK (
        trigger_value BETWEEN 0 AND 18446744073709551615
    ),
    recovery_value numeric(20,0) NOT NULL CHECK (
        recovery_value BETWEEN 0 AND 18446744073709551615
    ),
    stale_after_seconds bigint,
    threshold_identity bytea NOT NULL CHECK (octet_length(threshold_identity) = 32),
    enabled boolean NOT NULL,
    created_by_user_id uuid NOT NULL,
    created_at timestamptz NOT NULL CHECK (isfinite(created_at)),
    PRIMARY KEY (policy_id, revision),
    UNIQUE (tenant_scope_id, subscription_id, metric, revision),
    UNIQUE (tenant_scope_id, subscription_id, metric, threshold_identity),
    UNIQUE (
        policy_id, revision, tenant_scope_id, subscription_id,
        owner_user_id, metric, threshold_identity
    ),
    FOREIGN KEY (subscription_id, tenant_scope_id, owner_user_id)
        REFERENCES package_monitor_subscription_owners (
            subscription_id, tenant_scope_id, owner_user_id
        ) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_scope_id, created_by_user_id)
        REFERENCES memberships(scope_id, user_id) ON DELETE RESTRICT,
    CONSTRAINT package_monitor_expiration_trigger_positive_078 CHECK (
        metric <> 'expiration' OR trigger_value > 0
    ),
    CONSTRAINT package_monitor_expiration_stale_positive_078 CHECK (
        metric <> 'expiration' OR (
            stale_after_seconds IS NOT NULL AND stale_after_seconds > 0
        )
    ),
    CHECK (
        (metric = 'expiration'
         AND recovery_value > trigger_value
         AND stale_after_seconds > 0)
        OR
        (metric <> 'expiration'
         AND recovery_value < trigger_value
         AND stale_after_seconds IS NULL)
    ),
    CHECK (
        threshold_identity = package_monitor_threshold_sha256_078(
            policy_id, revision, metric, trigger_value,
            recovery_value, stale_after_seconds
        )
    )
);

CREATE TABLE package_monitor_policy_templates (
    policy_id uuid NOT NULL,
    policy_revision bigint NOT NULL,
    transition text NOT NULL CHECK (transition IN ('triggered', 'recovered')),
    channel text NOT NULL CHECK (channel IN ('sms', 'email')),
    template_id text NOT NULL,
    template_version bigint NOT NULL,
    PRIMARY KEY (policy_id, policy_revision, transition, channel),
    FOREIGN KEY (policy_id, policy_revision)
        REFERENCES package_monitor_policy_versions(policy_id, revision) ON DELETE RESTRICT,
    FOREIGN KEY (template_id, template_version, channel)
        REFERENCES notification_templates(template_id, version, channel) ON DELETE RESTRICT
);

CREATE TABLE package_monitor_policy_heads (
    policy_id uuid PRIMARY KEY,
    tenant_scope_id uuid NOT NULL,
    subscription_id uuid NOT NULL,
    owner_user_id uuid NOT NULL,
    metric text NOT NULL,
    current_revision bigint NOT NULL CHECK (current_revision > 0),
    current_threshold_identity bytea NOT NULL CHECK (
        octet_length(current_threshold_identity) = 32
    ),
    next_evaluation_at timestamptz CHECK (
        next_evaluation_at IS NULL OR isfinite(next_evaluation_at)
    ),
    revision bigint NOT NULL CHECK (revision > 0),
    updated_at timestamptz NOT NULL CHECK (isfinite(updated_at)),
    UNIQUE (tenant_scope_id, subscription_id, metric),
    FOREIGN KEY (
        policy_id, current_revision, tenant_scope_id, subscription_id,
        owner_user_id, metric, current_threshold_identity
    ) REFERENCES package_monitor_policy_versions (
        policy_id, revision, tenant_scope_id, subscription_id,
        owner_user_id, metric, threshold_identity
    ) ON DELETE RESTRICT
);

CREATE INDEX package_monitor_policy_heads_due_078
    ON package_monitor_policy_heads (
        next_evaluation_at, tenant_scope_id, policy_id
    ) WHERE next_evaluation_at IS NOT NULL;

CREATE TABLE package_monitor_evaluation_clocks (
    evaluation_clock_id uuid PRIMARY KEY,
    transaction_id text NOT NULL UNIQUE CHECK (
        transaction_id ~ '^[1-9][0-9]*$'
    ),
    evaluated_at timestamptz NOT NULL CHECK (isfinite(evaluated_at)),
    UNIQUE (evaluation_clock_id, evaluated_at)
);

CREATE FUNCTION bind_package_monitor_evaluation_clock_078()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    NEW.transaction_id := pg_current_xact_id()::text;
    NEW.evaluated_at := clock_timestamp();
    RETURN NEW;
END;
$$;

CREATE TRIGGER package_monitor_evaluation_clocks_bind_078
BEFORE INSERT ON package_monitor_evaluation_clocks
FOR EACH ROW EXECUTE FUNCTION bind_package_monitor_evaluation_clock_078();

CREATE FUNCTION package_monitor_transaction_clock_078()
RETURNS TABLE(evaluation_clock_id uuid, evaluated_at timestamptz)
LANGUAGE plpgsql
VOLATILE
AS $$
DECLARE
    current_transaction_id text := pg_current_xact_id()::text;
BEGIN
    SELECT clock.evaluation_clock_id, clock.evaluated_at
    INTO evaluation_clock_id, evaluated_at
    FROM package_monitor_evaluation_clocks AS clock
    WHERE clock.transaction_id = current_transaction_id;
    IF FOUND THEN
        RETURN NEXT;
        RETURN;
    END IF;
    INSERT INTO package_monitor_evaluation_clocks (
        evaluation_clock_id, transaction_id, evaluated_at
    ) VALUES (
        gen_random_uuid(), current_transaction_id, '-infinity'
    )
    RETURNING package_monitor_evaluation_clocks.evaluation_clock_id,
              package_monitor_evaluation_clocks.evaluated_at
    INTO evaluation_clock_id, evaluated_at;
    RETURN NEXT;
END;
$$;

CREATE TABLE package_monitor_alert_heads (
    id uuid PRIMARY KEY,
    tenant_scope_id uuid NOT NULL,
    subscription_id uuid NOT NULL,
    owner_user_id uuid NOT NULL,
    policy_id uuid NOT NULL,
    policy_revision bigint NOT NULL CHECK (policy_revision > 0),
    metric text NOT NULL,
    period_key text NOT NULL CHECK (
        octet_length(period_key) BETWEEN 1 AND 256
        AND period_key = btrim(period_key)
        AND period_key !~ '[[:cntrl:]]'
    ),
    threshold_identity bytea NOT NULL CHECK (octet_length(threshold_identity) = 32),
    state text NOT NULL CHECK (
        state IN ('before', 'triggered', 'recovered', 'suppressed_stale')
    ),
    revision bigint NOT NULL CHECK (revision > 0),
    last_source_watermark numeric(20,0) NOT NULL CHECK (
        last_source_watermark BETWEEN 0 AND 18446744073709551615
    ),
    last_finalized_through timestamptz NOT NULL CHECK (
        isfinite(last_finalized_through)
    ),
    last_evidence_digest bytea NOT NULL CHECK (octet_length(last_evidence_digest) = 32),
    last_evaluation_clock_id uuid NOT NULL,
    last_evaluated_at timestamptz NOT NULL CHECK (isfinite(last_evaluated_at)),
    updated_at timestamptz NOT NULL CHECK (isfinite(updated_at)),
    UNIQUE (
        tenant_scope_id, subscription_id, metric, period_key, threshold_identity
    ),
    UNIQUE (
        id, tenant_scope_id, subscription_id, owner_user_id, policy_id,
        policy_revision, metric, period_key, threshold_identity
    ),
    FOREIGN KEY (subscription_id, tenant_scope_id, owner_user_id)
        REFERENCES package_monitor_subscription_owners (
            subscription_id, tenant_scope_id, owner_user_id
        ) ON DELETE RESTRICT,
    FOREIGN KEY (
        policy_id, policy_revision, tenant_scope_id, subscription_id,
        owner_user_id, metric, threshold_identity
    ) REFERENCES package_monitor_policy_versions (
        policy_id, revision, tenant_scope_id, subscription_id,
        owner_user_id, metric, threshold_identity
    ) ON DELETE RESTRICT,
    FOREIGN KEY (last_evaluation_clock_id, last_evaluated_at)
        REFERENCES package_monitor_evaluation_clocks (
            evaluation_clock_id, evaluated_at
        ) ON DELETE RESTRICT
);

CREATE INDEX package_monitor_alert_heads_owner_updated_078
    ON package_monitor_alert_heads (
        tenant_scope_id, owner_user_id, updated_at DESC, id DESC
    );

CREATE INDEX package_monitor_alert_heads_policy_period_078
    ON package_monitor_alert_heads (policy_id, policy_revision, period_key);

CREATE TABLE package_monitor_transition_facts (
    alert_id uuid NOT NULL,
    revision bigint NOT NULL CHECK (revision > 0),
    tenant_scope_id uuid NOT NULL,
    subscription_id uuid NOT NULL,
    owner_user_id uuid NOT NULL,
    policy_id uuid NOT NULL,
    policy_revision bigint NOT NULL CHECK (policy_revision > 0),
    metric text NOT NULL,
    period_key text NOT NULL,
    threshold_identity bytea NOT NULL CHECK (octet_length(threshold_identity) = 32),
    phase text NOT NULL CHECK (
        phase IN ('before', 'triggered', 'recovered', 'suppressed_stale')
    ),
    observed_value numeric(20,0) NOT NULL CHECK (
        (metric = 'expiration' AND observed_value BETWEEN -18446744073709551615 AND 18446744073709551615)
        OR (metric <> 'expiration' AND observed_value BETWEEN 0 AND 18446744073709551615)
    ),
    metric_schema_version text NOT NULL CHECK (
        (metric = 'expiration' AND metric_schema_version = 'deadline/v1')
        OR (metric <> 'expiration' AND metric_schema_version = 'package-monitor-metric/v1')
    ),
    source_watermark numeric(20,0) NOT NULL CHECK (
        source_watermark BETWEEN 0 AND 18446744073709551615
    ),
    observed_at timestamptz NOT NULL CHECK (isfinite(observed_at)),
    finalized_through timestamptz NOT NULL CHECK (
        isfinite(finalized_through) AND finalized_through >= observed_at
    ),
    evidence_digest bytea NOT NULL CHECK (octet_length(evidence_digest) = 32),
    evaluation_clock_id uuid NOT NULL,
    evaluated_at timestamptz NOT NULL CHECK (isfinite(evaluated_at)),
    reason_code text NOT NULL CHECK (
        reason_code ~ '^[a-z][a-z0-9._-]{0,95}$'
    ),
    source_event_id text CHECK (
        source_event_id IS NULL OR (
            octet_length(source_event_id) BETWEEN 1 AND 256
            AND source_event_id = btrim(source_event_id)
        )
    ),
    notification_event_id uuid,
    notification_event_type text,
    PRIMARY KEY (alert_id, revision),
    UNIQUE (alert_id, phase),
    UNIQUE (alert_id, revision, notification_event_id),
    UNIQUE (alert_id, revision, observed_at),
    FOREIGN KEY (
        alert_id, tenant_scope_id, subscription_id, owner_user_id, policy_id,
        policy_revision, metric, period_key, threshold_identity
    ) REFERENCES package_monitor_alert_heads (
        id, tenant_scope_id, subscription_id, owner_user_id, policy_id,
        policy_revision, metric, period_key, threshold_identity
    ) ON DELETE RESTRICT,
    FOREIGN KEY (
        tenant_scope_id, notification_event_id, owner_user_id,
        source_event_id, notification_event_type
    ) REFERENCES notification_events (
        scope_id, id, recipient_user_id, source_event_id, event_type
    ) ON DELETE RESTRICT,
    FOREIGN KEY (evaluation_clock_id, evaluated_at)
        REFERENCES package_monitor_evaluation_clocks (
            evaluation_clock_id, evaluated_at
        ) ON DELETE RESTRICT,
    CHECK (
        (phase IN ('triggered', 'recovered')
         AND source_event_id IS NOT NULL
         AND notification_event_id IS NOT NULL
         AND notification_event_type = 'package.monitor.' ||
             CASE metric
                 WHEN 'traffic_bytes' THEN 'traffic'
                 WHEN 'bandwidth_bps' THEN 'bandwidth'
                 WHEN 'connections' THEN 'connections'
                 WHEN 'expiration' THEN 'expiration'
             END || '.' || phase)
        OR
        (phase IN ('before', 'suppressed_stale')
         AND source_event_id IS NULL
         AND notification_event_id IS NULL
         AND notification_event_type IS NULL)
    )
);

CREATE UNIQUE INDEX package_monitor_transition_source_event_078
    ON package_monitor_transition_facts (tenant_scope_id, source_event_id)
    WHERE source_event_id IS NOT NULL;

CREATE TABLE package_monitor_evaluation_receipts (
    receipt_id uuid PRIMARY KEY,
    alert_id uuid NOT NULL,
    tenant_scope_id uuid NOT NULL,
    subscription_id uuid NOT NULL,
    owner_user_id uuid NOT NULL,
    policy_id uuid NOT NULL,
    policy_revision bigint NOT NULL CHECK (policy_revision > 0),
    metric text NOT NULL,
    period_key text NOT NULL,
    threshold_identity bytea NOT NULL CHECK (octet_length(threshold_identity) = 32),
    result_revision bigint NOT NULL CHECK (result_revision > 0),
    result_state text NOT NULL CHECK (
        result_state IN ('before', 'triggered', 'recovered', 'suppressed_stale')
    ),
    result_transition text NOT NULL CHECK (
        result_transition IN ('', 'triggered', 'recovered', 'suppressed_stale')
    ),
    transition_fact_revision bigint,
    metric_schema_version text NOT NULL CHECK (
        (metric = 'expiration' AND metric_schema_version = 'deadline/v1')
        OR (metric <> 'expiration' AND metric_schema_version = 'package-monitor-metric/v1')
    ),
    source_watermark numeric(20,0) NOT NULL CHECK (
        source_watermark BETWEEN 0 AND 18446744073709551615
    ),
    observed_at timestamptz NOT NULL CHECK (isfinite(observed_at)),
    finalized_through timestamptz NOT NULL CHECK (
        isfinite(finalized_through) AND finalized_through >= observed_at
    ),
    evidence_digest bytea NOT NULL CHECK (octet_length(evidence_digest) = 32),
    evaluation_clock_id uuid NOT NULL,
    evaluated_at timestamptz NOT NULL CHECK (isfinite(evaluated_at)),
    notification_event_id uuid,
    job_id uuid NOT NULL,
    job_attempt bigint NOT NULL CHECK (job_attempt BETWEEN 1 AND 4294967295),
    job_item_id text NOT NULL CHECK (
        octet_length(job_item_id) BETWEEN 1 AND 128
        AND job_item_id = btrim(job_item_id)
        AND job_item_id !~ '[[:cntrl:]]'
    ),
    request_id text NOT NULL CHECK (
        octet_length(request_id) BETWEEN 1 AND 128
        AND request_id = btrim(request_id)
        AND request_id !~ '[[:cntrl:]]'
    ),
    created_at timestamptz NOT NULL CHECK (isfinite(created_at)),
    UNIQUE (alert_id, source_watermark, evidence_digest),
    FOREIGN KEY (
        alert_id, tenant_scope_id, subscription_id, owner_user_id, policy_id,
        policy_revision, metric, period_key, threshold_identity
    ) REFERENCES package_monitor_alert_heads (
        id, tenant_scope_id, subscription_id, owner_user_id, policy_id,
        policy_revision, metric, period_key, threshold_identity
    ) ON DELETE RESTRICT,
    FOREIGN KEY (alert_id, transition_fact_revision)
        REFERENCES package_monitor_transition_facts(alert_id, revision) ON DELETE RESTRICT,
    FOREIGN KEY (alert_id, transition_fact_revision, notification_event_id)
        REFERENCES package_monitor_transition_facts(
            alert_id, revision, notification_event_id
        ) ON DELETE RESTRICT,
    FOREIGN KEY (alert_id, transition_fact_revision, observed_at)
        REFERENCES package_monitor_transition_facts(
            alert_id, revision, observed_at
        ) ON DELETE RESTRICT,
    FOREIGN KEY (evaluation_clock_id, evaluated_at)
        REFERENCES package_monitor_evaluation_clocks (
            evaluation_clock_id, evaluated_at
        ) ON DELETE RESTRICT,
    CHECK (transition_fact_revision IS NULL OR transition_fact_revision = result_revision),
    CHECK (result_transition = '' OR transition_fact_revision IS NOT NULL),
    CHECK (
        (result_transition IN ('triggered', 'recovered') AND notification_event_id IS NOT NULL)
        OR (result_transition NOT IN ('triggered', 'recovered') AND notification_event_id IS NULL)
    )
);

CREATE INDEX package_monitor_evaluation_receipts_job_078
    ON package_monitor_evaluation_receipts (tenant_scope_id, job_id, job_attempt, job_item_id);

CREATE FUNCTION prevent_package_monitor_immutable_078()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'package monitor facts are append-only'
        USING ERRCODE = '55000';
END;
$$;

CREATE TRIGGER package_monitor_evaluation_clocks_immutable_078
BEFORE UPDATE OR DELETE OR TRUNCATE ON package_monitor_evaluation_clocks
FOR EACH STATEMENT EXECUTE FUNCTION prevent_package_monitor_immutable_078();

CREATE TRIGGER package_monitor_subscription_owners_immutable_078
BEFORE UPDATE OR DELETE OR TRUNCATE ON package_monitor_subscription_owners
FOR EACH STATEMENT EXECUTE FUNCTION prevent_package_monitor_immutable_078();

CREATE TRIGGER package_monitor_policy_versions_immutable_078
BEFORE UPDATE OR DELETE OR TRUNCATE ON package_monitor_policy_versions
FOR EACH STATEMENT EXECUTE FUNCTION prevent_package_monitor_immutable_078();

CREATE TRIGGER package_monitor_policy_templates_immutable_078
BEFORE UPDATE OR DELETE OR TRUNCATE ON package_monitor_policy_templates
FOR EACH STATEMENT EXECUTE FUNCTION prevent_package_monitor_immutable_078();

CREATE TRIGGER package_monitor_transition_facts_immutable_078
BEFORE UPDATE OR DELETE OR TRUNCATE ON package_monitor_transition_facts
FOR EACH STATEMENT EXECUTE FUNCTION prevent_package_monitor_immutable_078();

CREATE TRIGGER package_monitor_evaluation_receipts_immutable_078
BEFORE UPDATE OR DELETE OR TRUNCATE ON package_monitor_evaluation_receipts
FOR EACH STATEMENT EXECUTE FUNCTION prevent_package_monitor_immutable_078();

CREATE FUNCTION validate_package_monitor_evaluation_clock_078()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    row_clock_id uuid;
    row_evaluated_at timestamptz;
    matching_count bigint;
BEGIN
    IF TG_TABLE_NAME = 'package_monitor_alert_heads' THEN
        row_clock_id := NEW.last_evaluation_clock_id;
        row_evaluated_at := NEW.last_evaluated_at;
        IF NEW.updated_at IS DISTINCT FROM row_evaluated_at THEN
            RAISE EXCEPTION 'package monitor evaluation clock mismatch'
                USING ERRCODE = '23514';
        END IF;
    ELSIF TG_TABLE_NAME = 'package_monitor_evaluation_receipts' THEN
        row_clock_id := NEW.evaluation_clock_id;
        row_evaluated_at := NEW.evaluated_at;
        IF NEW.created_at IS DISTINCT FROM row_evaluated_at THEN
            RAISE EXCEPTION 'package monitor evaluation clock mismatch'
                USING ERRCODE = '23514';
        END IF;
    ELSE
        row_clock_id := NEW.evaluation_clock_id;
        row_evaluated_at := NEW.evaluated_at;
    END IF;
    SELECT count(*)
    INTO matching_count
    FROM package_monitor_evaluation_clocks AS clock
    WHERE clock.evaluation_clock_id = row_clock_id
      AND clock.evaluated_at = row_evaluated_at
      AND clock.transaction_id = pg_current_xact_id()::text;
    IF matching_count <> 1 THEN
        RAISE EXCEPTION 'package monitor evaluation clock mismatch'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER package_monitor_alert_heads_00_clock_078
BEFORE INSERT OR UPDATE ON package_monitor_alert_heads
FOR EACH ROW EXECUTE FUNCTION validate_package_monitor_evaluation_clock_078();

CREATE TRIGGER package_monitor_transition_facts_00_clock_078
BEFORE INSERT ON package_monitor_transition_facts
FOR EACH ROW EXECUTE FUNCTION validate_package_monitor_evaluation_clock_078();

CREATE TRIGGER package_monitor_evaluation_receipts_00_clock_078
BEFORE INSERT ON package_monitor_evaluation_receipts
FOR EACH ROW EXECUTE FUNCTION validate_package_monitor_evaluation_clock_078();

CREATE FUNCTION protect_package_monitor_policy_head_078()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.revision <> 1 THEN
            RAISE EXCEPTION 'package monitor policy head must start at revision one'
                USING ERRCODE = '23514';
        END IF;
        RETURN NEW;
    END IF;
    IF TG_OP <> 'UPDATE' THEN
        RAISE EXCEPTION 'package monitor policy heads cannot be deleted or truncated'
            USING ERRCODE = '55000';
    END IF;
    IF ROW(NEW.policy_id, NEW.tenant_scope_id, NEW.subscription_id,
           NEW.owner_user_id, NEW.metric)
       IS DISTINCT FROM
       ROW(OLD.policy_id, OLD.tenant_scope_id, OLD.subscription_id,
           OLD.owner_user_id, OLD.metric)
       OR NEW.revision <> OLD.revision + 1
       OR NEW.current_revision < OLD.current_revision
       OR NEW.updated_at < OLD.updated_at THEN
        RAISE EXCEPTION 'package monitor policy head transition is invalid'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER package_monitor_policy_heads_protect_078
BEFORE INSERT OR UPDATE OR DELETE ON package_monitor_policy_heads
FOR EACH ROW EXECUTE FUNCTION protect_package_monitor_policy_head_078();

CREATE TRIGGER package_monitor_policy_heads_no_truncate_078
BEFORE TRUNCATE ON package_monitor_policy_heads
FOR EACH STATEMENT EXECUTE FUNCTION prevent_package_monitor_immutable_078();

CREATE FUNCTION protect_package_monitor_alert_head_078()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.revision <> 1
           OR NEW.state NOT IN ('before', 'triggered', 'suppressed_stale') THEN
            RAISE EXCEPTION 'package monitor alert head initial state is invalid'
                USING ERRCODE = '23514';
        END IF;
        RETURN NEW;
    END IF;
    IF TG_OP <> 'UPDATE' THEN
        RAISE EXCEPTION 'package monitor alert heads cannot be deleted or truncated'
            USING ERRCODE = '55000';
    END IF;
    IF ROW(NEW.id, NEW.tenant_scope_id, NEW.subscription_id, NEW.owner_user_id,
           NEW.policy_id, NEW.policy_revision, NEW.metric, NEW.period_key,
           NEW.threshold_identity)
       IS DISTINCT FROM
       ROW(OLD.id, OLD.tenant_scope_id, OLD.subscription_id, OLD.owner_user_id,
           OLD.policy_id, OLD.policy_revision, OLD.metric, OLD.period_key,
           OLD.threshold_identity)
       OR NEW.last_source_watermark <= OLD.last_source_watermark
       OR NEW.last_finalized_through < OLD.last_finalized_through
       OR NEW.last_evaluated_at < OLD.last_evaluated_at
       OR NEW.updated_at < OLD.updated_at THEN
        RAISE EXCEPTION 'package monitor alert head identity or watermark is invalid'
            USING ERRCODE = '23514';
    END IF;
    IF NEW.revision = OLD.revision AND NEW.state = OLD.state THEN
        RETURN NEW;
    END IF;
    IF NEW.revision <> OLD.revision + 1
       OR NOT (
           (OLD.state = 'before' AND NEW.state IN ('triggered', 'suppressed_stale'))
           OR (OLD.state = 'triggered' AND NEW.state = 'recovered')
       ) THEN
        RAISE EXCEPTION 'package monitor alert state transition is invalid'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER package_monitor_alert_heads_protect_078
BEFORE INSERT OR UPDATE OR DELETE ON package_monitor_alert_heads
FOR EACH ROW EXECUTE FUNCTION protect_package_monitor_alert_head_078();

CREATE TRIGGER package_monitor_alert_heads_no_truncate_078
BEFORE TRUNCATE ON package_monitor_alert_heads
FOR EACH STATEMENT EXECUTE FUNCTION prevent_package_monitor_immutable_078();

CREATE FUNCTION validate_package_monitor_head_fact_078()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    target_alert_id uuid;
    head_revision bigint;
    head_state text;
    fact_revision bigint;
    fact_phase text;
    exact_fact_exists boolean;
    requires_exact_fact boolean;
BEGIN
    IF TG_TABLE_NAME = 'package_monitor_transition_facts' THEN
        target_alert_id := NEW.alert_id;
    ELSE
        target_alert_id := NEW.id;
        requires_exact_fact := TG_OP = 'INSERT';
        IF TG_OP = 'UPDATE' THEN
            requires_exact_fact := NEW.revision IS DISTINCT FROM OLD.revision
                OR NEW.state IS DISTINCT FROM OLD.state;
        END IF;
        IF requires_exact_fact THEN
            SELECT EXISTS (
                SELECT 1
                FROM package_monitor_transition_facts AS exact_fact
                WHERE exact_fact.alert_id = target_alert_id
                  AND exact_fact.revision = NEW.revision
                  AND exact_fact.phase = NEW.state
                  AND exact_fact.source_watermark = NEW.last_source_watermark
                  AND exact_fact.finalized_through = NEW.last_finalized_through
                  AND exact_fact.evidence_digest = NEW.last_evidence_digest
                  AND exact_fact.evaluation_clock_id = NEW.last_evaluation_clock_id
                  AND exact_fact.evaluated_at = NEW.last_evaluated_at
            )
            INTO exact_fact_exists;
            IF NOT exact_fact_exists THEN
                RAISE EXCEPTION 'package monitor alert head transition has no exact fact'
                    USING ERRCODE = '23514';
            END IF;
        END IF;
    END IF;
    SELECT revision, state
    INTO head_revision, head_state
    FROM package_monitor_alert_heads
    WHERE id = target_alert_id;
    SELECT revision, phase
    INTO fact_revision, fact_phase
    FROM package_monitor_transition_facts
    WHERE alert_id = target_alert_id
    ORDER BY revision DESC
    LIMIT 1;
    IF head_revision IS NULL OR fact_revision IS NULL
       OR head_revision IS DISTINCT FROM fact_revision
       OR head_state IS DISTINCT FROM fact_phase THEN
        RAISE EXCEPTION 'package monitor alert head does not equal its last transition fact'
            USING ERRCODE = '23514';
    END IF;
    RETURN NULL;
END;
$$;

CREATE CONSTRAINT TRIGGER package_monitor_alert_heads_fact_consistent_078
AFTER INSERT OR UPDATE ON package_monitor_alert_heads
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION validate_package_monitor_head_fact_078();

CREATE CONSTRAINT TRIGGER package_monitor_transition_facts_head_consistent_078
AFTER INSERT ON package_monitor_transition_facts
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION validate_package_monitor_head_fact_078();

CREATE FUNCTION validate_package_monitor_new_receipt_078()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    matching_count bigint;
BEGIN
    SELECT count(*)
    INTO matching_count
    FROM package_monitor_alert_heads AS head
    WHERE head.id = NEW.alert_id
      AND head.tenant_scope_id = NEW.tenant_scope_id
      AND head.subscription_id = NEW.subscription_id
      AND head.owner_user_id = NEW.owner_user_id
      AND head.policy_id = NEW.policy_id
      AND head.policy_revision = NEW.policy_revision
      AND head.metric = NEW.metric
      AND head.period_key = NEW.period_key
      AND head.threshold_identity = NEW.threshold_identity
      AND head.revision = NEW.result_revision
      AND head.state = NEW.result_state
      AND head.last_source_watermark = NEW.source_watermark
      AND head.last_finalized_through = NEW.finalized_through
      AND head.last_evidence_digest = NEW.evidence_digest
      AND head.last_evaluation_clock_id = NEW.evaluation_clock_id
      AND head.last_evaluated_at = NEW.evaluated_at
      AND (
          (NEW.transition_fact_revision IS NULL AND NEW.result_transition = '')
          OR EXISTS (
              SELECT 1
              FROM package_monitor_transition_facts AS fact
              WHERE fact.alert_id = NEW.alert_id
                AND fact.revision = NEW.transition_fact_revision
                AND fact.phase = NEW.result_state
                AND fact.source_watermark = NEW.source_watermark
                AND fact.observed_at = NEW.observed_at
                AND fact.finalized_through = NEW.finalized_through
                AND fact.evidence_digest = NEW.evidence_digest
                AND fact.evaluation_clock_id = NEW.evaluation_clock_id
                AND fact.evaluated_at = NEW.evaluated_at
                AND fact.notification_event_id IS NOT DISTINCT FROM NEW.notification_event_id
                AND (
                    (NEW.result_transition = '' AND fact.phase = 'before')
                    OR NEW.result_transition = fact.phase
                )
          )
      );
    IF matching_count <> 1 THEN
        RAISE EXCEPTION 'new evaluation receipt does not equal current alert head'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER package_monitor_evaluation_receipts_current_head_078
BEFORE INSERT ON package_monitor_evaluation_receipts
FOR EACH ROW EXECUTE FUNCTION validate_package_monitor_new_receipt_078();

CREATE FUNCTION validate_package_monitor_head_receipt_078()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    target_alert_id uuid;
    matching_count bigint;
BEGIN
    IF TG_TABLE_NAME = 'package_monitor_evaluation_receipts' THEN
        target_alert_id := NEW.alert_id;
    ELSE
        target_alert_id := NEW.id;
    END IF;
    SELECT count(*)
    INTO matching_count
    FROM package_monitor_alert_heads AS head
    JOIN package_monitor_evaluation_receipts AS receipt
      ON receipt.alert_id = head.id
     AND receipt.result_revision = head.revision
     AND receipt.result_state = head.state
     AND receipt.source_watermark = head.last_source_watermark
     AND receipt.finalized_through = head.last_finalized_through
     AND receipt.evidence_digest = head.last_evidence_digest
     AND receipt.evaluation_clock_id = head.last_evaluation_clock_id
     AND receipt.evaluated_at = head.last_evaluated_at
    WHERE head.id = target_alert_id;
    IF matching_count <> 1 THEN
        RAISE EXCEPTION 'package monitor alert head requires one exact evaluation receipt'
            USING ERRCODE = '23514';
    END IF;
    RETURN NULL;
END;
$$;

CREATE CONSTRAINT TRIGGER package_monitor_alert_heads_receipt_consistent_078
AFTER INSERT OR UPDATE ON package_monitor_alert_heads
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION validate_package_monitor_head_receipt_078();

CREATE CONSTRAINT TRIGGER package_monitor_evaluation_receipts_head_consistent_078
AFTER INSERT ON package_monitor_evaluation_receipts
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION validate_package_monitor_head_receipt_078();

CREATE FUNCTION package_monitor_go_json_string_078(input_text text)
RETURNS text
LANGUAGE sql
IMMUTABLE
STRICT
AS $$
    SELECT replace(replace(replace(replace(replace(
        to_json(input_text)::text,
        '&', E'\\u0026'),
        '<', E'\\u003c'),
        '>', E'\\u003e'),
        U&'\2028', E'\\u2028'),
        U&'\2029', E'\\u2029');
$$;

CREATE FUNCTION package_monitor_json_canonical_078(input_json jsonb)
RETURNS text
LANGUAGE plpgsql
IMMUTABLE
STRICT
AS $$
DECLARE
    canonical text;
BEGIN
    CASE jsonb_typeof(input_json)
        WHEN 'object' THEN
            SELECT '{' || COALESCE(string_agg(
                package_monitor_go_json_string_078(member_key) || ':' ||
                package_monitor_json_canonical_078(member_value),
                ',' ORDER BY member_key COLLATE "C"
            ), '') || '}'
            INTO canonical
            FROM jsonb_each(input_json) AS members(member_key, member_value);
        WHEN 'array' THEN
            SELECT '[' || COALESCE(string_agg(
                package_monitor_json_canonical_078(element_value),
                ',' ORDER BY element_order
            ), '') || ']'
            INTO canonical
            FROM jsonb_array_elements(input_json) WITH ORDINALITY
                AS elements(element_value, element_order);
        WHEN 'string' THEN
            canonical := package_monitor_go_json_string_078(input_json #>> '{}');
        ELSE
            canonical := input_json::text;
    END CASE;
    RETURN canonical;
END;
$$;

CREATE FUNCTION package_monitor_rfc3339nano_078(input_timestamp timestamptz)
RETURNS text
LANGUAGE sql
IMMUTABLE
STRICT
AS $$
    SELECT to_char(input_timestamp AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS') ||
        CASE
            WHEN extract(microseconds FROM input_timestamp)::bigint % 1000000 = 0 THEN ''
            ELSE '.' || rtrim(to_char(
                extract(microseconds FROM input_timestamp)::bigint % 1000000,
                'FM000000'
            ), '0')
        END || 'Z';
$$;

CREATE FUNCTION package_monitor_audit_hash_078(
    event_id uuid,
    event_scope_id uuid,
    event_stream_position bigint,
    event_actor_user_id uuid,
    event_action text,
    event_resource_type text,
    event_resource_id text,
    event_request_id text,
    event_result text,
    event_payload jsonb,
    event_previous_hash bytea,
    event_occurred_at timestamptz
)
RETURNS bytea
LANGUAGE sql
IMMUTABLE
AS $$
    SELECT sha256(convert_to(
        '{"version":1,"id":' || package_monitor_go_json_string_078(event_id::text) ||
        ',"scope_id":' || package_monitor_go_json_string_078(event_scope_id::text) ||
        ',"stream_position":' || event_stream_position::text ||
        ',"actor_user_id":' || COALESCE(package_monitor_go_json_string_078(event_actor_user_id::text), 'null') ||
        ',"action":' || package_monitor_go_json_string_078(event_action) ||
        ',"resource_type":' || package_monitor_go_json_string_078(event_resource_type) ||
        ',"resource_id":' || package_monitor_go_json_string_078(event_resource_id) ||
        ',"request_id":' || package_monitor_go_json_string_078(event_request_id) ||
        ',"result":' || package_monitor_go_json_string_078(event_result) ||
        ',"payload":' || package_monitor_json_canonical_078(event_payload) ||
        ',"previous_hash":' || package_monitor_go_json_string_078(COALESCE(encode(event_previous_hash, 'hex'), '')) ||
        ',"occurred_at":' || package_monitor_go_json_string_078(package_monitor_rfc3339nano_078(event_occurred_at)) ||
        '}',
        'UTF8'
    ));
$$;

CREATE FUNCTION bind_package_monitor_audit_clock_078()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    payload_clock_id uuid;
    payload_evaluated_at_text text;
    payload_evaluated_at timestamptz;
    database_evaluated_at timestamptz;
BEGIN
    IF jsonb_typeof(NEW.payload -> 'evaluation_clock_id') IS DISTINCT FROM 'string'
       OR jsonb_typeof(NEW.payload -> 'evaluated_at') IS DISTINCT FROM 'string' THEN
        RAISE EXCEPTION 'package monitor evaluation clock mismatch'
            USING ERRCODE = '23514';
    END IF;
    payload_evaluated_at_text := NEW.payload ->> 'evaluated_at';
    BEGIN
        payload_clock_id := (NEW.payload ->> 'evaluation_clock_id')::uuid;
        payload_evaluated_at := payload_evaluated_at_text::timestamptz;
    EXCEPTION WHEN OTHERS THEN
        RAISE EXCEPTION 'package monitor evaluation clock mismatch'
            USING ERRCODE = '23514';
    END;
    SELECT clock.evaluated_at
    INTO database_evaluated_at
    FROM package_monitor_evaluation_clocks AS clock
    WHERE clock.evaluation_clock_id = payload_clock_id
      AND clock.transaction_id = pg_current_xact_id()::text;
    IF NOT FOUND OR NOT isfinite(payload_evaluated_at)
       OR payload_evaluated_at IS DISTINCT FROM database_evaluated_at
       OR payload_evaluated_at_text IS DISTINCT FROM
           package_monitor_rfc3339nano_078(database_evaluated_at) THEN
        RAISE EXCEPTION 'package monitor evaluation clock mismatch'
            USING ERRCODE = '23514';
    END IF;
    NEW.occurred_at := database_evaluated_at;
    NEW.event_hash := package_monitor_audit_hash_078(
        NEW.id, NEW.scope_id, NEW.stream_position, NEW.actor_user_id,
        NEW.action, NEW.resource_type, NEW.resource_id, NEW.request_id,
        NEW.result, NEW.payload, NEW.previous_hash, NEW.occurred_at
    );
    RETURN NEW;
END;
$$;

CREATE TRIGGER audit_events_package_monitor_clock_078
BEFORE INSERT ON audit_events
FOR EACH ROW
WHEN (NEW.action IN (
    'package_monitor.alert.observe_before',
    'package_monitor.alert.trigger',
    'package_monitor.alert.recover',
    'package_monitor.alert.suppress_stale',
    'package_monitor.evaluation.commit'
))
EXECUTE FUNCTION bind_package_monitor_audit_clock_078();

CREATE FUNCTION validate_package_monitor_audit_078()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    fact package_monitor_transition_facts%ROWTYPE;
    expected_action text;
    triggering_audit_id uuid;
    matching_count bigint;
BEGIN
    IF TG_TABLE_NAME = 'package_monitor_transition_facts' THEN
        fact := NEW;
    ELSE
        triggering_audit_id := NEW.id;
        SELECT transition.*
        INTO fact
        FROM package_monitor_transition_facts AS transition
        WHERE transition.tenant_scope_id = NEW.scope_id
          AND transition.alert_id::text || ':' || transition.revision::text = NEW.resource_id
          AND CASE transition.phase
                WHEN 'before' THEN 'package_monitor.alert.observe_before'
                WHEN 'triggered' THEN 'package_monitor.alert.trigger'
                WHEN 'recovered' THEN 'package_monitor.alert.recover'
                WHEN 'suppressed_stale' THEN 'package_monitor.alert.suppress_stale'
              END = NEW.action;
    END IF;
    IF fact.alert_id IS NULL THEN
        RAISE EXCEPTION 'package monitor audit has no exact transition fact'
            USING ERRCODE = '23514';
    END IF;
    expected_action := CASE fact.phase
        WHEN 'before' THEN 'package_monitor.alert.observe_before'
        WHEN 'triggered' THEN 'package_monitor.alert.trigger'
        WHEN 'recovered' THEN 'package_monitor.alert.recover'
        WHEN 'suppressed_stale' THEN 'package_monitor.alert.suppress_stale'
    END;
    SELECT count(*)
    INTO matching_count
    FROM package_monitor_evaluation_receipts AS receipt
    JOIN audit_events AS audit_event
      ON audit_event.scope_id = fact.tenant_scope_id
     AND audit_event.request_id = receipt.job_item_id
    WHERE receipt.alert_id = fact.alert_id
      AND receipt.transition_fact_revision = fact.revision
      AND receipt.result_revision = fact.revision
      AND receipt.result_state = fact.phase
      AND receipt.tenant_scope_id = fact.tenant_scope_id
      AND receipt.subscription_id = fact.subscription_id
      AND receipt.owner_user_id = fact.owner_user_id
      AND receipt.policy_id = fact.policy_id
      AND receipt.policy_revision = fact.policy_revision
      AND receipt.metric = fact.metric
      AND receipt.period_key = fact.period_key
      AND receipt.threshold_identity = fact.threshold_identity
      AND receipt.source_watermark = fact.source_watermark
      AND receipt.observed_at = fact.observed_at
      AND receipt.finalized_through = fact.finalized_through
      AND receipt.evidence_digest = fact.evidence_digest
      AND receipt.evaluation_clock_id = fact.evaluation_clock_id
      AND receipt.evaluated_at = fact.evaluated_at
      AND receipt.notification_event_id IS NOT DISTINCT FROM fact.notification_event_id
      AND (triggering_audit_id IS NULL OR audit_event.id = triggering_audit_id)
      AND audit_event.action = expected_action
      AND audit_event.resource_type = 'package_monitor_alert_transition'
      AND audit_event.resource_id = fact.alert_id::text || ':' || fact.revision::text
      AND audit_event.result = 'success'
      AND audit_event.occurred_at = fact.evaluated_at
      AND audit_event.payload ->> 'evaluation_clock_id' = fact.evaluation_clock_id::text
      AND jsonb_typeof(audit_event.payload -> 'evaluated_at') = 'string'
      AND audit_event.payload ->> 'evaluated_at' =
          package_monitor_rfc3339nano_078(fact.evaluated_at)
      AND jsonb_typeof(audit_event.payload -> 'observed_at') = 'string'
      AND audit_event.payload ->> 'observed_at' =
          package_monitor_rfc3339nano_078(fact.observed_at)
      AND audit_event.payload ->> 'tenant_scope_id' = fact.tenant_scope_id::text
      AND audit_event.payload ->> 'subscription_id' = fact.subscription_id::text
      AND audit_event.payload ->> 'owner_user_id' = fact.owner_user_id::text
      AND audit_event.payload ->> 'policy_id' = fact.policy_id::text
      AND audit_event.payload ->> 'policy_revision' = fact.policy_revision::text
      AND audit_event.payload ->> 'metric' = fact.metric
      AND audit_event.payload ->> 'period_key' = fact.period_key
      AND audit_event.payload ->> 'threshold_identity' = encode(fact.threshold_identity, 'hex')
      AND audit_event.payload ->> 'source_watermark' = fact.source_watermark::text
      AND audit_event.payload ->> 'evidence_digest' = encode(fact.evidence_digest, 'hex')
      AND audit_event.payload ->> 'reason_code' = fact.reason_code
      AND audit_event.payload ? 'notification_event_id'
      AND (
          (fact.notification_event_id IS NULL
           AND jsonb_typeof(audit_event.payload -> 'notification_event_id') = 'null')
          OR audit_event.payload ->> 'notification_event_id' = fact.notification_event_id::text
      )
      AND audit_event.payload ?& ARRAY[
          'job_id', 'job_attempt', 'job_item_id', 'request_id',
          'evaluation_clock_id', 'evaluated_at', 'observed_at'
      ]
      AND audit_event.payload - ARRAY[
          'job_id', 'job_attempt', 'job_item_id', 'request_id',
          'evaluation_clock_id', 'evaluated_at', 'observed_at'
      ] =
          jsonb_build_object(
              'tenant_scope_id', fact.tenant_scope_id::text,
              'subscription_id', fact.subscription_id::text,
              'owner_user_id', fact.owner_user_id::text,
              'policy_id', fact.policy_id::text,
              'policy_revision', fact.policy_revision,
              'metric', fact.metric,
              'period_key', fact.period_key,
              'threshold_identity', encode(fact.threshold_identity, 'hex'),
              'source_watermark', fact.source_watermark,
              'evidence_digest', encode(fact.evidence_digest, 'hex'),
              'reason_code', fact.reason_code,
              'notification_event_id', fact.notification_event_id
          )
      AND jsonb_typeof(audit_event.payload -> 'job_id') = 'string'
      AND audit_event.payload ->> 'job_id' = receipt.job_id::text
      AND jsonb_typeof(audit_event.payload -> 'job_attempt') = 'number'
      AND audit_event.payload ->> 'job_attempt' = receipt.job_attempt::text
      AND jsonb_typeof(audit_event.payload -> 'job_item_id') = 'string'
      AND audit_event.payload ->> 'job_item_id' = receipt.job_item_id
      AND jsonb_typeof(audit_event.payload -> 'request_id') = 'string'
      AND audit_event.payload ->> 'request_id' = receipt.request_id;
    IF matching_count <> 1 THEN
        RAISE EXCEPTION 'package monitor transition requires one exact success audit event'
            USING ERRCODE = '23514';
    END IF;
    RETURN NULL;
END;
$$;

CREATE CONSTRAINT TRIGGER package_monitor_transition_facts_audit_078
AFTER INSERT ON package_monitor_transition_facts
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION validate_package_monitor_audit_078();

CREATE CONSTRAINT TRIGGER audit_events_package_monitor_transition_078
AFTER INSERT ON audit_events
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW
WHEN (NEW.action IN (
    'package_monitor.alert.observe_before',
    'package_monitor.alert.trigger',
    'package_monitor.alert.recover',
    'package_monitor.alert.suppress_stale'
))
EXECUTE FUNCTION validate_package_monitor_audit_078();

CREATE FUNCTION validate_package_monitor_receipt_audit_078()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    receipt package_monitor_evaluation_receipts%ROWTYPE;
    triggering_audit_id uuid;
    matching_count bigint;
BEGIN
    IF TG_TABLE_NAME = 'package_monitor_evaluation_receipts' THEN
        receipt := NEW;
    ELSE
        triggering_audit_id := NEW.id;
        SELECT stored.*
        INTO receipt
        FROM package_monitor_evaluation_receipts AS stored
        WHERE stored.tenant_scope_id = NEW.scope_id
          AND stored.receipt_id::text = NEW.resource_id;
    END IF;
    IF receipt.receipt_id IS NULL THEN
        RAISE EXCEPTION 'package monitor evaluation audit has no exact receipt'
            USING ERRCODE = '23514';
    END IF;
    SELECT count(*)
    INTO matching_count
    FROM audit_events AS audit_event
    WHERE audit_event.scope_id = receipt.tenant_scope_id
      AND (triggering_audit_id IS NULL OR audit_event.id = triggering_audit_id)
      AND audit_event.actor_user_id = receipt.owner_user_id
      AND audit_event.action = 'package_monitor.evaluation.commit'
      AND audit_event.resource_type = 'package_monitor_evaluation_receipt'
      AND audit_event.resource_id = receipt.receipt_id::text
      AND audit_event.request_id = receipt.job_item_id
      AND audit_event.result = 'success'
      AND audit_event.occurred_at = receipt.evaluated_at
      AND audit_event.payload ->> 'evaluation_clock_id' = receipt.evaluation_clock_id::text
      AND jsonb_typeof(audit_event.payload -> 'evaluated_at') = 'string'
      AND audit_event.payload ->> 'evaluated_at' =
          package_monitor_rfc3339nano_078(receipt.evaluated_at)
      AND jsonb_typeof(audit_event.payload -> 'observed_at') = 'string'
      AND audit_event.payload ->> 'observed_at' =
          package_monitor_rfc3339nano_078(receipt.observed_at)
      AND audit_event.payload = jsonb_build_object(
          'receipt_id', receipt.receipt_id::text,
          'alert_id', receipt.alert_id::text,
          'tenant_scope_id', receipt.tenant_scope_id::text,
          'subscription_id', receipt.subscription_id::text,
          'owner_user_id', receipt.owner_user_id::text,
          'policy_id', receipt.policy_id::text,
          'policy_revision', receipt.policy_revision,
          'metric', receipt.metric,
          'period_key', receipt.period_key,
          'threshold_identity', encode(receipt.threshold_identity, 'hex'),
          'result_revision', receipt.result_revision,
          'result_state', receipt.result_state,
          'result_transition', receipt.result_transition,
          'source_watermark', receipt.source_watermark,
          'observed_at', package_monitor_rfc3339nano_078(receipt.observed_at),
          'evidence_digest', encode(receipt.evidence_digest, 'hex'),
          'evaluation_clock_id', receipt.evaluation_clock_id::text,
          'evaluated_at', package_monitor_rfc3339nano_078(receipt.evaluated_at),
          'notification_event_id', receipt.notification_event_id,
          'job_id', receipt.job_id::text,
          'job_attempt', receipt.job_attempt,
          'job_item_id', receipt.job_item_id,
          'request_id', receipt.request_id
      );
    IF matching_count <> 1 THEN
        RAISE EXCEPTION 'package monitor evaluation receipt requires one exact success audit event'
            USING ERRCODE = '23514';
    END IF;
    RETURN NULL;
END;
$$;

CREATE CONSTRAINT TRIGGER package_monitor_evaluation_receipts_audit_078
AFTER INSERT ON package_monitor_evaluation_receipts
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION validate_package_monitor_receipt_audit_078();

CREATE CONSTRAINT TRIGGER audit_events_package_monitor_receipt_078
AFTER INSERT ON audit_events
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW
WHEN (NEW.action = 'package_monitor.evaluation.commit')
EXECUTE FUNCTION validate_package_monitor_receipt_audit_078();

REVOKE ALL ON TABLE package_monitor_subscription_owners FROM PUBLIC;
REVOKE ALL ON TABLE package_monitor_policy_versions FROM PUBLIC;
REVOKE ALL ON TABLE package_monitor_policy_templates FROM PUBLIC;
REVOKE ALL ON TABLE package_monitor_policy_heads FROM PUBLIC;
REVOKE ALL ON TABLE package_monitor_evaluation_clocks FROM PUBLIC;
REVOKE ALL ON TABLE package_monitor_alert_heads FROM PUBLIC;
REVOKE ALL ON TABLE package_monitor_transition_facts FROM PUBLIC;
REVOKE ALL ON TABLE package_monitor_evaluation_receipts FROM PUBLIC;
REVOKE ALL ON FUNCTION package_monitor_template_sha256_078(
    text, text, text, text, text[], bigint
) FROM PUBLIC;
REVOKE ALL ON FUNCTION package_monitor_threshold_sha256_078(
    uuid, bigint, text, numeric, numeric, bigint
) FROM PUBLIC;
REVOKE ALL ON FUNCTION validate_package_monitor_owner_078() FROM PUBLIC;
REVOKE ALL ON FUNCTION validate_package_monitor_owner_provenance_078() FROM PUBLIC;
REVOKE ALL ON FUNCTION prevent_package_monitor_immutable_078() FROM PUBLIC;
REVOKE ALL ON FUNCTION protect_package_monitor_policy_head_078() FROM PUBLIC;
REVOKE ALL ON FUNCTION protect_package_monitor_alert_head_078() FROM PUBLIC;
REVOKE ALL ON FUNCTION bind_package_monitor_evaluation_clock_078() FROM PUBLIC;
REVOKE ALL ON FUNCTION package_monitor_transaction_clock_078() FROM PUBLIC;
REVOKE ALL ON FUNCTION validate_package_monitor_evaluation_clock_078() FROM PUBLIC;
REVOKE ALL ON FUNCTION validate_package_monitor_head_fact_078() FROM PUBLIC;
REVOKE ALL ON FUNCTION validate_package_monitor_audit_078() FROM PUBLIC;
REVOKE ALL ON FUNCTION validate_package_monitor_new_receipt_078() FROM PUBLIC;
REVOKE ALL ON FUNCTION validate_package_monitor_head_receipt_078() FROM PUBLIC;
REVOKE ALL ON FUNCTION validate_package_monitor_receipt_audit_078() FROM PUBLIC;
REVOKE ALL ON FUNCTION package_monitor_go_json_string_078(text) FROM PUBLIC;
REVOKE ALL ON FUNCTION package_monitor_json_canonical_078(jsonb) FROM PUBLIC;
REVOKE ALL ON FUNCTION package_monitor_rfc3339nano_078(timestamptz) FROM PUBLIC;
REVOKE ALL ON FUNCTION package_monitor_audit_hash_078(
    uuid, uuid, bigint, uuid, text, text, text, text, text, jsonb, bytea, timestamptz
) FROM PUBLIC;
REVOKE ALL ON FUNCTION bind_package_monitor_audit_clock_078() FROM PUBLIC;
