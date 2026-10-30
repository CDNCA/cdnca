-- 584（fix-finrefund CFIN-D，占位号，合入时按集成头连号改号）：退款/作废执行改为
-- 意图持久化 → 提交 → 按稳定渠道退款号外调 → 验真记录 → 事务化落账本与回执 → 可恢复查询。
-- 原流程在批准/再认证后直接外调渠道，之后才写命令；命令写失败或进程中断时外部已退款、
-- 本地无任何可恢复记录，且命令不落账本。本迁移新增退款意图（每张审批单至多一条，
-- 每个订单至多一条在途）与逐次外调记录；在途意图的金额即对租户余额的预留。
-- 前驱 583，守卫钉 583 校验和。
LOCK TABLE schema_migrations, recharge_orders_v1, recharge_payment_approval_executions_v1, billing_transactions
    IN ACCESS EXCLUSIVE MODE;

DO $migration_584_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 583 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 583 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=583 AND
        migration_id='583_recharge_approval_decision_alias' AND
        checksum_sha256='6fa605b83ad700bec6da7d1e9471103584f78b32dc39b47517374e3c2394311a' AND
        down_checksum_sha256='54c7bb05b58411f5b68e2f06875b1efe69b8dd33487df586ef10b8a222ac86ae' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR to_regclass('recharge_payment_compensations_v1') IS NOT NULL OR
         to_regclass('recharge_payment_compensation_attempts_v1') IS NOT NULL THEN
        RAISE EXCEPTION 'migration 584 requires the exact verified 583 release head' USING ERRCODE='P5840';
    END IF;
END;
$migration_584_up$;

CREATE TABLE recharge_payment_compensations_v1 (
    id uuid PRIMARY KEY CHECK(id<>'00000000-0000-0000-0000-000000000000'::uuid),
    approval_request_id uuid NOT NULL UNIQUE
        REFERENCES recharge_payment_approval_executions_v1(approval_request_id) ON DELETE RESTRICT,
    order_id uuid NOT NULL,
    tenant_scope_id uuid NOT NULL,
    provider text NOT NULL CHECK(provider IN ('alipay','wechat')),
    provider_account_id text NOT NULL CHECK(provider_account_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'),
    external_payment_id text NOT NULL CHECK(external_payment_id ~ '^[A-Za-z0-9][A-Za-z0-9._:@-]{0,191}$'),
    operation text NOT NULL CHECK(operation IN ('refund','void')),
    amount_minor bigint NOT NULL CHECK(amount_minor BETWEEN 1 AND 9000000000000000),
    captured_minor bigint NOT NULL CHECK(captured_minor BETWEEN 1 AND 9000000000000000 AND amount_minor<=captured_minor),
    expected_revision bigint NOT NULL CHECK(expected_revision>0),
    actor_scope_id uuid NOT NULL,
    actor_user_id uuid NOT NULL,
    actor_session_id uuid NOT NULL,
    idempotency_key text NOT NULL CHECK(idempotency_key ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$'),
    request_id text NOT NULL CHECK(request_id ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$'),
    request_digest_sha256 bytea NOT NULL CHECK(octet_length(request_digest_sha256)=32),
    provider_request_id text NOT NULL CHECK(provider_request_id ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$'),
    status text NOT NULL CHECK(status IN ('pending','succeeded','failed','unknown')),
    reason_code text NOT NULL CHECK(reason_code ~ '^[A-Z][A-Z0-9_]{0,63}$'),
    attempt_count bigint NOT NULL CHECK(attempt_count>0),
    revision bigint NOT NULL CHECK(revision>0),
    lease_token uuid,
    lease_started_at timestamptz CHECK(lease_started_at IS NULL OR isfinite(lease_started_at)),
    lease_expires_at timestamptz CHECK(lease_expires_at IS NULL OR isfinite(lease_expires_at)),
    created_at timestamptz NOT NULL CHECK(isfinite(created_at)),
    updated_at timestamptz NOT NULL CHECK(isfinite(updated_at) AND updated_at>=created_at),
    completed_at timestamptz CHECK(completed_at IS NULL OR isfinite(completed_at)),
    FOREIGN KEY(order_id,tenant_scope_id) REFERENCES recharge_orders_v1(id,tenant_scope_id) ON DELETE RESTRICT,
    FOREIGN KEY(actor_session_id,actor_scope_id,actor_user_id) REFERENCES auth_sessions(id,scope_id,user_id) ON DELETE RESTRICT,
    UNIQUE(actor_session_id,idempotency_key),
    UNIQUE(actor_session_id,request_id),
    UNIQUE(provider,provider_account_id,provider_request_id),
    UNIQUE(id,order_id,tenant_scope_id,provider_request_id),
    CHECK((lease_token IS NULL AND lease_started_at IS NULL AND lease_expires_at IS NULL) OR
          (lease_token IS NOT NULL AND lease_started_at IS NOT NULL AND lease_expires_at>lease_started_at)),
    CHECK((status='pending' AND lease_token IS NOT NULL AND completed_at IS NULL) OR
          (status='unknown' AND lease_token IS NULL AND completed_at IS NULL) OR
          (status IN ('succeeded','failed') AND lease_token IS NULL AND completed_at IS NOT NULL))
);

-- 每个订单同一时间至多一条在途退款/作废；在途金额按租户汇总即余额预留。
CREATE UNIQUE INDEX recharge_payment_compensations_order_active_584_idx
    ON recharge_payment_compensations_v1(order_id) WHERE status IN ('pending','unknown');
CREATE INDEX recharge_payment_compensations_tenant_active_584_idx
    ON recharge_payment_compensations_v1(tenant_scope_id) WHERE status IN ('pending','unknown');

CREATE TABLE recharge_payment_compensation_attempts_v1 (
    id uuid PRIMARY KEY,
    compensation_id uuid NOT NULL,
    order_id uuid NOT NULL,
    tenant_scope_id uuid NOT NULL,
    attempt_number bigint NOT NULL CHECK(attempt_number>0),
    provider_request_id text NOT NULL CHECK(provider_request_id ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$'),
    started_at timestamptz NOT NULL CHECK(isfinite(started_at)),
    finished_at timestamptz NOT NULL CHECK(isfinite(finished_at) AND finished_at>=started_at),
    provider_status text NOT NULL CHECK(provider_status IN ('succeeded','failed','unknown')),
    definite boolean NOT NULL,
    response_signed boolean NOT NULL,
    verification_key_id text CHECK(verification_key_id IS NULL OR verification_key_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'),
    payload_sha256 bytea CHECK(payload_sha256 IS NULL OR octet_length(payload_sha256)=32),
    signature_sha256 bytea CHECK(signature_sha256 IS NULL OR octet_length(signature_sha256)=32),
    error_code text NOT NULL CHECK(error_code ~ '^[A-Z][A-Z0-9_]{0,63}$'),
    retryable boolean NOT NULL,
    FOREIGN KEY(compensation_id,order_id,tenant_scope_id,provider_request_id)
        REFERENCES recharge_payment_compensations_v1(id,order_id,tenant_scope_id,provider_request_id) ON DELETE RESTRICT,
    UNIQUE(compensation_id,attempt_number),
    CHECK(definite=(provider_status IN ('succeeded','failed'))),
    CHECK(retryable=(NOT definite)),
    CHECK((response_signed AND verification_key_id IS NOT NULL AND payload_sha256 IS NOT NULL AND signature_sha256 IS NOT NULL) OR
          (NOT response_signed AND verification_key_id IS NULL AND payload_sha256 IS NULL AND signature_sha256 IS NULL))
);

CREATE FUNCTION guard_recharge_payment_compensation_head_584()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    PERFORM pg_advisory_xact_lock(hashtextextended('recharge-compensation-head:'||OLD.id::text,0));
    IF TG_OP='DELETE' OR OLD.id<>NEW.id OR OLD.approval_request_id<>NEW.approval_request_id OR
       OLD.order_id<>NEW.order_id OR OLD.tenant_scope_id<>NEW.tenant_scope_id OR
       OLD.provider<>NEW.provider OR OLD.provider_account_id<>NEW.provider_account_id OR
       OLD.external_payment_id<>NEW.external_payment_id OR OLD.operation<>NEW.operation OR
       OLD.amount_minor<>NEW.amount_minor OR OLD.captured_minor<>NEW.captured_minor OR
       OLD.expected_revision<>NEW.expected_revision OR OLD.actor_scope_id<>NEW.actor_scope_id OR
       OLD.actor_user_id<>NEW.actor_user_id OR OLD.actor_session_id<>NEW.actor_session_id OR
       OLD.idempotency_key<>NEW.idempotency_key OR OLD.request_id<>NEW.request_id OR
       OLD.request_digest_sha256<>NEW.request_digest_sha256 OR OLD.provider_request_id<>NEW.provider_request_id OR
       OLD.created_at<>NEW.created_at OR NEW.revision<>OLD.revision+1 OR
       NOT ((NEW.status='pending' AND NEW.attempt_count=OLD.attempt_count+1) OR
            (NEW.status IN ('succeeded','failed','unknown') AND NEW.attempt_count=OLD.attempt_count)) OR
       NEW.updated_at<OLD.updated_at OR NOT (
          (OLD.status='pending' AND NEW.status IN ('pending','succeeded','failed','unknown')) OR
          (OLD.status='unknown' AND NEW.status IN ('pending','succeeded','failed'))
       ) THEN
        RAISE EXCEPTION 'recharge payment compensation transition is invalid' USING ERRCODE='P5841';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION validate_recharge_payment_compensation_attempt_584()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    PERFORM pg_advisory_xact_lock(hashtextextended('recharge-compensation-head:'||NEW.compensation_id::text,0));
    IF NOT EXISTS (
        SELECT 1 FROM recharge_payment_compensations_v1 compensation
        WHERE compensation.id=NEW.compensation_id AND compensation.order_id=NEW.order_id AND
              compensation.tenant_scope_id=NEW.tenant_scope_id AND
              compensation.provider_request_id=NEW.provider_request_id AND
              NEW.attempt_number<=compensation.attempt_count
    ) THEN
        RAISE EXCEPTION 'recharge payment compensation attempt binding is invalid' USING ERRCODE='P5842';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION prevent_recharge_payment_compensation_mutation_584()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'recharge payment compensation facts are append-only' USING ERRCODE='P5842';
END;
$$;

CREATE TRIGGER recharge_payment_compensations_guard_584
BEFORE UPDATE OR DELETE ON recharge_payment_compensations_v1
FOR EACH ROW EXECUTE FUNCTION guard_recharge_payment_compensation_head_584();
CREATE TRIGGER recharge_payment_compensation_attempts_append_only_584
BEFORE UPDATE OR DELETE ON recharge_payment_compensation_attempts_v1
FOR EACH ROW EXECUTE FUNCTION prevent_recharge_payment_compensation_mutation_584();
CREATE TRIGGER recharge_payment_compensation_attempts_validate_584
BEFORE INSERT ON recharge_payment_compensation_attempts_v1
FOR EACH ROW EXECUTE FUNCTION validate_recharge_payment_compensation_attempt_584();
CREATE TRIGGER recharge_payment_compensations_truncate_584
BEFORE TRUNCATE ON recharge_payment_compensations_v1
FOR EACH STATEMENT EXECUTE FUNCTION prevent_recharge_payment_compensation_mutation_584();
CREATE TRIGGER recharge_payment_compensation_attempts_truncate_584
BEFORE TRUNCATE ON recharge_payment_compensation_attempts_v1
FOR EACH STATEMENT EXECUTE FUNCTION prevent_recharge_payment_compensation_mutation_584();

REVOKE ALL ON recharge_payment_compensations_v1,recharge_payment_compensation_attempts_v1 FROM PUBLIC;

-- 152 本意删除 133 的“非 pending 时 revision=2”约束，但按自动命名删成了 check1（provider 三字段同空/同非空），
-- check2（revision=2）留了下来：订单修订号无法超过 2，退款/作废落账（revision 2→3）必然失败。这里补删。
ALTER TABLE recharge_orders_v1 DROP CONSTRAINT recharge_orders_v1_check2;

-- 555 重建 billing_transactions_commerce_shape 时漏掉了 549 的升级包购买分支：新装库上任何加购扣款都违反约束。
-- 这里按 555 原文重建并补回 549 分支（加购是本迁移起计入可用余额判定的扣款路径之一）。
ALTER TABLE billing_transactions DROP CONSTRAINT billing_transactions_commerce_shape;
ALTER TABLE billing_transactions
    ADD CONSTRAINT billing_transactions_commerce_shape CHECK(
        (operation='manual_adjustment' AND commercial_order_id IS NULL AND reverses_transaction_id IS NULL
            AND payment_attempt_id IS NULL AND recharge_order_id IS NULL AND recharge_provider_event_id IS NULL)
        OR (operation='provider_payment' AND commercial_order_id IS NOT NULL AND reverses_transaction_id IS NULL
            AND payment_attempt_id IS NOT NULL AND recharge_order_id IS NULL AND recharge_provider_event_id IS NULL AND direction='credit')
        OR (operation IN ('package_purchase','package_renewal','package_upgrade','package_downgrade','traffic_package_purchase')
            AND commercial_order_id IS NOT NULL AND reverses_transaction_id IS NULL AND recharge_order_id IS NULL AND recharge_provider_event_id IS NULL)
        OR (operation IN ('package_refund','package_void') AND commercial_order_id IS NOT NULL
            AND reverses_transaction_id IS NOT NULL AND recharge_order_id IS NULL AND recharge_provider_event_id IS NULL AND direction='credit')
        OR (operation='recharge_payment' AND commercial_order_id IS NULL AND reverses_transaction_id IS NULL
            AND payment_attempt_id IS NULL AND recharge_order_id IS NOT NULL AND recharge_provider_event_id IS NOT NULL AND direction='credit')
        OR (operation IN ('recharge_refund','recharge_void') AND commercial_order_id IS NULL
            AND reverses_transaction_id IS NOT NULL AND payment_attempt_id IS NULL AND recharge_order_id IS NOT NULL
            AND recharge_provider_event_id IS NOT NULL AND direction='debit')
        OR (operation='migrate_import_credit' AND commercial_order_id IS NULL AND reverses_transaction_id IS NULL
            AND payment_attempt_id IS NULL AND recharge_order_id IS NULL AND recharge_provider_event_id IS NULL
            AND adjustment_request_id IS NULL AND direction='credit')
        OR (operation='reseller_sale' AND commercial_order_id IS NOT NULL AND payment_attempt_id IS NULL
            AND recharge_order_id IS NULL AND recharge_provider_event_id IS NULL AND balance_hold_id IS NULL
            AND direction = CASE WHEN reverses_transaction_id IS NULL THEN 'credit' ELSE 'debit' END)
        -- 555：首笔方向由 assert_reseller_transaction_483 按订单核对（升降级可为 credit）。
        OR (operation='reseller_wholesale' AND commercial_order_id IS NOT NULL AND payment_attempt_id IS NULL
            AND recharge_order_id IS NULL AND recharge_provider_event_id IS NULL AND balance_hold_id IS NULL
            AND (reverses_transaction_id IS NULL OR direction='credit'))
        -- 549：升级包购买，绑升级包订单，只扣不退。
        OR (operation='package_addon_purchase' AND addon_order_id IS NOT NULL AND commercial_order_id IS NULL
            AND reverses_transaction_id IS NULL AND payment_attempt_id IS NULL AND recharge_order_id IS NULL
            AND recharge_provider_event_id IS NULL AND balance_hold_id IS NULL AND adjustment_request_id IS NULL
            AND direction='debit')
    );

