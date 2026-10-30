-- 583（fix-finrefund，占位号，合入时按集成头连号改号）：CFIN-01 退款审批执行被触发器挡住。
-- 435 重定义的 validate_recharge_payment_approval_171() 里记录变量 decision 与列 decision 同名，
-- 执行分支 "AND decision='approved'" 报 42702 ambiguous，已批准退款在调用渠道前全部失败。
-- 435 已上线不得改字节，这里前滚替换函数：只给该查询加表别名 approved_row，其余守卫（审批人=执行人、
-- 订单修订、金额、过期、maker-checker、平台管理员自审）逐字保留。前驱 578，守卫钉 578 校验和。
LOCK TABLE schema_migrations, recharge_payment_approval_requests_v1, recharge_payment_approval_decisions_v1,
    recharge_payment_approval_executions_v1 IN ACCESS EXCLUSIVE MODE;

DO $migration_583_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 582 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 582 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=582 AND
        migration_id='582_node_deployment_frozen_refusals' AND
        checksum_sha256='9f6f4fb87a5ded956990bcd9e5c1bbca22e1826ac6e877c1e4e9d091da299038' AND
        down_checksum_sha256='dd80b8d1057da31098896541327dc1ecf34cd43f70b31533a4e10a697c43f1bf' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR to_regprocedure(current_schema() || '.validate_recharge_payment_approval_171()') IS NULL THEN
        RAISE EXCEPTION 'migration 583 requires the exact verified 582 release head' USING ERRCODE='P5830';
    END IF;
END;
$migration_583_up$;

CREATE OR REPLACE FUNCTION validate_recharge_payment_approval_171()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    request recharge_payment_approval_requests_v1%ROWTYPE;
    decision recharge_payment_approval_decisions_v1%ROWTYPE;
    order_scope uuid;
    order_revision bigint;
    order_state text;
    captured bigint;
    refunded bigint;
BEGIN
    IF TG_TABLE_NAME='recharge_payment_approval_requests_v1' THEN
        IF NOT EXISTS(SELECT 1 FROM access_scopes WHERE id=NEW.proposed_by_scope_id AND kind='platform') THEN
            RAISE EXCEPTION 'approval proposer must belong to the platform scope' USING ERRCODE='P1711';
        END IF;
        SELECT tenant_scope_id,revision,state,captured_minor,refunded_minor
        INTO order_scope,order_revision,order_state,captured,refunded
        FROM recharge_orders_v1 WHERE id=NEW.order_id FOR SHARE;
        IF order_scope IS NULL OR order_scope<>NEW.tenant_scope_id OR order_revision<>NEW.expected_order_revision OR
           order_state NOT IN ('paid','partially_refunded') OR captured<=0 OR NEW.amount_minor>captured-refunded THEN
            RAISE EXCEPTION 'approval proposal does not match the live recharge order' USING ERRCODE='P1712';
        END IF;
    ELSIF TG_TABLE_NAME='recharge_payment_approval_decisions_v1' THEN
        SELECT * INTO request FROM recharge_payment_approval_requests_v1
        WHERE id=NEW.approval_request_id FOR SHARE;
        IF request.id IS NULL OR (NEW.decided_by_user_id=request.proposed_by_user_id AND
           NOT control_platform_admin_435(NEW.decided_by_user_id,NEW.decided_by_scope_id)) OR
           NEW.decided_at>=request.expires_at OR
           NOT EXISTS(SELECT 1 FROM access_scopes WHERE id=NEW.decided_by_scope_id AND kind='platform') THEN
            RAISE EXCEPTION 'approval decision violates maker-checker or expiry' USING ERRCODE='P1713';
        END IF;
        IF EXISTS(SELECT 1 FROM recharge_payment_approval_decisions_v1 WHERE approval_request_id=request.id) THEN
            RAISE EXCEPTION 'approval request already has a decision' USING ERRCODE='P1714';
        END IF;
    ELSIF TG_TABLE_NAME='recharge_payment_approval_executions_v1' THEN
        SELECT * INTO request FROM recharge_payment_approval_requests_v1
        WHERE id=NEW.approval_request_id FOR SHARE;
        SELECT approved_row.* INTO decision FROM recharge_payment_approval_decisions_v1 approved_row
        WHERE approved_row.approval_request_id=NEW.approval_request_id AND approved_row.decision='approved' FOR SHARE;
        IF request.id IS NULL OR decision.id IS NULL OR NEW.authorized_at>=request.expires_at OR
           (NEW.actor_scope_id,NEW.actor_user_id,NEW.actor_session_id) IS DISTINCT FROM
           (decision.decided_by_scope_id,decision.decided_by_user_id,decision.decided_by_session_id) THEN
            RAISE EXCEPTION 'approval execution is not bound to the approved checker' USING ERRCODE='P1715';
        END IF;
    END IF;
    RETURN NEW;
END;
$$;
