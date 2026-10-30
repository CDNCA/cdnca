-- 583 回退：函数恢复为 435 的定义（逐字），即回到含 42702 歧义的旧版本。
LOCK TABLE schema_migrations, recharge_payment_approval_requests_v1, recharge_payment_approval_decisions_v1,
    recharge_payment_approval_executions_v1 IN ACCESS EXCLUSIVE MODE;

DO $migration_583_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 583 OR
       (SELECT max(version) FROM schema_migrations) <> 583 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=583 AND
        migration_id='583_recharge_approval_decision_alias' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 583 down requires the exact verified migration head' USING ERRCODE='P5831';
    END IF;
END;
$migration_583_down$;

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
        SELECT * INTO decision FROM recharge_payment_approval_decisions_v1
        WHERE approval_request_id=NEW.approval_request_id AND decision='approved' FOR SHARE;
        IF request.id IS NULL OR decision.id IS NULL OR NEW.authorized_at>=request.expires_at OR
           (NEW.actor_scope_id,NEW.actor_user_id,NEW.actor_session_id) IS DISTINCT FROM
           (decision.decided_by_scope_id,decision.decided_by_user_id,decision.decided_by_session_id) THEN
            RAISE EXCEPTION 'approval execution is not bound to the approved checker' USING ERRCODE='P1715';
        END IF;
    END IF;
    RETURN NEW;
END;
$$;
