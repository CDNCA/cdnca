-- 700（前驱 699_billing_bridge_log_request_id）。
-- 节点升级创建原先在 HTTP 请求内向授权端签发授权并下载、校验正向与回滚两个约 110MB 的升级包（实测约 116 秒），
-- nginx 60 秒先回 504，计划迟到落库。现在创建请求只落 096 的创建意图和这里的一条准备记录后立即返回；
-- 后台 worker 认领准备记录，签发授权、下载并校验制品，就绪后由意图生成可执行计划。
-- 一条准备记录对应一个意图（plan_id 即意图的 candidate_plan_id）；request_bytes 是创建请求体，重启后据此续跑。
-- state：preparing（排队或执行中，phase 为当前阶段）/ failed（failure_code 为稳定失败原因，授权端业务拒绝时
-- failure_reason 带授权端原因码）/ ready（计划已落库）。failed 与 ready 为终态；重试是用同一批节点发起新的创建。
-- start_when_ready（控制台默认带上）：计划落库后由 worker 按原「创建后立即开始」的流程以创建者身份开始计划
-- （phase=starting）；审批中心开启「主控升级」规则时不自动开始，留给控制台的「开始升级」走审批。自动开始没有执行或
-- 失败时计划仍为 queued，记录照样 ready，start_failure_code 记原因（approval_required / start_refused /
-- 与 failure_code 同一组码），控制台在该计划上提示并可手动开始。
-- 授权端不带原因码的 400/401/403/422 也记 license_rejected，failure_reason 为 http_<状态码>。
-- 认领带租约（claim_token/claim_expires_at），执行中定期续约；进程退出后租约到期即被重新认领续跑。
-- 错误码：头检查 P7003；down 头检查 P7004；记录不变量 P7005。
LOCK TABLE schema_migrations, control_upgrade_grant_intents_096 IN ACCESS EXCLUSIVE MODE;

DO $migration_700_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 699 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 699 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=699 AND
        migration_id='699_billing_bridge_log_request_id' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR to_regclass(current_schema() || '.control_upgrade_create_preparations') IS NOT NULL THEN
        RAISE EXCEPTION 'migration 700 requires the exact verified 699 release head' USING ERRCODE='P7003';
    END IF;
END;
$migration_700_up$;

CREATE TABLE control_upgrade_create_preparations (
    intent_id uuid PRIMARY KEY REFERENCES control_upgrade_grant_intents_096(id) ON DELETE RESTRICT,
    plan_id uuid NOT NULL UNIQUE,
    actor_scope_id uuid NOT NULL,
    actor_user_id uuid NOT NULL,
    node_ids uuid[] NOT NULL CHECK (
        cardinality(node_ids) BETWEEN 1 AND 1000 AND array_position(node_ids, NULL) IS NULL
    ),
    request_bytes bytea NOT NULL CHECK (octet_length(request_bytes) BETWEEN 2 AND 262144),
    start_when_ready boolean NOT NULL,
    state text NOT NULL CHECK (state IN ('preparing','failed','ready')),
    phase text NOT NULL CHECK (phase IN ('queued','issuing','downloading','finalizing','starting','done')),
    failure_code text CHECK (failure_code IN (
        'license_unavailable','license_outcome_unknown','license_rejected','grant_invalid',
        'artifact_download_failed','artifact_invalid','cohort_incompatible','permission_denied',
        'resource_unavailable','internal_error'
    )),
    start_failure_code text CHECK (start_failure_code IN (
        'approval_required','start_refused',
        'license_unavailable','license_outcome_unknown','license_rejected','grant_invalid',
        'artifact_download_failed','artifact_invalid','cohort_incompatible','permission_denied',
        'resource_unavailable','internal_error'
    )),
    failure_reason text CHECK (failure_reason ~ '^[a-z][a-z0-9_]{0,63}$'),
    attempt_count integer NOT NULL CHECK (attempt_count >= 0),
    available_at timestamptz NOT NULL,
    claimed_by text CHECK (char_length(claimed_by) BETWEEN 1 AND 128),
    claim_token uuid,
    claim_expires_at timestamptz,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    CHECK (updated_at >= created_at),
    CHECK ((state='failed') = (failure_code IS NOT NULL)),
    CHECK (failure_reason IS NULL OR failure_code IS NOT DISTINCT FROM 'license_rejected' OR
        start_failure_code IS NOT DISTINCT FROM 'license_rejected'),
    CHECK ((state='ready') = (phase='done')),
    CHECK (phase<>'starting' OR start_when_ready),
    CHECK (start_failure_code IS NULL OR (state='ready' AND start_when_ready)),
    CHECK ((claim_token IS NULL) = (claimed_by IS NULL) AND (claim_token IS NULL) = (claim_expires_at IS NULL)),
    CHECK (state='preparing' OR claim_token IS NULL)
);
CREATE INDEX control_upgrade_create_preparations_due_700_idx
    ON control_upgrade_create_preparations(available_at,created_at,intent_id) WHERE state='preparing';
CREATE INDEX control_upgrade_create_preparations_scope_700_idx
    ON control_upgrade_create_preparations(actor_scope_id,created_at DESC,intent_id DESC)
    WHERE state<>'ready' OR start_failure_code IS NOT NULL;

CREATE FUNCTION validate_control_upgrade_create_preparation_700()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP<>'UPDATE' THEN
        RAISE EXCEPTION 'control upgrade create preparations are durable facts' USING ERRCODE='P7005';
    END IF;
    IF ROW(NEW.intent_id,NEW.plan_id,NEW.actor_scope_id,NEW.actor_user_id,NEW.node_ids,NEW.request_bytes,
           NEW.start_when_ready,NEW.created_at)
       IS DISTINCT FROM ROW(OLD.intent_id,OLD.plan_id,OLD.actor_scope_id,OLD.actor_user_id,OLD.node_ids,
           OLD.request_bytes,OLD.start_when_ready,OLD.created_at) OR NEW.updated_at<OLD.updated_at THEN
        RAISE EXCEPTION 'control upgrade create preparation identity is immutable' USING ERRCODE='P7005';
    END IF;
    IF OLD.state<>'preparing' THEN
        RAISE EXCEPTION 'control upgrade create preparation is terminal' USING ERRCODE='P7005';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER control_upgrade_create_preparation_validate_700
BEFORE UPDATE OR DELETE ON control_upgrade_create_preparations
FOR EACH ROW EXECUTE FUNCTION validate_control_upgrade_create_preparation_700();
CREATE TRIGGER control_upgrade_create_preparation_no_truncate_700
BEFORE TRUNCATE ON control_upgrade_create_preparations
FOR EACH STATEMENT EXECUTE FUNCTION validate_control_upgrade_create_preparation_700();

REVOKE ALL ON TABLE control_upgrade_create_preparations FROM PUBLIC;
REVOKE ALL ON FUNCTION validate_control_upgrade_create_preparation_700() FROM PUBLIC;
