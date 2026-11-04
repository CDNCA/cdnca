-- 627（前驱 626 node_metric_host_epoch）。
-- "重装此节点"（re_enrollment）或过期后重新注册给同一节点 ID 签发新的 initial 证书后，新机器不持有旧机器
-- 上任何在途部署。旧部署若停在 started/staged 等，要到截止时间 + 1 分钟才由 348 超时收尾；停在 activated/
-- reverting 则永远等不到（只认 agent 上报），一直占着 288/291 的"每节点每范围一个在途部署"索引，新发布报
-- node already has an active deployment。
-- node_deployment_host_replacements 记录"该部署早于节点最近一次注册（证书 certificate_id），按主机已更换收尾"，
-- 是部署 failed 的事实依据（同 348 超时、477 状态拒收）。状态机与事实断言改用 _627 函数（046 函数不改），
-- 只多一条：有该事实时任何非终态可转 failed。触发器名不变（多个历史迁移测试按名停用它们）。
LOCK TABLE schema_migrations, node_deployments, node_deployment_timeouts, node_deployment_status_refusals
    IN ACCESS EXCLUSIVE MODE;

DO $migration_627_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 626 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 626 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=626 AND migration_id='626_node_metric_host_epoch' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR to_regclass(current_schema() || '.node_deployment_host_replacements') IS NOT NULL OR
         to_regprocedure('enforce_node_deployment_state_627()') IS NOT NULL OR
         to_regprocedure('assert_node_deployment_fact_627()') IS NOT NULL OR NOT EXISTS (
        SELECT 1 FROM pg_trigger WHERE tgrelid='node_deployments'::regclass AND
        tgname='node_deployments_state_046' AND tgfoid='enforce_node_deployment_state_046()'::regprocedure
       ) OR NOT EXISTS (
        SELECT 1 FROM pg_trigger WHERE tgrelid='node_deployments'::regclass AND
        tgname='node_deployments_fact_046' AND tgfoid='assert_node_deployment_fact_046()'::regprocedure
       ) OR to_regclass(current_schema() || '.node_deployment_timeouts') IS NULL OR
         to_regclass(current_schema() || '.node_deployment_status_refusals') IS NULL THEN
        RAISE EXCEPTION 'migration 627 requires the verified 626 release head with the 046 deployment triggers'
            USING ERRCODE='P6270';
    END IF;
END;
$migration_627_up$;

CREATE TABLE node_deployment_host_replacements (
    deployment_id uuid NOT NULL,
    attempt integer NOT NULL,
    previous_state text NOT NULL CHECK (previous_state IN (
        'queued', 'delivered', 'agent_queued', 'started', 'staged', 'prechecked', 'activated', 'reverting')),
    reason_code text NOT NULL CHECK (reason_code = 'host_replaced'),
    node_id uuid NOT NULL,
    certificate_id uuid NOT NULL,
    replaced_at timestamptz NOT NULL CHECK (isfinite(replaced_at)),
    PRIMARY KEY (deployment_id, attempt),
    FOREIGN KEY (deployment_id, attempt) REFERENCES node_deployments (id, attempt) ON DELETE CASCADE,
    FOREIGN KEY (certificate_id, node_id) REFERENCES node_certificates (id, node_id) ON DELETE CASCADE
);
CREATE INDEX node_deployment_host_replacements_certificate_627_idx
    ON node_deployment_host_replacements (certificate_id);

-- A fact names the node's newest enrollment certificate, issued after the
-- deployment was created (edgedeployment.CurrentHostDeployment's boundary),
-- and the deployment's state at that moment. Immutable; deleted only with the
-- node (284/616 node_purge_in_progress cascade).
CREATE FUNCTION guard_node_deployment_host_replacement_627() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP <> 'INSERT' THEN
        RAISE EXCEPTION 'node deployment host replacements are immutable' USING ERRCODE='P6274';
    END IF;
    IF NEW.replaced_at > clock_timestamp() OR NOT EXISTS (
        SELECT 1 FROM node_deployments deployment
        JOIN node_certificates enrollment ON enrollment.id = NEW.certificate_id AND enrollment.node_id = deployment.node_id
        WHERE deployment.id = NEW.deployment_id AND deployment.attempt = NEW.attempt
          AND deployment.node_id = NEW.node_id AND deployment.state = NEW.previous_state
          AND enrollment.issuance_kind = 'initial' AND enrollment.issued_at > deployment.created_at
          AND enrollment.issued_at = (SELECT max(newest.issued_at) FROM node_certificates newest
                                      WHERE newest.node_id = deployment.node_id AND newest.issuance_kind = 'initial')
    ) THEN
        RAISE EXCEPTION 'node deployment host replacement does not match a running deployment of a previous host'
            USING ERRCODE='P6273';
    END IF;
    RETURN NEW;
END;
$$;
REVOKE ALL ON FUNCTION guard_node_deployment_host_replacement_627() FROM PUBLIC;
CREATE TRIGGER node_deployment_host_replacements_guard_627
BEFORE INSERT OR UPDATE ON node_deployment_host_replacements
FOR EACH ROW EXECUTE FUNCTION guard_node_deployment_host_replacement_627();
CREATE TRIGGER node_deployment_host_replacements_guard_627_del
BEFORE DELETE ON node_deployment_host_replacements
FOR EACH ROW WHEN (NOT node_purge_in_progress()) EXECUTE FUNCTION guard_node_deployment_host_replacement_627();
CREATE TRIGGER zz_core_fact_truncate_guard_627
BEFORE TRUNCATE ON node_deployment_host_replacements
FOR EACH STATEMENT EXECUTE FUNCTION prevent_core_fact_truncate_045();

REVOKE ALL ON node_deployment_host_replacements FROM PUBLIC;
GRANT SELECT, INSERT ON node_deployment_host_replacements TO cdnca_control_app, cdnca_control_runtime;

CREATE FUNCTION enforce_node_deployment_state_627() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF OLD.state = NEW.state THEN
        RETURN NEW;
    END IF;
    -- 627: a deployment of a previous host of the node ends as failed.
    IF NEW.state = 'failed' AND EXISTS (
        SELECT 1 FROM node_deployment_host_replacements replaced
        WHERE replaced.deployment_id = NEW.id AND replaced.attempt = NEW.attempt AND replaced.previous_state = OLD.state
    ) THEN
        RETURN NEW;
    END IF;
    IF OLD.state = 'queued' AND NEW.state IN ('delivered', 'cancelled') THEN
        RETURN NEW;
    END IF;
    IF OLD.state = 'queued' AND NEW.state = 'failed' AND EXISTS (
        SELECT 1 FROM node_deployment_timeouts timeout
        WHERE timeout.deployment_id = NEW.id AND timeout.attempt = NEW.attempt AND timeout.previous_state = 'queued'
    ) THEN
        RETURN NEW;
    END IF;
    IF OLD.state = 'queued' AND NEW.state = 'failed' AND EXISTS (
        SELECT 1 FROM node_deployment_status_refusals refusal
        WHERE refusal.deployment_id = NEW.id AND refusal.attempt = NEW.attempt AND refusal.previous_state = 'queued'
    ) THEN
        RETURN NEW;
    END IF;
    IF OLD.state = 'delivered' AND NEW.state IN ('agent_queued', 'staged', 'failed') THEN
        RETURN NEW;
    END IF;
    IF OLD.state = 'agent_queued' AND NEW.state IN ('started', 'failed') THEN
        RETURN NEW;
    END IF;
    IF OLD.state = 'started' AND NEW.state IN ('staged', 'failed') THEN
        RETURN NEW;
    END IF;
    IF OLD.state = 'staged' AND NEW.state IN ('prechecked', 'failed') THEN
        RETURN NEW;
    END IF;
    IF OLD.state = 'prechecked' AND NEW.state IN ('activated', 'reverting', 'failed') THEN
        RETURN NEW;
    END IF;
    IF OLD.state = 'activated' AND NEW.state IN ('healthy', 'reverting') THEN
        RETURN NEW;
    END IF;
    IF OLD.state = 'reverting' AND NEW.state IN ('reverted', 'failed', 'rollback_failed') THEN
        RETURN NEW;
    END IF;
    RAISE EXCEPTION 'invalid node deployment state transition' USING ERRCODE = 'P0001';
END;
$$;

CREATE FUNCTION assert_node_deployment_fact_627()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    rollout_contract smallint;
BEGIN
    SELECT contract_version INTO rollout_contract FROM rollouts WHERE id = NEW.rollout_id;
    IF rollout_contract <> 1 THEN
        RETURN NULL;
    END IF;
    IF TG_OP = 'INSERT' AND NEW.attempt = 1 THEN
        RETURN NULL;
    END IF;
    IF TG_OP = 'INSERT' THEN
        IF NOT EXISTS (
            SELECT 1
            FROM edge_rollout_write_requests request
            JOIN rollouts rollout ON rollout.id = request.rollout_id
            JOIN audit_events event
              ON event.scope_id = request.actor_scope_id
             AND event.actor_user_id = request.actor_user_id
             AND event.action = request.operation
             AND event.resource_type = 'edge_rollout'
             AND event.resource_id = request.rollout_id::text
             AND event.request_id = request.request_id::text
             AND event.result = 'success'
            WHERE request.rollout_id = NEW.rollout_id
              AND request.operation = 'edge_rollout.retry'
              AND request.expected_revision = rollout.revision - 1
              AND request.completed_at IS NOT NULL
        ) THEN
            RAISE EXCEPTION 'deployment retry requires a completed rollout command' USING ERRCODE = 'P0001';
        END IF;
        RETURN NULL;
    END IF;
    IF NEW.state = 'cancelled' THEN
        IF NOT EXISTS (
            SELECT 1
            FROM edge_rollout_write_requests request
            JOIN rollouts rollout ON rollout.id = request.rollout_id
            JOIN audit_events event
              ON event.scope_id = request.actor_scope_id
             AND event.actor_user_id = request.actor_user_id
             AND event.action = request.operation
             AND event.resource_type = 'edge_rollout'
             AND event.resource_id = request.rollout_id::text
             AND event.request_id = request.request_id::text
             AND event.result = 'success'
            WHERE request.rollout_id = NEW.rollout_id
              AND request.operation = 'edge_rollout.cancel'
              AND request.expected_revision = rollout.revision - 1
              AND request.completed_at IS NOT NULL
        ) THEN
            RAISE EXCEPTION 'deployment cancellation requires a completed rollout command' USING ERRCODE = 'P0001';
        END IF;
        RETURN NULL;
    END IF;
    IF NEW.state = 'failed' AND EXISTS (
        SELECT 1 FROM node_deployment_timeouts timeout
        WHERE timeout.deployment_id = NEW.id AND timeout.attempt = NEW.attempt
          AND timeout.previous_state = OLD.state
    ) THEN
        RETURN NULL;
    END IF;
    IF NEW.state = 'failed' AND EXISTS (
        SELECT 1 FROM node_deployment_status_refusals refusal
        WHERE refusal.deployment_id = NEW.id AND refusal.attempt = NEW.attempt
          AND refusal.previous_state = OLD.state
    ) THEN
        RETURN NULL;
    END IF;
    IF NEW.state = 'failed' AND EXISTS (
        SELECT 1 FROM node_deployment_host_replacements replaced
        WHERE replaced.deployment_id = NEW.id AND replaced.attempt = NEW.attempt
          AND replaced.previous_state = OLD.state
    ) THEN
        RETURN NULL;
    END IF;
    IF OLD.state IS DISTINCT FROM NEW.state AND NOT EXISTS (
        SELECT 1 FROM deployment_status_events event
        WHERE event.deployment_id = NEW.id AND event.attempt = NEW.attempt AND event.state = NEW.state
    ) THEN
        RAISE EXCEPTION 'deployment state requires a matching agent status event' USING ERRCODE = 'P0001';
    END IF;
    RETURN NULL;
END;
$$;

REVOKE ALL ON FUNCTION enforce_node_deployment_state_627() FROM PUBLIC;
REVOKE ALL ON FUNCTION assert_node_deployment_fact_627() FROM PUBLIC;

-- Same trigger names and timing (046), the 627 functions.
DROP TRIGGER node_deployments_state_046 ON node_deployments;
CREATE TRIGGER node_deployments_state_046
BEFORE UPDATE OF state ON node_deployments
FOR EACH ROW EXECUTE FUNCTION enforce_node_deployment_state_627();
DROP TRIGGER node_deployments_fact_046 ON node_deployments;
CREATE CONSTRAINT TRIGGER node_deployments_fact_046
AFTER INSERT OR UPDATE OF state ON node_deployments
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION assert_node_deployment_fact_627();
