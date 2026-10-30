-- 582（fix-stoppolicy2，占位号，合入时主会话按集成头连号）：冻结节点拒收的发布“冻结中待补发”。
-- 用户 10-28 00:1x：票据过期的节点冻结（继续服务已有配置，拒绝新发布），回 FAILED + installation_frozen。
-- 这类拒收在主控记一行：不算失败（灰度失败阈值、自动发布结果、手动重试、配置同步禁用都不计），
-- 节点续票解冻后由系统重新发布通道（node_sync 触发）补发一次，redelivered_at 记补发时间（清标，只写一次）。
-- 前驱 581（plugin_installation_resume），守卫钉 581 校验和。
LOCK TABLE schema_migrations, node_deployments IN ACCESS EXCLUSIVE MODE;

DO $migration_582_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 581 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 581 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=581 AND
        migration_id='581_plugin_installation_resume' AND
        checksum_sha256='4efdce42b601f8c8918c0aa28d2ef8d9925466bac2bfbfab5e994b58ae8386e1' AND
        down_checksum_sha256='8343058a9922b5cad7b570a9aef60889100285ce2ba2bbadb1a6b7989d4b551c' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR to_regclass(current_schema() || '.node_deployment_frozen_refusals') IS NOT NULL THEN
        RAISE EXCEPTION 'migration 582 requires the exact verified 581 release head' USING ERRCODE='P5820';
    END IF;
END;
$migration_582_up$;

CREATE TABLE node_deployment_frozen_refusals (
    deployment_id uuid NOT NULL,
    attempt integer NOT NULL,
    node_id uuid NOT NULL,
    configuration_scope_id uuid NOT NULL,
    refused_at timestamptz NOT NULL,
    redelivered_at timestamptz CHECK (redelivered_at IS NULL OR redelivered_at >= refused_at),
    PRIMARY KEY (deployment_id, attempt),
    FOREIGN KEY (deployment_id, attempt) REFERENCES node_deployments (id, attempt) ON DELETE CASCADE
);

-- 补发器按节点找待补发的作用域。
CREATE INDEX node_deployment_frozen_refusals_pending_582_idx
    ON node_deployment_frozen_refusals (node_id, configuration_scope_id) WHERE redelivered_at IS NULL;

-- 只记失败的 APPLY 本身；之后只允许把 redelivered_at 从空写成时间一次（重复解冻幂等）。
CREATE FUNCTION guard_node_deployment_frozen_refusal_582() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.redelivered_at IS NOT NULL OR NEW.refused_at > clock_timestamp() OR NOT EXISTS (
            SELECT 1 FROM node_deployments deployment
            WHERE deployment.id = NEW.deployment_id AND deployment.attempt = NEW.attempt
              AND deployment.node_id = NEW.node_id AND deployment.configuration_scope_id = NEW.configuration_scope_id
              AND deployment.action = 'apply' AND deployment.state = 'failed'
        ) THEN
            RAISE EXCEPTION 'frozen refusal does not match a failed apply' USING ERRCODE='P5821';
        END IF;
        RETURN NEW;
    END IF;
    IF OLD.redelivered_at IS NOT NULL OR NEW.redelivered_at IS NULL OR
       (NEW.deployment_id, NEW.attempt, NEW.node_id, NEW.configuration_scope_id, NEW.refused_at) IS DISTINCT FROM
       (OLD.deployment_id, OLD.attempt, OLD.node_id, OLD.configuration_scope_id, OLD.refused_at) THEN
        RAISE EXCEPTION 'frozen refusal is only marked redelivered once' USING ERRCODE='P5822';
    END IF;
    RETURN NEW;
END;
$$;
REVOKE ALL ON FUNCTION guard_node_deployment_frozen_refusal_582() FROM PUBLIC;

CREATE TRIGGER node_deployment_frozen_refusals_guard_582
BEFORE INSERT OR UPDATE ON node_deployment_frozen_refusals
FOR EACH ROW EXECUTE FUNCTION guard_node_deployment_frozen_refusal_582();

GRANT SELECT, INSERT, UPDATE ON node_deployment_frozen_refusals TO cdnca_control_app, cdnca_control_runtime;
