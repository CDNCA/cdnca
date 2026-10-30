-- 582 回退：删冻结拒收标记表。回到 579 后这些部署按普通失败显示（节点回执原文仍在 deployment_status_events）。
LOCK TABLE schema_migrations, node_deployment_frozen_refusals IN ACCESS EXCLUSIVE MODE;

DO $migration_582_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 582 OR
       (SELECT max(version) FROM schema_migrations) <> 582 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=582 AND
        migration_id='582_node_deployment_frozen_refusals' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 582 down requires the exact verified migration head' USING ERRCODE='P5823';
    END IF;
END;
$migration_582_down$;

DROP TABLE node_deployment_frozen_refusals;
DROP FUNCTION guard_node_deployment_frozen_refusal_582();
