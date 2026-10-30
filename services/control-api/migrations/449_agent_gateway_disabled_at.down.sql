LOCK TABLE schema_migrations, agent_gateways IN ACCESS EXCLUSIVE MODE;

DO $migration_449_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 449 OR
       (SELECT max(version) FROM schema_migrations) <> 449 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=449 AND
        migration_id='449_agent_gateway_disabled_at' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 449 down requires the exact verified migration head' USING ERRCODE='P4491';
    END IF;
END;
$migration_449_down$;

-- 448 只看 status：停用网关仍是 disabled，丢掉的只是停用时刻（宽限期按 448 语义不再存在）。
ALTER TABLE agent_gateways DROP CONSTRAINT agent_gateways_disabled_449_ck;
ALTER TABLE agent_gateways DROP COLUMN disabled_at;
