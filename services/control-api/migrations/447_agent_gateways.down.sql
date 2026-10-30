LOCK TABLE schema_migrations, permissions, role_permissions IN ACCESS EXCLUSIVE MODE;

DO $migration_447_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 447 OR
       (SELECT max(version) FROM schema_migrations) <> 447 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=447 AND
        migration_id='447_agent_gateways' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 447 down requires the exact verified migration head' USING ERRCODE='P4471';
    END IF;
    -- A bound Gateway would keep valid certificates the control plane no
    -- longer knows how to revoke: refuse until every Gateway is deleted.
    IF EXISTS (SELECT 1 FROM agent_gateways WHERE status <> 'deleted') THEN
        RAISE EXCEPTION 'migration 447 rollback requires every Agent Gateway to be deleted first' USING ERRCODE='P4472';
    END IF;
END;
$migration_447_down$;

DELETE FROM role_permissions WHERE permission_name = 'system.gateway.manage';
DELETE FROM permissions WHERE name = 'system.gateway.manage';
DROP TABLE agent_gateway_certificates;
DROP TABLE agent_gateway_binding_tokens;
DROP TABLE agent_gateways;
