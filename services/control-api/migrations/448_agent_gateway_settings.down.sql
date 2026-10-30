LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;

DO $migration_448_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 448 OR
       (SELECT max(version) FROM schema_migrations) <> 448 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=448 AND
        migration_id='448_agent_gateway_settings' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 448 down requires the exact verified migration head' USING ERRCODE='P4481';
    END IF;
END;
$migration_448_down$;

-- 434 reads agent_gateways.source_ip again: the binding address of each
-- Gateway is still there (the allow-list edits are dropped).
DROP TABLE agent_gateway_entrypoints;
DROP TABLE agent_gateway_allowed_ips;
DROP TABLE agent_gateway_trusted_ranges;
