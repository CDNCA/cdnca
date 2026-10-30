LOCK TABLE schema_migrations, node_line_groups IN ACCESS EXCLUSIVE MODE;

DO $migration_427_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 427 OR
       (SELECT max(version) FROM schema_migrations) <> 427 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=427 AND
        migration_id='427_market_supply_line_groups' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 427 down requires the exact verified migration head' USING ERRCODE='P4273';
    END IF;
    -- Dropping the column would turn hidden supply groups into ordinary
    -- line groups every tenant package could pick: refuse instead.
    IF EXISTS (SELECT 1 FROM node_line_groups WHERE purpose = 'market_supply') THEN
        RAISE EXCEPTION 'migration 427 rollback would expose market supply line groups' USING ERRCODE='P4274';
    END IF;
END;
$migration_427_down$;

DROP INDEX node_line_groups_market_supply_427_idx;
DROP TRIGGER node_line_groups_purpose_427 ON node_line_groups;
DROP FUNCTION assert_node_line_group_purpose_427();
ALTER TABLE node_line_groups
    DROP CONSTRAINT node_line_groups_purpose_427_check,
    DROP COLUMN purpose;
