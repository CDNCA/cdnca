LOCK TABLE schema_migrations, edge_system_republication_heads, edge_system_republication_attempts,
    theme_error_page_republications IN ACCESS EXCLUSIVE MODE;

DO $migration_365_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 365 OR
       (SELECT max(version) FROM schema_migrations) <> 365 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=365 AND
        migration_id='365_theme_error_page_republication' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 365 down requires the exact verified migration head' USING ERRCODE='P3651';
    END IF;
    -- Republication progress and attempts are durable facts; the narrower
    -- checks cannot hold them.
    IF EXISTS (SELECT 1 FROM theme_error_page_republications) OR
       EXISTS (SELECT 1 FROM edge_system_republication_heads
        WHERE 'theme_activation' = ANY(triggers) OR cardinality(triggers) > 8) OR
       EXISTS (SELECT 1 FROM edge_system_republication_attempts
        WHERE 'theme_activation' = ANY(triggers) OR cardinality(triggers) > 8 OR error_page_rollout_id IS NOT NULL) THEN
        RAISE EXCEPTION 'migration 365 rollback would orphan theme error page republication facts' USING ERRCODE='P3651';
    END IF;
END;
$migration_365_down$;

-- Error page rollouts stay valid facts: 046's guard runs on insert and update
-- only, and the error page branch is removed with the rest of 365.
DO $migration_365_down_contract$
DECLARE
    definition text;
    start_marker text := E'        IF NEW.action = ''apply'' AND EXISTS (\n            SELECT 1 FROM configuration_artifacts artifact\n';
    end_marker text := E'            RETURN NULL;\n        END IF;\n        RAISE EXCEPTION ''contract rollout requires an audited publication or security activation fact''';
    head integer;
    tail integer;
BEGIN
    SELECT pg_get_functiondef('assert_rollout_contract_046()'::regprocedure) INTO definition;
    head := strpos(definition, start_marker);
    tail := strpos(definition, end_marker);
    IF head = 0 OR tail < head THEN
        RAISE EXCEPTION 'migration 365 down cannot find the error page rollout contract branch' USING ERRCODE='P3653';
    END IF;
    EXECUTE substr(definition, 1, head - 1) ||
        substr(definition, tail + length(E'            RETURN NULL;\n        END IF;\n'));
END;
$migration_365_down_contract$;

ALTER TABLE edge_system_republication_attempts
    DROP CONSTRAINT edge_system_republication_attempts_check,
    DROP COLUMN error_page_rollout_id,
    ADD CONSTRAINT edge_system_republication_attempts_check CHECK ((outcome = 'published') = (publication_id IS NOT NULL)),
    DROP CONSTRAINT edge_system_republication_attempts_triggers_check,
    ADD CONSTRAINT edge_system_republication_attempts_triggers_check CHECK (cardinality(triggers) BETWEEN 1 AND 9);

ALTER TABLE edge_system_republication_heads
    DROP CONSTRAINT edge_system_republication_heads_triggers_check,
    ADD CONSTRAINT edge_system_republication_heads_triggers_check CHECK (cardinality(triggers) BETWEEN 1 AND 9 AND
        triggers <@ ARRAY['node_capability', 'traffic_enforcement', 'line_group', 'node_sync', 'domain_ownership',
            'secondary_verification', 'rule_catalog', 'challenge_delivery', 'module_entitlement']::text[]);

DROP TABLE theme_error_page_republications;
