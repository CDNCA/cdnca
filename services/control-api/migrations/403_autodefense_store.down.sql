LOCK TABLE schema_migrations, autodefense_platform_settings, autodefense_sites, autodefense_port_groups,
    autodefense_site_node_states, autodefense_events, autodefense_signatures, autodefense_mitigations,
    autodefense_verdict_releases, autodefense_false_positives, autodefense_report_receipts IN ACCESS EXCLUSIVE MODE;

DO $migration_403_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 403 OR
       (SELECT max(version) FROM schema_migrations) <> 403 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=403 AND
        migration_id='403_autodefense_store' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 403 down requires the exact verified migration head' USING ERRCODE='P4031';
    END IF;
    -- Settings a person chose and mitigations in force are durable facts.
    IF EXISTS (SELECT 1 FROM autodefense_sites) OR EXISTS (SELECT 1 FROM autodefense_port_groups) OR
       EXISTS (SELECT 1 FROM autodefense_mitigations WHERE released_at IS NULL) THEN
        RAISE EXCEPTION 'migration 403 rollback would drop smart auto defense settings or mitigations in force'
            USING ERRCODE='P4032';
    END IF;
END;
$migration_403_down$;

DROP TABLE autodefense_report_receipts;
DROP TABLE autodefense_false_positives;
DROP TABLE autodefense_verdict_releases;
DROP TABLE autodefense_mitigations;
DROP TABLE autodefense_signatures;
DROP TABLE autodefense_events;
DROP TABLE autodefense_site_node_states;
DROP TABLE autodefense_port_groups;
DROP TABLE autodefense_sites;
DROP TABLE autodefense_platform_settings;
