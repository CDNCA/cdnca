LOCK TABLE schema_migrations,cc_coordination_releases,cc_coordination_actions,
    cc_coordination_states,cc_coordination_facts,cc_coordination_setting_targets,
    cc_coordination_settings IN ACCESS EXCLUSIVE MODE;

DO $migration_127$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 127 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 127 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version=127 AND migration_id='127_cc_coordination'
          AND checksum_sha256='8098d631b3dd7db67be67de8d1e3d0faed61e1d4c0d647c5cea86a2f6217b713'
          AND integrity_state='verified' AND metadata_recorded_at IS NOT NULL
          AND applied_at IS NOT NULL
    ) THEN
        RAISE EXCEPTION 'migration 127 rollback requires the exact verified 127 head'
            USING ERRCODE='P1270';
    END IF;
    IF EXISTS (SELECT 1 FROM cc_coordination_releases) OR
       EXISTS (SELECT 1 FROM cc_coordination_actions) OR
       EXISTS (SELECT 1 FROM cc_coordination_states) OR
       EXISTS (SELECT 1 FROM cc_coordination_facts) OR
       EXISTS (SELECT 1 FROM cc_coordination_setting_targets) OR
       EXISTS (SELECT 1 FROM cc_coordination_settings)
    THEN
        RAISE EXCEPTION 'migration 127 rollback would discard durable CC coordination facts'
            USING ERRCODE='P1275';
    END IF;
END;
$migration_127$;

DROP TRIGGER cc_coordination_releases_no_truncate_127 ON cc_coordination_releases;
DROP TRIGGER cc_coordination_releases_protected_127 ON cc_coordination_releases;
DROP TRIGGER cc_coordination_actions_no_truncate_127 ON cc_coordination_actions;
DROP TRIGGER cc_coordination_actions_protected_127 ON cc_coordination_actions;
DROP TRIGGER cc_coordination_states_no_truncate_127 ON cc_coordination_states;
DROP TRIGGER cc_coordination_states_protected_127 ON cc_coordination_states;
DROP TRIGGER cc_coordination_facts_no_truncate_127 ON cc_coordination_facts;
DROP TRIGGER cc_coordination_facts_immutable_127 ON cc_coordination_facts;
DROP TRIGGER cc_coordination_targets_no_truncate_127 ON cc_coordination_setting_targets;
DROP TRIGGER cc_coordination_targets_immutable_127 ON cc_coordination_setting_targets;
DROP TRIGGER cc_coordination_settings_no_truncate_127 ON cc_coordination_settings;
DROP TRIGGER cc_coordination_settings_immutable_127 ON cc_coordination_settings;

DROP TABLE cc_coordination_releases;
DROP TABLE cc_coordination_actions;
DROP TABLE cc_coordination_states;
DROP TABLE cc_coordination_facts;
DROP TABLE cc_coordination_setting_targets;
DROP TABLE cc_coordination_settings;

DROP FUNCTION protect_cc_coordination_release_127();
DROP FUNCTION protect_cc_coordination_action_127();
DROP FUNCTION protect_cc_coordination_state_127();
DROP FUNCTION protect_cc_coordination_immutable_127();
