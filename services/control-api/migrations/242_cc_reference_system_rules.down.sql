LOCK TABLE schema_migrations, cc_reference_matchers, cc_reference_filters IN ACCESS EXCLUSIVE MODE;

DO $migration_242_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 242 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 242 OR
       NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version = 242 AND migration_id = '242_cc_reference_system_rules' AND
              integrity_state = 'verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 242 rollback requires the exact verified 242 release head'
            USING ERRCODE = 'P2421';
    END IF;
END;
$migration_242_down$;

DROP INDEX cc_reference_matchers_system_rule_idx;
DROP INDEX cc_reference_filters_system_rule_idx;
DROP INDEX cc_reference_matchers_scope_system_key_active_idx;
DROP INDEX cc_reference_filters_scope_system_key_active_idx;
DROP INDEX cc_reference_matchers_scope_name_kind_active_idx;
DROP INDEX cc_reference_filters_scope_name_kind_active_idx;
CREATE UNIQUE INDEX cc_reference_matchers_scope_name_active_idx
    ON cc_reference_matchers(scope_id,lower(name)) WHERE deleted_at IS NULL;
CREATE UNIQUE INDEX cc_reference_filters_scope_name_active_idx
    ON cc_reference_filters(scope_id,lower(name)) WHERE deleted_at IS NULL;
ALTER TABLE cc_reference_matchers DROP COLUMN system_rule_key, DROP COLUMN system_rule_sort, DROP COLUMN system_rule_id, DROP COLUMN system_rule;
ALTER TABLE cc_reference_filters DROP COLUMN system_rule_key, DROP COLUMN system_rule_sort, DROP COLUMN system_rule_id, DROP COLUMN system_rule;
