LOCK TABLE schema_migrations, cc_reference_matchers, cc_reference_filters IN ACCESS EXCLUSIVE MODE;

DO $migration_242_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 241 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 241 OR
       NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version = 241 AND migration_id = '241_l2_topology_management' AND
              checksum_sha256 = 'da19054e99340bce06c1bf8b64b99bb986ed05ef951085e8c8936b871308ee63' AND
              down_checksum_sha256 = '227520f20eb7bdbd9e0a939d101cd4d43511a3d4a4839e0aceee6d9ef2fa053d' AND
              integrity_state = 'verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 242 requires the exact verified 241 release head'
            USING ERRCODE = 'P2420';
    END IF;
END;
$migration_242_up$;

ALTER TABLE cc_reference_matchers
    ADD COLUMN system_rule boolean NOT NULL DEFAULT false,
    ADD COLUMN system_rule_id text NOT NULL DEFAULT ''
        CHECK (system_rule_id=btrim(system_rule_id) AND char_length(system_rule_id) <= 32),
    ADD COLUMN system_rule_sort integer NOT NULL DEFAULT 0
        CHECK (system_rule_sort >= 0 AND system_rule_sort <= 10000),
    ADD COLUMN system_rule_key text NOT NULL DEFAULT ''
        CHECK (system_rule_key=btrim(system_rule_key) AND char_length(system_rule_key) <= 128);
ALTER TABLE cc_reference_filters
    ADD COLUMN system_rule boolean NOT NULL DEFAULT false,
    ADD COLUMN system_rule_id text NOT NULL DEFAULT ''
        CHECK (system_rule_id=btrim(system_rule_id) AND char_length(system_rule_id) <= 32),
    ADD COLUMN system_rule_sort integer NOT NULL DEFAULT 0
        CHECK (system_rule_sort >= 0 AND system_rule_sort <= 10000),
    ADD COLUMN system_rule_key text NOT NULL DEFAULT ''
        CHECK (system_rule_key=btrim(system_rule_key) AND char_length(system_rule_key) <= 128);

CREATE INDEX cc_reference_matchers_system_rule_idx
    ON cc_reference_matchers(scope_id,system_rule,system_rule_id,system_rule_key)
    WHERE deleted_at IS NULL AND system_rule;
CREATE INDEX cc_reference_filters_system_rule_idx
    ON cc_reference_filters(scope_id,system_rule,system_rule_id,system_rule_key)
    WHERE deleted_at IS NULL AND system_rule;

DROP INDEX cc_reference_matchers_scope_name_active_idx;
DROP INDEX cc_reference_filters_scope_name_active_idx;
CREATE UNIQUE INDEX cc_reference_matchers_scope_name_kind_active_idx
    ON cc_reference_matchers(scope_id,lower(name),system_rule) WHERE deleted_at IS NULL;
CREATE UNIQUE INDEX cc_reference_filters_scope_name_kind_active_idx
    ON cc_reference_filters(scope_id,lower(name),system_rule) WHERE deleted_at IS NULL;
CREATE UNIQUE INDEX cc_reference_matchers_scope_system_key_active_idx
    ON cc_reference_matchers(scope_id,system_rule_key) WHERE deleted_at IS NULL AND system_rule AND system_rule_key <> '';
CREATE UNIQUE INDEX cc_reference_filters_scope_system_key_active_idx
    ON cc_reference_filters(scope_id,system_rule_key) WHERE deleted_at IS NULL AND system_rule AND system_rule_key <> '';
