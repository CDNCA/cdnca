LOCK TABLE schema_migrations, edge_system_republication_heads, edge_system_revision_segments
    IN ACCESS EXCLUSIVE MODE;

DO $migration_652_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 652 OR
       (SELECT max(version) FROM schema_migrations) <> 652 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=652 AND
        migration_id='652_security_string_sets' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 652 down requires the exact verified migration head' USING ERRCODE='P6532';
    END IF;
    -- A rule referencing a set, or a pending string_set republication,
    -- cannot be expressed by the 651 schema.
    IF EXISTS (SELECT 1 FROM security_string_sets WHERE deleted_at IS NULL) OR
       EXISTS (SELECT 1 FROM edge_system_republication_heads WHERE 'string_set' = ANY(triggers)) OR
       EXISTS (SELECT 1 FROM edge_system_republication_attempts WHERE 'string_set' = ANY(triggers)) OR
       EXISTS (SELECT 1 FROM edge_system_revision_segments WHERE source = 'string_set') THEN
        RAISE EXCEPTION 'migration 652 rollback would drop string sets' USING ERRCODE='P6533';
    END IF;
END;
$migration_652_down$;

ALTER TABLE edge_system_revision_segments
    DROP CONSTRAINT edge_system_revision_segments_source_check,
    ADD CONSTRAINT edge_system_revision_segments_source_check CHECK (source IN ('node_capability', 'traffic_enforcement',
        'line_group', 'node_sync', 'domain_ownership', 'secondary_verification', 'rule_catalog', 'challenge_delivery',
        'module_entitlement', 'account_suspension', 'node_networks', 'error_page_published', 'origin_auth_published',
        'origin_failover', 'market_limits', 'ip_list', 'attack_escalation', 'package_expiry', 'node_storage',
        'package_suspension', 'certificate_renewal', 'security_hold'));
ALTER TABLE edge_system_republication_attempts
    DROP CONSTRAINT edge_system_republication_attempts_triggers_check,
    ADD CONSTRAINT edge_system_republication_attempts_triggers_check CHECK (cardinality(triggers) BETWEEN 1 AND 23);
ALTER TABLE edge_system_republication_heads
    DROP CONSTRAINT edge_system_republication_heads_triggers_check,
    ADD CONSTRAINT edge_system_republication_heads_triggers_check CHECK (cardinality(triggers) BETWEEN 1 AND 23 AND
        triggers <@ ARRAY['node_capability', 'traffic_enforcement', 'line_group', 'node_sync', 'domain_ownership',
            'secondary_verification', 'rule_catalog', 'challenge_delivery', 'module_entitlement',
            'theme_activation', 'account_suspension', 'node_networks', 'error_page_published',
            'origin_auth_published', 'origin_failover', 'market_limits', 'ip_list', 'attack_escalation',
            'package_expiry', 'node_storage', 'package_suspension', 'certificate_renewal',
            'security_hold']::text[]);
DROP TABLE security_string_set_write_requests;
DROP TABLE security_string_set_revisions;
DROP TRIGGER security_string_sets_fixed_mode ON security_string_sets;
DROP TABLE security_string_sets;
DROP FUNCTION security_string_sets_fixed_mode();
