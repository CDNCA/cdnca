LOCK TABLE schema_migrations, edge_system_republication_heads, edge_system_republication_attempts,
    edge_system_revision_segments IN ACCESS EXCLUSIVE MODE;

DO $migration_416_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 415 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 415 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=415 AND
        migration_id='415_autodefense_federation' AND
        checksum_sha256='19630777fa57cb6c4ea973bc88db4b0300c7b665c92725056aaf0276cf34927b' AND
        down_checksum_sha256='4d3590d7fd3ce6ab961c1a7406b71657fa370973de76f0ef0861c24459da7b7e' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) THEN
        RAISE EXCEPTION 'migration 416 requires the exact verified 415 release head' USING ERRCODE='P4160';
    END IF;
END;
$migration_416_up$;

-- 416 (r136 D13-b2 1, placeholder number: integration head 415 + 1,
-- renumbered on merge). A dynamic routing (site_runtime 9) node reads a
-- site's error pages and origin authentication from its site object, which
-- the control plane builds at publication time from the scope's latest error
-- page snapshot and origin auth publication. Publishing either changes no
-- tenant row the edge publication compiles, so the scope's nodes kept the old
-- facts until the next site publication. Two new system triggers,
-- error_page_published and origin_auth_published, republish the scope
-- through the system channel (debounced content triggers). Each check
-- extends 400's by these values (cardinality 12 -> 14).
ALTER TABLE edge_system_republication_heads
    DROP CONSTRAINT edge_system_republication_heads_triggers_check,
    ADD CONSTRAINT edge_system_republication_heads_triggers_check CHECK (cardinality(triggers) BETWEEN 1 AND 14 AND
        triggers <@ ARRAY['node_capability', 'traffic_enforcement', 'line_group', 'node_sync', 'domain_ownership',
            'secondary_verification', 'rule_catalog', 'challenge_delivery', 'module_entitlement',
            'theme_activation', 'account_suspension', 'node_networks', 'error_page_published',
            'origin_auth_published']::text[]);
ALTER TABLE edge_system_republication_attempts
    DROP CONSTRAINT edge_system_republication_attempts_triggers_check,
    ADD CONSTRAINT edge_system_republication_attempts_triggers_check CHECK (cardinality(triggers) BETWEEN 1 AND 14);
ALTER TABLE edge_system_revision_segments
    DROP CONSTRAINT edge_system_revision_segments_source_check,
    ADD CONSTRAINT edge_system_revision_segments_source_check CHECK (source IN ('node_capability', 'traffic_enforcement',
        'line_group', 'node_sync', 'domain_ownership', 'secondary_verification', 'rule_catalog', 'challenge_delivery',
        'module_entitlement', 'account_suspension', 'node_networks', 'error_page_published', 'origin_auth_published'));
