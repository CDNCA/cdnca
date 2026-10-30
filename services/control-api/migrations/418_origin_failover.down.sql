LOCK TABLE schema_migrations, site_origin_pools, site_origins, edge_system_republication_heads,
    edge_system_republication_attempts, edge_system_revision_segments, notification_event_policies,
    notification_templates IN ACCESS EXCLUSIVE MODE;

DO $migration_418_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 418 OR
       (SELECT max(version) FROM schema_migrations) <> 418 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=418 AND
        migration_id='418_origin_failover' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 418 down requires the exact verified migration head' USING ERRCODE='P4181';
    END IF;
    -- A pool with level 2+ origins or republication facts of a switch cannot
    -- be expressed by the 417 schema.
    IF EXISTS (SELECT 1 FROM site_origins WHERE level > 1) OR
       EXISTS (SELECT 1 FROM edge_system_republication_heads WHERE 'origin_failover' = ANY(triggers)) OR
       EXISTS (SELECT 1 FROM edge_system_republication_attempts WHERE 'origin_failover' = ANY(triggers)) OR
       EXISTS (SELECT 1 FROM edge_system_revision_segments WHERE source = 'origin_failover') OR
       EXISTS (SELECT 1 FROM notification_events WHERE event_type IN ('site.origin.failover', 'site.origin.recovered')) THEN
        RAISE EXCEPTION 'migration 418 rollback would drop origin failover facts' USING ERRCODE='P4182';
    END IF;
END;
$migration_418_down$;

ALTER TABLE notification_templates DISABLE TRIGGER notification_templates_immutable;
DELETE FROM notification_templates WHERE template_id IN ('site.origin.failover.zh-cn', 'site.origin.recovered.zh-cn');
ALTER TABLE notification_templates ENABLE TRIGGER notification_templates_immutable;
DELETE FROM notification_event_policies WHERE event_type IN ('site.origin.failover', 'site.origin.recovered');

ALTER TABLE edge_system_revision_segments
    DROP CONSTRAINT edge_system_revision_segments_source_check,
    ADD CONSTRAINT edge_system_revision_segments_source_check CHECK (source IN ('node_capability', 'traffic_enforcement',
        'line_group', 'node_sync', 'domain_ownership', 'secondary_verification', 'rule_catalog', 'challenge_delivery',
        'module_entitlement', 'account_suspension', 'node_networks', 'error_page_published', 'origin_auth_published'));
ALTER TABLE edge_system_republication_attempts
    DROP CONSTRAINT edge_system_republication_attempts_triggers_check,
    ADD CONSTRAINT edge_system_republication_attempts_triggers_check CHECK (cardinality(triggers) BETWEEN 1 AND 14);
ALTER TABLE edge_system_republication_heads
    DROP CONSTRAINT edge_system_republication_heads_triggers_check,
    ADD CONSTRAINT edge_system_republication_heads_triggers_check CHECK (cardinality(triggers) BETWEEN 1 AND 14 AND
        triggers <@ ARRAY['node_capability', 'traffic_enforcement', 'line_group', 'node_sync', 'domain_ownership',
            'secondary_verification', 'rule_catalog', 'challenge_delivery', 'module_entitlement',
            'theme_activation', 'account_suspension', 'node_networks', 'error_page_published',
            'origin_auth_published']::text[]);

DROP TABLE site_origin_probe_states;
DROP TABLE site_origin_failover_states;

ALTER TABLE site_origins ADD COLUMN backup boolean NOT NULL DEFAULT false;
UPDATE site_origins SET backup = true WHERE level > 0;
SET CONSTRAINTS ALL IMMEDIATE;
SET CONSTRAINTS ALL DEFERRED;

CREATE OR REPLACE FUNCTION validate_site_origin_pool(target_site_id uuid) RETURNS void
LANGUAGE plpgsql AS $$
DECLARE
    pool_failover smallint;
    origin_count integer;
    enabled_count integer;
    primary_count integer;
BEGIN
    IF NOT EXISTS (SELECT 1 FROM sites WHERE id = target_site_id) THEN
        RETURN;
    END IF;

    SELECT failover_tries
    INTO pool_failover
    FROM site_origin_pools
    WHERE site_id = target_site_id;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'site origin pool is required for site %', target_site_id
            USING ERRCODE = '23514';
    END IF;

    SELECT count(*), count(*) FILTER (WHERE enabled), count(*) FILTER (WHERE enabled AND NOT backup)
    INTO origin_count, enabled_count, primary_count
    FROM site_origins
    WHERE site_id = target_site_id;

    IF origin_count < 1 OR origin_count > 32 OR enabled_count < 1 OR primary_count < 1 OR
       pool_failover > enabled_count THEN
        RAISE EXCEPTION 'site origin pool invariant failed for site %', target_site_id
            USING ERRCODE = '23514';
    END IF;
END;
$$;

ALTER TABLE site_origins DROP COLUMN level;
ALTER TABLE site_origin_pools DROP COLUMN health_check_path, DROP COLUMN failback_mode;
