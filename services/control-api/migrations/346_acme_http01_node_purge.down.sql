LOCK TABLE schema_migrations, acme_http01_node_overlay_generations, acme_http01_node_overlay_states,
    acme_http01_site_overlay_epoch_members IN ACCESS EXCLUSIVE MODE;

DO $migration_346_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 346 OR
       (SELECT max(version) FROM schema_migrations) <> 346 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=346 AND
        migration_id='346_acme_http01_node_purge' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 346 down requires the exact verified migration head' USING ERRCODE='P3469';
    END IF;
    -- Without the tombstones an epoch of a purged member no longer matches
    -- its frozen count and digest.
    IF EXISTS (SELECT 1 FROM acme_http01_site_overlay_epoch_purged_members) THEN
        RAISE EXCEPTION 'migration 346 down refuses to drop the members of purged nodes' USING ERRCODE='P0001';
    END IF;
END;
$migration_346_down$;

DO $purge_guards_346_down$
DECLARE
    item text[];
BEGIN
    FOREACH item SLICE 1 IN ARRAY ARRAY[
        ARRAY['acme_http01_node_challenge_targets', 'acme_http01_node_challenge_targets_append_only_337',
              'acme_http01_node_append_only_337', 'UPDATE OR DELETE'],
        ARRAY['acme_http01_node_overlay_generations', 'acme_http01_node_overlay_generations_append_only_337',
              'acme_http01_node_append_only_337', 'UPDATE OR DELETE'],
        ARRAY['acme_http01_node_overlay_generation_tokens', 'acme_http01_node_overlay_generation_tokens_append_only_337',
              'acme_http01_node_append_only_337', 'UPDATE OR DELETE'],
        ARRAY['acme_http01_node_overlay_states', 'acme_http01_node_overlay_states_guard_337',
              'guard_acme_http01_node_overlay_state_337', 'INSERT OR UPDATE OR DELETE'],
        ARRAY['acme_http01_node_overlay_deliveries', 'acme_http01_node_overlay_deliveries_guard_337',
              'guard_acme_http01_node_overlay_delivery_337', 'INSERT OR UPDATE OR DELETE'],
        ARRAY['acme_http01_site_overlay_epoch_members', 'acme_http01_site_overlay_epoch_members_guard_342',
              'guard_acme_http01_site_overlay_epoch_member_342', 'INSERT OR UPDATE OR DELETE'],
        ARRAY['acme_http01_site_overlay_epoch_releases', 'acme_http01_site_overlay_epoch_releases_guard_342',
              'guard_acme_http01_site_overlay_epoch_release_342', 'INSERT OR UPDATE OR DELETE'],
        ARRAY['acme_http01_node_overlay_cleanup_debts', 'acme_http01_node_overlay_cleanup_debts_guard_342',
              'guard_acme_http01_cleanup_debt_342', 'INSERT OR UPDATE OR DELETE'],
        ARRAY['acme_http01_node_overlay_cleanup_debt_events', 'acme_http01_node_overlay_cleanup_debt_events_guard_342',
              'guard_acme_http01_cleanup_debt_event_342', 'INSERT OR UPDATE OR DELETE'],
        ARRAY['acme_http01_node_overlay_generation_coverages', 'acme_http01_node_overlay_generation_coverages_append_only_342',
              'guard_acme_http01_overlay_fact_342', 'UPDATE OR DELETE'],
        ARRAY['acme_http01_overlay_backfill_nodes', 'acme_http01_overlay_backfill_nodes_guard_342',
              'guard_acme_http01_backfill_node_342', 'INSERT OR UPDATE OR DELETE'],
        ARRAY['acme_http01_overlay_backfill_quarantines', 'acme_http01_overlay_backfill_quarantines_append_only_342',
              'guard_acme_http01_overlay_fact_342', 'UPDATE OR DELETE']]
    LOOP
        EXECUTE format('DROP TRIGGER IF EXISTS %I ON %I', item[1] || '_purged_346', item[1]);
        EXECUTE format('DROP TRIGGER %I ON %I', item[1] || '_del_346', item[1]);
        EXECUTE format('DROP TRIGGER %I ON %I', item[2], item[1]);
        EXECUTE format('CREATE TRIGGER %I BEFORE %s ON %I FOR EACH ROW EXECUTE FUNCTION %I()',
            item[2], item[4], item[1], item[3]);
    END LOOP;
END;
$purge_guards_346_down$;

CREATE OR REPLACE FUNCTION validate_acme_http01_site_overlay_epoch_342()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    value acme_http01_site_overlay_epochs%ROWTYPE;
BEGIN
    IF TG_TABLE_NAME = 'acme_http01_site_overlay_epochs' THEN
        SELECT * INTO value FROM acme_http01_site_overlay_epochs WHERE id = NEW.id;
    ELSE
        SELECT * INTO value FROM acme_http01_site_overlay_epochs WHERE id = NEW.epoch_id;
    END IF;
    IF NOT FOUND OR value.member_count <> (SELECT count(*) FROM acme_http01_site_overlay_epoch_members WHERE epoch_id=value.id) OR
       value.member_set_sha256 IS DISTINCT FROM acme_http01_node_set_digest(ARRAY(
           SELECT node_id FROM acme_http01_site_overlay_epoch_members WHERE epoch_id=value.id)) OR
       (value.closed_at IS NULL) <> EXISTS (
           SELECT 1 FROM acme_http01_site_overlay_states state
           WHERE state.tenant_scope_id=value.tenant_scope_id AND state.site_id=value.site_id AND state.open_epoch_id=value.id) OR
       (value.closed_at IS NOT NULL AND (
           EXISTS (SELECT 1 FROM acme_http01_site_overlay_epoch_members member
                   WHERE member.epoch_id=value.id AND NOT EXISTS (
                       SELECT 1 FROM acme_http01_site_overlay_epoch_releases released
                       WHERE released.epoch_id=member.epoch_id AND released.node_id=member.node_id)) OR
           NOT EXISTS (SELECT 1 FROM acme_http01_site_overlay_versions version
                       WHERE version.epoch_id=value.id AND version.token_count=0 AND version.source='refresh'))) OR
       EXISTS (SELECT 1 FROM acme_http01_site_overlay_epoch_releases released
               WHERE released.epoch_id=value.id AND NOT EXISTS (
                   SELECT 1 FROM acme_http01_node_overlay_cleanup_debt_events event
                   WHERE event.debt_id=released.debt_id AND event.event IN ('opened', 'coalesced')
                     AND event.epoch_id=released.epoch_id AND event.reason=released.reason)) THEN
        RAISE EXCEPTION 'ACME HTTP-01 site overlay epoch is inconsistent' USING ERRCODE='P3423';
    END IF;
    RETURN NULL;
END;
$$;

DROP FUNCTION acme_http01_purge_node_346(uuid);
DROP FUNCTION validate_acme_http01_node_purged_346();
DROP TABLE acme_http01_site_overlay_epoch_purged_members;
DROP FUNCTION guard_acme_http01_epoch_purged_member_346();
DROP FUNCTION acme_http01_debt_purge_permits_346(uuid);
DROP FUNCTION acme_http01_generation_purge_permits_346(uuid);
DROP FUNCTION acme_http01_node_purge_permits_346(uuid);
