LOCK TABLE schema_migrations, acme_http01_node_overlay_generations, acme_http01_node_overlay_states,
    acme_http01_site_overlay_epoch_members IN ACCESS EXCLUSIVE MODE;

DO $migration_346_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 345 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 345 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=345 AND
        migration_id='345_challenge_wildcard_site_binding' AND
        checksum_sha256='4d88859e1cd695ea20c29d6466aa346aaf6f0164771d3741d7ccc6a0ec9dd69c' AND
        down_checksum_sha256='af50113884d47396c6daa1dd369624b9038ca5bde76d07b5f1799e3b4eb582b2' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR to_regclass(current_schema() || '.acme_http01_site_overlay_epoch_purged_members') IS NOT NULL THEN
        RAISE EXCEPTION 'migration 346 requires the exact verified 345 release head' USING ERRCODE='P3460';
    END IF;
END;
$migration_346_up$;

-- ADR 0006 node purge for the ADR-0003 HTTP-01 facts (337/342). A purged
-- node's generations, tokens, deliveries, state, challenge targets, epoch
-- memberships and releases, debts, debt events, coverage and backfill marks
-- are deleted: the node no longer exists, so tokens it may still hold mean
-- nothing. The foreign keys stay RESTRICT; node.Store calls
-- acme_http01_purge_node_346 inside the purge transaction (after setting
-- cdnca.node_purge, before DELETE FROM nodes). Every delete is gated on that
-- marker and re-checked at commit: the node row must be gone.
--
-- Site facts stay. An epoch froze its member count and digest; a purged
-- member leaves a tombstone so the epoch still accounts for it, and from then
-- on counts as gone (not active, not owing a release).
CREATE TABLE acme_http01_site_overlay_epoch_purged_members (
    epoch_id uuid NOT NULL REFERENCES acme_http01_site_overlay_epochs(id) ON DELETE RESTRICT,
    node_id uuid NOT NULL,
    purged_at timestamptz NOT NULL CHECK (isfinite(purged_at)),
    PRIMARY KEY (epoch_id, node_id)
);
CREATE INDEX acme_http01_site_overlay_epoch_purged_members_node_346_idx
    ON acme_http01_site_overlay_epoch_purged_members(node_id);

-- The node named by this transaction's purge marker.
CREATE FUNCTION acme_http01_node_purge_permits_346(target_node_id uuid)
RETURNS boolean LANGUAGE sql STABLE AS $$
    SELECT target_node_id IS NOT NULL AND CASE
        WHEN current_setting('cdnca.node_purge', true) ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
        THEN current_setting('cdnca.node_purge', true)::uuid = target_node_id
        ELSE false END
$$;

CREATE FUNCTION acme_http01_generation_purge_permits_346(target_generation_id uuid)
RETURNS boolean LANGUAGE sql STABLE AS $$
    SELECT acme_http01_node_purge_permits_346(
        (SELECT node_id FROM acme_http01_node_overlay_generations WHERE id=target_generation_id))
$$;

CREATE FUNCTION acme_http01_debt_purge_permits_346(target_debt_id uuid)
RETURNS boolean LANGUAGE sql STABLE AS $$
    SELECT acme_http01_node_purge_permits_346(
        (SELECT node_id FROM acme_http01_node_overlay_cleanup_debts WHERE id=target_debt_id))
$$;

-- Tombstones: inserted by the purge only, for an existing membership.
CREATE FUNCTION guard_acme_http01_epoch_purged_member_346()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP <> 'INSERT' OR NOT acme_http01_node_purge_permits_346(NEW.node_id) OR NOT EXISTS (
        SELECT 1 FROM acme_http01_site_overlay_epoch_members member
        WHERE member.epoch_id=NEW.epoch_id AND member.node_id=NEW.node_id) THEN
        RAISE EXCEPTION 'ACME HTTP-01 epoch tombstones are written only by a node purge' USING ERRCODE='P3461';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER acme_http01_site_overlay_epoch_purged_members_guard_346
    BEFORE INSERT OR UPDATE OR DELETE ON acme_http01_site_overlay_epoch_purged_members
    FOR EACH ROW EXECUTE FUNCTION guard_acme_http01_epoch_purged_member_346();
CREATE TRIGGER acme_http01_site_overlay_epoch_purged_members_truncate_346
    BEFORE TRUNCATE ON acme_http01_site_overlay_epoch_purged_members
    FOR EACH STATEMENT EXECUTE FUNCTION guard_acme_http01_epoch_purged_member_346();

-- At commit: a purged HTTP-01 fact belongs to a node that was deleted too.
CREATE FUNCTION validate_acme_http01_node_purged_346()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF EXISTS (SELECT 1 FROM nodes WHERE id = OLD.node_id) THEN
        RAISE EXCEPTION 'ACME HTTP-01 facts of node % can only be deleted with the node', OLD.node_id
            USING ERRCODE='P3462';
    END IF;
    RETURN NULL;
END;
$$;

-- Split every DELETE guard of the node-owned HTTP-01 tables (as 284 did): the
-- original trigger keeps INSERT/UPDATE; <table>_del_346 fires the same guard on
-- DELETE unless the purge marker names the row's node. Tables carrying
-- node_id also re-check at commit that the node was deleted. Tokens and debt
-- events have no node_id: their parent row (generation, debt) is deleted in
-- the same purge and carries the check.
DO $purge_guards_346$
DECLARE
    item text[];
BEGIN
    FOREACH item SLICE 1 IN ARRAY ARRAY[
        -- table, trigger, function, kept events, delete permit, commit check
        ARRAY['acme_http01_node_challenge_targets', 'acme_http01_node_challenge_targets_append_only_337',
              'acme_http01_node_append_only_337', 'UPDATE', 'acme_http01_node_purge_permits_346(OLD.node_id)', 'yes'],
        ARRAY['acme_http01_node_overlay_generations', 'acme_http01_node_overlay_generations_append_only_337',
              'acme_http01_node_append_only_337', 'UPDATE', 'acme_http01_node_purge_permits_346(OLD.node_id)', 'yes'],
        ARRAY['acme_http01_node_overlay_generation_tokens', 'acme_http01_node_overlay_generation_tokens_append_only_337',
              'acme_http01_node_append_only_337', 'UPDATE', 'acme_http01_generation_purge_permits_346(OLD.generation_id)', 'no'],
        ARRAY['acme_http01_node_overlay_states', 'acme_http01_node_overlay_states_guard_337',
              'guard_acme_http01_node_overlay_state_337', 'INSERT OR UPDATE', 'acme_http01_node_purge_permits_346(OLD.node_id)', 'yes'],
        ARRAY['acme_http01_node_overlay_deliveries', 'acme_http01_node_overlay_deliveries_guard_337',
              'guard_acme_http01_node_overlay_delivery_337', 'INSERT OR UPDATE', 'acme_http01_node_purge_permits_346(OLD.node_id)', 'yes'],
        ARRAY['acme_http01_site_overlay_epoch_members', 'acme_http01_site_overlay_epoch_members_guard_342',
              'guard_acme_http01_site_overlay_epoch_member_342', 'INSERT OR UPDATE', 'acme_http01_node_purge_permits_346(OLD.node_id)', 'yes'],
        ARRAY['acme_http01_site_overlay_epoch_releases', 'acme_http01_site_overlay_epoch_releases_guard_342',
              'guard_acme_http01_site_overlay_epoch_release_342', 'INSERT OR UPDATE', 'acme_http01_node_purge_permits_346(OLD.node_id)', 'yes'],
        ARRAY['acme_http01_node_overlay_cleanup_debts', 'acme_http01_node_overlay_cleanup_debts_guard_342',
              'guard_acme_http01_cleanup_debt_342', 'INSERT OR UPDATE', 'acme_http01_node_purge_permits_346(OLD.node_id)', 'yes'],
        ARRAY['acme_http01_node_overlay_cleanup_debt_events', 'acme_http01_node_overlay_cleanup_debt_events_guard_342',
              'guard_acme_http01_cleanup_debt_event_342', 'INSERT OR UPDATE', 'acme_http01_debt_purge_permits_346(OLD.debt_id)', 'no'],
        ARRAY['acme_http01_node_overlay_generation_coverages', 'acme_http01_node_overlay_generation_coverages_append_only_342',
              'guard_acme_http01_overlay_fact_342', 'UPDATE', 'acme_http01_node_purge_permits_346(OLD.node_id)', 'yes'],
        ARRAY['acme_http01_overlay_backfill_nodes', 'acme_http01_overlay_backfill_nodes_guard_342',
              'guard_acme_http01_backfill_node_342', 'INSERT OR UPDATE', 'acme_http01_node_purge_permits_346(OLD.node_id)', 'yes'],
        ARRAY['acme_http01_overlay_backfill_quarantines', 'acme_http01_overlay_backfill_quarantines_append_only_342',
              'guard_acme_http01_overlay_fact_342', 'UPDATE', 'acme_http01_node_purge_permits_346(OLD.node_id)', 'yes']]
    LOOP
        EXECUTE format('DROP TRIGGER %I ON %I', item[2], item[1]);
        EXECUTE format('CREATE TRIGGER %I BEFORE %s ON %I FOR EACH ROW EXECUTE FUNCTION %I()',
            item[2], item[4], item[1], item[3]);
        EXECUTE format('CREATE TRIGGER %I BEFORE DELETE ON %I FOR EACH ROW WHEN (NOT %s) EXECUTE FUNCTION %I()',
            item[1] || '_del_346', item[1], item[5], item[3]);
        IF item[6] = 'yes' THEN
            EXECUTE format('CREATE CONSTRAINT TRIGGER %I AFTER DELETE ON %I DEFERRABLE INITIALLY DEFERRED '
                'FOR EACH ROW EXECUTE FUNCTION validate_acme_http01_node_purged_346()',
                item[1] || '_purged_346', item[1]);
        END IF;
    END LOOP;
END;
$purge_guards_346$;

-- 342's epoch check with tombstones: the frozen count and digest cover the
-- remaining members and the purged ones; everything else is unchanged.
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
    IF NOT FOUND OR value.member_count <> (SELECT count(*) FROM acme_http01_site_overlay_epoch_members WHERE epoch_id=value.id) +
           (SELECT count(*) FROM acme_http01_site_overlay_epoch_purged_members WHERE epoch_id=value.id) OR
       value.member_set_sha256 IS DISTINCT FROM acme_http01_node_set_digest(ARRAY(
           SELECT node_id FROM acme_http01_site_overlay_epoch_members WHERE epoch_id=value.id
           UNION ALL
           SELECT node_id FROM acme_http01_site_overlay_epoch_purged_members WHERE epoch_id=value.id)) OR
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

-- The purge itself, in the node's purge transaction (internal/node/purge.go):
-- serialized with every HTTP-01 writer, then children before parents. Runs
-- as the schema owner; the application roles get EXECUTE, never DELETE.
DO $purge_function_346$
BEGIN
    EXECUTE format($ddl$
        CREATE FUNCTION %1$I.acme_http01_purge_node_346(target_node_id uuid) RETURNS void
        LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, %1$I, pg_temp AS $body$
        BEGIN
            PERFORM pg_advisory_xact_lock(hashtextextended('acme-http01-overlay', 0));
            IF NOT acme_http01_node_purge_permits_346(target_node_id) THEN
                RAISE EXCEPTION 'ACME HTTP-01 facts are purged only inside the purge of their node'
                    USING ERRCODE='P3463';
            END IF;
            INSERT INTO acme_http01_site_overlay_epoch_purged_members(epoch_id, node_id, purged_at)
            SELECT epoch_id, node_id, clock_timestamp() FROM acme_http01_site_overlay_epoch_members
            WHERE node_id = target_node_id;
            DELETE FROM acme_http01_node_overlay_cleanup_debt_events event
            USING acme_http01_node_overlay_cleanup_debts debt
            WHERE event.debt_id = debt.id AND debt.node_id = target_node_id;
            DELETE FROM acme_http01_node_overlay_generation_coverages WHERE node_id = target_node_id;
            DELETE FROM acme_http01_site_overlay_epoch_releases WHERE node_id = target_node_id;
            DELETE FROM acme_http01_node_overlay_cleanup_debts WHERE node_id = target_node_id;
            DELETE FROM acme_http01_site_overlay_epoch_members WHERE node_id = target_node_id;
            DELETE FROM acme_http01_overlay_backfill_nodes WHERE node_id = target_node_id;
            DELETE FROM acme_http01_overlay_backfill_quarantines WHERE node_id = target_node_id;
            DELETE FROM acme_http01_node_overlay_states WHERE node_id = target_node_id;
            DELETE FROM acme_http01_node_overlay_deliveries WHERE node_id = target_node_id;
            DELETE FROM acme_http01_node_overlay_generation_tokens token
            USING acme_http01_node_overlay_generations generation
            WHERE token.generation_id = generation.id AND generation.node_id = target_node_id;
            DELETE FROM acme_http01_node_overlay_generations WHERE node_id = target_node_id;
            DELETE FROM acme_http01_node_challenge_targets WHERE node_id = target_node_id;
        END;
        $body$;
    $ddl$, current_schema());
END;
$purge_function_346$;

-- Every 337/342 HTTP-01 table that references nodes is emptied by the purge
-- above (the 063 tables are 284's and 287's).
DO $purge_closure_346$
DECLARE
    missing text;
BEGIN
    SELECT string_agg(constraint_row.conrelid::regclass::text, ', ') INTO missing
    FROM pg_constraint constraint_row
    WHERE constraint_row.contype = 'f' AND constraint_row.confrelid = (current_schema() || '.nodes')::regclass
      AND constraint_row.confdeltype <> 'c' AND (constraint_row.conrelid::regclass::text LIKE 'acme_http01_node_%' OR
           constraint_row.conrelid::regclass::text LIKE 'acme_http01_site_overlay_%' OR
           constraint_row.conrelid::regclass::text LIKE 'acme_http01_overlay_backfill_%')
      AND constraint_row.conrelid::regclass::text NOT IN (
          'acme_http01_node_challenge_targets', 'acme_http01_node_overlay_generations',
          'acme_http01_node_overlay_states', 'acme_http01_site_overlay_epoch_members',
          'acme_http01_node_overlay_cleanup_debts', 'acme_http01_node_overlay_generation_coverages',
          'acme_http01_overlay_backfill_nodes', 'acme_http01_overlay_backfill_quarantines');
    IF missing IS NOT NULL THEN
        RAISE EXCEPTION 'migration 346 leaves HTTP-01 node references unpurged: %', missing USING ERRCODE='P3460';
    END IF;
END;
$purge_closure_346$;

REVOKE ALL ON acme_http01_site_overlay_epoch_purged_members FROM PUBLIC;
GRANT SELECT ON acme_http01_site_overlay_epoch_purged_members TO cdnca_control_app, cdnca_control_runtime;
REVOKE ALL ON FUNCTION acme_http01_purge_node_346(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION acme_http01_purge_node_346(uuid) TO cdnca_control_app, cdnca_control_runtime;
