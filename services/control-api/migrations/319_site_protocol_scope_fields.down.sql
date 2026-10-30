LOCK TABLE schema_migrations, site_protocol_batches, site_protocol_states, site_protocol_batch_items,
    site_protocol_node_results IN ACCESS EXCLUSIVE MODE;

DO $migration_319_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 319 OR
       (SELECT max(version) FROM schema_migrations) <> 319 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=319 AND
        migration_id='319_site_protocol_scope_fields' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 319 down requires the exact verified migration head' USING ERRCODE='P3191';
    END IF;
END;
$migration_319_down$;

-- Restores the exact 136 body (including its defect) so 136..318 stay as released.
CREATE OR REPLACE FUNCTION validate_site_protocol_scope_136()
RETURNS trigger LANGUAGE plpgsql AS $function$
BEGIN
    IF NOT EXISTS(SELECT 1 FROM access_scopes WHERE id=NEW.tenant_scope_id AND kind='tenant') THEN
        RAISE EXCEPTION 'site protocol scope must be tenant' USING ERRCODE='P1361';
    END IF;
    IF TG_TABLE_NAME IN ('site_protocol_states','site_protocol_batch_items') AND
       NOT EXISTS(SELECT 1 FROM sites WHERE id=NEW.site_id AND scope_id=NEW.tenant_scope_id AND deleted_at IS NULL) THEN
        RAISE EXCEPTION 'site protocol site scope mismatch' USING ERRCODE='P1362';
    END IF;
    IF TG_TABLE_NAME='site_protocol_node_results' AND
       (NOT EXISTS(SELECT 1 FROM sites WHERE id=NEW.site_id AND scope_id=NEW.tenant_scope_id AND deleted_at IS NULL) OR
        NOT EXISTS(SELECT 1 FROM nodes WHERE id=NEW.node_id AND scope_id=NEW.tenant_scope_id AND admin_state<>'retired')) THEN
        RAISE EXCEPTION 'site protocol node scope mismatch' USING ERRCODE='P1362';
    END IF;
    RETURN NEW;
END;
$function$;
