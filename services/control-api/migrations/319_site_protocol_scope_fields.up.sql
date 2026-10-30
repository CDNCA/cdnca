LOCK TABLE schema_migrations, site_protocol_batches, site_protocol_states, site_protocol_batch_items,
    site_protocol_node_results IN ACCESS EXCLUSIVE MODE;

DO $migration_319_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 318 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 318 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=318 AND
        migration_id='318_edge_publication_compile_inputs' AND
        checksum_sha256='9b31c6f7d9f9247e3fd02d9e9b85955f672b46b8b6cbae96c614d63f0ae58e1b' AND
        down_checksum_sha256='cd2ae2c483ec22bd32f36c146b7087a3464e9e05025f71833ebc1fbc333e57c8' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR checksum_sha256 IS NULL OR
        down_checksum_sha256 IS NULL OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR to_regprocedure('validate_site_protocol_scope_136()') IS NULL THEN
        RAISE EXCEPTION 'migration 319 requires the exact verified 318 release head' USING ERRCODE='P3190';
    END IF;
END;
$migration_319_up$;

-- 136 defect: the scope trigger read NEW.site_id / NEW.node_id inside IF
-- expressions guarded only by TG_TABLE_NAME. PL/pgSQL resolves every field
-- of an expression before evaluating it, so inserts into site_protocol_batches
-- (no site_id) and into states/items (no node_id) failed with 42703 and every
-- HTTP/3 batch create returned 503. Each table now gets its own branch that
-- only reads fields it has; the checks themselves are unchanged.
CREATE OR REPLACE FUNCTION validate_site_protocol_scope_136()
RETURNS trigger LANGUAGE plpgsql AS $function$
BEGIN
    IF NOT EXISTS(SELECT 1 FROM access_scopes WHERE id=NEW.tenant_scope_id AND kind='tenant') THEN
        RAISE EXCEPTION 'site protocol scope must be tenant' USING ERRCODE='P1361';
    END IF;
    IF TG_TABLE_NAME IN ('site_protocol_states','site_protocol_batch_items') THEN
        IF NOT EXISTS(SELECT 1 FROM sites WHERE id=NEW.site_id AND scope_id=NEW.tenant_scope_id AND deleted_at IS NULL) THEN
            RAISE EXCEPTION 'site protocol site scope mismatch' USING ERRCODE='P1362';
        END IF;
    ELSIF TG_TABLE_NAME='site_protocol_node_results' THEN
        IF NOT EXISTS(SELECT 1 FROM sites WHERE id=NEW.site_id AND scope_id=NEW.tenant_scope_id AND deleted_at IS NULL) OR
           NOT EXISTS(SELECT 1 FROM nodes WHERE id=NEW.node_id AND scope_id=NEW.tenant_scope_id AND admin_state<>'retired') THEN
            RAISE EXCEPTION 'site protocol node scope mismatch' USING ERRCODE='P1362';
        END IF;
    END IF;
    RETURN NEW;
END;
$function$;
