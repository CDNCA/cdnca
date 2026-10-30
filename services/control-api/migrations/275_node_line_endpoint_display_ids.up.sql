LOCK TABLE schema_migrations, node_line_endpoints IN ACCESS EXCLUSIVE MODE;

DO $migration_275_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 274 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 274 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=274 AND
        migration_id='274_node_line_endpoint_sort_order' AND
        checksum_sha256='1524569c2e62c6ddf98c7079e17523175d5c41b7f693634c6bfa779d18f389b9' AND
        down_checksum_sha256='a23ff8055f90da8547f7c615a0917dc848f5b33cc7b2be8ef7774b045e72a9d4' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR checksum_sha256 IS NULL OR
        down_checksum_sha256 IS NULL OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) THEN
        RAISE EXCEPTION 'migration 275 requires the exact verified 274 release head' USING ERRCODE='P2750';
    END IF;
END;
$migration_275_up$;

CREATE TABLE node_line_endpoint_display_ids (
    tenant_scope_id uuid NOT NULL,
    line_group_id uuid NOT NULL,
    endpoint_id uuid NOT NULL,
    display_id bigint GENERATED ALWAYS AS IDENTITY UNIQUE NOT NULL CHECK (display_id > 0),
    PRIMARY KEY(tenant_scope_id, line_group_id, endpoint_id),
    FOREIGN KEY(tenant_scope_id, line_group_id) REFERENCES node_line_groups(tenant_scope_id, id) ON DELETE RESTRICT
);

INSERT INTO node_line_endpoint_display_ids(tenant_scope_id,line_group_id,endpoint_id)
SELECT tenant_scope_id,line_group_id,id FROM node_line_endpoints
GROUP BY tenant_scope_id,line_group_id,id
ORDER BY tenant_scope_id,line_group_id,min(config_revision),id;

DO $migration_275_allocator$
BEGIN
    EXECUTE format($ddl$
        CREATE FUNCTION %I.assign_node_line_endpoint_display_id_275() RETURNS trigger
        LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $body$
        BEGIN
            INSERT INTO %I.node_line_endpoint_display_ids(tenant_scope_id,line_group_id,endpoint_id)
            VALUES(NEW.tenant_scope_id,NEW.line_group_id,NEW.id)
            ON CONFLICT(tenant_scope_id,line_group_id,endpoint_id) DO NOTHING;
            RETURN NEW;
        END;
        $body$;
    $ddl$,current_schema(),current_schema());
END;
$migration_275_allocator$;

CREATE TRIGGER node_line_endpoints_assign_display_id_275 AFTER INSERT ON node_line_endpoints
FOR EACH ROW EXECUTE FUNCTION assign_node_line_endpoint_display_id_275();

CREATE FUNCTION protect_node_line_endpoint_display_ids_275() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    RAISE EXCEPTION 'node line endpoint display IDs are immutable' USING ERRCODE='P2751';
END;
$$;
CREATE TRIGGER node_line_endpoint_display_ids_immutable_275 BEFORE UPDATE OR DELETE ON node_line_endpoint_display_ids
FOR EACH ROW EXECUTE FUNCTION protect_node_line_endpoint_display_ids_275();
CREATE TRIGGER node_line_endpoint_display_ids_no_truncate_275 BEFORE TRUNCATE ON node_line_endpoint_display_ids
FOR EACH STATEMENT EXECUTE FUNCTION protect_node_line_endpoint_display_ids_275();

REVOKE ALL ON FUNCTION assign_node_line_endpoint_display_id_275(),protect_node_line_endpoint_display_ids_275() FROM PUBLIC,cdnca_control_app;
REVOKE ALL ON node_line_endpoint_display_ids FROM PUBLIC,cdnca_control_app;
REVOKE ALL ON SEQUENCE node_line_endpoint_display_ids_display_id_seq FROM PUBLIC,cdnca_control_app;
GRANT SELECT ON node_line_endpoint_display_ids TO cdnca_control_app;
