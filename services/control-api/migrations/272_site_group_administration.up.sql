LOCK TABLE schema_migrations, site_groups IN ACCESS EXCLUSIVE MODE;

DO $migration_272_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 271 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 271 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=271 AND migration_id='271_node_network_inventory' AND
        checksum_sha256='994f0b28e574bf8df27edef0e1ff5583cf9241dfdecfb5bfd0eaa2b227a2a19c' AND
        down_checksum_sha256='c0cab19d06f0e4f886ad9cb3f17cdf532bb904ee60aad65e32e3399469b32be7' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
           migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR
           checksum_sha256 IS NULL OR down_checksum_sha256 IS NULL OR metadata_recorded_at IS NULL OR applied_at IS NULL) THEN
        RAISE EXCEPTION 'migration 272 requires the exact verified 271 release head' USING ERRCODE='P2720';
    END IF;
END;
$migration_272_up$;

CREATE TABLE site_group_display_ids (
    scope_id uuid NOT NULL,
    group_id uuid NOT NULL,
    display_id bigint GENERATED ALWAYS AS IDENTITY UNIQUE NOT NULL CHECK (display_id > 0),
    PRIMARY KEY(scope_id, group_id),
    FOREIGN KEY(scope_id, group_id) REFERENCES site_groups(scope_id, id) ON DELETE RESTRICT
);
INSERT INTO site_group_display_ids(scope_id, group_id, display_id)
OVERRIDING SYSTEM VALUE
SELECT scope_id, id, row_number() OVER (ORDER BY created_at, id, scope_id) FROM site_groups;

DO $migration_272_sequence$
DECLARE highest_id bigint;
BEGIN
    SELECT max(display_id) INTO highest_id FROM site_group_display_ids;
    IF highest_id IS NOT NULL THEN
        PERFORM setval(format('%I.site_group_display_ids_display_id_seq',current_schema())::regclass,highest_id,true);
    END IF;
END;
$migration_272_sequence$;

DO $migration_272_allocator$
BEGIN
    EXECUTE format($ddl$
        CREATE FUNCTION %I.assign_site_group_display_id_272() RETURNS trigger
        LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $body$
        BEGIN
            INSERT INTO %I.site_group_display_ids(scope_id,group_id) VALUES(NEW.scope_id,NEW.id);
            RETURN NEW;
        END;
        $body$;
    $ddl$,current_schema(),current_schema());
END;
$migration_272_allocator$;
CREATE TRIGGER site_groups_assign_display_id_272 AFTER INSERT ON site_groups
FOR EACH ROW EXECUTE FUNCTION assign_site_group_display_id_272();

CREATE FUNCTION protect_site_group_display_ids_272() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    RAISE EXCEPTION 'site group display IDs are immutable' USING ERRCODE='P2721';
END;
$$;
CREATE TRIGGER site_group_display_ids_immutable_272 BEFORE UPDATE OR DELETE ON site_group_display_ids
FOR EACH ROW EXECUTE FUNCTION protect_site_group_display_ids_272();
CREATE TRIGGER site_group_display_ids_no_truncate_272 BEFORE TRUNCATE ON site_group_display_ids
FOR EACH STATEMENT EXECUTE FUNCTION protect_site_group_display_ids_272();

CREATE FUNCTION site_group_remark_is_valid_272(value text) RETURNS boolean
LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE AS $$
    SELECT char_length(value) <= 1024 AND NOT EXISTS (
        SELECT 1 FROM generate_series(1,char_length(value)) AS position
        WHERE (ascii(substr(value,position,1)) BETWEEN 0 AND 31 AND ascii(substr(value,position,1)) NOT IN (9,10,13))
           OR ascii(substr(value,position,1)) BETWEEN 127 AND 159
    );
$$;
ALTER TABLE site_groups ADD COLUMN remark text NOT NULL DEFAULT '' CHECK (site_group_remark_is_valid_272(remark));

CREATE OR REPLACE FUNCTION guard_site_group_mutation_082() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'site groups cannot be hard deleted' USING ERRCODE='P8208';
    END IF;
    IF OLD.deleted_at IS NOT NULL THEN
        RAISE EXCEPTION 'deleted site groups cannot be mutated or restored' USING ERRCODE='P8209';
    END IF;
    IF NEW.id IS DISTINCT FROM OLD.id OR NEW.scope_id IS DISTINCT FROM OLD.scope_id OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
        RAISE EXCEPTION 'site group identity is immutable' USING ERRCODE='P8209';
    END IF;
    IF NEW.name IS DISTINCT FROM OLD.name OR NEW.remark IS DISTINCT FROM OLD.remark OR
       NEW.active IS DISTINCT FROM OLD.active OR NEW.deleted_at IS DISTINCT FROM OLD.deleted_at THEN
        IF NEW.revision <> OLD.revision + 1 OR NEW.updated_at < OLD.updated_at THEN
            RAISE EXCEPTION 'site group revision must advance exactly once' USING ERRCODE='P8209';
        END IF;
    ELSIF NEW.revision IS DISTINCT FROM OLD.revision THEN
        RAISE EXCEPTION 'site group revision cannot change without a resource mutation' USING ERRCODE='P8209';
    END IF;
    IF OLD.deleted_at IS NULL AND NEW.deleted_at IS NOT NULL AND EXISTS (
        SELECT 1 FROM sites WHERE scope_id=OLD.scope_id AND group_id=OLD.id
    ) THEN
        RAISE EXCEPTION 'site group is referenced by a site' USING ERRCODE='P8207';
    END IF;
    RETURN NEW;
END;
$$;

REVOKE ALL ON FUNCTION assign_site_group_display_id_272(),protect_site_group_display_ids_272() FROM PUBLIC,cdnca_control_app;
REVOKE ALL ON site_group_display_ids FROM PUBLIC,cdnca_control_app;
REVOKE ALL ON SEQUENCE site_group_display_ids_display_id_seq FROM PUBLIC,cdnca_control_app;
GRANT SELECT ON site_group_display_ids TO cdnca_control_app;
