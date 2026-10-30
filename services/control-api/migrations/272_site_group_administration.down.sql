-- Application rollback retains this additive schema. Never discard published IDs or remarks.
LOCK TABLE schema_migrations, site_groups, site_group_display_ids, site_group_write_requests IN ACCESS EXCLUSIVE MODE;
DO $migration_272_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 272 OR (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 272 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=272 AND migration_id='272_site_group_administration' AND
        checksum_sha256='aa6fdfc3d0d59309b78c71ef0ce412648135a771a791fbdc76e860c911e9d7ee' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=271 AND migration_id='271_node_network_inventory' AND
        checksum_sha256='994f0b28e574bf8df27edef0e1ff5583cf9241dfdecfb5bfd0eaa2b227a2a19c' AND
        down_checksum_sha256='c0cab19d06f0e4f886ad9cb3f17cdf532bb904ee60aad65e32e3399469b32be7' AND integrity_state='verified'
       ) OR EXISTS (SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
           migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR
           checksum_sha256 IS NULL OR down_checksum_sha256 IS NULL OR metadata_recorded_at IS NULL OR applied_at IS NULL) THEN
        RAISE EXCEPTION 'migration 272 rollback requires the exact verified 272 release head' USING ERRCODE='P2720';
    END IF;
    IF EXISTS(SELECT 1 FROM site_group_display_ids) OR EXISTS(SELECT 1 FROM site_groups WHERE remark<>'') OR
       EXISTS(SELECT 1 FROM site_group_write_requests WHERE response_body ? 'remark') THEN
        RAISE EXCEPTION 'migration 272 rollback cannot discard group metadata or receipts' USING ERRCODE='P2722';
    END IF;
END;
$migration_272_down$;

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
    IF NEW.name IS DISTINCT FROM OLD.name OR NEW.active IS DISTINCT FROM OLD.active OR NEW.deleted_at IS DISTINCT FROM OLD.deleted_at THEN
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
ALTER TABLE site_groups DROP COLUMN remark;
DROP FUNCTION site_group_remark_is_valid_272(text);
DROP TRIGGER site_groups_assign_display_id_272 ON site_groups;
DROP FUNCTION assign_site_group_display_id_272();
DROP TABLE site_group_display_ids;
DROP FUNCTION protect_site_group_display_ids_272();
