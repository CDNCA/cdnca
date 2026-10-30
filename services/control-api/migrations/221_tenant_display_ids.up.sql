LOCK TABLE schema_migrations, tenants IN ACCESS EXCLUSIVE MODE;

DO $migration_221$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 220 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 220 OR
       EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE migration_id IS NULL OR migration_id = '' OR
              checksum_sha256 IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
              down_checksum_sha256 IS NULL OR down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR
              integrity_state IS DISTINCT FROM 'verified' OR
              metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version = 220 AND migration_id = '220_error_page_scope_overrides' AND
              checksum_sha256 = '340dc49da585b3f9e2f85da9ffeb42ba7a5e184a48c8b157a88ad27fd26cf713' AND
              down_checksum_sha256 = '4567747996feb94eb56bf01f31ac1875b141485c381b6c2e6fe90b7c08d78493' AND
              integrity_state = 'verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema = current_schema() AND table_name = 'tenants' AND column_name = 'display_id'
       ) OR to_regclass(current_schema() || '.tenants_display_id_seq') IS NOT NULL OR
       to_regprocedure(current_schema() || '.protect_tenant_display_id_221()') IS NOT NULL THEN
        RAISE EXCEPTION 'migration 221 requires the exact verified 220 release head and an untouched tenant display ID schema'
            USING ERRCODE = 'P2210';
    END IF;
END;
$migration_221$;

CREATE SEQUENCE tenants_display_id_seq AS bigint MINVALUE 1 NO MAXVALUE NO CYCLE;

ALTER TABLE tenants ADD COLUMN display_id bigint;

WITH ranked AS (
    SELECT id, row_number() OVER (ORDER BY created_at, id) AS display_id
    FROM tenants
)
UPDATE tenants
SET display_id = ranked.display_id
FROM ranked
WHERE tenants.id = ranked.id;

SELECT setval(
    'tenants_display_id_seq',
    COALESCE((SELECT max(display_id) FROM tenants), 0) + 1,
    false
);

ALTER TABLE tenants
    ALTER COLUMN display_id SET DEFAULT nextval('tenants_display_id_seq'),
    ALTER COLUMN display_id SET NOT NULL,
    ADD CONSTRAINT tenants_display_id_positive CHECK (display_id > 0),
    ADD CONSTRAINT tenants_display_id_unique UNIQUE (display_id);

ALTER SEQUENCE tenants_display_id_seq OWNED BY tenants.display_id;

CREATE FUNCTION protect_tenant_display_id_221()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.display_id IS DISTINCT FROM OLD.display_id THEN
        RAISE EXCEPTION 'tenant display ID is immutable' USING ERRCODE = 'P2211';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER tenants_display_id_immutable_221
BEFORE UPDATE OF display_id ON tenants
FOR EACH ROW EXECUTE FUNCTION protect_tenant_display_id_221();

GRANT USAGE, SELECT ON SEQUENCE tenants_display_id_seq TO cdnca_control_app;
