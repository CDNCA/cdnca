LOCK TABLE schema_migrations, access_scopes, certificate_assets, cache_operations
IN ACCESS EXCLUSIVE MODE;

DO $migration_213$
BEGIN
    IF (SELECT count(*) FROM schema_migrations)<>212 OR
       (SELECT min(version) FROM schema_migrations)<>1 OR
       (SELECT max(version) FROM schema_migrations)<>212 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version=212 AND migration_id='212_order_display_ids' AND
              checksum_sha256='aae821853f38ee391750d5da69e346c3e29f3ffdb7e33c012421b3e753492dcd' AND
              down_checksum_sha256='7b70b5c0eea67790c9e9f238a764a50eed20006aaa18c9200f7f5b3206143764' AND
              integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
    ) OR EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema=current_schema() AND column_name='display_id' AND
              table_name IN ('certificate_assets','cache_operations')
    ) OR to_regclass(current_schema() || '.certificate_asset_display_id_sequences') IS NOT NULL OR
         to_regclass(current_schema() || '.cache_operation_display_id_sequences') IS NOT NULL THEN
        RAISE EXCEPTION 'migration 213 requires the exact verified 212 release head and an untouched certificate/cache display ID schema'
            USING ERRCODE='P2130';
    END IF;
END;
$migration_213$;

CREATE TABLE certificate_asset_display_id_sequences (
    scope_id uuid PRIMARY KEY REFERENCES access_scopes(id) ON DELETE RESTRICT,
    next_value bigint NOT NULL CHECK(next_value>0),
    updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE cache_operation_display_id_sequences (
    scope_id uuid PRIMARY KEY REFERENCES access_scopes(id) ON DELETE RESTRICT,
    next_value bigint NOT NULL CHECK(next_value>0),
    updated_at timestamptz NOT NULL DEFAULT now()
);

ALTER TABLE certificate_assets ADD COLUMN display_id bigint;
ALTER TABLE cache_operations ADD COLUMN display_id bigint;

ALTER TABLE certificate_assets DISABLE TRIGGER certificate_assets_protect;
ALTER TABLE cache_operations DISABLE TRIGGER cache_operations_protected;

WITH ranked AS (
    SELECT id,tenant_scope_id,
           row_number() OVER(PARTITION BY tenant_scope_id ORDER BY created_at,id) AS display_id
    FROM certificate_assets
)
UPDATE certificate_assets SET display_id=ranked.display_id FROM ranked
WHERE certificate_assets.tenant_scope_id=ranked.tenant_scope_id AND certificate_assets.id=ranked.id;

WITH ranked AS (
    SELECT id,scope_id,
           row_number() OVER(PARTITION BY scope_id ORDER BY created_at,id) AS display_id
    FROM cache_operations
)
UPDATE cache_operations SET display_id=ranked.display_id FROM ranked
WHERE cache_operations.scope_id=ranked.scope_id AND cache_operations.id=ranked.id;

SET CONSTRAINTS ALL IMMEDIATE;
ALTER TABLE cache_operations ENABLE TRIGGER cache_operations_protected;
ALTER TABLE certificate_assets ENABLE TRIGGER certificate_assets_protect;
SET CONSTRAINTS ALL DEFERRED;

INSERT INTO certificate_asset_display_id_sequences(scope_id,next_value)
SELECT scope.id,COALESCE(max(asset.display_id),0)+1 FROM access_scopes scope
LEFT JOIN certificate_assets asset ON asset.tenant_scope_id=scope.id
WHERE scope.kind='tenant' GROUP BY scope.id;
INSERT INTO cache_operation_display_id_sequences(scope_id,next_value)
SELECT scope.id,COALESCE(max(operation.display_id),0)+1 FROM access_scopes scope
LEFT JOIN cache_operations operation ON operation.scope_id=scope.id
WHERE scope.kind='tenant' GROUP BY scope.id;

ALTER TABLE certificate_assets
    ALTER COLUMN display_id SET NOT NULL,
    ADD CONSTRAINT certificate_assets_display_id_positive CHECK(display_id>0),
    ADD CONSTRAINT certificate_assets_scope_display_id_unique UNIQUE(tenant_scope_id,display_id);
ALTER TABLE cache_operations
    ALTER COLUMN display_id SET NOT NULL,
    ADD CONSTRAINT cache_operations_display_id_positive CHECK(display_id>0),
    ADD CONSTRAINT cache_operations_scope_display_id_unique UNIQUE(scope_id,display_id);

CREATE FUNCTION protect_display_id_213()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.display_id IS DISTINCT FROM OLD.display_id THEN
        RAISE EXCEPTION 'display ID is immutable' USING ERRCODE='P2133';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION allocate_certificate_asset_display_id_213()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.display_id IS NOT NULL THEN
        RAISE EXCEPTION 'certificate asset display ID is allocator-owned' USING ERRCODE='P2131';
    END IF;
    INSERT INTO certificate_asset_display_id_sequences(scope_id,next_value,updated_at)
    VALUES(NEW.tenant_scope_id,2,now())
    ON CONFLICT(scope_id) DO UPDATE
    SET next_value=certificate_asset_display_id_sequences.next_value+1,updated_at=now()
    RETURNING next_value-1 INTO NEW.display_id;
    RETURN NEW;
END;
$$;
CREATE FUNCTION allocate_cache_operation_display_id_213()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.display_id IS NOT NULL THEN
        RAISE EXCEPTION 'cache operation display ID is allocator-owned' USING ERRCODE='P2132';
    END IF;
    INSERT INTO cache_operation_display_id_sequences(scope_id,next_value,updated_at)
    VALUES(NEW.scope_id,2,now())
    ON CONFLICT(scope_id) DO UPDATE
    SET next_value=cache_operation_display_id_sequences.next_value+1,updated_at=now()
    RETURNING next_value-1 INTO NEW.display_id;
    RETURN NEW;
END;
$$;

CREATE TRIGGER certificate_assets_display_id_213 BEFORE INSERT ON certificate_assets
FOR EACH ROW EXECUTE FUNCTION allocate_certificate_asset_display_id_213();
CREATE TRIGGER cache_operations_display_id_213 BEFORE INSERT ON cache_operations
FOR EACH ROW EXECUTE FUNCTION allocate_cache_operation_display_id_213();
CREATE TRIGGER certificate_assets_display_id_immutable_213 BEFORE UPDATE ON certificate_assets
FOR EACH ROW EXECUTE FUNCTION protect_display_id_213();
CREATE TRIGGER cache_operations_display_id_immutable_213 BEFORE UPDATE ON cache_operations
FOR EACH ROW EXECUTE FUNCTION protect_display_id_213();

REVOKE ALL ON FUNCTION allocate_certificate_asset_display_id_213(),
    allocate_cache_operation_display_id_213(),protect_display_id_213() FROM PUBLIC;
GRANT SELECT,INSERT,UPDATE ON certificate_asset_display_id_sequences,
    cache_operation_display_id_sequences TO cdnca_control_app;
