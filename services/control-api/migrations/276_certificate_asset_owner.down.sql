LOCK TABLE schema_migrations, certificate_assets IN ACCESS EXCLUSIVE MODE;

DO $migration_276_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 276 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 276 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=276 AND
        migration_id='276_certificate_asset_owner' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 276 down requires the exact verified migration head' USING ERRCODE='P2760';
    END IF;
    IF EXISTS (SELECT 1 FROM certificate_assets WHERE owner_user_id IS NOT NULL) THEN
        RAISE EXCEPTION 'migration 276 down refuses to discard recorded certificate owners' USING ERRCODE='P2762';
    END IF;
END;
$migration_276_down$;

DROP TRIGGER certificate_assets_owner_immutable_276 ON certificate_assets;
DROP FUNCTION protect_certificate_asset_owner_276();
ALTER TABLE certificate_assets DROP COLUMN owner_user_id;
