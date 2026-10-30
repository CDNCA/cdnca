LOCK TABLE schema_migrations, certificate_assets IN ACCESS EXCLUSIVE MODE;

DO $migration_276_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 275 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 275 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=275 AND
        migration_id='275_node_line_endpoint_display_ids' AND
        checksum_sha256='4bad15845ee9443d6549666f558c0b2fb70437cc63e09ee718db4bfb3d26c214' AND
        down_checksum_sha256='17f22069d8b7ed032746b58721975df0aec2fe6e46571036f417ffa6767c289e' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR checksum_sha256 IS NULL OR
        down_checksum_sha256 IS NULL OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) THEN
        RAISE EXCEPTION 'migration 276 requires the exact verified 275 release head' USING ERRCODE='P2760';
    END IF;
END;
$migration_276_up$;

-- No backfill: the uploading actor does not establish a certificate's owner.
ALTER TABLE certificate_assets ADD COLUMN owner_user_id uuid
    REFERENCES users(id) ON DELETE RESTRICT;

CREATE FUNCTION protect_certificate_asset_owner_276() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF NEW.owner_user_id IS DISTINCT FROM OLD.owner_user_id THEN
        RAISE EXCEPTION 'certificate asset owner is immutable' USING ERRCODE='P2761';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER certificate_assets_owner_immutable_276 BEFORE UPDATE OF owner_user_id ON certificate_assets
FOR EACH ROW EXECUTE FUNCTION protect_certificate_asset_owner_276();
REVOKE ALL ON FUNCTION protect_certificate_asset_owner_276() FROM PUBLIC,cdnca_control_app;
