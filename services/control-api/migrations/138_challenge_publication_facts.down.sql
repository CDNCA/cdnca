LOCK TABLE schema_migrations, challenge_site_binding_revisions_138,
    challenge_site_bindings_138, challenge_key_facts_138 IN ACCESS EXCLUSIVE MODE;

DO $migration_138$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 138 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 138 OR EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE migration_id IS NULL OR migration_id = '' OR
              checksum_sha256 IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
              down_checksum_sha256 IS NULL OR down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR
              integrity_state IS DISTINCT FROM 'verified' OR
              metadata_recorded_at IS NULL OR applied_at IS NULL
    ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version = 138 AND migration_id = '138_challenge_publication_facts' AND
              checksum_sha256 = '14399e504508dbe31dd78711d22ef2c2f4e5a20aad0fc299ee355553e3a3ae9e' AND
              integrity_state = 'verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
    ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version = 137 AND migration_id = '137_tcp_billing_factor' AND
              checksum_sha256 = '741cabd2ca7d32915d7c2a5e13f42a75ccd9888f3662be8f572cacd3b6d7a4df' AND
              down_checksum_sha256 = 'c6d3329f35c73745eaaef8a9d75aaf4f16ee925aef8d4145211152ea2669923b' AND
              integrity_state = 'verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
    ) THEN
        RAISE EXCEPTION 'migration 138 rollback requires the exact verified 138 head'
            USING ERRCODE = 'P1380';
    END IF;
    IF EXISTS (SELECT 1 FROM challenge_site_binding_revisions_138) OR
       EXISTS (SELECT 1 FROM challenge_site_bindings_138) OR
       EXISTS (SELECT 1 FROM challenge_key_facts_138) THEN
        RAISE EXCEPTION 'migration 138 rollback would discard durable challenge publication facts'
            USING ERRCODE = 'P138A';
    END IF;
END;
$migration_138$;

DROP TRIGGER challenge_site_bindings_no_truncate_138 ON challenge_site_bindings_138;
DROP TRIGGER challenge_site_bindings_protected_138 ON challenge_site_bindings_138;
DROP TRIGGER challenge_binding_revisions_no_truncate_138 ON challenge_site_binding_revisions_138;
DROP TRIGGER challenge_binding_revisions_no_delete_138 ON challenge_site_binding_revisions_138;
DROP TRIGGER challenge_binding_revisions_validate_138 ON challenge_site_binding_revisions_138;
DROP TRIGGER challenge_key_facts_no_truncate_138 ON challenge_key_facts_138;
DROP TRIGGER challenge_key_facts_immutable_138 ON challenge_key_facts_138;
DROP TRIGGER challenge_key_facts_validate_138 ON challenge_key_facts_138;

ALTER TABLE challenge_site_bindings_138
    DROP CONSTRAINT challenge_site_bindings_active_revision_138_fk,
    DROP CONSTRAINT challenge_site_bindings_lkg_revision_138_fk;
ALTER TABLE challenge_site_binding_revisions_138
    DROP CONSTRAINT challenge_binding_revisions_binding_138_fk;

DROP TABLE challenge_site_binding_revisions_138;
DROP TABLE challenge_site_bindings_138;
DROP TABLE challenge_key_facts_138;

DROP FUNCTION prevent_challenge_fact_mutation_138();
DROP FUNCTION protect_challenge_site_binding_138();
DROP FUNCTION validate_challenge_binding_revision_138();
DROP FUNCTION validate_challenge_key_fact_138();
