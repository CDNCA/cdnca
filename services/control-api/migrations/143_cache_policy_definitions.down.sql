LOCK TABLE schema_migrations, cache_policy_heads, cache_policy_revisions,
    cache_policy_definition_heads, cache_policy_definition_revisions
IN ACCESS EXCLUSIVE MODE;

DO $migration_143$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 143 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 143 OR EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE migration_id IS NULL OR migration_id = '' OR
              checksum_sha256 IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
              down_checksum_sha256 IS NULL OR down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR
              integrity_state IS DISTINCT FROM 'verified' OR
              metadata_recorded_at IS NULL OR applied_at IS NULL
    ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version = 143 AND migration_id = '143_cache_policy_definitions' AND
              checksum_sha256 = 'bbe9d4210c9cd5d58a831e210a5a57586723824d25c1deb70cabcdf5efbd8147' AND
              integrity_state = 'verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
    ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version = 142 AND migration_id = '142_cache_policy_schema_v2' AND
              checksum_sha256 = '49efd140a0340330159d97baa9573b2a82992a76a5a596e19450bf1bb2fc5e25' AND
              down_checksum_sha256 = '36fd6ac4f28a4381d3b66ede33d81c2abbb01661cdeabae6fdd39341d5b9e52c' AND
              integrity_state = 'verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
    ) THEN
        RAISE EXCEPTION 'migration 143 rollback requires the exact verified 143 head'
            USING ERRCODE = 'P1430';
    END IF;
    IF EXISTS (
        SELECT 1
        FROM cache_policy_revisions revision
        WHERE revision.binding_mode <> 'override' OR revision.definition_id <> revision.site_id OR
              revision.definition_revision <> revision.revision
    ) OR EXISTS (
        SELECT 1
        FROM cache_policy_definition_revisions definition
        LEFT JOIN cache_policy_revisions revision
          ON revision.scope_id = definition.scope_id
         AND revision.site_id = definition.source_site_id
         AND revision.revision = definition.revision
         AND revision.definition_id = definition.definition_id
         AND revision.definition_revision = definition.revision
        WHERE revision.site_id IS NULL OR definition.definition_id <> definition.source_site_id
    ) OR EXISTS (
        SELECT 1
        FROM cache_policy_definition_heads definition
        LEFT JOIN cache_policy_heads policy
          ON policy.scope_id = definition.scope_id AND policy.site_id = definition.definition_id
         AND policy.current_revision = definition.current_revision
        WHERE policy.site_id IS NULL
    ) THEN
        RAISE EXCEPTION 'migration 143 rollback would discard reusable cache policy bindings'
            USING ERRCODE = 'P1437';
    END IF;
END;
$migration_143$;

DROP TRIGGER cache_policy_revisions_binding_validate_143 ON cache_policy_revisions;
DROP FUNCTION validate_cache_policy_binding_143();

ALTER TABLE cache_policy_revisions
    DROP CONSTRAINT cache_policy_revisions_definition_143_fk,
    DROP CONSTRAINT cache_policy_revisions_definition_revision_143_check,
    DROP CONSTRAINT cache_policy_revisions_binding_mode_143_check,
    DROP COLUMN definition_revision,
    DROP COLUMN definition_id,
    DROP COLUMN binding_mode;

DROP TRIGGER cache_policy_definition_revisions_no_truncate_143 ON cache_policy_definition_revisions;
DROP TRIGGER cache_policy_definition_heads_no_truncate_143 ON cache_policy_definition_heads;
DROP FUNCTION prevent_cache_policy_definition_truncate_143();
DROP TRIGGER cache_policy_definition_revisions_integrity_143 ON cache_policy_definition_revisions;
DROP TRIGGER cache_policy_definition_heads_integrity_143 ON cache_policy_definition_heads;
DROP FUNCTION validate_cache_policy_definition_integrity_143();
DROP TRIGGER cache_policy_definition_revisions_append_only_143 ON cache_policy_definition_revisions;
DROP FUNCTION protect_cache_policy_definition_revision_143();
DROP TRIGGER cache_policy_definition_heads_protected_143 ON cache_policy_definition_heads;
DROP FUNCTION protect_cache_policy_definition_head_143();

ALTER TABLE cache_policy_definition_heads
    DROP CONSTRAINT cache_policy_definition_heads_current_143_fk;
DROP TABLE cache_policy_definition_revisions;
DROP TABLE cache_policy_definition_heads;
