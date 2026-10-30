LOCK TABLE schema_migrations, challenge_site_bindings_138 IN ACCESS EXCLUSIVE MODE;

DO $migration_345_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 345 OR
       (SELECT max(version) FROM schema_migrations) <> 345 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=345 AND
        migration_id='345_challenge_wildcard_site_binding' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 345 down requires the exact verified migration head' USING ERRCODE='P3451';
    END IF;
    -- 138's guard cannot hold a binding whose host is not the site domain: a
    -- wildcard site's live JS challenge must not silently become unbindable.
    IF EXISTS (
        SELECT 1 FROM challenge_site_bindings_138 binding
        JOIN sites site ON site.scope_id = binding.tenant_scope_id AND site.id = binding.site_id
        WHERE binding.host <> site.domain
    ) THEN
        RAISE EXCEPTION 'migration 345 down refuses to orphan wildcard site challenge bindings' USING ERRCODE='P3453';
    END IF;
END;
$migration_345_down$;

DROP TRIGGER challenge_site_bindings_protected_345 ON challenge_site_bindings_138;
CREATE TRIGGER challenge_site_bindings_protected_138
BEFORE INSERT OR UPDATE OR DELETE ON challenge_site_bindings_138
FOR EACH ROW EXECUTE FUNCTION protect_challenge_site_binding_138();
DROP FUNCTION protect_challenge_site_binding_345();
