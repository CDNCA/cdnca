LOCK TABLE schema_migrations, challenge_site_bindings_138 IN ACCESS EXCLUSIVE MODE;

DO $migration_345_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 344 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 344 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=344 AND
        migration_id='344_waf_quick_block' AND
        checksum_sha256='87d82def44efd10278d556dd200b3a12bf17fa04f6b0b1cb8ca95f45f366058b' AND
        down_checksum_sha256='938c1939ac43a039eb9239361fe6fe930a02c9ee34d0a10cb3115da8a7baf384' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR to_regprocedure(current_schema() || '.protect_challenge_site_binding_345()') IS NOT NULL OR NOT EXISTS (
        SELECT 1 FROM pg_trigger WHERE tgrelid='challenge_site_bindings_138'::regclass AND
        tgname='challenge_site_bindings_protected_138' AND
        tgfoid='protect_challenge_site_binding_138()'::regprocedure
       ) THEN
        RAISE EXCEPTION 'migration 345 requires the exact verified 344 release head' USING ERRCODE='P3450';
    END IF;
END;
$migration_345_up$;

-- JS challenge on a wildcard site (r136 wildcard-b). 053 lets a wildcard
-- site's ("*.x.example") policy name one concrete host under it, but 138's
-- binding guard required binding.host = sites.domain (and the host CHECK
-- refuses '*'), so such a policy could never be bound. The node matches the
-- bound rule by site identity, so the policy challenges every host the site
-- serves. A wildcard site's binding now names the host of its current policy
-- (covered by the wildcard, as in 053) and moves to another covered host when
-- another host's policy is bound; the active revision names the same host.
-- Every other site keeps 138's rules (host = sites.domain, host immutable).
CREATE FUNCTION protect_challenge_site_binding_345()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE site_tenant_id uuid;
DECLARE site_host text;
DECLARE revision_host text;
DECLARE wildcard boolean;
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'challenge site bindings are durable facts' USING ERRCODE = 'P1385';
    END IF;
    SELECT scope.tenant_id, site.domain INTO site_tenant_id, site_host
    FROM sites site
    JOIN access_scopes scope ON scope.id = site.scope_id AND scope.kind = 'tenant'
    WHERE site.scope_id = NEW.tenant_scope_id AND site.id = NEW.site_id
    FOR SHARE OF site, scope;
    wildcard := FOUND AND left(site_host, 2) = '*.';
    IF NOT FOUND OR site_tenant_id <> NEW.tenant_id OR NOT (
        CASE WHEN wildcard THEN
            right(NEW.host, length(site_host) - 1) = substring(site_host FROM 2) AND
            length(NEW.host) > length(site_host) - 1
        ELSE NEW.host = site_host END
    ) THEN
        RAISE EXCEPTION 'challenge site binding scope mismatch' USING ERRCODE = 'P1386';
    END IF;
    IF TG_OP = 'INSERT' THEN
        IF NEW.active_binding_revision IS NOT NULL OR NEW.lkg_binding_revision IS NOT NULL THEN
            RAISE EXCEPTION 'new challenge site binding must start empty' USING ERRCODE = 'P1387';
        END IF;
    ELSIF ROW(NEW.tenant_scope_id, NEW.tenant_id, NEW.site_id, NEW.created_at)
            IS DISTINCT FROM ROW(OLD.tenant_scope_id, OLD.tenant_id, OLD.site_id, OLD.created_at) OR
          (NEW.host IS DISTINCT FROM OLD.host AND NOT wildcard) OR
          NEW.updated_at < OLD.updated_at OR
          NEW.active_binding_revision IS NULL OR
          NOT (
              (OLD.active_binding_revision IS NULL AND NEW.active_binding_revision = 1 AND NEW.lkg_binding_revision IS NULL) OR
              (OLD.active_binding_revision IS NOT NULL AND
               NEW.active_binding_revision = OLD.active_binding_revision + 1 AND
               NEW.lkg_binding_revision = OLD.active_binding_revision)
          ) THEN
        RAISE EXCEPTION 'invalid challenge site binding promotion' USING ERRCODE = 'P1388';
    END IF;
    IF TG_OP = 'UPDATE' AND NEW.host IS DISTINCT FROM OLD.host THEN
        SELECT host INTO revision_host FROM challenge_site_binding_revisions_138
        WHERE tenant_scope_id = NEW.tenant_scope_id AND site_id = NEW.site_id
          AND binding_revision = NEW.active_binding_revision;
        IF revision_host IS DISTINCT FROM NEW.host THEN
            RAISE EXCEPTION 'challenge site binding host must be its active revision''s host'
                USING ERRCODE = 'P3452';
        END IF;
    END IF;
    RETURN NEW;
END;
$$;
REVOKE ALL ON FUNCTION protect_challenge_site_binding_345() FROM PUBLIC;

DROP TRIGGER challenge_site_bindings_protected_138 ON challenge_site_bindings_138;
CREATE TRIGGER challenge_site_bindings_protected_345
BEFORE INSERT OR UPDATE OR DELETE ON challenge_site_bindings_138
FOR EACH ROW EXECUTE FUNCTION protect_challenge_site_binding_345();
