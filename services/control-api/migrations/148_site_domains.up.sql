LOCK TABLE schema_migrations, permissions, custom_rbac_permission_catalog, roles, role_permissions,
    access_scopes, memberships, sites IN ACCESS EXCLUSIVE MODE;

DO $migration_148$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 147 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 147 OR EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE migration_id IS NULL OR migration_id = '' OR
              checksum_sha256 IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
              down_checksum_sha256 IS NULL OR down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR
              integrity_state IS DISTINCT FROM 'verified' OR
              metadata_recorded_at IS NULL OR applied_at IS NULL
    ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version = 147 AND migration_id = '147_site_capture_policy' AND
              checksum_sha256 = '353df42d5169317c797469af9341f827d16f51ba7312b2f4185326bc4934cab0' AND
              down_checksum_sha256 = 'e536c664a82d23e7b61d89380c69f22476770e5eaa0a5c3bd69de6bad3c02ede' AND
              integrity_state = 'verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
    ) OR to_regclass('site_domain_facts') IS NOT NULL OR
         to_regclass('site_domain_export_snapshots') IS NOT NULL OR
         to_regclass('site_domain_export_rows') IS NOT NULL THEN
        RAISE EXCEPTION 'migration 148 requires the exact verified 147 release head'
            USING ERRCODE = 'P1480';
    END IF;
END;
$migration_148$;

INSERT INTO permissions(name,description)
VALUES ('sites.export','Export immutable site domain snapshots');
INSERT INTO custom_rbac_permission_catalog(permission_name,step_up_required)
VALUES ('sites.export',false);
INSERT INTO role_permissions(role_id,permission_name)
SELECT id,'sites.export' FROM roles
WHERE system_role AND name IN ('platform_owner','tenant_owner','tenant_viewer')
ON CONFLICT DO NOTHING;

CREATE FUNCTION grant_site_domain_permissions_148()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.system_role AND NEW.name IN ('platform_owner','tenant_owner','tenant_viewer') THEN
        INSERT INTO role_permissions(role_id,permission_name)
        VALUES(NEW.id,'sites.export') ON CONFLICT DO NOTHING;
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER roles_site_domain_permissions_148
AFTER INSERT ON roles FOR EACH ROW EXECUTE FUNCTION grant_site_domain_permissions_148();

CREATE TABLE site_domain_facts (
    global_sequence bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    scope_id uuid NOT NULL,
    site_id uuid NOT NULL,
    site_revision bigint NOT NULL CHECK (site_revision > 0 AND site_revision <= 9007199254740991),
    action text NOT NULL CHECK (action IN ('activate','deactivate')),
    canonical_domain text NOT NULL CHECK (
        canonical_domain = lower(canonical_domain) AND
        canonical_domain ~ '^(\*\.)?([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$' AND
        length(canonical_domain) <= 253
    ),
    actor_scope_id uuid NOT NULL,
    actor_user_id uuid NOT NULL,
    request_id text NOT NULL CHECK (request_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'),
    occurred_at timestamptz NOT NULL CHECK (isfinite(occurred_at)),
    FOREIGN KEY (scope_id,site_id) REFERENCES sites(scope_id,id) ON DELETE RESTRICT,
    FOREIGN KEY (actor_scope_id,actor_user_id) REFERENCES memberships(scope_id,user_id) ON DELETE RESTRICT
);
CREATE INDEX site_domain_facts_site_148_idx
    ON site_domain_facts(scope_id,site_id,canonical_domain,global_sequence DESC);
CREATE INDEX site_domain_facts_domain_148_idx
    ON site_domain_facts(canonical_domain,global_sequence DESC);

CREATE FUNCTION guard_site_domain_fact_148()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    candidate_base text := regexp_replace(NEW.canonical_domain,'^\*\.','');
BEGIN
    PERFORM pg_advisory_xact_lock(148, 1);
    IF NEW.action = 'activate' AND EXISTS (
        WITH latest AS (
            SELECT DISTINCT ON (canonical_domain) scope_id,site_id,canonical_domain,action
            FROM site_domain_facts
            ORDER BY canonical_domain,global_sequence DESC
        )
        SELECT 1 FROM latest
        WHERE action='activate' AND (scope_id,site_id) <> (NEW.scope_id,NEW.site_id) AND (
            canonical_domain = NEW.canonical_domain OR
            (canonical_domain LIKE '*.%' AND NEW.canonical_domain NOT LIKE '*.%' AND
             NEW.canonical_domain LIKE '%.' || substring(canonical_domain FROM 3) AND
             array_length(string_to_array(NEW.canonical_domain,'.'),1) =
                array_length(string_to_array(substring(canonical_domain FROM 3),'.'),1) + 1) OR
            (NEW.canonical_domain LIKE '*.%' AND canonical_domain NOT LIKE '*.%' AND
             canonical_domain LIKE '%.' || candidate_base AND
             array_length(string_to_array(canonical_domain,'.'),1) =
                array_length(string_to_array(candidate_base,'.'),1) + 1)
        )
    ) THEN
        RAISE EXCEPTION 'site domain wildcard overlap'
            USING ERRCODE = '23505', CONSTRAINT = 'site_domain_facts_overlap_148';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER site_domain_facts_overlap_148
BEFORE INSERT ON site_domain_facts
FOR EACH ROW EXECUTE FUNCTION guard_site_domain_fact_148();

INSERT INTO site_domain_facts(
    scope_id,site_id,site_revision,action,canonical_domain,
    actor_scope_id,actor_user_id,request_id,occurred_at
)
SELECT site.scope_id,site.id,site.revision,'activate',site.domain,
       site.scope_id,site.owner_user_id,'migration-148-backfill',site.created_at
FROM sites site
WHERE site.deleted_at IS NULL;

CREATE TABLE site_domain_export_snapshots (
    id uuid PRIMARY KEY CHECK (id <> '00000000-0000-0000-0000-000000000000'::uuid),
    actor_user_id uuid NOT NULL,
    actor_scope_id uuid NOT NULL,
    target_scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE RESTRICT,
    filter_sha256 bytea NOT NULL CHECK (octet_length(filter_sha256)=32),
    row_count integer NOT NULL CHECK (row_count BETWEEN 0 AND 1000000),
    created_at timestamptz NOT NULL CHECK (isfinite(created_at)),
    expires_at timestamptz NOT NULL CHECK (isfinite(expires_at) AND expires_at > created_at),
    FOREIGN KEY (actor_scope_id,actor_user_id) REFERENCES memberships(scope_id,user_id) ON DELETE RESTRICT
);
CREATE TABLE site_domain_export_rows (
    snapshot_id uuid NOT NULL REFERENCES site_domain_export_snapshots(id) ON DELETE RESTRICT,
    row_sequence integer NOT NULL CHECK (row_sequence > 0),
    site_id uuid NOT NULL,
    canonical_domain text NOT NULL,
    site_revision bigint NOT NULL,
    enabled boolean NOT NULL,
    created_at timestamptz NOT NULL CHECK (isfinite(created_at)),
    PRIMARY KEY (snapshot_id,row_sequence),
    UNIQUE (snapshot_id,site_id,canonical_domain)
);

CREATE FUNCTION protect_site_domain_immutable_148()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_TABLE_NAME = 'site_domain_facts' THEN
        RAISE EXCEPTION 'site domain facts are append-only' USING ERRCODE = 'P1481';
    ELSIF TG_TABLE_NAME = 'site_domain_export_snapshots' THEN
        RAISE EXCEPTION 'site domain export snapshots are immutable' USING ERRCODE = 'P1482';
    END IF;
    RAISE EXCEPTION 'site domain export rows are immutable' USING ERRCODE = 'P1483';
END;
$$;
CREATE TRIGGER site_domain_facts_immutable_148
BEFORE UPDATE OR DELETE OR TRUNCATE ON site_domain_facts
FOR EACH STATEMENT EXECUTE FUNCTION protect_site_domain_immutable_148();
CREATE TRIGGER site_domain_export_snapshots_immutable_148
BEFORE UPDATE OR DELETE OR TRUNCATE ON site_domain_export_snapshots
FOR EACH STATEMENT EXECUTE FUNCTION protect_site_domain_immutable_148();
CREATE TRIGGER site_domain_export_rows_immutable_148
BEFORE UPDATE OR DELETE OR TRUNCATE ON site_domain_export_rows
FOR EACH STATEMENT EXECUTE FUNCTION protect_site_domain_immutable_148();

REVOKE ALL ON site_domain_facts, site_domain_export_snapshots, site_domain_export_rows FROM PUBLIC;
REVOKE ALL ON FUNCTION grant_site_domain_permissions_148() FROM PUBLIC;
REVOKE ALL ON FUNCTION guard_site_domain_fact_148() FROM PUBLIC;
REVOKE ALL ON FUNCTION protect_site_domain_immutable_148() FROM PUBLIC;
