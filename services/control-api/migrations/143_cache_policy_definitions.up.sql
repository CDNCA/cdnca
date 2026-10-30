LOCK TABLE schema_migrations, cache_policy_heads, cache_policy_revisions,
    sites, access_scopes, memberships IN ACCESS EXCLUSIVE MODE;

DO $migration_143$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 142 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 142 OR EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE migration_id IS NULL OR migration_id = '' OR
              checksum_sha256 IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
              down_checksum_sha256 IS NULL OR down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR
              integrity_state IS DISTINCT FROM 'verified' OR
              metadata_recorded_at IS NULL OR applied_at IS NULL
    ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version = 142 AND migration_id = '142_cache_policy_schema_v2' AND
              checksum_sha256 = '49efd140a0340330159d97baa9573b2a82992a76a5a596e19450bf1bb2fc5e25' AND
              down_checksum_sha256 = '36fd6ac4f28a4381d3b66ede33d81c2abbb01661cdeabae6fdd39341d5b9e52c' AND
              integrity_state = 'verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
    ) THEN
        RAISE EXCEPTION 'migration 143 requires the exact verified 142 release head'
            USING ERRCODE = 'P1430';
    END IF;
END;
$migration_143$;

CREATE TABLE cache_policy_definition_heads (
    scope_id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    definition_id uuid NOT NULL,
    current_revision bigint NOT NULL CHECK (current_revision > 0),
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    PRIMARY KEY (scope_id,definition_id),
    UNIQUE (scope_id,definition_id,current_revision),
    FOREIGN KEY (scope_id,tenant_id)
        REFERENCES access_scopes(id,tenant_id) ON DELETE RESTRICT,
    CHECK (updated_at >= created_at)
);

CREATE TABLE cache_policy_definition_revisions (
    scope_id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    definition_id uuid NOT NULL,
    revision bigint NOT NULL CHECK (revision > 0),
    source_site_id uuid NOT NULL,
    schema_version smallint NOT NULL CHECK (schema_version IN (1,2)),
    mode text NOT NULL CHECK (mode IN ('disabled','follow_origin','override')),
    rules jsonb NOT NULL CHECK (
        jsonb_typeof(rules) = 'array' AND jsonb_array_length(rules) <= 100
    ),
    query_mode text NOT NULL CHECK (query_mode IN ('preserve','ignore','include','exclude')),
    query_names text[] NOT NULL DEFAULT ARRAY[]::text[] CHECK (cardinality(query_names) <= 64),
    vary_headers text[] NOT NULL DEFAULT ARRAY[]::text[] CHECK (cardinality(vary_headers) <= 16),
    disk_quota_bytes bigint NOT NULL CHECK (disk_quota_bytes BETWEEN 0 AND 17592186044416),
    request_digest bytea NOT NULL CHECK (octet_length(request_digest) = 32),
    actor_scope_id uuid NOT NULL,
    created_by_user_id uuid NOT NULL,
    request_id text NOT NULL CHECK (
        char_length(request_id) BETWEEN 1 AND 128 AND request_id = btrim(request_id) AND
        request_id !~ '[[:cntrl:]]' AND position(U&'\2028' in request_id) = 0 AND
        position(U&'\2029' in request_id) = 0
    ),
    created_at timestamptz NOT NULL,
    PRIMARY KEY (scope_id,definition_id,revision),
    FOREIGN KEY (scope_id,definition_id)
        REFERENCES cache_policy_definition_heads(scope_id,definition_id) ON DELETE RESTRICT,
    FOREIGN KEY (scope_id,tenant_id)
        REFERENCES access_scopes(id,tenant_id) ON DELETE RESTRICT,
    FOREIGN KEY (scope_id,source_site_id)
        REFERENCES sites(scope_id,id) ON DELETE RESTRICT,
    FOREIGN KEY (actor_scope_id,created_by_user_id)
        REFERENCES memberships(scope_id,user_id) ON DELETE RESTRICT,
    CHECK (
        (mode = 'disabled' AND jsonb_array_length(rules) = 0 AND disk_quota_bytes = 0) OR
        (mode = 'follow_origin' AND jsonb_array_length(rules) = 0 AND disk_quota_bytes > 0) OR
        (mode = 'override' AND jsonb_array_length(rules) > 0 AND disk_quota_bytes > 0)
    ),
    CHECK (
        (query_mode IN ('preserve','ignore') AND cardinality(query_names) = 0) OR
        (query_mode IN ('include','exclude') AND cardinality(query_names) > 0)
    )
);

CREATE INDEX cache_policy_definition_revisions_scope_created_143_idx
    ON cache_policy_definition_revisions(scope_id,created_at DESC,definition_id,revision DESC);

INSERT INTO cache_policy_definition_heads (
    scope_id,tenant_id,definition_id,current_revision,created_at,updated_at
)
SELECT scope_id,tenant_id,site_id,current_revision,created_at,updated_at
FROM cache_policy_heads;

INSERT INTO cache_policy_definition_revisions (
    scope_id,tenant_id,definition_id,revision,source_site_id,schema_version,mode,rules,
    query_mode,query_names,vary_headers,disk_quota_bytes,request_digest,actor_scope_id,
    created_by_user_id,request_id,created_at
)
SELECT scope_id,tenant_id,site_id,revision,site_id,schema_version,mode,rules,
       query_mode,query_names,vary_headers,disk_quota_bytes,request_digest,actor_scope_id,
       created_by_user_id,request_id,created_at
FROM cache_policy_revisions;

ALTER TABLE cache_policy_definition_heads
    ADD CONSTRAINT cache_policy_definition_heads_current_143_fk
    FOREIGN KEY (scope_id,definition_id,current_revision)
    REFERENCES cache_policy_definition_revisions(scope_id,definition_id,revision)
    ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED;

ALTER TABLE cache_policy_revisions
    ADD COLUMN binding_mode text,
    ADD COLUMN definition_id uuid,
    ADD COLUMN definition_revision bigint;

ALTER TABLE cache_policy_revisions DISABLE TRIGGER cache_policy_revisions_append_only;
UPDATE cache_policy_revisions
SET binding_mode = 'override', definition_id = site_id, definition_revision = revision;
ALTER TABLE cache_policy_revisions ENABLE TRIGGER cache_policy_revisions_append_only;

ALTER TABLE cache_policy_revisions
    ALTER COLUMN binding_mode SET NOT NULL,
    ALTER COLUMN definition_id SET NOT NULL,
    ALTER COLUMN definition_revision SET NOT NULL,
    ADD CONSTRAINT cache_policy_revisions_binding_mode_143_check
        CHECK (binding_mode IN ('inherit','override')),
    ADD CONSTRAINT cache_policy_revisions_definition_revision_143_check
        CHECK (definition_revision > 0),
    ADD CONSTRAINT cache_policy_revisions_definition_143_fk
        FOREIGN KEY (scope_id,definition_id,definition_revision)
        REFERENCES cache_policy_definition_revisions(scope_id,definition_id,revision)
        ON DELETE RESTRICT;

CREATE FUNCTION validate_cache_policy_binding_143()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    definition cache_policy_definition_revisions%ROWTYPE;
BEGIN
    SELECT * INTO definition
    FROM cache_policy_definition_revisions
    WHERE scope_id = NEW.scope_id AND definition_id = NEW.definition_id
      AND revision = NEW.definition_revision
    FOR SHARE;
    IF NOT FOUND OR definition.tenant_id IS DISTINCT FROM NEW.tenant_id OR
       definition.schema_version IS DISTINCT FROM NEW.schema_version OR
       definition.mode IS DISTINCT FROM NEW.mode OR definition.rules IS DISTINCT FROM NEW.rules OR
       definition.query_mode IS DISTINCT FROM NEW.query_mode OR
       definition.query_names IS DISTINCT FROM NEW.query_names OR
       definition.vary_headers IS DISTINCT FROM NEW.vary_headers OR
       definition.disk_quota_bytes IS DISTINCT FROM NEW.disk_quota_bytes THEN
        RAISE EXCEPTION 'cache policy binding document does not match definition revision'
            USING ERRCODE = 'P1431';
    END IF;
    IF NEW.binding_mode = 'override' AND definition.source_site_id IS DISTINCT FROM NEW.site_id THEN
        RAISE EXCEPTION 'cache policy override definition source does not match site'
            USING ERRCODE = 'P1432';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER cache_policy_revisions_binding_validate_143
BEFORE INSERT OR UPDATE ON cache_policy_revisions
FOR EACH ROW EXECUTE FUNCTION validate_cache_policy_binding_143();

CREATE FUNCTION protect_cache_policy_definition_revision_143()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'cache policy definition revisions are append-only'
        USING ERRCODE = 'P1433';
END;
$$;

CREATE TRIGGER cache_policy_definition_revisions_append_only_143
BEFORE UPDATE OR DELETE ON cache_policy_definition_revisions
FOR EACH ROW EXECUTE FUNCTION protect_cache_policy_definition_revision_143();

CREATE FUNCTION protect_cache_policy_definition_head_143()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'DELETE' OR
       ROW(NEW.scope_id,NEW.tenant_id,NEW.definition_id,NEW.created_at)
       IS DISTINCT FROM ROW(OLD.scope_id,OLD.tenant_id,OLD.definition_id,OLD.created_at) OR
       NEW.current_revision <> OLD.current_revision + 1 OR NEW.updated_at < OLD.updated_at THEN
        RAISE EXCEPTION 'invalid cache policy definition head transition'
            USING ERRCODE = 'P1434';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER cache_policy_definition_heads_protected_143
BEFORE UPDATE OR DELETE ON cache_policy_definition_heads
FOR EACH ROW EXECUTE FUNCTION protect_cache_policy_definition_head_143();

CREATE FUNCTION validate_cache_policy_definition_integrity_143()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    checked_scope_id uuid := COALESCE(NEW.scope_id,OLD.scope_id);
    checked_definition_id uuid := COALESCE(NEW.definition_id,OLD.definition_id);
    head_revision bigint;
    minimum_revision bigint;
    maximum_revision bigint;
    revision_count bigint;
BEGIN
    SELECT current_revision INTO head_revision
    FROM cache_policy_definition_heads
    WHERE scope_id = checked_scope_id AND definition_id = checked_definition_id;
    SELECT min(revision),max(revision),count(*)
    INTO minimum_revision,maximum_revision,revision_count
    FROM cache_policy_definition_revisions
    WHERE scope_id = checked_scope_id AND definition_id = checked_definition_id;
    IF head_revision IS NULL OR minimum_revision <> 1 OR maximum_revision <> head_revision OR
       revision_count <> head_revision THEN
        RAISE EXCEPTION 'cache policy definition history is not contiguous'
            USING ERRCODE = 'P1435';
    END IF;
    RETURN NULL;
END;
$$;

CREATE CONSTRAINT TRIGGER cache_policy_definition_heads_integrity_143
AFTER INSERT OR UPDATE OR DELETE ON cache_policy_definition_heads
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION validate_cache_policy_definition_integrity_143();

CREATE CONSTRAINT TRIGGER cache_policy_definition_revisions_integrity_143
AFTER INSERT OR UPDATE OR DELETE ON cache_policy_definition_revisions
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION validate_cache_policy_definition_integrity_143();

CREATE FUNCTION prevent_cache_policy_definition_truncate_143()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'cache policy definition tables cannot be truncated'
        USING ERRCODE = 'P1436';
END;
$$;

CREATE TRIGGER cache_policy_definition_heads_no_truncate_143
BEFORE TRUNCATE ON cache_policy_definition_heads
FOR EACH STATEMENT EXECUTE FUNCTION prevent_cache_policy_definition_truncate_143();

CREATE TRIGGER cache_policy_definition_revisions_no_truncate_143
BEFORE TRUNCATE ON cache_policy_definition_revisions
FOR EACH STATEMENT EXECUTE FUNCTION prevent_cache_policy_definition_truncate_143();
