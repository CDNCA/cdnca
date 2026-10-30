LOCK TABLE sites IN ACCESS EXCLUSIVE MODE;

DO $$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 81 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 81 THEN
        RAISE EXCEPTION 'site groups require frozen migration head 081'
            USING ERRCODE = 'P8200';
    END IF;
END;
$$;

CREATE FUNCTION site_group_trim_name_082(value text)
RETURNS text
LANGUAGE sql
IMMUTABLE
STRICT
PARALLEL SAFE
AS $$
    SELECT btrim(value,
        chr(9) || chr(10) || chr(11) || chr(12) || chr(13) || chr(32) ||
        chr(133) || chr(160) || chr(5760) || chr(8192) || chr(8193) ||
        chr(8194) || chr(8195) || chr(8196) || chr(8197) || chr(8198) ||
        chr(8199) || chr(8200) || chr(8201) || chr(8202) || chr(8232) ||
        chr(8233) || chr(8239) || chr(8287) || chr(12288));
$$;

CREATE FUNCTION site_group_name_is_valid_082(value text)
RETURNS boolean
LANGUAGE sql
IMMUTABLE
STRICT
PARALLEL SAFE
AS $$
    SELECT value = site_group_trim_name_082(value)
       AND char_length(value) BETWEEN 1 AND 128
       AND NOT EXISTS (
           SELECT 1
           FROM generate_series(1, char_length(value)) AS position
           WHERE ascii(substr(value, position, 1)) BETWEEN 0 AND 31
              OR ascii(substr(value, position, 1)) BETWEEN 127 AND 159
       );
$$;

DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM sites
        WHERE (group_id IS NULL) <> (group_name IS NULL)
           OR (group_name IS NOT NULL AND NOT site_group_name_is_valid_082(group_name))
    ) THEN
        RAISE EXCEPTION 'legacy site group fields are invalid'
            USING ERRCODE = 'P8201';
    END IF;
    IF EXISTS (
        SELECT 1 FROM sites
        WHERE group_id IS NOT NULL
        GROUP BY scope_id, group_id
        HAVING count(DISTINCT group_name) <> 1
    ) THEN
        RAISE EXCEPTION 'legacy site group names are inconsistent'
            USING ERRCODE = 'P8202';
    END IF;
    IF EXISTS (
        SELECT 1 FROM sites
        WHERE group_id IS NOT NULL
        GROUP BY scope_id, group_name
        HAVING count(DISTINCT group_id) <> 1
    ) THEN
        RAISE EXCEPTION 'legacy site group names identify multiple groups'
            USING ERRCODE = 'P8203';
    END IF;
    IF EXISTS (
        SELECT 1
        FROM sites site
        JOIN access_scopes scope ON scope.id = site.scope_id
        WHERE site.group_id IS NOT NULL AND scope.kind <> 'tenant'
    ) THEN
        RAISE EXCEPTION 'legacy site groups must belong to tenant scopes'
            USING ERRCODE = 'P8204';
    END IF;
END;
$$;

CREATE TABLE site_groups (
    id uuid NOT NULL,
    scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE RESTRICT,
    name text NOT NULL CHECK (site_group_name_is_valid_082(name)),
    revision bigint NOT NULL DEFAULT 1 CHECK (revision > 0),
    active boolean NOT NULL DEFAULT true,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    deleted_at timestamptz,
    PRIMARY KEY (scope_id, id),
    UNIQUE (scope_id, id, name),
    UNIQUE (scope_id, id, active),
    CHECK (active = (deleted_at IS NULL)),
    CHECK (updated_at >= created_at),
    CHECK (deleted_at IS NULL OR deleted_at >= created_at)
);

CREATE UNIQUE INDEX site_groups_scope_name_active_idx
    ON site_groups(scope_id, name) WHERE deleted_at IS NULL;
CREATE INDEX site_groups_scope_created_active_idx
    ON site_groups(scope_id, created_at, id) WHERE deleted_at IS NULL;

CREATE FUNCTION validate_site_group_scope_082()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    PERFORM 1 FROM access_scopes
    WHERE id = NEW.scope_id AND kind = 'tenant'
    FOR KEY SHARE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'site groups require a tenant target scope'
            USING ERRCODE = 'P8204';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER site_groups_validate_scope_082
BEFORE INSERT OR UPDATE OF scope_id ON site_groups
FOR EACH ROW EXECUTE FUNCTION validate_site_group_scope_082();

INSERT INTO site_groups(id, scope_id, name, revision, created_at, updated_at)
SELECT group_id, scope_id, min(group_name), 1, min(created_at), max(updated_at)
FROM sites
WHERE group_id IS NOT NULL
GROUP BY scope_id, group_id;

ALTER TABLE sites ADD COLUMN group_active boolean;
UPDATE sites SET group_active = true WHERE group_id IS NOT NULL;

ALTER TABLE sites
    ADD CONSTRAINT sites_group_reference_pair_082 CHECK (
        (group_id IS NULL AND group_name IS NULL AND group_active IS NULL) OR
        (group_id IS NOT NULL AND group_name IS NOT NULL AND group_active IS TRUE)
    ),
    ADD CONSTRAINT sites_group_reference_exact_082
        FOREIGN KEY(scope_id, group_id, group_name)
        REFERENCES site_groups(scope_id, id, name)
        ON UPDATE CASCADE ON DELETE RESTRICT,
    ADD CONSTRAINT sites_group_reference_active_082
        FOREIGN KEY(scope_id, group_id, group_active)
        REFERENCES site_groups(scope_id, id, active)
        ON UPDATE CASCADE ON DELETE RESTRICT;

CREATE FUNCTION validate_site_group_reference_082()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.group_id IS NULL AND NEW.group_name IS NULL THEN
        NEW.group_active := NULL;
        RETURN NEW;
    END IF;
    IF NEW.group_id IS NULL OR NEW.group_name IS NULL THEN
        RAISE EXCEPTION 'site group reference fields must be paired'
            USING ERRCODE = 'P8205';
    END IF;
    NEW.group_active := true;
    PERFORM 1 FROM site_groups
    WHERE scope_id = NEW.scope_id
      AND id = NEW.group_id
      AND name = NEW.group_name
      AND active
      AND deleted_at IS NULL
    FOR SHARE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'site group reference is not an exact active resource'
            USING ERRCODE = 'P8206';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER sites_validate_group_reference_082
BEFORE INSERT OR UPDATE OF scope_id, group_id, group_name, group_active ON sites
FOR EACH ROW EXECUTE FUNCTION validate_site_group_reference_082();

CREATE FUNCTION guard_site_group_mutation_082()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'site groups cannot be hard deleted'
            USING ERRCODE = 'P8208';
    END IF;
    IF OLD.deleted_at IS NOT NULL THEN
        RAISE EXCEPTION 'deleted site groups cannot be mutated or restored'
            USING ERRCODE = 'P8209';
    END IF;
    IF NEW.id IS DISTINCT FROM OLD.id OR NEW.scope_id IS DISTINCT FROM OLD.scope_id OR
       NEW.created_at IS DISTINCT FROM OLD.created_at THEN
        RAISE EXCEPTION 'site group identity is immutable'
            USING ERRCODE = 'P8209';
    END IF;
    IF NEW.name IS DISTINCT FROM OLD.name OR NEW.active IS DISTINCT FROM OLD.active OR
       NEW.deleted_at IS DISTINCT FROM OLD.deleted_at THEN
        IF NEW.revision <> OLD.revision + 1 OR NEW.updated_at < OLD.updated_at THEN
            RAISE EXCEPTION 'site group revision must advance exactly once'
                USING ERRCODE = 'P8209';
        END IF;
    ELSIF NEW.revision IS DISTINCT FROM OLD.revision THEN
        RAISE EXCEPTION 'site group revision cannot change without a resource mutation'
            USING ERRCODE = 'P8209';
    END IF;
    IF OLD.deleted_at IS NULL AND NEW.deleted_at IS NOT NULL AND EXISTS (
        SELECT 1 FROM sites
        WHERE scope_id = OLD.scope_id AND group_id = OLD.id
    ) THEN
        RAISE EXCEPTION 'site group is referenced by a site'
            USING ERRCODE = 'P8207';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER site_groups_guard_mutation_082
BEFORE UPDATE OR DELETE ON site_groups
FOR EACH ROW EXECUTE FUNCTION guard_site_group_mutation_082();

CREATE FUNCTION prevent_site_group_truncate_082()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'site groups cannot be truncated'
        USING ERRCODE = 'P8208';
END;
$$;

CREATE TRIGGER site_groups_prevent_truncate_082
BEFORE TRUNCATE ON site_groups
FOR EACH STATEMENT EXECUTE FUNCTION prevent_site_group_truncate_082();

CREATE TABLE site_group_write_requests (
    id uuid PRIMARY KEY,
    actor_user_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    actor_scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE RESTRICT,
    target_scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE RESTRICT,
    operation text NOT NULL CHECK (operation IN (
        'site_group.create', 'site_group.rename', 'site_group.delete'
    )),
    idempotency_key text NOT NULL CHECK (
        idempotency_key ~ '^[A-Za-z0-9._-]{1,128}$'
    ),
    request_digest bytea NOT NULL CHECK (octet_length(request_digest) = 32),
    resource_id uuid NOT NULL,
    response_status integer CHECK (response_status BETWEEN 200 AND 299),
    response_body jsonb CHECK (response_body IS NULL OR jsonb_typeof(response_body) = 'object'),
    created_at timestamptz NOT NULL DEFAULT now(),
    completed_at timestamptz,
    UNIQUE(actor_user_id, actor_scope_id, operation, idempotency_key),
    CHECK (
        (completed_at IS NULL AND response_status IS NULL AND response_body IS NULL) OR
        (completed_at IS NOT NULL AND response_status IS NOT NULL AND response_body IS NOT NULL)
    )
);

CREATE INDEX site_group_write_requests_target_created_idx
    ON site_group_write_requests(target_scope_id, created_at DESC);

CREATE FUNCTION prevent_site_group_write_request_mutation_082()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'UPDATE' AND
       NEW.id = OLD.id AND
       NEW.actor_user_id = OLD.actor_user_id AND
       NEW.actor_scope_id = OLD.actor_scope_id AND
       NEW.target_scope_id = OLD.target_scope_id AND
       NEW.operation = OLD.operation AND
       NEW.idempotency_key = OLD.idempotency_key AND
       NEW.request_digest = OLD.request_digest AND
       NEW.resource_id = OLD.resource_id AND
       OLD.completed_at IS NULL AND NEW.completed_at IS NOT NULL AND
       OLD.response_status IS NULL AND NEW.response_status IS NOT NULL AND
       OLD.response_body IS NULL AND NEW.response_body IS NOT NULL AND
       NEW.created_at = OLD.created_at THEN
        RETURN NEW;
    END IF;
    RAISE EXCEPTION 'site group write receipts are immutable after completion'
        USING ERRCODE = 'P8212';
END;
$$;

CREATE TRIGGER site_group_write_requests_immutable_082
BEFORE UPDATE OR DELETE ON site_group_write_requests
FOR EACH ROW EXECUTE FUNCTION prevent_site_group_write_request_mutation_082();

CREATE TRIGGER site_group_write_requests_prevent_truncate_082
BEFORE TRUNCATE ON site_group_write_requests
FOR EACH STATEMENT EXECUTE FUNCTION prevent_site_group_write_request_mutation_082();
