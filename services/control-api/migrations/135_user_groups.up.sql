LOCK TABLE schema_migrations, access_scopes, users, memberships IN ACCESS EXCLUSIVE MODE;

DO $migration_135$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 134 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 134 OR EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE migration_id IS NULL OR migration_id = '' OR
              checksum_sha256 IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
              down_checksum_sha256 IS NULL OR down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR
              integrity_state IS DISTINCT FROM 'verified' OR
              metadata_recorded_at IS NULL OR applied_at IS NULL
    ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version = 134 AND migration_id = '134_global_firewall' AND
              checksum_sha256 = 'cedf471ecef9136cf9480b298d2dfb9dcdfb98c6bd34011c5d3a56d649bd1624' AND
              down_checksum_sha256 = 'c36ab4bf4bf18253d1a7e357a45d60df38c0aaded3e26f4f31118b375feae22e' AND
              integrity_state = 'verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
    ) OR to_regclass('identity_user_groups') IS NOT NULL OR
         to_regclass('identity_user_group_memberships') IS NOT NULL OR
         to_regclass('identity_user_group_write_requests') IS NOT NULL THEN
        RAISE EXCEPTION 'migration 135 requires the exact verified 134 release head'
            USING ERRCODE = 'P1350';
    END IF;
END;
$migration_135$;

CREATE TABLE identity_user_groups (
    id uuid NOT NULL,
    platform_scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE RESTRICT,
    name text NOT NULL CHECK (
        name = btrim(name) AND
        char_length(name) BETWEEN 1 AND 128 AND
        name !~ '[[:cntrl:]]'
    ),
    revision bigint NOT NULL DEFAULT 1 CHECK (revision > 0),
    created_at timestamptz NOT NULL DEFAULT now() CHECK (isfinite(created_at)),
    updated_at timestamptz NOT NULL DEFAULT now() CHECK (isfinite(updated_at) AND updated_at >= created_at),
    PRIMARY KEY (id),
    UNIQUE (platform_scope_id, id)
);

CREATE UNIQUE INDEX identity_user_groups_scope_name_idx
    ON identity_user_groups (platform_scope_id, lower(name));
CREATE INDEX identity_user_groups_scope_created_idx
    ON identity_user_groups (platform_scope_id, created_at DESC, id DESC);

CREATE FUNCTION validate_identity_user_group_135()
RETURNS trigger LANGUAGE plpgsql AS $function$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM access_scopes
        WHERE id = NEW.platform_scope_id AND kind = 'platform' AND tenant_id IS NULL
    ) THEN
        RAISE EXCEPTION 'identity user group scope must be the platform scope'
            USING ERRCODE = 'P1351';
    END IF;
    IF TG_OP = 'UPDATE' THEN
        IF NEW.id IS DISTINCT FROM OLD.id OR
           NEW.platform_scope_id IS DISTINCT FROM OLD.platform_scope_id OR
           NEW.created_at IS DISTINCT FROM OLD.created_at OR
           NEW.revision <> OLD.revision + 1 OR
           NEW.updated_at < OLD.updated_at THEN
            RAISE EXCEPTION 'identity user group update must advance exactly one revision'
                USING ERRCODE = 'P1352';
        END IF;
    END IF;
    RETURN NEW;
END;
$function$;

CREATE TRIGGER identity_user_groups_validate_135
BEFORE INSERT OR UPDATE ON identity_user_groups
FOR EACH ROW EXECUTE FUNCTION validate_identity_user_group_135();

CREATE TABLE identity_user_group_memberships (
    platform_scope_id uuid NOT NULL,
    group_id uuid NOT NULL,
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    created_at timestamptz NOT NULL DEFAULT now() CHECK (isfinite(created_at)),
    updated_at timestamptz NOT NULL DEFAULT now() CHECK (isfinite(updated_at) AND updated_at >= created_at),
    PRIMARY KEY (user_id),
    FOREIGN KEY (platform_scope_id, group_id)
        REFERENCES identity_user_groups(platform_scope_id, id) ON DELETE RESTRICT
);

CREATE INDEX identity_user_group_memberships_group_idx
    ON identity_user_group_memberships (platform_scope_id, group_id, user_id);

CREATE FUNCTION validate_identity_user_group_membership_135()
RETURNS trigger LANGUAGE plpgsql AS $function$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM memberships membership
        JOIN access_scopes scope ON scope.id = membership.scope_id AND scope.kind = 'tenant'
        WHERE membership.user_id = NEW.user_id
    ) THEN
        RAISE EXCEPTION 'identity user groups may contain tenant users only'
            USING ERRCODE = 'P1353';
    END IF;
    IF TG_OP = 'UPDATE' THEN
        IF NEW.user_id IS DISTINCT FROM OLD.user_id OR
           NEW.created_at IS DISTINCT FROM OLD.created_at OR
           NEW.updated_at < OLD.updated_at THEN
            RAISE EXCEPTION 'identity user group membership update is invalid'
                USING ERRCODE = 'P1354';
        END IF;
    END IF;
    RETURN NEW;
END;
$function$;

CREATE TRIGGER identity_user_group_memberships_validate_135
BEFORE INSERT OR UPDATE ON identity_user_group_memberships
FOR EACH ROW EXECUTE FUNCTION validate_identity_user_group_membership_135();

CREATE TABLE identity_user_group_write_requests (
    id uuid PRIMARY KEY,
    actor_user_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    actor_scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE RESTRICT,
    operation text NOT NULL CHECK (operation IN (
        'identity.user_group.create',
        'identity.user_group.update',
        'identity.user_group.delete'
    )),
    idempotency_key text NOT NULL CHECK (char_length(idempotency_key) BETWEEN 1 AND 128),
    request_digest bytea NOT NULL CHECK (octet_length(request_digest) = 32),
    resource_id uuid,
    response_status integer,
    response_body jsonb,
    created_at timestamptz NOT NULL DEFAULT now() CHECK (isfinite(created_at)),
    completed_at timestamptz,
    UNIQUE (actor_user_id, operation, idempotency_key),
    CHECK (
        (completed_at IS NULL AND response_status IS NULL AND resource_id IS NULL AND response_body IS NULL) OR
        (completed_at IS NOT NULL AND isfinite(completed_at) AND response_status IS NOT NULL AND
         resource_id IS NOT NULL AND response_body IS NOT NULL AND jsonb_typeof(response_body) = 'object')
    ),
    CHECK (
        response_status IS NULL OR
        (operation = 'identity.user_group.create' AND response_status = 201) OR
        (operation = 'identity.user_group.update' AND response_status = 200) OR
        (operation = 'identity.user_group.delete' AND response_status = 204)
    )
);

CREATE INDEX identity_user_group_write_requests_scope_created_idx
    ON identity_user_group_write_requests (actor_scope_id, created_at DESC);

CREATE FUNCTION guard_identity_user_group_write_requests_135()
RETURNS trigger LANGUAGE plpgsql AS $function$
BEGIN
    IF TG_OP IN ('DELETE', 'TRUNCATE') THEN
        RAISE EXCEPTION 'identity user group write receipts are append-only'
            USING ERRCODE = 'P1355';
    END IF;
    IF OLD.completed_at IS NOT NULL OR
       NEW.id IS DISTINCT FROM OLD.id OR
       NEW.actor_user_id IS DISTINCT FROM OLD.actor_user_id OR
       NEW.actor_scope_id IS DISTINCT FROM OLD.actor_scope_id OR
       NEW.operation IS DISTINCT FROM OLD.operation OR
       NEW.idempotency_key IS DISTINCT FROM OLD.idempotency_key OR
       NEW.request_digest IS DISTINCT FROM OLD.request_digest OR
       NEW.created_at IS DISTINCT FROM OLD.created_at OR
       NEW.completed_at IS NULL OR
       NEW.response_status IS NULL OR
       NEW.resource_id IS NULL OR
       NEW.response_body IS NULL THEN
        RAISE EXCEPTION 'identity user group write receipts are append-only'
            USING ERRCODE = 'P1355';
    END IF;
    RETURN NEW;
END;
$function$;

CREATE TRIGGER identity_user_group_write_requests_guard_135
BEFORE UPDATE OR DELETE ON identity_user_group_write_requests
FOR EACH ROW EXECUTE FUNCTION guard_identity_user_group_write_requests_135();

CREATE TRIGGER identity_user_group_write_requests_truncate_guard_135
BEFORE TRUNCATE ON identity_user_group_write_requests
FOR EACH STATEMENT EXECUTE FUNCTION guard_identity_user_group_write_requests_135();
