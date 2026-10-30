ALTER TABLE security_policies
    DROP CONSTRAINT security_policies_kind_check,
    ADD CONSTRAINT security_policies_kind_check CHECK (kind IN ('waf', 'cc', 'acl'));

CREATE UNIQUE INDEX sites_scope_id_security_binding_idx ON sites (scope_id, id);
CREATE UNIQUE INDEX nodes_scope_id_security_binding_idx ON nodes (scope_id, id);
CREATE UNIQUE INDEX security_policies_scope_id_kind_binding_idx
    ON security_policies (scope_id, id, kind);

CREATE TABLE security_policy_site_bindings (
    id uuid PRIMARY KEY,
    tenant_scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE RESTRICT,
    site_id uuid NOT NULL,
    policy_id uuid NOT NULL,
    policy_kind text NOT NULL CHECK (policy_kind IN ('waf', 'cc', 'acl')),
    active_policy_version bigint,
    last_claimed_policy_version bigint,
    last_bundle_id uuid,
    revision bigint NOT NULL DEFAULT 0 CHECK (revision >= 0),
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    CONSTRAINT security_policy_site_bindings_scope_site_kind
        UNIQUE (tenant_scope_id, site_id, policy_kind),
    UNIQUE (tenant_scope_id, id),
    FOREIGN KEY (tenant_scope_id, site_id)
        REFERENCES sites(scope_id, id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_scope_id, policy_id, policy_kind)
        REFERENCES security_policies(scope_id, id, kind) ON DELETE RESTRICT,
    FOREIGN KEY (policy_id, active_policy_version)
        REFERENCES security_policy_versions(policy_id, revision) ON DELETE RESTRICT,
    CHECK (active_policy_version IS NULL OR active_policy_version > 0),
    CHECK (last_claimed_policy_version IS NULL OR last_claimed_policy_version > 0),
    CHECK (active_policy_version IS NULL OR (
        last_claimed_policy_version IS NOT NULL AND active_policy_version <= last_claimed_policy_version
    )),
    CHECK (
        (revision = 0 AND active_policy_version IS NULL AND
         last_claimed_policy_version IS NULL AND last_bundle_id IS NULL) OR
        (revision > 0 AND last_claimed_policy_version IS NOT NULL AND last_bundle_id IS NOT NULL)
    )
);

CREATE TABLE security_policy_publications (
    id uuid PRIMARY KEY,
    binding_id uuid NOT NULL,
    tenant_scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE RESTRICT,
    site_id uuid NOT NULL,
    policy_id uuid NOT NULL,
    policy_kind text NOT NULL CHECK (policy_kind IN ('waf', 'cc', 'acl')),
    policy_version bigint NOT NULL CHECK (policy_version > 0),
    expected_binding_revision bigint NOT NULL CHECK (expected_binding_revision >= 0),
    binding_revision bigint NOT NULL CHECK (binding_revision > 0),
    expected_active_version bigint NOT NULL CHECK (expected_active_version >= 0),
    rollout_id uuid NOT NULL UNIQUE,
    idempotency_key text NOT NULL CHECK (
        char_length(idempotency_key) BETWEEN 1 AND 128 AND
        idempotency_key ~ '^[A-Za-z0-9._-]+$'
    ),
    request_digest bytea NOT NULL CHECK (octet_length(request_digest) = 32),
    plan_request_digest bytea NOT NULL CHECK (octet_length(plan_request_digest) = 32),
    canonical_payload bytea NOT NULL CHECK (octet_length(canonical_payload) BETWEEN 1 AND 1048576),
    canonical_payload_sha256 bytea NOT NULL CHECK (octet_length(canonical_payload_sha256) = 32),
    runtime_snapshot_sha256 bytea NOT NULL CHECK (octet_length(runtime_snapshot_sha256) = 32),
    bundle_bytes bytea NOT NULL CHECK (octet_length(bundle_bytes) BETWEEN 1 AND 1048576),
    bundle_sha256 bytea NOT NULL CHECK (octet_length(bundle_sha256) = 32),
    signing_key_id text NOT NULL CHECK (
        char_length(signing_key_id) BETWEEN 1 AND 128 AND
        signing_key_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]*$'
    ),
    issued_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    actor_scope_id uuid NOT NULL,
    actor_user_id uuid NOT NULL,
    request_id text NOT NULL CHECK (
        request_id = btrim(request_id) AND char_length(request_id) BETWEEN 1 AND 128 AND
        request_id !~ '[[:cntrl:]]' AND
        position(U&'\2028' in request_id) = 0 AND position(U&'\2029' in request_id) = 0
    ),
    created_at timestamptz NOT NULL,
    CONSTRAINT security_policy_publications_scope_idempotency_key
        UNIQUE (tenant_scope_id, idempotency_key),
    UNIQUE (tenant_scope_id, id),
    UNIQUE (tenant_scope_id, id, binding_id),
    UNIQUE (binding_id, binding_revision),
    FOREIGN KEY (tenant_scope_id, binding_id)
        REFERENCES security_policy_site_bindings(tenant_scope_id, id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_scope_id, site_id)
        REFERENCES sites(scope_id, id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_scope_id, policy_id, policy_kind)
        REFERENCES security_policies(scope_id, id, kind) ON DELETE RESTRICT,
    FOREIGN KEY (policy_id, policy_version)
        REFERENCES security_policy_versions(policy_id, revision) ON DELETE RESTRICT,
    FOREIGN KEY (actor_scope_id, actor_user_id)
        REFERENCES memberships(scope_id, user_id) ON DELETE RESTRICT,
    CHECK (binding_revision = expected_binding_revision + 1),
    CHECK (expires_at > issued_at),
    CHECK (created_at >= issued_at AND created_at < expires_at)
);

ALTER TABLE security_policy_site_bindings
    ADD CONSTRAINT security_policy_site_bindings_last_bundle_fk
    FOREIGN KEY (last_bundle_id) REFERENCES security_policy_publications(id)
    ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED;

CREATE INDEX security_policy_publications_binding_created_idx
    ON security_policy_publications (binding_id, created_at DESC, id DESC);
CREATE INDEX security_policy_publications_scope_created_idx
    ON security_policy_publications (tenant_scope_id, created_at DESC, id DESC);

CREATE TABLE security_policy_publication_targets (
    publication_id uuid NOT NULL,
    tenant_scope_id uuid NOT NULL,
    binding_id uuid NOT NULL,
    node_id uuid NOT NULL,
    claimed_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    released_at timestamptz,
    release_reason text CHECK (release_reason IN ('expired', 'completed', 'cancelled')),
    PRIMARY KEY (publication_id, node_id),
    FOREIGN KEY (tenant_scope_id, publication_id, binding_id)
        REFERENCES security_policy_publications(tenant_scope_id, id, binding_id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_scope_id, node_id)
        REFERENCES nodes(scope_id, id) ON DELETE RESTRICT,
    CHECK (expires_at > claimed_at),
    CHECK (
        (released_at IS NULL AND release_reason IS NULL) OR
        (released_at IS NOT NULL AND released_at >= claimed_at AND release_reason IS NOT NULL)
    )
);

CREATE UNIQUE INDEX security_policy_publication_targets_one_open_per_node_idx
    ON security_policy_publication_targets (node_id) WHERE released_at IS NULL;
CREATE INDEX security_policy_publication_targets_expiry_idx
    ON security_policy_publication_targets (expires_at, node_id) WHERE released_at IS NULL;

CREATE FUNCTION validate_security_policy_publication_insert()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    binding security_policy_site_bindings%ROWTYPE;
BEGIN
    SELECT * INTO binding FROM security_policy_site_bindings
    WHERE id = NEW.binding_id FOR UPDATE;
    IF NOT FOUND OR binding.tenant_scope_id <> NEW.tenant_scope_id OR
       binding.site_id <> NEW.site_id OR binding.policy_id <> NEW.policy_id OR
       binding.policy_kind <> NEW.policy_kind OR binding.revision <> NEW.expected_binding_revision OR
       COALESCE(binding.active_policy_version, 0) <> NEW.expected_active_version OR
       (binding.last_claimed_policy_version IS NOT NULL AND
        NEW.policy_version <= binding.last_claimed_policy_version) OR
       NEW.policy_version <= COALESCE(binding.active_policy_version, 0) THEN
        RAISE EXCEPTION 'security publication binding or version conflict';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER security_policy_publications_validate_insert
BEFORE INSERT ON security_policy_publications
FOR EACH ROW EXECUTE FUNCTION validate_security_policy_publication_insert();

CREATE FUNCTION prevent_security_policy_publication_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'security policy publications are append-only';
END;
$$;

CREATE TRIGGER security_policy_publications_append_only
BEFORE UPDATE OR DELETE ON security_policy_publications
FOR EACH ROW EXECUTE FUNCTION prevent_security_policy_publication_mutation();
CREATE TRIGGER security_policy_publications_no_truncate
BEFORE TRUNCATE ON security_policy_publications
FOR EACH STATEMENT EXECUTE FUNCTION prevent_security_policy_publication_mutation();

CREATE FUNCTION protect_security_policy_site_binding()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
	IF TG_OP IN ('DELETE', 'TRUNCATE') THEN
		RAISE EXCEPTION 'security policy site bindings cannot be deleted';
    END IF;
    IF ROW(NEW.id, NEW.tenant_scope_id, NEW.site_id, NEW.policy_id, NEW.policy_kind, NEW.created_at)
       IS DISTINCT FROM
       ROW(OLD.id, OLD.tenant_scope_id, OLD.site_id, OLD.policy_id, OLD.policy_kind, OLD.created_at) OR
       NEW.revision <> OLD.revision + 1 OR NEW.updated_at < OLD.updated_at OR
       (OLD.active_policy_version IS NOT NULL AND
        (NEW.active_policy_version IS NULL OR NEW.active_policy_version < OLD.active_policy_version)) OR
       (NEW.last_claimed_policy_version IS DISTINCT FROM OLD.last_claimed_policy_version AND
        OLD.last_claimed_policy_version IS NOT NULL AND
        (NEW.last_claimed_policy_version IS NULL OR
         NEW.last_claimed_policy_version <= OLD.last_claimed_policy_version)) OR
       (NEW.last_bundle_id IS NOT NULL AND NOT EXISTS (
           SELECT 1 FROM security_policy_publications publication
           WHERE publication.id = NEW.last_bundle_id AND publication.binding_id = NEW.id
             AND publication.tenant_scope_id = NEW.tenant_scope_id
             AND publication.policy_version = NEW.last_claimed_policy_version
       )) OR
       (NEW.active_policy_version IS NOT NULL AND NOT EXISTS (
           SELECT 1 FROM security_policy_publications publication
           WHERE publication.binding_id = NEW.id
             AND publication.tenant_scope_id = NEW.tenant_scope_id
             AND publication.policy_version = NEW.active_policy_version
       )) THEN
        RAISE EXCEPTION 'invalid security policy site binding transition';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER security_policy_site_bindings_protected
BEFORE UPDATE OR DELETE ON security_policy_site_bindings
FOR EACH ROW EXECUTE FUNCTION protect_security_policy_site_binding();
CREATE TRIGGER security_policy_site_bindings_no_truncate
BEFORE TRUNCATE ON security_policy_site_bindings
FOR EACH STATEMENT EXECUTE FUNCTION protect_security_policy_site_binding();

CREATE FUNCTION protect_security_policy_publication_target()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
	IF TG_OP IN ('DELETE', 'TRUNCATE') OR
       ROW(NEW.publication_id, NEW.tenant_scope_id, NEW.binding_id, NEW.node_id,
           NEW.claimed_at, NEW.expires_at)
       IS DISTINCT FROM
       ROW(OLD.publication_id, OLD.tenant_scope_id, OLD.binding_id, OLD.node_id,
           OLD.claimed_at, OLD.expires_at) OR
       OLD.released_at IS NOT NULL OR NEW.released_at IS NULL OR NEW.release_reason IS NULL THEN
        RAISE EXCEPTION 'invalid security policy publication target transition';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER security_policy_publication_targets_protected
BEFORE UPDATE OR DELETE ON security_policy_publication_targets
FOR EACH ROW EXECUTE FUNCTION protect_security_policy_publication_target();
CREATE TRIGGER security_policy_publication_targets_no_truncate
BEFORE TRUNCATE ON security_policy_publication_targets
FOR EACH STATEMENT EXECUTE FUNCTION protect_security_policy_publication_target();
