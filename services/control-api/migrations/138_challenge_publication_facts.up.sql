LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;

DO $migration_138$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 137 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 137 OR EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE migration_id IS NULL OR migration_id = '' OR
              checksum_sha256 IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
              down_checksum_sha256 IS NULL OR down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR
              integrity_state IS DISTINCT FROM 'verified' OR
              metadata_recorded_at IS NULL OR applied_at IS NULL
    ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version = 137 AND migration_id = '137_tcp_billing_factor' AND
              checksum_sha256 = '741cabd2ca7d32915d7c2a5e13f42a75ccd9888f3662be8f572cacd3b6d7a4df' AND
              down_checksum_sha256 = 'c6d3329f35c73745eaaef8a9d75aaf4f16ee925aef8d4145211152ea2669923b' AND
              integrity_state = 'verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
    ) OR to_regclass('challenge_key_facts_138') IS NOT NULL OR
         to_regclass('challenge_site_bindings_138') IS NOT NULL OR
         to_regclass('challenge_site_binding_revisions_138') IS NOT NULL THEN
        RAISE EXCEPTION 'migration 138 requires the exact verified 137 release head'
            USING ERRCODE = 'P1380';
    END IF;
END;
$migration_138$;

LOCK TABLE access_scopes, tenants, sites, challenge_policies, challenge_policy_revisions,
    memberships, artifact_signing_keys, config_versions, rollouts, edge_config_publications
    IN SHARE ROW EXCLUSIVE MODE;

CREATE TABLE challenge_key_facts_138 (
    id uuid PRIMARY KEY CHECK (id <> '00000000-0000-0000-0000-000000000000'::uuid),
    tenant_scope_id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    site_id uuid NOT NULL,
    host text NOT NULL CHECK (
        host = lower(host) AND octet_length(host) BETWEEN 1 AND 253 AND
        host ~ '^[a-z0-9.-]+$'
    ),
    policy_id uuid NOT NULL,
    policy_revision bigint NOT NULL CHECK (policy_revision > 0),
    role text NOT NULL CHECK (role IN ('current','previous','app')),
    reference text NOT NULL CHECK (
        octet_length(reference) BETWEEN 8 AND 128 AND
        reference ~ '^(keyref|vault|kms|appref):[A-Za-z0-9][A-Za-z0-9._:/-]*$'
    ),
    material_key_id text NOT NULL CHECK (
        octet_length(material_key_id) BETWEEN 1 AND 128 AND
        material_key_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]*$'
    ),
    wrapping_key_id text NOT NULL CHECK (
        octet_length(wrapping_key_id) BETWEEN 1 AND 128 AND
        wrapping_key_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]*$'
    ),
    signing_key_id text NOT NULL REFERENCES artifact_signing_keys(id) ON DELETE RESTRICT,
    ciphertext bytea NOT NULL CHECK (octet_length(ciphertext) BETWEEN 29 AND 4096),
    signature bytea NOT NULL CHECK (octet_length(signature) = 64),
    active boolean NOT NULL DEFAULT true CHECK (active),
    created_by_scope_id uuid NOT NULL,
    created_by_user_id uuid NOT NULL,
    created_at timestamptz NOT NULL CHECK (isfinite(created_at)),
    FOREIGN KEY (tenant_scope_id, tenant_id)
        REFERENCES access_scopes(id, tenant_id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_scope_id, site_id)
        REFERENCES sites(scope_id, id) ON DELETE RESTRICT,
    FOREIGN KEY (policy_id, policy_revision)
        REFERENCES challenge_policy_revisions(policy_id, revision) ON DELETE RESTRICT,
    FOREIGN KEY (created_by_scope_id, created_by_user_id)
        REFERENCES memberships(scope_id, user_id) ON DELETE RESTRICT,
    UNIQUE (tenant_scope_id, site_id, policy_id, policy_revision, role),
    CHECK ((role = 'app') = (reference LIKE 'appref:%'))
);

CREATE TABLE challenge_site_bindings_138 (
    tenant_scope_id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    site_id uuid NOT NULL,
    host text NOT NULL CHECK (
        host = lower(host) AND octet_length(host) BETWEEN 1 AND 253 AND
        host ~ '^[a-z0-9.-]+$'
    ),
    active_binding_revision bigint CHECK (active_binding_revision > 0),
    lkg_binding_revision bigint CHECK (lkg_binding_revision > 0),
    created_at timestamptz NOT NULL CHECK (isfinite(created_at)),
    updated_at timestamptz NOT NULL CHECK (isfinite(updated_at) AND updated_at >= created_at),
    PRIMARY KEY (tenant_scope_id, site_id),
    FOREIGN KEY (tenant_scope_id, tenant_id)
        REFERENCES access_scopes(id, tenant_id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_scope_id, site_id)
        REFERENCES sites(scope_id, id) ON DELETE RESTRICT,
    CHECK (active_binding_revision IS NULL OR active_binding_revision IS DISTINCT FROM lkg_binding_revision)
);

CREATE TABLE challenge_site_binding_revisions_138 (
    tenant_scope_id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    site_id uuid NOT NULL,
    host text NOT NULL CHECK (
        host = lower(host) AND octet_length(host) BETWEEN 1 AND 253 AND
        host ~ '^[a-z0-9.-]+$'
    ),
    binding_revision bigint NOT NULL CHECK (binding_revision > 0),
    policy_id uuid NOT NULL,
    policy_revision bigint NOT NULL CHECK (policy_revision > 0),
    secret_rollout_id uuid NOT NULL,
    secret_config_version_id uuid NOT NULL,
    secret_revision bigint NOT NULL CHECK (secret_revision > 0),
    state text NOT NULL CHECK (state IN ('candidate','active')),
    idempotency_key text NOT NULL CHECK (
        octet_length(idempotency_key) BETWEEN 1 AND 128 AND
        idempotency_key ~ '^[A-Za-z0-9][A-Za-z0-9._:-]*$'
    ),
    request_digest bytea NOT NULL CHECK (octet_length(request_digest) = 32),
    request_id text NOT NULL CHECK (
        octet_length(request_id) BETWEEN 1 AND 128 AND
        request_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]*$'
    ),
    correlation_id text NOT NULL CHECK (
        octet_length(correlation_id) BETWEEN 1 AND 128 AND
        correlation_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]*$'
    ),
    actor_scope_id uuid NOT NULL,
    actor_user_id uuid NOT NULL,
    edge_publication_id uuid REFERENCES edge_config_publications(id) ON DELETE RESTRICT,
    edge_source_revision bigint CHECK (edge_source_revision > 0),
    created_at timestamptz NOT NULL CHECK (isfinite(created_at)),
    activated_at timestamptz CHECK (activated_at IS NULL OR isfinite(activated_at) AND activated_at >= created_at),
    PRIMARY KEY (tenant_scope_id, site_id, binding_revision),
    FOREIGN KEY (tenant_scope_id, tenant_id)
        REFERENCES access_scopes(id, tenant_id) ON DELETE RESTRICT,
    CONSTRAINT challenge_binding_revisions_binding_138_fk
    FOREIGN KEY (tenant_scope_id, site_id)
        REFERENCES challenge_site_bindings_138(tenant_scope_id, site_id) ON DELETE RESTRICT,
    FOREIGN KEY (policy_id, policy_revision)
        REFERENCES challenge_policy_revisions(policy_id, revision) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_scope_id, secret_rollout_id)
        REFERENCES rollouts(configuration_scope_id, id) ON DELETE RESTRICT,
    FOREIGN KEY (secret_rollout_id, secret_config_version_id)
        REFERENCES rollouts(id, config_version_id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_scope_id, secret_config_version_id)
        REFERENCES config_versions(configuration_scope_id, id) ON DELETE RESTRICT,
    FOREIGN KEY (actor_scope_id, actor_user_id)
        REFERENCES memberships(scope_id, user_id) ON DELETE RESTRICT,
    UNIQUE (tenant_scope_id, idempotency_key),
    UNIQUE (tenant_scope_id, request_id),
    CHECK (
        (state = 'candidate' AND edge_publication_id IS NULL AND edge_source_revision IS NULL AND activated_at IS NULL) OR
        (state = 'active' AND edge_publication_id IS NOT NULL AND edge_source_revision IS NOT NULL AND activated_at IS NOT NULL)
    )
);

ALTER TABLE challenge_site_bindings_138
    ADD CONSTRAINT challenge_site_bindings_active_revision_138_fk
        FOREIGN KEY (tenant_scope_id, site_id, active_binding_revision)
        REFERENCES challenge_site_binding_revisions_138(tenant_scope_id, site_id, binding_revision)
        ON DELETE RESTRICT,
    ADD CONSTRAINT challenge_site_bindings_lkg_revision_138_fk
        FOREIGN KEY (tenant_scope_id, site_id, lkg_binding_revision)
        REFERENCES challenge_site_binding_revisions_138(tenant_scope_id, site_id, binding_revision)
        ON DELETE RESTRICT;

CREATE FUNCTION validate_challenge_key_fact_138()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE policy_row challenge_policy_revisions%ROWTYPE;
BEGIN
    SELECT * INTO policy_row FROM challenge_policy_revisions
    WHERE policy_id = NEW.policy_id AND revision = NEW.policy_revision
    FOR SHARE;
    IF NOT FOUND OR ROW(policy_row.tenant_scope_id, policy_row.tenant_id, policy_row.site_id, policy_row.host)
        IS DISTINCT FROM ROW(NEW.tenant_scope_id, NEW.tenant_id, NEW.site_id, NEW.host) OR
       (NEW.role = 'current' AND NEW.reference IS DISTINCT FROM policy_row.key_reference) OR
       (NEW.role = 'app' AND NEW.reference IS DISTINCT FROM policy_row.external_app_reference) OR
       (NEW.role = 'previous' AND NEW.reference = policy_row.key_reference) THEN
        RAISE EXCEPTION 'challenge key fact scope or role does not match policy revision'
            USING ERRCODE = 'P1381';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION validate_challenge_binding_revision_138()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE policy_row challenge_policy_revisions%ROWTYPE;
DECLARE publication_scope uuid;
DECLARE publication_revision bigint;
BEGIN
    SELECT * INTO policy_row FROM challenge_policy_revisions
    WHERE policy_id = NEW.policy_id AND revision = NEW.policy_revision
    FOR SHARE;
    IF NOT FOUND OR NOT policy_row.enabled OR policy_row.deleted OR
       ROW(policy_row.tenant_scope_id, policy_row.tenant_id, policy_row.site_id, policy_row.host)
        IS DISTINCT FROM ROW(NEW.tenant_scope_id, NEW.tenant_id, NEW.site_id, NEW.host) THEN
        RAISE EXCEPTION 'challenge binding scope does not match active policy revision'
            USING ERRCODE = 'P1382';
    END IF;
    IF TG_OP = 'UPDATE' THEN
        IF OLD.state <> 'candidate' OR NEW.state <> 'active' OR
           ROW(NEW.tenant_scope_id, NEW.tenant_id, NEW.site_id, NEW.host, NEW.binding_revision,
               NEW.policy_id, NEW.policy_revision, NEW.secret_rollout_id, NEW.secret_config_version_id,
               NEW.secret_revision, NEW.idempotency_key, NEW.request_digest, NEW.request_id,
               NEW.correlation_id, NEW.actor_scope_id, NEW.actor_user_id, NEW.created_at)
            IS DISTINCT FROM
           ROW(OLD.tenant_scope_id, OLD.tenant_id, OLD.site_id, OLD.host, OLD.binding_revision,
               OLD.policy_id, OLD.policy_revision, OLD.secret_rollout_id, OLD.secret_config_version_id,
               OLD.secret_revision, OLD.idempotency_key, OLD.request_digest, OLD.request_id,
               OLD.correlation_id, OLD.actor_scope_id, OLD.actor_user_id, OLD.created_at) THEN
            RAISE EXCEPTION 'invalid challenge binding revision transition'
                USING ERRCODE = 'P1383';
        END IF;
        SELECT configuration_scope_id, source_revision
        INTO publication_scope, publication_revision
        FROM edge_config_publications WHERE id = NEW.edge_publication_id FOR SHARE;
        IF NOT FOUND OR publication_scope <> NEW.tenant_scope_id OR
           publication_revision <> NEW.edge_source_revision THEN
            RAISE EXCEPTION 'challenge binding publication identity mismatch'
                USING ERRCODE = 'P1384';
        END IF;
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION protect_challenge_site_binding_138()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE site_tenant_id uuid;
DECLARE site_host text;
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'challenge site bindings are durable facts' USING ERRCODE = 'P1385';
    END IF;
    SELECT scope.tenant_id, site.domain INTO site_tenant_id, site_host
    FROM sites site
    JOIN access_scopes scope ON scope.id = site.scope_id AND scope.kind = 'tenant'
    WHERE site.scope_id = NEW.tenant_scope_id AND site.id = NEW.site_id
    FOR SHARE OF site, scope;
    IF NOT FOUND OR site_tenant_id <> NEW.tenant_id OR site_host <> NEW.host THEN
        RAISE EXCEPTION 'challenge site binding scope mismatch' USING ERRCODE = 'P1386';
    END IF;
    IF TG_OP = 'INSERT' THEN
        IF NEW.active_binding_revision IS NOT NULL OR NEW.lkg_binding_revision IS NOT NULL THEN
            RAISE EXCEPTION 'new challenge site binding must start empty' USING ERRCODE = 'P1387';
        END IF;
    ELSIF ROW(NEW.tenant_scope_id, NEW.tenant_id, NEW.site_id, NEW.host, NEW.created_at)
            IS DISTINCT FROM ROW(OLD.tenant_scope_id, OLD.tenant_id, OLD.site_id, OLD.host, OLD.created_at) OR
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
    RETURN NEW;
END;
$$;

CREATE FUNCTION prevent_challenge_fact_mutation_138()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'challenge publication facts are immutable' USING ERRCODE = 'P1389';
END;
$$;

CREATE TRIGGER challenge_key_facts_validate_138
BEFORE INSERT ON challenge_key_facts_138
FOR EACH ROW EXECUTE FUNCTION validate_challenge_key_fact_138();
CREATE TRIGGER challenge_key_facts_immutable_138
BEFORE UPDATE OR DELETE ON challenge_key_facts_138
FOR EACH ROW EXECUTE FUNCTION prevent_challenge_fact_mutation_138();
CREATE TRIGGER challenge_key_facts_no_truncate_138
BEFORE TRUNCATE ON challenge_key_facts_138
FOR EACH STATEMENT EXECUTE FUNCTION prevent_challenge_fact_mutation_138();

CREATE TRIGGER challenge_binding_revisions_validate_138
BEFORE INSERT OR UPDATE ON challenge_site_binding_revisions_138
FOR EACH ROW EXECUTE FUNCTION validate_challenge_binding_revision_138();
CREATE TRIGGER challenge_binding_revisions_no_delete_138
BEFORE DELETE ON challenge_site_binding_revisions_138
FOR EACH ROW EXECUTE FUNCTION prevent_challenge_fact_mutation_138();
CREATE TRIGGER challenge_binding_revisions_no_truncate_138
BEFORE TRUNCATE ON challenge_site_binding_revisions_138
FOR EACH STATEMENT EXECUTE FUNCTION prevent_challenge_fact_mutation_138();

CREATE TRIGGER challenge_site_bindings_protected_138
BEFORE INSERT OR UPDATE OR DELETE ON challenge_site_bindings_138
FOR EACH ROW EXECUTE FUNCTION protect_challenge_site_binding_138();
CREATE TRIGGER challenge_site_bindings_no_truncate_138
BEFORE TRUNCATE ON challenge_site_bindings_138
FOR EACH STATEMENT EXECUTE FUNCTION prevent_challenge_fact_mutation_138();

CREATE INDEX challenge_key_facts_lookup_138
    ON challenge_key_facts_138 (tenant_scope_id, tenant_id, site_id, host, policy_id, policy_revision, role)
    WHERE active;
CREATE INDEX challenge_binding_revisions_policy_138
    ON challenge_site_binding_revisions_138 (tenant_scope_id, policy_id, policy_revision, binding_revision DESC);

REVOKE ALL ON FUNCTION validate_challenge_key_fact_138() FROM PUBLIC;
REVOKE ALL ON FUNCTION validate_challenge_binding_revision_138() FROM PUBLIC;
REVOKE ALL ON FUNCTION protect_challenge_site_binding_138() FROM PUBLIC;
REVOKE ALL ON FUNCTION prevent_challenge_fact_mutation_138() FROM PUBLIC;
