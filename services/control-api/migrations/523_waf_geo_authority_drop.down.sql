-- 523（r136 wafgeo-check）回退：按 144 的定义恢复空的 waf_geo_* 表、函数与触发器（以下自 144 原样复制）。
LOCK TABLE schema_migrations, sites, access_scopes, memberships IN ACCESS EXCLUSIVE MODE;

DO $migration_523_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 523 OR
       (SELECT max(version) FROM schema_migrations) <> 523 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=523 AND
        migration_id='523_waf_geo_authority_drop' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR to_regclass(current_schema() || '.waf_geo_site_heads') IS NOT NULL THEN
        RAISE EXCEPTION 'migration 523 down requires the exact verified migration head' USING ERRCODE='P5231';
    END IF;
END;
$migration_523_down$;

CREATE FUNCTION valid_waf_geo_trusted_crawlers_144(value jsonb)
RETURNS boolean LANGUAGE plpgsql IMMUTABLE AS $$
DECLARE
    crawler jsonb;
    item jsonb;
BEGIN
    IF jsonb_typeof(value) <> 'array' OR jsonb_array_length(value) > 64 THEN
        RETURN false;
    END IF;
    FOR crawler IN SELECT entry FROM jsonb_array_elements(value) entry LOOP
        IF jsonb_typeof(crawler) <> 'object' OR
           crawler - 'networks' - 'user_agent_prefixes' <> '{}'::jsonb OR
           jsonb_typeof(crawler->'networks') <> 'array' OR
           jsonb_typeof(crawler->'user_agent_prefixes') <> 'array' OR
           jsonb_array_length(crawler->'networks') NOT BETWEEN 1 AND 64 OR
           jsonb_array_length(crawler->'user_agent_prefixes') NOT BETWEEN 1 AND 64 THEN
            RETURN false;
        END IF;
        FOR item IN SELECT entry FROM jsonb_array_elements(crawler->'networks') entry LOOP
            IF jsonb_typeof(item) <> 'string' OR char_length(item #>> '{}') NOT BETWEEN 1 AND 64 THEN
                RETURN false;
            END IF;
        END LOOP;
        FOR item IN SELECT entry FROM jsonb_array_elements(crawler->'user_agent_prefixes') entry LOOP
            IF jsonb_typeof(item) <> 'string' OR char_length(item #>> '{}') NOT BETWEEN 1 AND 128 THEN
                RETURN false;
            END IF;
        END LOOP;
    END LOOP;
    RETURN true;
END;
$$;

CREATE TABLE waf_geo_site_heads (
    tenant_scope_id uuid NOT NULL,
    site_id uuid NOT NULL,
    latest_revision bigint,
    active_revision bigint,
    lkg_revision bigint,
    binding_revision bigint NOT NULL DEFAULT 0 CHECK (binding_revision >= 0),
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_scope_id,site_id),
    FOREIGN KEY (tenant_scope_id,site_id)
        REFERENCES sites(scope_id,id) ON DELETE RESTRICT,
    CHECK (
        (binding_revision = 0 AND latest_revision IS NULL AND active_revision IS NULL AND lkg_revision IS NULL) OR
        (binding_revision > 0 AND latest_revision > 0 AND active_revision > 0 AND lkg_revision > 0 AND
         latest_revision >= active_revision AND latest_revision >= lkg_revision)
    ),
    CHECK (updated_at >= created_at)
);

CREATE TABLE waf_geo_catalog_revisions (
    tenant_scope_id uuid NOT NULL,
    site_id uuid NOT NULL,
    revision bigint NOT NULL CHECK (revision > 0 AND revision <= 9007199254740991),
    enabled boolean NOT NULL,
    blocked_countries text[] NOT NULL DEFAULT ARRAY[]::text[] CHECK (cardinality(blocked_countries) <= 64),
    geo_ranges jsonb NOT NULL CHECK (jsonb_typeof(geo_ranges) = 'array' AND jsonb_array_length(geo_ranges) <= 4096),
    trusted_crawlers jsonb NOT NULL DEFAULT '[]'::jsonb
        CHECK (valid_waf_geo_trusted_crawlers_144(trusted_crawlers)),
    trusted_proxy_cidrs text[] NOT NULL DEFAULT ARRAY[]::text[] CHECK (cardinality(trusted_proxy_cidrs) <= 256),
    source_provider text NOT NULL CHECK (source_provider = btrim(source_provider) AND char_length(source_provider) BETWEEN 1 AND 128),
    source_version text NOT NULL CHECK (source_version = btrim(source_version) AND char_length(source_version) BETWEEN 1 AND 128),
    source_sha256 bytea NOT NULL CHECK (octet_length(source_sha256) = 32),
    source_retrieved_at timestamptz NOT NULL,
    source_expires_at timestamptz NOT NULL,
    document_sha256 bytea NOT NULL CHECK (octet_length(document_sha256) = 32),
    actor_scope_id uuid NOT NULL,
    created_by_user_id uuid NOT NULL,
    request_id text NOT NULL CHECK (
        request_id = btrim(request_id) AND char_length(request_id) BETWEEN 1 AND 128 AND
        request_id !~ '[[:cntrl:]]' AND position(U&'\2028' in request_id) = 0 AND position(U&'\2029' in request_id) = 0
    ),
    created_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_scope_id,site_id,revision),
    FOREIGN KEY (tenant_scope_id,site_id)
        REFERENCES waf_geo_site_heads(tenant_scope_id,site_id) ON DELETE RESTRICT,
    FOREIGN KEY (actor_scope_id,created_by_user_id)
        REFERENCES memberships(scope_id,user_id) ON DELETE RESTRICT,
    CHECK (source_expires_at > source_retrieved_at),
    CHECK (
        (enabled AND cardinality(blocked_countries) > 0 AND jsonb_array_length(geo_ranges) > 0) OR
        (NOT enabled AND cardinality(blocked_countries) = 0 AND jsonb_array_length(geo_ranges) = 0)
    )
);

ALTER TABLE waf_geo_site_heads
    ADD CONSTRAINT waf_geo_site_heads_latest_144_fk
        FOREIGN KEY (tenant_scope_id,site_id,latest_revision)
        REFERENCES waf_geo_catalog_revisions(tenant_scope_id,site_id,revision)
        ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
    ADD CONSTRAINT waf_geo_site_heads_active_144_fk
        FOREIGN KEY (tenant_scope_id,site_id,active_revision)
        REFERENCES waf_geo_catalog_revisions(tenant_scope_id,site_id,revision)
        ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
    ADD CONSTRAINT waf_geo_site_heads_lkg_144_fk
        FOREIGN KEY (tenant_scope_id,site_id,lkg_revision)
        REFERENCES waf_geo_catalog_revisions(tenant_scope_id,site_id,revision)
        ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED;

CREATE TABLE waf_geo_publications (
    id uuid PRIMARY KEY,
    tenant_scope_id uuid NOT NULL,
    site_id uuid NOT NULL,
    revision bigint NOT NULL,
    binding_revision bigint NOT NULL CHECK (binding_revision > 0),
    expected_active_revision bigint NOT NULL CHECK (expected_active_revision >= 0),
    canonical_payload bytea NOT NULL CHECK (octet_length(canonical_payload) BETWEEN 1 AND 1048576),
    canonical_payload_sha256 bytea NOT NULL CHECK (octet_length(canonical_payload_sha256) = 32),
    signing_bytes bytea NOT NULL CHECK (octet_length(signing_bytes) BETWEEN 1 AND 1048576),
    signing_bytes_sha256 bytea NOT NULL CHECK (octet_length(signing_bytes_sha256) = 32),
    signing_key_id text NOT NULL CHECK (char_length(signing_key_id) BETWEEN 1 AND 128 AND signing_key_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]*$'),
    signature_algorithm text NOT NULL CHECK (signature_algorithm = 'ed25519'),
    signature bytea NOT NULL CHECK (octet_length(signature) = 64),
    idempotency_key text NOT NULL CHECK (char_length(idempotency_key) BETWEEN 1 AND 128 AND idempotency_key ~ '^[A-Za-z0-9._:-]+$'),
    request_digest bytea NOT NULL CHECK (octet_length(request_digest) = 32),
    created_at timestamptz NOT NULL,
    UNIQUE (tenant_scope_id,site_id,revision),
    UNIQUE (tenant_scope_id,site_id,binding_revision),
    UNIQUE (tenant_scope_id,site_id,binding_revision,id),
    UNIQUE (tenant_scope_id,site_id,idempotency_key),
    FOREIGN KEY (tenant_scope_id,site_id,revision)
        REFERENCES waf_geo_catalog_revisions(tenant_scope_id,site_id,revision) ON DELETE RESTRICT
);

CREATE TABLE waf_geo_binding_transitions (
    id uuid PRIMARY KEY,
    tenant_scope_id uuid NOT NULL,
    site_id uuid NOT NULL,
    binding_revision bigint NOT NULL CHECK (binding_revision > 0),
    operation text NOT NULL CHECK (operation IN ('promote','rollback')),
    from_active_revision bigint NOT NULL CHECK (from_active_revision >= 0),
    to_active_revision bigint NOT NULL CHECK (to_active_revision > 0),
    lkg_revision bigint NOT NULL CHECK (lkg_revision > 0),
    publication_id uuid,
    actor_scope_id uuid NOT NULL,
    actor_user_id uuid NOT NULL,
    request_id text NOT NULL CHECK (request_id = btrim(request_id) AND char_length(request_id) BETWEEN 1 AND 128),
    created_at timestamptz NOT NULL,
    UNIQUE (tenant_scope_id,site_id,binding_revision),
    FOREIGN KEY (tenant_scope_id,site_id)
        REFERENCES waf_geo_site_heads(tenant_scope_id,site_id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_scope_id,site_id,to_active_revision)
        REFERENCES waf_geo_catalog_revisions(tenant_scope_id,site_id,revision) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_scope_id,site_id,lkg_revision)
        REFERENCES waf_geo_catalog_revisions(tenant_scope_id,site_id,revision) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_scope_id,site_id,binding_revision,publication_id)
        REFERENCES waf_geo_publications(tenant_scope_id,site_id,binding_revision,id) ON DELETE RESTRICT,
    FOREIGN KEY (actor_scope_id,actor_user_id) REFERENCES memberships(scope_id,user_id) ON DELETE RESTRICT,
    CHECK ((operation = 'promote' AND publication_id IS NOT NULL) OR (operation = 'rollback' AND publication_id IS NULL))
);

CREATE FUNCTION protect_waf_geo_revision_144()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'WAF geo catalog revisions are append-only' USING ERRCODE = 'P1441';
END;
$$;

CREATE TRIGGER waf_geo_catalog_revisions_append_only_144
BEFORE UPDATE OR DELETE ON waf_geo_catalog_revisions
FOR EACH ROW EXECUTE FUNCTION protect_waf_geo_revision_144();

CREATE FUNCTION protect_waf_geo_publication_144()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'WAF geo publications are append-only' USING ERRCODE = 'P1442';
END;
$$;

CREATE TRIGGER waf_geo_publications_append_only_144
BEFORE UPDATE OR DELETE ON waf_geo_publications
FOR EACH ROW EXECUTE FUNCTION protect_waf_geo_publication_144();

CREATE FUNCTION protect_waf_geo_transition_144()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'WAF geo binding transitions are append-only' USING ERRCODE = 'P1443';
END;
$$;

CREATE TRIGGER waf_geo_binding_transitions_append_only_144
BEFORE UPDATE OR DELETE ON waf_geo_binding_transitions
FOR EACH ROW EXECUTE FUNCTION protect_waf_geo_transition_144();

CREATE FUNCTION validate_waf_geo_head_transition_144()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' OR
       ROW(NEW.tenant_scope_id,NEW.site_id,NEW.created_at) IS DISTINCT FROM
       ROW(OLD.tenant_scope_id,OLD.site_id,OLD.created_at) OR
       NEW.binding_revision <> OLD.binding_revision + 1 OR NEW.updated_at < OLD.updated_at THEN
        RAISE EXCEPTION 'invalid WAF geo authority head transition' USING ERRCODE = 'P1444';
    END IF;
    IF NOT (
        (NEW.latest_revision = COALESCE(OLD.latest_revision,0) + 1 AND
         NEW.active_revision = NEW.latest_revision AND
         NEW.lkg_revision = COALESCE(OLD.active_revision,NEW.active_revision)) OR
        (NEW.latest_revision = OLD.latest_revision AND OLD.lkg_revision IS NOT NULL AND
         NEW.active_revision = OLD.lkg_revision AND NEW.lkg_revision = OLD.lkg_revision AND
         OLD.active_revision <> OLD.lkg_revision)
    ) THEN
        RAISE EXCEPTION 'invalid WAF geo promotion or rollback' USING ERRCODE = 'P1445';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER waf_geo_site_heads_transition_144
BEFORE UPDATE OR DELETE ON waf_geo_site_heads
FOR EACH ROW EXECUTE FUNCTION validate_waf_geo_head_transition_144();

CREATE FUNCTION prevent_waf_geo_truncate_144()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'WAF geo authority tables cannot be truncated' USING ERRCODE = 'P1446';
END;
$$;

CREATE TRIGGER waf_geo_site_heads_no_truncate_144 BEFORE TRUNCATE ON waf_geo_site_heads
FOR EACH STATEMENT EXECUTE FUNCTION prevent_waf_geo_truncate_144();
CREATE TRIGGER waf_geo_catalog_revisions_no_truncate_144 BEFORE TRUNCATE ON waf_geo_catalog_revisions
FOR EACH STATEMENT EXECUTE FUNCTION prevent_waf_geo_truncate_144();
CREATE TRIGGER waf_geo_publications_no_truncate_144 BEFORE TRUNCATE ON waf_geo_publications
FOR EACH STATEMENT EXECUTE FUNCTION prevent_waf_geo_truncate_144();
CREATE TRIGGER waf_geo_binding_transitions_no_truncate_144 BEFORE TRUNCATE ON waf_geo_binding_transitions
FOR EACH STATEMENT EXECUTE FUNCTION prevent_waf_geo_truncate_144();
