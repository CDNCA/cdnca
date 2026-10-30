LOCK TABLE schema_migrations,
    certificate_site_binding_facts,
    certificate_asset_versions,
    memberships
IN ACCESS EXCLUSIVE MODE;

DO $$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 115 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 115 OR EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE migration_id IS NULL OR checksum_sha256 IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$'
           OR down_checksum_sha256 IS NULL OR down_checksum_sha256 !~ '^[0-9a-f]{64}$'
           OR integrity_state IS DISTINCT FROM 'verified' OR metadata_recorded_at IS NULL OR applied_at IS NULL
    ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version=115 AND migration_id='115_dns_retry_after_voluntary_yield'
          AND checksum_sha256='7cb3487ac88e30576b9553f587c4c0f91973899db6863ecb427eed237ce0875f'
          AND down_checksum_sha256='008dd22e6504db2f602693abc94e14e9a094cbfa4a46f3d553c8c694325aced3'
          AND integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
    ) THEN
        RAISE EXCEPTION 'migration 116 requires the exact verified 115 release head'
            USING ERRCODE='P1160';
    END IF;
END;
$$;

ALTER TABLE certificate_site_binding_facts
    ADD COLUMN binding_xact_id xid8 NOT NULL DEFAULT pg_current_xact_id();

CREATE TABLE certificate_publication_intents (
    tenant_scope_id uuid NOT NULL,
    site_id uuid NOT NULL,
    binding_revision bigint NOT NULL CHECK (binding_revision > 0),
    operation text NOT NULL CHECK (operation IN ('publish','unpublish')),
    asset_id uuid NOT NULL,
    version_id uuid NOT NULL,
    is_default boolean NOT NULL,
    request_id text NOT NULL CHECK (
        octet_length(request_id) BETWEEN 1 AND 128 AND request_id=btrim(request_id)
        AND request_id !~ '[[:cntrl:]]'
    ),
    actor_scope_id uuid NOT NULL,
    actor_user_id uuid NOT NULL,
    publication_xact_id xid8 NOT NULL DEFAULT pg_current_xact_id(),
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp()
        CHECK (isfinite(created_at)),
    PRIMARY KEY (tenant_scope_id,site_id,binding_revision),
    FOREIGN KEY (tenant_scope_id,site_id,binding_revision)
        REFERENCES certificate_site_binding_facts(tenant_scope_id,site_id,sequence) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_scope_id,asset_id,version_id)
        REFERENCES certificate_asset_versions(tenant_scope_id,asset_id,id) ON DELETE RESTRICT,
    FOREIGN KEY (actor_scope_id,actor_user_id)
        REFERENCES memberships(scope_id,user_id) ON DELETE RESTRICT
);

CREATE INDEX certificate_publication_intents_pending_116_idx
    ON certificate_publication_intents(created_at,tenant_scope_id,site_id,binding_revision);

CREATE FUNCTION protect_certificate_publication_intent_116()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'certificate publication intents are append-only' USING ERRCODE='P1161';
END;
$$;

CREATE FUNCTION prevent_certificate_publication_intent_truncate_116()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'certificate publication intents are append-only' USING ERRCODE='P1161';
END;
$$;

CREATE FUNCTION validate_certificate_publication_intent_116()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    binding certificate_site_binding_facts%ROWTYPE;
BEGIN
    SELECT * INTO binding
    FROM certificate_site_binding_facts
    WHERE tenant_scope_id=NEW.tenant_scope_id AND site_id=NEW.site_id
      AND sequence=NEW.binding_revision;
    IF NOT FOUND OR NEW.publication_xact_id IS DISTINCT FROM pg_current_xact_id() OR
       binding.binding_xact_id IS DISTINCT FROM NEW.publication_xact_id OR
       NEW.operation IS DISTINCT FROM (CASE binding.action WHEN 'bind' THEN 'publish' ELSE 'unpublish' END) OR
       NEW.asset_id IS DISTINCT FROM binding.asset_id OR
       NEW.version_id IS DISTINCT FROM binding.version_id OR
       NEW.is_default IS DISTINCT FROM binding.is_default OR
       NEW.request_id IS DISTINCT FROM binding.request_id OR
       NEW.actor_scope_id IS DISTINCT FROM binding.actor_scope_id OR
       NEW.actor_user_id IS DISTINCT FROM binding.changed_by_user_id OR
       NEW.created_at IS DISTINCT FROM transaction_timestamp() THEN
        RAISE EXCEPTION 'certificate publication intent does not match its binding revision'
            USING ERRCODE='P1161';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION require_certificate_publication_intent_116()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM certificate_publication_intents intent
        WHERE intent.tenant_scope_id=NEW.tenant_scope_id AND intent.site_id=NEW.site_id
          AND intent.binding_revision=NEW.sequence
          AND intent.publication_xact_id=NEW.binding_xact_id
          AND intent.operation=(CASE NEW.action WHEN 'bind' THEN 'publish' ELSE 'unpublish' END)
          AND intent.asset_id=NEW.asset_id AND intent.version_id=NEW.version_id
          AND intent.is_default=NEW.is_default AND intent.request_id=NEW.request_id
          AND intent.actor_scope_id=NEW.actor_scope_id
          AND intent.actor_user_id=NEW.changed_by_user_id
    ) THEN
        RAISE EXCEPTION 'certificate binding revision requires a same-transaction publication intent'
            USING ERRCODE='P1161';
    END IF;
    RETURN NULL;
END;
$$;

CREATE TRIGGER certificate_publication_intents_validate_116
BEFORE INSERT ON certificate_publication_intents
FOR EACH ROW EXECUTE FUNCTION validate_certificate_publication_intent_116();

CREATE TRIGGER certificate_publication_intents_immutable_116
BEFORE UPDATE OR DELETE ON certificate_publication_intents
FOR EACH ROW EXECUTE FUNCTION protect_certificate_publication_intent_116();

CREATE TRIGGER certificate_publication_intents_no_truncate_116
BEFORE TRUNCATE ON certificate_publication_intents
FOR EACH STATEMENT EXECUTE FUNCTION prevent_certificate_publication_intent_truncate_116();

CREATE CONSTRAINT TRIGGER certificate_binding_requires_intent_116
AFTER INSERT ON certificate_site_binding_facts
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION require_certificate_publication_intent_116();
