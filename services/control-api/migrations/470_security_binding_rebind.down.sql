LOCK TABLE schema_migrations, security_policy_site_bindings, security_policy_publications IN ACCESS EXCLUSIVE MODE;

DO $migration_470_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 470 OR
       (SELECT max(version) FROM schema_migrations) <> 470 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=470 AND
        migration_id='470_security_binding_rebind' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 470 down requires the exact verified migration head' USING ERRCODE='P4701';
    END IF;
    -- 换绑或撤下过的站点无法用 470 之前的规则表达：拒绝回退，而不是改写发布历史。
    IF EXISTS (SELECT 1 FROM security_policy_publications WHERE detach) OR EXISTS (
        SELECT 1 FROM security_policy_publications publication
        JOIN security_policy_site_bindings binding ON binding.id=publication.binding_id
        WHERE publication.policy_id <> binding.policy_id
       ) OR EXISTS (
        SELECT 1 FROM security_policy_site_bindings
        WHERE active_policy_version > last_claimed_policy_version
       ) THEN
        RAISE EXCEPTION 'migration 470 rollback would drop security binding rebinds or detaches' USING ERRCODE='P4702';
    END IF;
END;
$migration_470_down$;

DROP TRIGGER aggregated_edge_site_activated_375 ON security_policy_site_bindings;
CREATE TRIGGER aggregated_edge_site_activated_375 AFTER UPDATE OF active_policy_version ON security_policy_site_bindings
    FOR EACH ROW WHEN (OLD.active_policy_version IS DISTINCT FROM NEW.active_policy_version)
    EXECUTE FUNCTION aggregated_edge_site_changed_375();

CREATE OR REPLACE FUNCTION validate_security_policy_publication_insert()
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

CREATE OR REPLACE FUNCTION protect_security_policy_site_binding()
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

ALTER TABLE security_policy_publications
    DROP CONSTRAINT security_policy_publications_detach_470,
    DROP CONSTRAINT security_policy_publications_expected_active_version_470,
    DROP CONSTRAINT security_policy_publications_expected_active_470,
    DROP COLUMN expected_active_policy_id,
    DROP COLUMN detach;

ALTER TABLE security_policy_site_bindings
    DROP CONSTRAINT security_policy_site_bindings_active_claimed_470,
    ADD CONSTRAINT security_policy_site_bindings_check CHECK (active_policy_version IS NULL OR (
        last_claimed_policy_version IS NOT NULL AND active_policy_version <= last_claimed_policy_version
    ));
