ALTER TABLE mfa_step_up_uses
    ADD COLUMN IF NOT EXISTS resource_binding_sha256 bytea
    CHECK (resource_binding_sha256 IS NULL OR octet_length(resource_binding_sha256) = 32);

CREATE TABLE custom_rbac_state_watermark (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    current_version bigint NOT NULL CHECK (current_version >= 0)
);

INSERT INTO custom_rbac_state_watermark (singleton, current_version) VALUES (true, 0);

LOCK TABLE custom_roles,
    custom_role_revisions,
    custom_role_deactivations,
    custom_role_grants,
    custom_role_grant_revocations,
    custom_rbac_state_watermark
IN ACCESS EXCLUSIVE MODE;

DROP TRIGGER custom_role_revisions_append_only ON custom_role_revisions;
DROP TRIGGER custom_role_deactivations_append_only ON custom_role_deactivations;
DROP TRIGGER custom_role_grants_append_only ON custom_role_grants;
DROP TRIGGER custom_role_grant_revocations_append_only ON custom_role_grant_revocations;

ALTER TABLE custom_roles ADD COLUMN created_state_version bigint;
ALTER TABLE custom_role_revisions ADD COLUMN state_version bigint;
ALTER TABLE custom_role_deactivations ADD COLUMN state_version bigint;
ALTER TABLE custom_role_grants ADD COLUMN state_version bigint;
ALTER TABLE custom_role_grant_revocations ADD COLUMN state_version bigint;

CREATE TEMPORARY TABLE custom_rbac_state_backfill (
    fact_kind text NOT NULL,
    fact_id uuid NOT NULL,
    fact_revision bigint,
    state_version bigint NOT NULL,
    PRIMARY KEY (fact_kind, fact_id, fact_revision)
) ON COMMIT DROP;

INSERT INTO custom_rbac_state_backfill (fact_kind, fact_id, fact_revision, state_version)
SELECT fact_kind, fact_id, fact_revision,
       row_number() OVER (ORDER BY occurred_at, fact_kind, fact_id, fact_revision NULLS FIRST)
FROM (
    SELECT 'role'::text AS fact_kind, id AS fact_id, 0::bigint AS fact_revision,
           created_at AS occurred_at
    FROM custom_roles
    UNION ALL
    SELECT 'revision', role_id, revision, created_at
    FROM custom_role_revisions
    UNION ALL
    SELECT 'deactivation', id, 0::bigint, deactivated_at
    FROM custom_role_deactivations
    UNION ALL
    SELECT 'grant', id, 0::bigint, granted_at
    FROM custom_role_grants
    UNION ALL
    SELECT 'revocation', id, 0::bigint, revoked_at
    FROM custom_role_grant_revocations
) facts;

UPDATE custom_roles role_row
SET created_state_version = backfill.state_version
FROM custom_rbac_state_backfill backfill
WHERE backfill.fact_kind = 'role' AND backfill.fact_id = role_row.id;

UPDATE custom_role_revisions revision
SET state_version = backfill.state_version
FROM custom_rbac_state_backfill backfill
WHERE backfill.fact_kind = 'revision' AND backfill.fact_id = revision.role_id AND
      backfill.fact_revision = revision.revision;

UPDATE custom_role_deactivations deactivation
SET state_version = backfill.state_version
FROM custom_rbac_state_backfill backfill
WHERE backfill.fact_kind = 'deactivation' AND backfill.fact_id = deactivation.id;

UPDATE custom_role_grants grant_row
SET state_version = backfill.state_version
FROM custom_rbac_state_backfill backfill
WHERE backfill.fact_kind = 'grant' AND backfill.fact_id = grant_row.id;

UPDATE custom_role_grant_revocations revocation
SET state_version = backfill.state_version
FROM custom_rbac_state_backfill backfill
WHERE backfill.fact_kind = 'revocation' AND backfill.fact_id = revocation.id;

UPDATE custom_rbac_state_watermark
SET current_version = COALESCE((SELECT max(state_version) FROM custom_rbac_state_backfill), 0)
WHERE singleton;

ALTER TABLE custom_roles
    ALTER COLUMN created_state_version SET NOT NULL,
    ADD CONSTRAINT custom_roles_created_state_version_positive CHECK (created_state_version > 0);
ALTER TABLE custom_role_revisions
    ALTER COLUMN state_version SET NOT NULL,
    ADD CONSTRAINT custom_role_revisions_state_version_positive CHECK (state_version > 0);
ALTER TABLE custom_role_deactivations
    ALTER COLUMN state_version SET NOT NULL,
    ADD CONSTRAINT custom_role_deactivations_state_version_positive CHECK (state_version > 0);
ALTER TABLE custom_role_grants
    ALTER COLUMN state_version SET NOT NULL,
    ADD CONSTRAINT custom_role_grants_state_version_positive CHECK (state_version > 0);
ALTER TABLE custom_role_grant_revocations
    ALTER COLUMN state_version SET NOT NULL,
    ADD CONSTRAINT custom_role_grant_revocations_state_version_positive CHECK (state_version > 0);

CREATE UNIQUE INDEX custom_roles_created_state_version_idx
    ON custom_roles (created_state_version);
CREATE UNIQUE INDEX custom_role_revisions_state_version_idx
    ON custom_role_revisions (state_version);
CREATE UNIQUE INDEX custom_role_deactivations_state_version_idx
    ON custom_role_deactivations (state_version);
CREATE UNIQUE INDEX custom_role_grants_state_version_idx
    ON custom_role_grants (state_version);
CREATE UNIQUE INDEX custom_role_grant_revocations_state_version_idx
    ON custom_role_grant_revocations (state_version);

CREATE FUNCTION allocate_custom_rbac_state_version()
RETURNS bigint
LANGUAGE plpgsql
AS $$
DECLARE
    allocated bigint;
BEGIN
    UPDATE custom_rbac_state_watermark
    SET current_version = current_version + 1
    WHERE singleton
    RETURNING current_version INTO allocated;
    IF allocated IS NULL THEN
        RAISE EXCEPTION 'custom RBAC state watermark is unavailable';
    END IF;
    RETURN allocated;
END;
$$;

CREATE FUNCTION assign_custom_role_created_state_version()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.created_state_version IS NOT NULL THEN
        RAISE EXCEPTION 'custom role creation state version is server assigned';
    END IF;
    NEW.created_state_version := allocate_custom_rbac_state_version();
    RETURN NEW;
END;
$$;

CREATE FUNCTION assign_custom_rbac_fact_state_version()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.state_version IS NOT NULL THEN
        RAISE EXCEPTION 'custom RBAC fact state version is server assigned';
    END IF;
    NEW.state_version := allocate_custom_rbac_state_version();
    RETURN NEW;
END;
$$;

CREATE FUNCTION protect_custom_role_created_state_version()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.created_state_version IS DISTINCT FROM OLD.created_state_version THEN
        RAISE EXCEPTION 'custom role creation state version is immutable';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER custom_roles_assign_state_version
BEFORE INSERT ON custom_roles
FOR EACH ROW EXECUTE FUNCTION assign_custom_role_created_state_version();
CREATE TRIGGER custom_roles_protect_state_version
BEFORE UPDATE ON custom_roles
FOR EACH ROW EXECUTE FUNCTION protect_custom_role_created_state_version();
CREATE TRIGGER custom_role_revisions_assign_state_version
BEFORE INSERT ON custom_role_revisions
FOR EACH ROW EXECUTE FUNCTION assign_custom_rbac_fact_state_version();
CREATE TRIGGER custom_role_deactivations_assign_state_version
BEFORE INSERT ON custom_role_deactivations
FOR EACH ROW EXECUTE FUNCTION assign_custom_rbac_fact_state_version();
CREATE TRIGGER custom_role_grants_assign_state_version
BEFORE INSERT ON custom_role_grants
FOR EACH ROW EXECUTE FUNCTION assign_custom_rbac_fact_state_version();
CREATE TRIGGER custom_role_grant_revocations_assign_state_version
BEFORE INSERT ON custom_role_grant_revocations
FOR EACH ROW EXECUTE FUNCTION assign_custom_rbac_fact_state_version();

CREATE TRIGGER custom_role_revisions_append_only
BEFORE UPDATE OR DELETE OR TRUNCATE ON custom_role_revisions
FOR EACH STATEMENT EXECUTE FUNCTION prevent_custom_rbac_fact_mutation();
CREATE TRIGGER custom_role_deactivations_append_only
BEFORE UPDATE OR DELETE OR TRUNCATE ON custom_role_deactivations
FOR EACH STATEMENT EXECUTE FUNCTION prevent_custom_rbac_fact_mutation();
CREATE TRIGGER custom_role_grants_append_only
BEFORE UPDATE OR DELETE OR TRUNCATE ON custom_role_grants
FOR EACH STATEMENT EXECUTE FUNCTION prevent_custom_rbac_fact_mutation();
CREATE TRIGGER custom_role_grant_revocations_append_only
BEFORE UPDATE OR DELETE OR TRUNCATE ON custom_role_grant_revocations
FOR EACH STATEMENT EXECUTE FUNCTION prevent_custom_rbac_fact_mutation();
