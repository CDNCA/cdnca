LOCK TABLE schema_migrations,access_scopes,identity_verification_cases IN ACCESS EXCLUSIVE MODE;

DO $migration_161$
BEGIN
    IF (SELECT count(*) FROM schema_migrations)<>160 OR
       (SELECT min(version) FROM schema_migrations)<>1 OR
       (SELECT max(version) FROM schema_migrations)<>160 OR EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE migration_id IS NULL OR migration_id='' OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
              down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR integrity_state IS DISTINCT FROM 'verified' OR
              metadata_recorded_at IS NULL OR applied_at IS NULL
    ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version=160 AND migration_id='160_site_tls_protocols' AND
              checksum_sha256='697dfe854b2e4423d799348e35776ab406f303a104a52c232ff2d5af0db1fe7f' AND
              down_checksum_sha256='9c55509f60c8e2c04d81fa4ac4be2c58deac5d520abe31cfec02072e3925e07e' AND
              integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
    ) OR to_regclass('recharge_identity_policy_revisions_v1') IS NOT NULL OR
         to_regclass('recharge_identity_policy_heads_v1') IS NOT NULL THEN
        RAISE EXCEPTION 'migration 161 requires a contiguous verified 160 release head'
            USING ERRCODE='P1610';
    END IF;
END;
$migration_161$;

CREATE TABLE recharge_identity_policy_revisions_v1 (
    tenant_scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE RESTRICT,
    revision bigint NOT NULL CHECK(revision>0),
    require_real_name boolean NOT NULL,
    created_at timestamptz NOT NULL CHECK(isfinite(created_at)),
    PRIMARY KEY(tenant_scope_id,revision)
);

CREATE TABLE recharge_identity_policy_heads_v1 (
    tenant_scope_id uuid PRIMARY KEY REFERENCES access_scopes(id) ON DELETE RESTRICT,
    active_revision bigint NOT NULL CHECK(active_revision>0),
    updated_at timestamptz NOT NULL CHECK(isfinite(updated_at)),
    FOREIGN KEY(tenant_scope_id,active_revision)
        REFERENCES recharge_identity_policy_revisions_v1(tenant_scope_id,revision) ON DELETE RESTRICT
);

CREATE FUNCTION lock_recharge_identity_policy_161()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE scope_id uuid := COALESCE(NEW.tenant_scope_id,OLD.tenant_scope_id);
BEGIN
    PERFORM pg_advisory_xact_lock(hashtextextended('billing-recharge-policy:v1:'||scope_id::text,0));
    IF TG_OP='DELETE' THEN
        RETURN OLD;
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION guard_recharge_identity_policy_revision_161()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP<>'INSERT' THEN
        RAISE EXCEPTION 'recharge identity policy revision mutation rejected' USING ERRCODE='P1611';
    END IF;
    IF NOT EXISTS(
        SELECT 1 FROM access_scopes WHERE id=NEW.tenant_scope_id AND kind='tenant' AND tenant_id IS NOT NULL
    ) THEN
        RAISE EXCEPTION 'recharge identity policy revision mutation rejected' USING ERRCODE='P1611';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION guard_recharge_identity_policy_head_161()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP='DELETE' THEN
        RAISE EXCEPTION 'recharge identity policy head mutation rejected' USING ERRCODE='P1611';
    END IF;
    IF NOT EXISTS(
        SELECT 1 FROM access_scopes WHERE id=NEW.tenant_scope_id AND kind='tenant' AND tenant_id IS NOT NULL
    ) OR (TG_OP='UPDATE' AND (
        NEW.tenant_scope_id IS DISTINCT FROM OLD.tenant_scope_id OR
        NEW.active_revision<=OLD.active_revision OR NEW.updated_at<OLD.updated_at
    )) THEN
        RAISE EXCEPTION 'recharge identity policy head mutation rejected' USING ERRCODE='P1611';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION lock_recharge_identity_subject_161()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    scope_id uuid := COALESCE(NEW.tenant_scope_id,OLD.tenant_scope_id);
    user_id uuid := COALESCE(NEW.applicant_user_id,OLD.applicant_user_id);
BEGIN
    PERFORM pg_advisory_xact_lock(hashtextextended(
        'billing-recharge-identity:v1:'||scope_id::text||':'||user_id::text,0));
    IF TG_OP='DELETE' THEN
        RETURN OLD;
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION prevent_recharge_identity_policy_truncate_161()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'recharge identity policy facts cannot be truncated' USING ERRCODE='P1611';
END;
$$;

CREATE TRIGGER recharge_identity_policy_revision_lock_161
BEFORE INSERT OR UPDATE OR DELETE ON recharge_identity_policy_revisions_v1
FOR EACH ROW EXECUTE FUNCTION lock_recharge_identity_policy_161();
CREATE TRIGGER recharge_identity_policy_revision_guard_161
BEFORE INSERT OR UPDATE OR DELETE ON recharge_identity_policy_revisions_v1
FOR EACH ROW EXECUTE FUNCTION guard_recharge_identity_policy_revision_161();
CREATE TRIGGER recharge_identity_policy_head_lock_161
BEFORE INSERT OR UPDATE OR DELETE ON recharge_identity_policy_heads_v1
FOR EACH ROW EXECUTE FUNCTION lock_recharge_identity_policy_161();
CREATE TRIGGER recharge_identity_policy_head_guard_161
BEFORE INSERT OR UPDATE OR DELETE ON recharge_identity_policy_heads_v1
FOR EACH ROW EXECUTE FUNCTION guard_recharge_identity_policy_head_161();
CREATE TRIGGER recharge_identity_policy_revision_truncate_161
BEFORE TRUNCATE ON recharge_identity_policy_revisions_v1
FOR EACH STATEMENT EXECUTE FUNCTION prevent_recharge_identity_policy_truncate_161();
CREATE TRIGGER recharge_identity_policy_head_truncate_161
BEFORE TRUNCATE ON recharge_identity_policy_heads_v1
FOR EACH STATEMENT EXECUTE FUNCTION prevent_recharge_identity_policy_truncate_161();
CREATE TRIGGER identity_verification_cases_recharge_lock_161
BEFORE INSERT OR UPDATE OR DELETE ON identity_verification_cases
FOR EACH ROW EXECUTE FUNCTION lock_recharge_identity_subject_161();

REVOKE ALL ON recharge_identity_policy_revisions_v1 FROM PUBLIC;
REVOKE ALL ON recharge_identity_policy_heads_v1 FROM PUBLIC;
