LOCK TABLE schema_migrations, users, memberships, auth_sessions, identity_write_requests
    IN ACCESS EXCLUSIVE MODE;

DO $migration_216$
BEGIN
    IF (SELECT count(*) FROM schema_migrations)<>215 OR
       (SELECT min(version) FROM schema_migrations)<>1 OR
       (SELECT max(version) FROM schema_migrations)<>215 OR EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE migration_id IS NULL OR migration_id='' OR
              checksum_sha256 !~ '^[0-9a-f]{64}$' OR
              down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR
              integrity_state IS DISTINCT FROM 'verified' OR
              metadata_recorded_at IS NULL OR applied_at IS NULL
    ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version=215 AND migration_id='215_node_line_group_display_ids' AND
              checksum_sha256='25e02d1226a48c7d6774c3a1b0d1973105a2a741cbd36d91f11be6d3bc48dc83' AND
              down_checksum_sha256='2937348fda507cc3bd03c6a330188ae9d2321b3019bd59b174f2060e31ead980' AND
              integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
    ) OR to_regclass(current_schema() || '.identity_user_deletions') IS NOT NULL THEN
        RAISE EXCEPTION 'migration 216 requires the exact verified 215 release head and an untouched user deletion schema'
            USING ERRCODE='P2160';
    END IF;
END;
$migration_216$;

CREATE TABLE identity_user_deletions (
    user_id uuid PRIMARY KEY REFERENCES users(id) ON DELETE RESTRICT,
    platform_scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE RESTRICT,
    deleted_by_user_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    deleted_at timestamptz NOT NULL CHECK (isfinite(deleted_at)),
    revision bigint NOT NULL CHECK (revision > 0),
    UNIQUE (platform_scope_id, user_id)
);

CREATE INDEX identity_user_deletions_scope_time_idx
    ON identity_user_deletions (platform_scope_id, deleted_at DESC, user_id);

ALTER TABLE identity_write_requests
    DROP CONSTRAINT identity_write_requests_operation_check,
    ADD CONSTRAINT identity_write_requests_operation_check CHECK (operation IN (
        'identity.user.create',
        'identity.user.update',
        'identity.self.update',
        'identity.membership.suspend',
        'identity.user.password.reset',
        'identity.user.delete'
    ));

CREATE FUNCTION guard_identity_user_deletions_216()
RETURNS trigger LANGUAGE plpgsql AS $function$
BEGIN
    IF TG_OP IN ('UPDATE', 'DELETE', 'TRUNCATE') THEN
        RAISE EXCEPTION 'identity user deletion facts are immutable'
            USING ERRCODE='P2161';
    END IF;
    RETURN NEW;
END;
$function$;

CREATE TRIGGER identity_user_deletions_guard_216
BEFORE UPDATE OR DELETE ON identity_user_deletions
FOR EACH ROW EXECUTE FUNCTION guard_identity_user_deletions_216();

CREATE TRIGGER identity_user_deletions_truncate_guard_216
BEFORE TRUNCATE ON identity_user_deletions
FOR EACH STATEMENT EXECUTE FUNCTION guard_identity_user_deletions_216();

REVOKE ALL ON TABLE identity_user_deletions FROM PUBLIC;
GRANT SELECT, INSERT ON TABLE identity_user_deletions TO cdnca_control_app;
