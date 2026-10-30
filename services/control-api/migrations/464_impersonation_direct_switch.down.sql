LOCK TABLE schema_migrations, admin_impersonation_grants IN ACCESS EXCLUSIVE MODE;

DO $migration_464_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 464 OR
       (SELECT max(version) FROM schema_migrations) <> 464 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=464 AND
        migration_id='464_impersonation_direct_switch' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 464 down requires the exact verified migration head' USING ERRCODE='P4641';
    END IF;
    -- 464 之后签发的授权没有工单号与 step-up 证据，无法补出 038 要求的非空事实。
    IF EXISTS (SELECT 1 FROM admin_impersonation_grants) THEN
        RAISE EXCEPTION 'migration 464 rollback cannot restore ticket and step-up facts for existing grants'
            USING ERRCODE='P4642';
    END IF;
END;
$migration_464_down$;

ALTER TABLE admin_impersonation_grants
    ADD COLUMN ticket text NOT NULL CHECK (
        ticket = btrim(ticket) AND char_length(ticket) BETWEEN 1 AND 128 AND
        ticket !~ '[[:cntrl:]]' AND
        position(U&'\2028' IN ticket) = 0 AND position(U&'\2029' IN ticket) = 0
    ),
    ADD COLUMN step_up_method text NOT NULL CHECK (step_up_method IN ('totp', 'webauthn')),
    ADD COLUMN step_up_evidence_id text NOT NULL CHECK (
        step_up_evidence_id = btrim(step_up_evidence_id) AND
        char_length(step_up_evidence_id) BETWEEN 1 AND 128 AND
        step_up_evidence_id !~ '[[:cntrl:]]' AND
        position(U&'\2028' IN step_up_evidence_id) = 0 AND position(U&'\2029' IN step_up_evidence_id) = 0
    ),
    ADD COLUMN step_up_at timestamptz NOT NULL,
    ADD COLUMN step_up_expires_at timestamptz NOT NULL,
    ADD UNIQUE (actor_scope_id, step_up_evidence_id),
    ADD CHECK (
        step_up_at <= created_at AND step_up_at >= created_at - interval '5 minutes' AND
        step_up_expires_at > created_at AND
        step_up_expires_at <= step_up_at + interval '5 minutes'
    );
