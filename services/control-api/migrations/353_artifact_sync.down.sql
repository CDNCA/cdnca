LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;

DO $migration_353_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 353 OR
       (SELECT max(version) FROM schema_migrations) <> 353 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=353 AND
        migration_id='353_artifact_sync' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 353 down requires the exact verified migration head' USING ERRCODE='P3531';
    END IF;
END;
$migration_353_down$;

-- Downloaded artifacts are fetched again after a re-upgrade; the previous
-- consumers' state tables come back empty (282 / 315 DDL). The materialized
-- security_system_rules rows stay.
DROP TABLE artifact_enablement_overrides;
DROP TABLE local_artifacts;
DROP FUNCTION protect_local_artifacts_353();
DROP TABLE artifact_objects;
DROP FUNCTION protect_artifact_objects_353();
DROP TABLE artifact_catalog_entries;
DROP TABLE artifact_catalog_state;

CREATE TABLE security_rule_catalog_consumer_state (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    delivery_id uuid NOT NULL,
    scope_revision bigint NOT NULL CHECK (scope_revision BETWEEN 1 AND 9007199254740991),
    catalog_sha256 text NOT NULL CHECK (char_length(catalog_sha256) = 43),
    key_id text NOT NULL CHECK (char_length(key_id) BETWEEN 1 AND 128),
    signed_document bytea NOT NULL CHECK (octet_length(signed_document) BETWEEN 2 AND 2097152),
    valid_from timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    applied_at timestamptz NOT NULL,
    last_attempt_at timestamptz,
    last_success_at timestamptz,
    last_error_code text NOT NULL DEFAULT '' CHECK (char_length(last_error_code) <= 96)
);

CREATE TABLE security_rule_catalog_ack_outbox (
    id uuid PRIMARY KEY,
    request_id text NOT NULL UNIQUE CHECK (char_length(request_id) BETWEEN 1 AND 128),
    delivery_id uuid NOT NULL,
    scope_revision bigint NOT NULL CHECK (scope_revision > 0),
    catalog_sha256 text NOT NULL CHECK (char_length(catalog_sha256) = 43),
    status text NOT NULL CHECK (status IN ('applied', 'rejected')),
    error_code text NOT NULL DEFAULT '' CHECK (char_length(error_code) <= 64),
    observed_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL,
    sent_at timestamptz,
    attempts integer NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    next_attempt_at timestamptz NOT NULL,
    last_error text NOT NULL DEFAULT '' CHECK (char_length(last_error) <= 200),
    UNIQUE (delivery_id, status),
    CHECK ((status = 'rejected') = (error_code <> ''))
);

CREATE INDEX security_rule_catalog_ack_outbox_pending_idx
    ON security_rule_catalog_ack_outbox(next_attempt_at) WHERE sent_at IS NULL;

CREATE TABLE ip_intel_library (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    revision bigint NOT NULL CHECK (revision BETWEEN 1 AND 9007199254740991),
    artifact_sha256 text NOT NULL CHECK (artifact_sha256 ~ '^[0-9a-f]{64}$'),
    artifact_bytes bigint NOT NULL CHECK (artifact_bytes > 64 AND artifact_bytes <= 268435456),
    artifact bytea NOT NULL CHECK (octet_length(artifact) = artifact_bytes),
    signed_release bytea NOT NULL CHECK (octet_length(signed_release) BETWEEN 2 AND 16384),
    key_id text NOT NULL CHECK (char_length(key_id) BETWEEN 1 AND 128),
    capability_version integer NOT NULL CHECK (capability_version >= 1),
    source_release text NOT NULL DEFAULT '' CHECK (char_length(source_release) <= 128),
    data_updated_at timestamptz NOT NULL,
    applied_at timestamptz NOT NULL
);

CREATE FUNCTION protect_ip_intel_library_315() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'the verified ip intel library is never deleted' USING ERRCODE = '23514';
    END IF;
    IF NEW.revision < OLD.revision OR
       (NEW.revision = OLD.revision AND (NEW.artifact_sha256 <> OLD.artifact_sha256 OR NEW.artifact <> OLD.artifact)) THEN
        RAISE EXCEPTION 'ip intel library revisions only move forward' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER ip_intel_library_forward_315 BEFORE UPDATE OR DELETE ON ip_intel_library
    FOR EACH ROW EXECUTE FUNCTION protect_ip_intel_library_315();

CREATE TABLE ip_intel_sync_state (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    last_attempt_at timestamptz,
    last_success_at timestamptz,
    last_error_code text NOT NULL DEFAULT '' CHECK (last_error_code ~ '^[a-z_]{0,64}$'),
    rejected_revision bigint CHECK (rejected_revision IS NULL OR rejected_revision > 0),
    updated_at timestamptz NOT NULL
);

INSERT INTO ip_intel_sync_state(singleton, updated_at) VALUES (true, CURRENT_TIMESTAMP);

REVOKE ALL ON FUNCTION protect_ip_intel_library_315() FROM PUBLIC;
GRANT SELECT, INSERT, UPDATE ON security_rule_catalog_consumer_state, security_rule_catalog_ack_outbox,
    ip_intel_library, ip_intel_sync_state TO cdnca_control_app, cdnca_control_runtime;
