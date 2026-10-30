LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;

DO $migration_315_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 314 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 314 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=314 AND
        migration_id='314_ticket_attachment_cleanup' AND
        checksum_sha256='e5b4dc29d293a7fbbf64a089f26f443f49e3d703021e32fdc64a48a7aadd7ffa' AND
        down_checksum_sha256='62230c4fca3eabef097e6b338508fef63bed34642af0a69109345733b81d1c3d' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR to_regclass(current_schema() || '.ip_intel_library') IS NOT NULL THEN
        RAISE EXCEPTION 'migration 315 requires the exact verified 314 release head' USING ERRCODE='P3150';
    END IF;
END;
$migration_315_up$;

-- r136-g3b (placeholder number; renumbered on merge): IP intelligence library
-- synced from the license service (libs/entitlement/ipintel). One row holds the
-- last verified library (LKG): the canonical license-signed release envelope
-- and the artifact it describes. It is replaced only by a higher revision that
-- verified, or re-signed (same revision and artifact, new key). The library
-- does not expire by time. Sync state is the operator view of the last attempt.
-- @ip-intel-library-ddl
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
-- @end-ip-intel-library-ddl

REVOKE ALL ON FUNCTION protect_ip_intel_library_315() FROM PUBLIC;
GRANT SELECT, INSERT, UPDATE ON ip_intel_library, ip_intel_sync_state TO cdnca_control_app, cdnca_control_runtime;
