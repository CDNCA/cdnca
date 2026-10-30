LOCK TABLE schema_migrations,control_installation_entitlement IN ACCESS EXCLUSIVE MODE;

DO $migration_153$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 152 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 152 OR EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE migration_id IS NULL OR migration_id='' OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
              down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR integrity_state IS DISTINCT FROM 'verified' OR
              metadata_recorded_at IS NULL OR applied_at IS NULL
    ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version=152 AND migration_id='152_recharge_payment_lifecycle' AND
              checksum_sha256='5aa5c735685cb02cce34fca432592f280c8f53a4f8c8c006067e43e997d279e0' AND
              down_checksum_sha256='1bf753f13c76111d465396b6ac2b446892325b18ff3b8929ead84985963decce' AND
              integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
    ) OR to_regclass('node_revocation_checkpoint_history') IS NOT NULL OR
         to_regclass('node_revocation_checkpoint_lkg') IS NOT NULL OR
         to_regprocedure('guard_node_revocation_checkpoint_history_insert_153()') IS NOT NULL OR
         to_regprocedure('prevent_node_revocation_checkpoint_history_mutation_153()') IS NOT NULL OR
         to_regprocedure('guard_node_revocation_checkpoint_lkg_153()') IS NOT NULL OR
         to_regprocedure('prevent_node_revocation_checkpoint_lkg_truncate_153()') IS NOT NULL THEN
        RAISE EXCEPTION 'migration 153 requires the exact verified 152 release head'
            USING ERRCODE='P1530';
    END IF;
END;
$migration_153$;

CREATE TABLE node_revocation_checkpoint_history (
    installation_id text NOT NULL REFERENCES control_installation_entitlement(installation_id) ON DELETE RESTRICT,
    revision bigint NOT NULL CHECK(revision>0),
    issued_at timestamptz NOT NULL CHECK(isfinite(issued_at)),
    expires_at timestamptz NOT NULL CHECK(isfinite(expires_at) AND expires_at>issued_at),
    key_id text NOT NULL CHECK(key_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,254}$'),
    artifact_sha256 bytea NOT NULL CHECK(octet_length(artifact_sha256)=32),
    wire_bytes bytea NOT NULL CHECK(octet_length(wire_bytes) BETWEEN 1 AND 4194304),
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp() CHECK(isfinite(created_at)),
    PRIMARY KEY(installation_id,revision),
    UNIQUE(installation_id,revision,artifact_sha256),
    CHECK(artifact_sha256=sha256(wire_bytes))
);

CREATE TABLE node_revocation_checkpoint_lkg (
    installation_id text PRIMARY KEY REFERENCES control_installation_entitlement(installation_id) ON DELETE RESTRICT,
    revision bigint NOT NULL CHECK(revision>0),
    issued_at timestamptz NOT NULL CHECK(isfinite(issued_at)),
    expires_at timestamptz NOT NULL CHECK(isfinite(expires_at) AND expires_at>issued_at),
    key_id text NOT NULL CHECK(key_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,254}$'),
    artifact_sha256 bytea NOT NULL CHECK(octet_length(artifact_sha256)=32),
    wire_bytes bytea NOT NULL CHECK(octet_length(wire_bytes) BETWEEN 1 AND 4194304),
    applied_at timestamptz NOT NULL DEFAULT transaction_timestamp() CHECK(isfinite(applied_at)),
    FOREIGN KEY(installation_id,revision,artifact_sha256)
        REFERENCES node_revocation_checkpoint_history(installation_id,revision,artifact_sha256) ON DELETE RESTRICT,
    CHECK(artifact_sha256=sha256(wire_bytes))
);

CREATE FUNCTION guard_node_revocation_checkpoint_history_insert_153()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    PERFORM pg_advisory_xact_lock(hashtextextended(NEW.installation_id,153));
    IF EXISTS (
        SELECT 1 FROM node_revocation_checkpoint_history
        WHERE installation_id=NEW.installation_id AND revision>=NEW.revision
    ) THEN
        RAISE EXCEPTION 'node revocation checkpoint revision must increase strictly'
            USING ERRCODE='P1531';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION prevent_node_revocation_checkpoint_history_mutation_153()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'node revocation checkpoint history is append-only'
        USING ERRCODE='P1532';
END;
$$;

CREATE FUNCTION guard_node_revocation_checkpoint_lkg_153()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP='DELETE' THEN
        RAISE EXCEPTION 'node revocation checkpoint LKG cannot be deleted'
            USING ERRCODE='P1533';
    END IF;
    IF TG_OP='UPDATE' AND (
        NEW.installation_id IS DISTINCT FROM OLD.installation_id OR
        NEW.revision<=OLD.revision OR NEW.issued_at<OLD.issued_at
    ) THEN
        RAISE EXCEPTION 'node revocation checkpoint LKG revision must increase strictly'
            USING ERRCODE='P1533';
    END IF;
    NEW.applied_at:=transaction_timestamp();
    RETURN NEW;
END;
$$;

CREATE FUNCTION prevent_node_revocation_checkpoint_lkg_truncate_153()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'node revocation checkpoint LKG cannot be truncated'
        USING ERRCODE='P1533';
END;
$$;

CREATE TRIGGER node_revocation_checkpoint_history_sequence_153
BEFORE INSERT ON node_revocation_checkpoint_history
FOR EACH ROW EXECUTE FUNCTION guard_node_revocation_checkpoint_history_insert_153();

CREATE TRIGGER node_revocation_checkpoint_history_immutable_153
BEFORE UPDATE OR DELETE OR TRUNCATE ON node_revocation_checkpoint_history
FOR EACH STATEMENT EXECUTE FUNCTION prevent_node_revocation_checkpoint_history_mutation_153();

CREATE TRIGGER node_revocation_checkpoint_lkg_guard_153
BEFORE INSERT OR UPDATE OR DELETE ON node_revocation_checkpoint_lkg
FOR EACH ROW EXECUTE FUNCTION guard_node_revocation_checkpoint_lkg_153();

CREATE TRIGGER node_revocation_checkpoint_lkg_truncate_153
BEFORE TRUNCATE ON node_revocation_checkpoint_lkg
FOR EACH STATEMENT EXECUTE FUNCTION prevent_node_revocation_checkpoint_lkg_truncate_153();

REVOKE ALL ON node_revocation_checkpoint_history,node_revocation_checkpoint_lkg FROM PUBLIC;
REVOKE ALL ON FUNCTION guard_node_revocation_checkpoint_history_insert_153() FROM PUBLIC;
REVOKE ALL ON FUNCTION prevent_node_revocation_checkpoint_history_mutation_153() FROM PUBLIC;
REVOKE ALL ON FUNCTION guard_node_revocation_checkpoint_lkg_153() FROM PUBLIC;
REVOKE ALL ON FUNCTION prevent_node_revocation_checkpoint_lkg_truncate_153() FROM PUBLIC;
