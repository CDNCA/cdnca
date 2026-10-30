CREATE TABLE control_signer_trust_snapshots (
    revision bigint PRIMARY KEY CHECK (revision > 0),
    previous_revision bigint UNIQUE REFERENCES control_signer_trust_snapshots(revision) ON DELETE RESTRICT,
    keyset_schema text NOT NULL CHECK (keyset_schema = 'cdnca.signing-keyset/v2'),
    keyset_etag text NOT NULL CHECK (keyset_etag ~ '^"[A-Za-z0-9_-]{43}"$'),
    keyset_active_key_id text NOT NULL CHECK (
        keyset_active_key_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
    ),
    keyset_payload bytea NOT NULL CHECK (octet_length(keyset_payload) BETWEEN 1 AND 1048576),
    keyset_payload_sha256 bytea NOT NULL CHECK (octet_length(keyset_payload_sha256) = 32),
    revocation_sequence bigint NOT NULL CHECK (revocation_sequence >= 0),
    revocation_manifest_sha256 bytea CHECK (octet_length(revocation_manifest_sha256) = 32),
    revocation_etag text CHECK (revocation_etag ~ '^"[A-Za-z0-9_-]{43}"$'),
    accepted_at timestamptz NOT NULL,
    CHECK ((revocation_sequence = 0) =
           (revocation_manifest_sha256 IS NULL AND revocation_etag IS NULL))
);

CREATE TABLE control_signer_revocation_manifests (
    sequence bigint PRIMARY KEY CHECK (sequence > 0),
    snapshot_revision bigint NOT NULL UNIQUE
        REFERENCES control_signer_trust_snapshots(revision) ON DELETE RESTRICT,
    previous_sequence bigint,
    previous_manifest_sha256 bytea CHECK (octet_length(previous_manifest_sha256) = 32),
    manifest_sha256 bytea NOT NULL UNIQUE CHECK (octet_length(manifest_sha256) = 32),
    etag text NOT NULL CHECK (etag ~ '^"[A-Za-z0-9_-]{43}"$'),
    revoked_key_id text NOT NULL CHECK (revoked_key_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'),
    revoked_key_generation bigint NOT NULL CHECK (revoked_key_generation > 0),
    artifact_classes text[] NOT NULL CHECK (
        cardinality(artifact_classes) BETWEEN 1 AND 3 AND
        artifact_classes <@ ARRAY['lease','policy','release']::text[]
    ),
    effective_not_before timestamptz NOT NULL,
    authority_kind text NOT NULL CHECK (authority_kind IN ('lineage','offline_root')),
    authority_key_id text NOT NULL CHECK (authority_key_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'),
    authority_key_generation bigint NOT NULL CHECK (authority_key_generation > 0),
    signed_manifest bytea NOT NULL CHECK (octet_length(signed_manifest) BETWEEN 1 AND 131072),
    accepted_at timestamptz NOT NULL,
    CHECK ((sequence = 1 AND previous_sequence IS NULL AND previous_manifest_sha256 IS NULL) OR
           (sequence > 1 AND previous_sequence = sequence - 1 AND previous_manifest_sha256 IS NOT NULL))
);

CREATE TABLE control_signer_revocation_events (
    id uuid PRIMARY KEY,
    stream_position bigint NOT NULL UNIQUE CHECK (stream_position > 0),
    operation_id uuid NOT NULL,
    stage text NOT NULL CHECK (stage IN ('fetch','verify','apply','reject')),
    result text NOT NULL CHECK (result IN ('success','failure')),
    reason_code text NOT NULL CHECK (reason_code ~ '^[a-z][a-z0-9_]{0,95}$'),
    snapshot_revision bigint,
    revocation_sequence bigint CHECK (revocation_sequence > 0),
    revocation_manifest_sha256 bytea CHECK (octet_length(revocation_manifest_sha256) = 32),
    keyset_etag text CHECK (keyset_etag ~ '^"[A-Za-z0-9_-]{43}"$'),
    revocation_etag text CHECK (revocation_etag ~ '^"[A-Za-z0-9_-]{43}"$'),
    occurred_at timestamptz NOT NULL
);

CREATE TABLE control_signer_revocation_audit (
    stream_position bigint PRIMARY KEY CHECK (stream_position > 0),
    event_id uuid NOT NULL UNIQUE REFERENCES control_signer_revocation_events(id) ON DELETE RESTRICT,
    previous_hash bytea CHECK (octet_length(previous_hash) = 32),
    event_hash bytea NOT NULL UNIQUE CHECK (octet_length(event_hash) = 32),
    occurred_at timestamptz NOT NULL,
    CHECK ((stream_position = 1) = (previous_hash IS NULL))
);

CREATE FUNCTION protect_control_signer_revocation_fact()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'control signer revocation facts are append-only' USING ERRCODE = 'P0001';
END;
$$;

CREATE FUNCTION validate_control_signer_trust_snapshot()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    latest control_signer_trust_snapshots%ROWTYPE;
BEGIN
    PERFORM pg_advisory_xact_lock(501809704351922);
    SELECT * INTO latest FROM control_signer_trust_snapshots ORDER BY revision DESC LIMIT 1;
    IF NOT FOUND THEN
        IF NEW.revision <> 1 OR NEW.previous_revision IS NOT NULL OR NEW.revocation_sequence NOT IN (0, 1) THEN
            RAISE EXCEPTION 'invalid initial control signer trust snapshot' USING ERRCODE = 'P0001';
        END IF;
    ELSIF NEW.revision <> latest.revision + 1 OR NEW.previous_revision <> latest.revision OR
          NEW.revocation_sequence NOT IN (latest.revocation_sequence, latest.revocation_sequence + 1) OR
          (NEW.revocation_sequence = latest.revocation_sequence AND
           ROW(NEW.revocation_manifest_sha256, NEW.revocation_etag) IS DISTINCT FROM
           ROW(latest.revocation_manifest_sha256, latest.revocation_etag)) THEN
        RAISE EXCEPTION 'control signer trust snapshot does not extend the LKG' USING ERRCODE = 'P0001';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION validate_control_signer_revocation_manifest()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    prior control_signer_revocation_manifests%ROWTYPE;
    snapshot control_signer_trust_snapshots%ROWTYPE;
BEGIN
    SELECT * INTO snapshot FROM control_signer_trust_snapshots
    WHERE revision = NEW.snapshot_revision FOR KEY SHARE;
    IF NOT FOUND OR snapshot.revocation_sequence <> NEW.sequence OR
       snapshot.revocation_manifest_sha256 <> NEW.manifest_sha256 OR snapshot.revocation_etag <> NEW.etag THEN
        RAISE EXCEPTION 'control signer revocation manifest is not bound to its snapshot' USING ERRCODE = 'P0001';
    END IF;
    IF NEW.sequence = 1 THEN
        RETURN NEW;
    END IF;
    SELECT * INTO prior FROM control_signer_revocation_manifests WHERE sequence = NEW.sequence - 1;
    IF NOT FOUND OR NEW.previous_sequence <> prior.sequence OR
       NEW.previous_manifest_sha256 <> prior.manifest_sha256 THEN
        RAISE EXCEPTION 'control signer revocation manifest does not extend the accepted chain'
            USING ERRCODE = 'P0001';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION assert_control_signer_snapshot_complete()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    prior_sequence bigint := 0;
BEGIN
    IF NEW.previous_revision IS NOT NULL THEN
        SELECT revocation_sequence INTO prior_sequence
        FROM control_signer_trust_snapshots WHERE revision = NEW.previous_revision;
    END IF;
    IF NEW.revocation_sequence = prior_sequence + 1 AND NOT EXISTS (
        SELECT 1 FROM control_signer_revocation_manifests
        WHERE sequence = NEW.revocation_sequence AND snapshot_revision = NEW.revision
    ) THEN
        RAISE EXCEPTION 'control signer trust snapshot is missing its revocation fact' USING ERRCODE = 'P0001';
    END IF;
    RETURN NULL;
END;
$$;

CREATE TRIGGER control_signer_trust_snapshots_validate
BEFORE INSERT ON control_signer_trust_snapshots
FOR EACH ROW EXECUTE FUNCTION validate_control_signer_trust_snapshot();
CREATE CONSTRAINT TRIGGER control_signer_trust_snapshots_complete
AFTER INSERT ON control_signer_trust_snapshots
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION assert_control_signer_snapshot_complete();
CREATE TRIGGER control_signer_revocation_manifests_validate
BEFORE INSERT ON control_signer_revocation_manifests
FOR EACH ROW EXECUTE FUNCTION validate_control_signer_revocation_manifest();

CREATE TRIGGER control_signer_trust_snapshots_immutable
BEFORE UPDATE OR DELETE ON control_signer_trust_snapshots
FOR EACH ROW EXECUTE FUNCTION protect_control_signer_revocation_fact();
CREATE TRIGGER control_signer_trust_snapshots_no_truncate
BEFORE TRUNCATE ON control_signer_trust_snapshots
FOR EACH STATEMENT EXECUTE FUNCTION protect_control_signer_revocation_fact();
CREATE TRIGGER control_signer_revocation_manifests_immutable
BEFORE UPDATE OR DELETE ON control_signer_revocation_manifests
FOR EACH ROW EXECUTE FUNCTION protect_control_signer_revocation_fact();
CREATE TRIGGER control_signer_revocation_manifests_no_truncate
BEFORE TRUNCATE ON control_signer_revocation_manifests
FOR EACH STATEMENT EXECUTE FUNCTION protect_control_signer_revocation_fact();
CREATE TRIGGER control_signer_revocation_events_immutable
BEFORE UPDATE OR DELETE ON control_signer_revocation_events
FOR EACH ROW EXECUTE FUNCTION protect_control_signer_revocation_fact();
CREATE TRIGGER control_signer_revocation_events_no_truncate
BEFORE TRUNCATE ON control_signer_revocation_events
FOR EACH STATEMENT EXECUTE FUNCTION protect_control_signer_revocation_fact();
CREATE TRIGGER control_signer_revocation_audit_immutable
BEFORE UPDATE OR DELETE ON control_signer_revocation_audit
FOR EACH ROW EXECUTE FUNCTION protect_control_signer_revocation_fact();
CREATE TRIGGER control_signer_revocation_audit_no_truncate
BEFORE TRUNCATE ON control_signer_revocation_audit
FOR EACH STATEMENT EXECUTE FUNCTION protect_control_signer_revocation_fact();

