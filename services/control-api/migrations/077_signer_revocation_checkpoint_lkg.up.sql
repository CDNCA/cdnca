CREATE TABLE control_signer_checkpoint_snapshots (
    revision bigint PRIMARY KEY CHECK (revision > 0),
    accepted_previous_revision bigint UNIQUE
        REFERENCES control_signer_checkpoint_snapshots(revision) ON DELETE RESTRICT,
    previous_revision bigint,
    previous_checkpoint_sha256 bytea CHECK (octet_length(previous_checkpoint_sha256) = 32),
    checkpoint_sha256 bytea NOT NULL UNIQUE CHECK (octet_length(checkpoint_sha256) = 32),
    etag text NOT NULL CHECK (etag ~ '^"[A-Za-z0-9_-]{43}"$'),
    signed_checkpoint bytea NOT NULL CHECK (octet_length(signed_checkpoint) BETWEEN 1 AND 8388608),
    keyset_payload bytea NOT NULL CHECK (octet_length(keyset_payload) BETWEEN 1 AND 1048576),
    keyset_sha256 bytea NOT NULL CHECK (octet_length(keyset_sha256) = 32),
    head_sequence bigint NOT NULL CHECK (head_sequence BETWEEN 0 AND 10000),
    head_manifest_sha256 bytea CHECK (octet_length(head_manifest_sha256) = 32),
    accepted_at timestamptz NOT NULL CHECK (isfinite(accepted_at)),
    CHECK ((revision = 1 AND previous_revision IS NULL AND previous_checkpoint_sha256 IS NULL) OR
           (revision > 1 AND previous_revision = revision - 1 AND previous_checkpoint_sha256 IS NOT NULL)),
    CHECK ((head_sequence = 0) = (head_manifest_sha256 IS NULL))
);

CREATE TABLE control_signer_checkpoint_manifests (
    checkpoint_revision bigint NOT NULL
        REFERENCES control_signer_checkpoint_snapshots(revision) ON DELETE RESTRICT,
    sequence bigint NOT NULL CHECK (sequence > 0),
    previous_sequence bigint,
    previous_manifest_sha256 bytea CHECK (octet_length(previous_manifest_sha256) = 32),
    manifest_sha256 bytea NOT NULL CHECK (octet_length(manifest_sha256) = 32),
    signed_manifest bytea NOT NULL CHECK (octet_length(signed_manifest) BETWEEN 1 AND 8388608),
    PRIMARY KEY (checkpoint_revision, sequence),
    CHECK ((sequence = 1 AND previous_sequence IS NULL AND previous_manifest_sha256 IS NULL) OR
           (sequence > 1 AND previous_sequence = sequence - 1 AND previous_manifest_sha256 IS NOT NULL))
);

CREATE TABLE control_signer_checkpoint_audit (
    stream_position bigint PRIMARY KEY CHECK (stream_position > 0),
    operation_id uuid NOT NULL,
    event_type text NOT NULL CHECK (event_type IN ('accept','replay','outage')),
    reason_code text NOT NULL CHECK (reason_code ~ '^[a-z][a-z0-9_]{0,95}$'),
    checkpoint_revision bigint REFERENCES control_signer_checkpoint_snapshots(revision) ON DELETE RESTRICT
        CHECK (checkpoint_revision > 0),
    checkpoint_sha256 bytea CHECK (octet_length(checkpoint_sha256) = 32),
    etag text CHECK (etag ~ '^"[A-Za-z0-9_-]{43}"$'),
    occurred_at timestamptz NOT NULL CHECK (isfinite(occurred_at)),
    previous_hash bytea CHECK (octet_length(previous_hash) = 32),
    event_hash bytea NOT NULL UNIQUE CHECK (octet_length(event_hash) = 32),
    CHECK ((stream_position = 1) = (previous_hash IS NULL)),
    CHECK ((event_type IN ('accept','replay')) =
           (checkpoint_revision IS NOT NULL AND checkpoint_sha256 IS NOT NULL AND etag IS NOT NULL))
);

CREATE UNIQUE INDEX control_signer_checkpoint_audit_accept_revision_077
ON control_signer_checkpoint_audit(checkpoint_revision)
WHERE event_type = 'accept';

CREATE FUNCTION protect_control_signer_checkpoint_fact_077()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'control signer checkpoint facts are append-only' USING ERRCODE = 'P0001';
END;
$$;

CREATE FUNCTION validate_control_signer_checkpoint_snapshot_077()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    latest control_signer_checkpoint_snapshots%ROWTYPE;
BEGIN
    PERFORM pg_advisory_xact_lock(501809704351924);
    SELECT * INTO latest FROM control_signer_checkpoint_snapshots ORDER BY revision DESC LIMIT 1;
    IF NOT FOUND THEN
        IF NEW.accepted_previous_revision IS NOT NULL THEN
            RAISE EXCEPTION 'invalid initial control signer checkpoint' USING ERRCODE = 'P0001';
        END IF;
    ELSIF NEW.revision <= latest.revision OR NEW.accepted_previous_revision <> latest.revision OR
          NEW.head_sequence < latest.head_sequence THEN
        RAISE EXCEPTION 'control signer checkpoint does not extend the LKG' USING ERRCODE = 'P0001';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION assert_control_signer_checkpoint_complete_077()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    manifest_count bigint;
    matching_accept_count bigint;
    projected_head bytea;
BEGIN
    SELECT count(*) INTO manifest_count
    FROM control_signer_checkpoint_manifests
    WHERE checkpoint_revision = NEW.revision;
    IF NEW.head_sequence > 0 THEN
        SELECT manifest_sha256 INTO projected_head
        FROM control_signer_checkpoint_manifests
        WHERE checkpoint_revision = NEW.revision AND sequence = NEW.head_sequence;
    END IF;
    SELECT count(*) INTO matching_accept_count
    FROM control_signer_checkpoint_audit
    WHERE event_type = 'accept'
      AND reason_code = 'checkpoint_accepted'
      AND checkpoint_revision = NEW.revision
      AND checkpoint_sha256 = NEW.checkpoint_sha256
      AND etag = NEW.etag
      AND occurred_at = NEW.accepted_at;
    IF manifest_count <> NEW.head_sequence OR
       (NEW.head_sequence > 0 AND projected_head IS DISTINCT FROM NEW.head_manifest_sha256) OR
       matching_accept_count <> 1 THEN
        RAISE EXCEPTION 'control signer checkpoint projection is incomplete' USING ERRCODE = 'P0001';
    END IF;
    RETURN NULL;
END;
$$;

CREATE FUNCTION validate_control_signer_checkpoint_manifest_077()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    snapshot control_signer_checkpoint_snapshots%ROWTYPE;
    prior control_signer_checkpoint_manifests%ROWTYPE;
BEGIN
    SELECT * INTO snapshot FROM control_signer_checkpoint_snapshots
    WHERE revision = NEW.checkpoint_revision FOR KEY SHARE;
    IF NOT FOUND OR NEW.sequence > snapshot.head_sequence OR
       (NEW.sequence = snapshot.head_sequence AND NEW.manifest_sha256 <> snapshot.head_manifest_sha256) THEN
        RAISE EXCEPTION 'control signer checkpoint manifest is not bound to its projection' USING ERRCODE = 'P0001';
    END IF;
    IF NEW.sequence > 1 THEN
        SELECT * INTO prior FROM control_signer_checkpoint_manifests
        WHERE checkpoint_revision = NEW.checkpoint_revision AND sequence = NEW.sequence - 1;
        IF NOT FOUND OR NEW.previous_sequence <> prior.sequence OR
           NEW.previous_manifest_sha256 <> prior.manifest_sha256 THEN
            RAISE EXCEPTION 'control signer checkpoint manifest chain is incomplete' USING ERRCODE = 'P0001';
        END IF;
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION validate_control_signer_checkpoint_audit_077()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    latest control_signer_checkpoint_audit%ROWTYPE;
BEGIN
    PERFORM pg_advisory_xact_lock(501809704351925);
    SELECT * INTO latest FROM control_signer_checkpoint_audit ORDER BY stream_position DESC LIMIT 1;
    IF NOT FOUND THEN
        IF NEW.stream_position <> 1 OR NEW.previous_hash IS NOT NULL THEN
            RAISE EXCEPTION 'invalid initial control signer checkpoint audit' USING ERRCODE = 'P0001';
        END IF;
    ELSIF NEW.stream_position <> latest.stream_position + 1 OR NEW.previous_hash <> latest.event_hash THEN
        RAISE EXCEPTION 'control signer checkpoint audit does not extend the chain' USING ERRCODE = 'P0001';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER control_signer_checkpoint_snapshots_validate_077
BEFORE INSERT ON control_signer_checkpoint_snapshots
FOR EACH ROW EXECUTE FUNCTION validate_control_signer_checkpoint_snapshot_077();
CREATE CONSTRAINT TRIGGER control_signer_checkpoint_snapshots_complete_077
AFTER INSERT ON control_signer_checkpoint_snapshots
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION assert_control_signer_checkpoint_complete_077();
CREATE TRIGGER control_signer_checkpoint_manifests_validate_077
BEFORE INSERT ON control_signer_checkpoint_manifests
FOR EACH ROW EXECUTE FUNCTION validate_control_signer_checkpoint_manifest_077();
CREATE TRIGGER control_signer_checkpoint_audit_validate_077
BEFORE INSERT ON control_signer_checkpoint_audit
FOR EACH ROW EXECUTE FUNCTION validate_control_signer_checkpoint_audit_077();

CREATE TRIGGER control_signer_checkpoint_snapshots_immutable_077
BEFORE UPDATE OR DELETE ON control_signer_checkpoint_snapshots
FOR EACH ROW EXECUTE FUNCTION protect_control_signer_checkpoint_fact_077();
CREATE TRIGGER control_signer_checkpoint_snapshots_no_truncate_077
BEFORE TRUNCATE ON control_signer_checkpoint_snapshots
FOR EACH STATEMENT EXECUTE FUNCTION protect_control_signer_checkpoint_fact_077();
CREATE TRIGGER control_signer_checkpoint_manifests_immutable_077
BEFORE UPDATE OR DELETE ON control_signer_checkpoint_manifests
FOR EACH ROW EXECUTE FUNCTION protect_control_signer_checkpoint_fact_077();
CREATE TRIGGER control_signer_checkpoint_manifests_no_truncate_077
BEFORE TRUNCATE ON control_signer_checkpoint_manifests
FOR EACH STATEMENT EXECUTE FUNCTION protect_control_signer_checkpoint_fact_077();
CREATE TRIGGER control_signer_checkpoint_audit_immutable_077
BEFORE UPDATE OR DELETE ON control_signer_checkpoint_audit
FOR EACH ROW EXECUTE FUNCTION protect_control_signer_checkpoint_fact_077();
CREATE TRIGGER control_signer_checkpoint_audit_no_truncate_077
BEFORE TRUNCATE ON control_signer_checkpoint_audit
FOR EACH STATEMENT EXECUTE FUNCTION protect_control_signer_checkpoint_fact_077();

ALTER TABLE control_signer_checkpoint_snapshots ENABLE ALWAYS TRIGGER control_signer_checkpoint_snapshots_immutable_077;
ALTER TABLE control_signer_checkpoint_snapshots ENABLE ALWAYS TRIGGER control_signer_checkpoint_snapshots_no_truncate_077;
ALTER TABLE control_signer_checkpoint_manifests ENABLE ALWAYS TRIGGER control_signer_checkpoint_manifests_immutable_077;
ALTER TABLE control_signer_checkpoint_manifests ENABLE ALWAYS TRIGGER control_signer_checkpoint_manifests_no_truncate_077;
ALTER TABLE control_signer_checkpoint_audit ENABLE ALWAYS TRIGGER control_signer_checkpoint_audit_immutable_077;
ALTER TABLE control_signer_checkpoint_audit ENABLE ALWAYS TRIGGER control_signer_checkpoint_audit_no_truncate_077;
