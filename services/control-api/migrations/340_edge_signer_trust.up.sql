LOCK TABLE schema_migrations, nodes IN ACCESS EXCLUSIVE MODE;

DO $migration_340_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 339 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 339 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=339 AND
        migration_id='339_security_rule_catalog_republication' AND
        checksum_sha256='9fa371339d29ea5ec41e6337d0291a8037185c6e0b7c39842753bd337626a310' AND
        down_checksum_sha256='31acae1731a07cf53a9dd0a3f20bf32ab212d4616bdb972d78996448abe9ff45' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR to_regclass(current_schema() || '.edge_signer_trust_documents') IS NOT NULL THEN
        RAISE EXCEPTION 'migration 340 requires the exact verified 339 release head' USING ERRCODE='P3400';
    END IF;
END;
$migration_340_up$;

-- Node signer trust (签名密钥泄露吊销·节点侧): every accepted offline-root
-- signed cdnca.edge-signer-trust/v1 document, by strictly increasing
-- revision. The exact bytes are forwarded to nodes; a document is security
-- evidence and is never changed or removed.
CREATE TABLE edge_signer_trust_documents (
    revision bigint PRIMARY KEY CHECK (revision > 0),
    document bytea NOT NULL CHECK (octet_length(document) BETWEEN 1 AND 278528),
    document_sha256 bytea NOT NULL UNIQUE CHECK (octet_length(document_sha256) = 32),
    root_key_id text NOT NULL CHECK (char_length(root_key_id) BETWEEN 1 AND 128),
    root_generation bigint NOT NULL CHECK (root_generation > 0),
    revoked_keys integer NOT NULL CHECK (revoked_keys >= 0),
    source text NOT NULL CHECK (source IN ('fetch', 'import')),
    accepted_at timestamptz NOT NULL
);

-- Accept / reject / outage facts of the fetcher and the import command
-- (recorded on change, not per poll).
CREATE TABLE edge_signer_trust_events (
    id uuid PRIMARY KEY,
    event text NOT NULL CHECK (event IN ('accepted', 'replayed', 'rejected', 'unavailable')),
    reason text NOT NULL CHECK (reason ~ '^[a-z][a-z0-9_]{0,63}$'),
    revision bigint CHECK (revision IS NULL OR revision > 0),
    document_sha256 bytea CHECK (document_sha256 IS NULL OR octet_length(document_sha256) = 32),
    occurred_at timestamptz NOT NULL
);
CREATE INDEX edge_signer_trust_events_occurred_340 ON edge_signer_trust_events (occurred_at DESC);

CREATE FUNCTION protect_edge_signer_trust_340() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'edge signer trust facts are append-only' USING ERRCODE='P3402';
END;
$$;
CREATE TRIGGER edge_signer_trust_documents_append_only_340
BEFORE UPDATE OR DELETE ON edge_signer_trust_documents
FOR EACH ROW EXECUTE FUNCTION protect_edge_signer_trust_340();
CREATE TRIGGER edge_signer_trust_documents_no_truncate_340
BEFORE TRUNCATE ON edge_signer_trust_documents
FOR EACH STATEMENT EXECUTE FUNCTION protect_edge_signer_trust_340();
CREATE TRIGGER edge_signer_trust_events_append_only_340
BEFORE UPDATE OR DELETE ON edge_signer_trust_events
FOR EACH ROW EXECUTE FUNCTION protect_edge_signer_trust_340();
CREATE TRIGGER edge_signer_trust_events_no_truncate_340
BEFORE TRUNCATE ON edge_signer_trust_events
FOR EACH STATEMENT EXECUTE FUNCTION protect_edge_signer_trust_340();

-- Latest receipt per node: the revision the node enforces. Operational
-- state, replaced on every receipt.
CREATE TABLE edge_signer_trust_node_state (
    node_id uuid PRIMARY KEY REFERENCES nodes(id) ON DELETE CASCADE,
    bundle_sha256 bytea NOT NULL CHECK (octet_length(bundle_sha256) = 32),
    enforced_revision bigint NOT NULL CHECK (enforced_revision >= 0),
    result text NOT NULL CHECK (result IN ('applied', 'rejected')),
    reason text NOT NULL CHECK (reason = '' OR reason ~ '^[a-z][a-z0-9_]{0,63}$'),
    reported_at timestamptz NOT NULL,
    recorded_at timestamptz NOT NULL
);

REVOKE ALL ON edge_signer_trust_documents, edge_signer_trust_events, edge_signer_trust_node_state FROM PUBLIC;
GRANT SELECT, INSERT ON edge_signer_trust_documents, edge_signer_trust_events TO cdnca_control_app, cdnca_control_runtime;
GRANT SELECT, INSERT, UPDATE, DELETE ON edge_signer_trust_node_state TO cdnca_control_app, cdnca_control_runtime;
