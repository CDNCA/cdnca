CREATE TABLE entitlement_signing_keyset_lkg (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    schema_version text NOT NULL CHECK (schema_version = 'cdnca.signing-keyset/v2'),
    etag text NOT NULL CHECK (char_length(etag) BETWEEN 4 AND 128),
    active_key_id text NOT NULL CHECK (
        char_length(active_key_id) BETWEEN 1 AND 128 AND
        active_key_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]*$'
    ),
    chain_depth integer NOT NULL CHECK (chain_depth > 0),
    payload bytea NOT NULL CHECK (octet_length(payload) BETWEEN 1 AND 1048576),
    payload_sha256 bytea NOT NULL CHECK (octet_length(payload_sha256) = 32),
    accepted_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL
);
