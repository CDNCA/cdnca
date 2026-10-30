CREATE TABLE control_installation_entitlement (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    installation_id text NOT NULL UNIQUE CHECK (
        char_length(installation_id) BETWEEN 1 AND 128 AND
        installation_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]*$'
    ),
    expected_audience text NOT NULL DEFAULT 'cdnca-control-plane'
        CHECK (expected_audience = 'cdnca-control-plane'),
    current_serial bigint CHECK (current_serial > 0),
    last_status text NOT NULL DEFAULT 'uninstalled'
        CHECK (last_status IN ('uninstalled', 'valid', 'grace', 'expired', 'revoked', 'invalid')),
    last_error_code text CHECK (
        last_error_code IS NULL OR char_length(last_error_code) BETWEEN 1 AND 96
    ),
    last_verified_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CHECK (
        (current_serial IS NULL AND last_status IN ('uninstalled', 'invalid')) OR
        (current_serial IS NOT NULL AND last_status <> 'uninstalled')
    )
);

CREATE TABLE entitlement_verification_keys (
    key_id text PRIMARY KEY CHECK (
        char_length(key_id) BETWEEN 1 AND 128 AND
        key_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]*$'
    ),
    public_key bytea NOT NULL CHECK (octet_length(public_key) = 32),
    first_seen_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE entitlement_cached_leases (
    serial bigint PRIMARY KEY CHECK (serial > 0),
    installation_id text NOT NULL REFERENCES control_installation_entitlement(installation_id) ON DELETE RESTRICT,
    customer_id text NOT NULL CHECK (char_length(customer_id) BETWEEN 1 AND 128),
    license_id text NOT NULL CHECK (char_length(license_id) BETWEEN 1 AND 128),
    key_id text NOT NULL REFERENCES entitlement_verification_keys(key_id) ON DELETE RESTRICT,
    signed_lease bytea NOT NULL CHECK (octet_length(signed_lease) BETWEEN 1 AND 65536),
    status text NOT NULL CHECK (status IN ('valid', 'grace', 'expired', 'revoked')),
    not_before timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    grace_until timestamptz NOT NULL,
    verified_at timestamptz NOT NULL,
    installed_at timestamptz NOT NULL DEFAULT now(),
    CHECK (expires_at > not_before AND grace_until >= expires_at)
);

ALTER TABLE control_installation_entitlement
    ADD CONSTRAINT control_installation_current_lease_fk
    FOREIGN KEY (current_serial) REFERENCES entitlement_cached_leases(serial) ON DELETE RESTRICT
    DEFERRABLE INITIALLY DEFERRED;

CREATE INDEX entitlement_cached_leases_installation_idx
    ON entitlement_cached_leases (installation_id, serial DESC);
