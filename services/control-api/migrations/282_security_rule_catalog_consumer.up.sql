LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;

DO $migration_282_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 281 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 281 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=281 AND
        migration_id='281_node_auto_disable_usage' AND
        checksum_sha256='9d452586cc12a60903266cb0418b752c871471af1b70f34e60b4a45e317717a6' AND
        down_checksum_sha256='1d7d99dd4066ebae4bcd4fabe030c5ab3d6201f88044b8b195783472a428a1a2' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR checksum_sha256 IS NULL OR
        down_checksum_sha256 IS NULL OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR to_regclass(current_schema() || '.security_system_rules') IS NOT NULL THEN
        RAISE EXCEPTION 'migration 282 requires the exact verified 281 release head' USING ERRCODE='P2820';
    END IF;
END;
$migration_282_up$;

-- @security-rule-catalog-consumer-ddl
-- Consumer of the signed cdnca.security-rule-catalog/v1 channel. System
-- rules are stored once per installation (not per tenant), so a fresh
-- install without tenants still shows the full catalog. Rows are written
-- only by the catalog consumer inside a verified apply; withdrawn rules keep
-- their last body frozen and are marked withdrawn.
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

CREATE TABLE security_system_rules (
    system_key text PRIMARY KEY CHECK (system_key ~ '^(cc_rule|cc_matcher|cc_filter|waf_set):[A-Za-z0-9._-]{1,64}$'),
    kind text NOT NULL CHECK (kind IN ('cc_rule_group', 'cc_matcher', 'cc_filter', 'waf_rule_set')),
    legacy_id text NOT NULL DEFAULT '' CHECK (legacy_id ~ '^[0-9]{0,32}$'),
    name text NOT NULL CHECK (char_length(name) BETWEEN 1 AND 128),
    description text NOT NULL DEFAULT '' CHECK (char_length(description) <= 1000),
    sort integer NOT NULL CHECK (sort BETWEEN 0 AND 100000),
    hidden boolean NOT NULL,
    revision bigint NOT NULL CHECK (revision > 0),
    body jsonb NOT NULL CHECK (jsonb_typeof(body) = 'object'),
    status text NOT NULL CHECK (status IN ('active', 'withdrawn')),
    delivery_id uuid NOT NULL,
    first_seen_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    withdrawn_at timestamptz,
    CHECK ((status = 'withdrawn') = (withdrawn_at IS NOT NULL))
);

CREATE INDEX security_system_rules_kind_idx ON security_system_rules(kind, sort, system_key);

CREATE FUNCTION protect_security_system_rules_282()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF current_setting('cdnca.security_rule_catalog_apply', true) IS DISTINCT FROM 'on' THEN
        RAISE EXCEPTION 'security system rules are written only by the signed catalog consumer' USING ERRCODE='P2821';
    END IF;
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'security system rules are never deleted; withdrawn rules stay frozen' USING ERRCODE='P2822';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER security_system_rules_protect
BEFORE INSERT OR UPDATE OR DELETE ON security_system_rules
FOR EACH ROW EXECUTE FUNCTION protect_security_system_rules_282();
CREATE TRIGGER security_system_rules_no_truncate
BEFORE TRUNCATE ON security_system_rules
FOR EACH STATEMENT EXECUTE FUNCTION protect_security_system_rules_282();

-- Local administrator overlay (competitor is_show/show_to): whether a system
-- rule is shown to tenants, and optionally only to listed tenant scopes.
CREATE TABLE security_system_rule_visibility (
    system_key text PRIMARY KEY REFERENCES security_system_rules(system_key) ON DELETE RESTRICT,
    visible boolean NOT NULL,
    show_to_scope_ids uuid[] NOT NULL DEFAULT '{}' CHECK (cardinality(show_to_scope_ids) <= 1000),
    revision bigint NOT NULL CHECK (revision > 0),
    updated_by_user_id uuid NOT NULL,
    updated_at timestamptz NOT NULL
);

-- Tenants may only enable or disable system rules (parameters are read-only).
CREATE TABLE security_system_rule_tenant_states (
    scope_id uuid NOT NULL,
    system_key text NOT NULL REFERENCES security_system_rules(system_key) ON DELETE RESTRICT,
    enabled boolean NOT NULL,
    revision bigint NOT NULL CHECK (revision > 0),
    updated_by_user_id uuid NOT NULL,
    updated_at timestamptz NOT NULL,
    PRIMARY KEY (scope_id, system_key)
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
-- @end-security-rule-catalog-consumer-ddl

REVOKE ALL ON FUNCTION protect_security_system_rules_282() FROM PUBLIC;
GRANT SELECT, INSERT, UPDATE ON security_rule_catalog_consumer_state, security_system_rules,
    security_system_rule_visibility, security_system_rule_tenant_states, security_rule_catalog_ack_outbox
    TO cdnca_control_app, cdnca_control_runtime;
