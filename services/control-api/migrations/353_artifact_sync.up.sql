LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;

DO $migration_353_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 352 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 352 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=352 AND
        migration_id='352_capability_hold_published' AND
        checksum_sha256='0da091ad25a8dbca26a0dc3f5b865704d6b8357ea1da686c4c757aaea15ff64e' AND
        down_checksum_sha256='fa4edbb55f03cb0c2bc93f4e30b1703d2dd0c92db817e1db5641e5a373cb600d' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR to_regclass(current_schema() || '.artifact_catalog_state') IS NOT NULL THEN
        RAISE EXCEPTION 'migration 353 requires the exact verified 352 release head' USING ERRCODE='P3530';
    END IF;
END;
$migration_353_up$;

-- r136 PA-02 (placeholder number; renumbered on merge): artifactsync, the
-- control-plane consumer of the license service's signed artifact catalog
-- (cdnca.artifact-catalog/v1, docs/adr/0007-plugin-platform-architecture.md
-- §4.1/§5.4). It replaces the security rule catalog consumer (282) and the IP
-- intelligence library sync (315); their state tables go (no data is kept:
-- compatibility baseline 1.0.35, the next sync downloads again).
--   * artifact_catalog_state: the last verified delivery (head) and attempts.
--   * artifact_catalog_entries: every entry of that delivery ("available");
--     entries no longer delivered stay as withdrawn.
--   * artifact_objects: downloaded bytes by sha256 (immutable; verified
--     against the signed entry before they are stored). This is the input
--     of the node artifact set distributor (PA-01).
--   * local_artifacts: what this control plane downloaded per artifact
--     ("downloaded", LKG: the revision only moves forward, a failed or
--     rejected download keeps the previous one) and download requests.
--   * artifact_enablement_overrides: reserved for PA-11 (enable / disable /
--     inherit per platform, tenant, site; downloading never enables).
-- security_system_rules stays the materialized view of the downloaded
-- ruleset / crs_profile artifacts (written only by artifactsync).
-- @artifact-sync-ddl
DROP TABLE security_rule_catalog_ack_outbox;
DROP TABLE security_rule_catalog_consumer_state;
DROP TABLE ip_intel_sync_state;
DROP TABLE ip_intel_library;
DROP FUNCTION protect_ip_intel_library_315();

CREATE TABLE artifact_catalog_state (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    delivery_id uuid,
    scope_revision bigint CHECK (scope_revision BETWEEN 1 AND 9007199254740991),
    catalog_sha256 text CHECK (char_length(catalog_sha256) = 43),
    key_id text CHECK (char_length(key_id) BETWEEN 1 AND 128),
    signed_document bytea CHECK (octet_length(signed_document) BETWEEN 2 AND 2162688),
    valid_from timestamptz,
    expires_at timestamptz,
    applied_at timestamptz,
    last_attempt_at timestamptz,
    last_success_at timestamptz,
    last_error_code text NOT NULL DEFAULT '' CHECK (last_error_code ~ '^[a-z_]{0,64}$'),
    updated_at timestamptz NOT NULL,
    CHECK ((delivery_id IS NULL) = (scope_revision IS NULL) AND (delivery_id IS NULL) = (catalog_sha256 IS NULL) AND
           (delivery_id IS NULL) = (key_id IS NULL) AND (delivery_id IS NULL) = (signed_document IS NULL) AND
           (delivery_id IS NULL) = (valid_from IS NULL) AND (delivery_id IS NULL) = (expires_at IS NULL) AND
           (delivery_id IS NULL) = (applied_at IS NULL))
);

INSERT INTO artifact_catalog_state(singleton, updated_at) VALUES (true, CURRENT_TIMESTAMP);

CREATE TABLE artifact_catalog_entries (
    artifact_id text PRIMARY KEY CHECK (artifact_id ~ '^[a-z][a-z0-9_]{0,31}/[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'),
    kind text NOT NULL CHECK (kind = split_part(artifact_id, '/', 1)),
    version text NOT NULL CHECK (char_length(version) BETWEEN 1 AND 64),
    revision bigint NOT NULL CHECK (revision BETWEEN 1 AND 9007199254740991),
    sha256 text NOT NULL CHECK (sha256 ~ '^[0-9a-f]{64}$'),
    size bigint NOT NULL CHECK (size BETWEEN 1 AND 268435456),
    media_type text NOT NULL CHECK (char_length(media_type) BETWEEN 1 AND 160),
    requires_feature text NOT NULL DEFAULT '' CHECK (requires_feature = '' OR requires_feature ~ '^[a-z][a-z0-9._-]{0,127}$'),
    requires_capability jsonb CHECK (requires_capability IS NULL OR jsonb_typeof(requires_capability) = 'object'),
    resident boolean NOT NULL,
    encryption text NOT NULL CHECK (encryption IN ('none', 'install_wrapped')),
    license_spdx text NOT NULL DEFAULT '' CHECK (char_length(license_spdx) <= 64),
    supersedes text NOT NULL DEFAULT '' CHECK (char_length(supersedes) <= 160),
    status text NOT NULL CHECK (status IN ('active', 'withdrawn')),
    delivery_id uuid NOT NULL,
    first_seen_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    withdrawn_at timestamptz,
    CHECK ((status = 'withdrawn') = (withdrawn_at IS NOT NULL))
);

CREATE TABLE artifact_objects (
    sha256 text PRIMARY KEY CHECK (sha256 ~ '^[0-9a-f]{64}$'),
    size bigint NOT NULL CHECK (size BETWEEN 1 AND 268435456),
    content bytea NOT NULL CHECK (octet_length(content) = size),
    stored_at timestamptz NOT NULL
);

CREATE FUNCTION protect_artifact_objects_353() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'artifact objects are immutable' USING ERRCODE = '23514';
END;
$$;

CREATE TRIGGER artifact_objects_immutable_353 BEFORE UPDATE ON artifact_objects
    FOR EACH ROW EXECUTE FUNCTION protect_artifact_objects_353();

CREATE TABLE local_artifacts (
    artifact_id text PRIMARY KEY REFERENCES artifact_catalog_entries(artifact_id) ON DELETE RESTRICT,
    current_revision bigint CHECK (current_revision BETWEEN 1 AND 9007199254740991),
    current_sha256 text REFERENCES artifact_objects(sha256) ON DELETE RESTRICT,
    current_version text CHECK (char_length(current_version) BETWEEN 1 AND 64),
    -- The node capability the downloaded revision needs (its signed entry's
    -- requires_capability; the catalog may already list a newer revision).
    current_requires_capability jsonb CHECK (current_requires_capability IS NULL OR
        jsonb_typeof(current_requires_capability) = 'object'),
    downloaded_at timestamptz,
    -- The digest last applied to security_system_rules (ruleset / crs_profile).
    materialized_sha256 text CHECK (materialized_sha256 ~ '^[0-9a-f]{64}$'),
    requested_at timestamptz,
    requested_by_user_id uuid,
    last_attempt_at timestamptz,
    last_error_code text NOT NULL DEFAULT '' CHECK (last_error_code ~ '^[a-z_]{0,64}$'),
    rejected_revision bigint CHECK (rejected_revision IS NULL OR rejected_revision > 0),
    updated_at timestamptz NOT NULL,
    CHECK ((current_revision IS NULL) = (current_sha256 IS NULL) AND (current_revision IS NULL) = (current_version IS NULL) AND
           (current_revision IS NULL) = (downloaded_at IS NULL)),
    CHECK ((requested_at IS NULL) = (requested_by_user_id IS NULL))
);

-- LKG: the downloaded revision of an artifact only moves forward.
CREATE FUNCTION protect_local_artifacts_353() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'local artifacts are never deleted by the sync' USING ERRCODE = '23514';
    END IF;
    IF OLD.current_revision IS NOT NULL AND (NEW.current_revision IS NULL OR NEW.current_revision < OLD.current_revision OR
       (NEW.current_revision = OLD.current_revision AND NEW.current_sha256 <> OLD.current_sha256)) THEN
        RAISE EXCEPTION 'local artifact revisions only move forward' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER local_artifacts_forward_353 BEFORE UPDATE OR DELETE ON local_artifacts
    FOR EACH ROW EXECUTE FUNCTION protect_local_artifacts_353();

-- Reserved for PA-11 (ADR 0007 §5.4): per layer (platform / tenant / site)
-- and artifact (optionally one exported rule) an enable state of inherit /
-- enabled / disabled, and whether lower layers may override it. Nothing
-- reads or writes it yet; downloading an artifact never enables it.
CREATE TABLE artifact_enablement_overrides (
    layer text NOT NULL CHECK (layer IN ('platform', 'tenant', 'site')),
    layer_object_id uuid NOT NULL,
    artifact_id text NOT NULL CHECK (artifact_id ~ '^[a-z][a-z0-9_]{0,31}/[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'),
    rule_id text NOT NULL DEFAULT '' CHECK (char_length(rule_id) <= 128),
    state text NOT NULL CHECK (state IN ('inherit', 'enabled', 'disabled')),
    allow_lower_override boolean NOT NULL DEFAULT true,
    updated_by_user_id uuid NOT NULL,
    updated_at timestamptz NOT NULL,
    PRIMARY KEY (layer, layer_object_id, artifact_id, rule_id)
);
-- @end-artifact-sync-ddl

REVOKE ALL ON FUNCTION protect_artifact_objects_353() FROM PUBLIC;
REVOKE ALL ON FUNCTION protect_local_artifacts_353() FROM PUBLIC;
GRANT SELECT, INSERT, UPDATE ON artifact_catalog_state, artifact_catalog_entries, local_artifacts,
    artifact_enablement_overrides TO cdnca_control_app, cdnca_control_runtime;
GRANT SELECT, INSERT ON artifact_objects TO cdnca_control_app, cdnca_control_runtime;
