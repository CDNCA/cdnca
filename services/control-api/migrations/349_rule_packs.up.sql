LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;

DO $migration_349_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 348 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 348 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=348 AND
        migration_id='348_node_deployment_timeouts' AND
        checksum_sha256='1073378383d2e63d4858913f637c54be738e2af70f73b0332e1176ed9f8b9a01' AND
        down_checksum_sha256='4066592c54f6f32b66fcd091d2c377e3cc11519d2c6c41c5cfec555cd57f2214' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR to_regclass(current_schema() || '.rule_packs') IS NOT NULL THEN
        RAISE EXCEPTION 'migration 349 requires the exact verified 348 release head' USING ERRCODE='P3490';
    END IF;
END;
$migration_349_up$;

-- r136 PA-10/PA-11 (placeholder number; renumbered on merge): rule packs
-- (cdnca.rule-pack/v1, libs/rulepack), "download" separate from "enable"
-- (ADR 0007 §5.4) and the resolved security.mounts of each site (ADR 0009
-- §8.4).
--
-- rule_packs: one row per pack_id. A user pack (user/<scope_id>/<name>) is
-- owned by that tenant scope; system / developer packs by the platform.
-- current_version is the version that is mounted when the pack is enabled;
-- update_policy says whether a newly downloaded version becomes current by
-- itself (system packs default to auto, others to manual).
CREATE TABLE rule_packs (
    pack_id text PRIMARY KEY CHECK (char_length(pack_id) BETWEEN 8 AND 160 AND pack_id ~ '^(system|dev|user)/'),
    layer text NOT NULL CHECK (layer IN ('system', 'developer', 'user')),
    owner_scope_id uuid REFERENCES access_scopes(id) ON DELETE RESTRICT,
    current_version text,
    update_policy text NOT NULL CHECK (update_policy IN ('auto', 'manual')),
    created_by_user_id uuid NOT NULL REFERENCES users(id),
    updated_by_user_id uuid NOT NULL REFERENCES users(id),
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    CHECK ((layer = 'user') = (owner_scope_id IS NOT NULL)),
    CHECK ((layer = 'system') = (pack_id LIKE 'system/%') AND (layer = 'developer') = (pack_id LIKE 'dev/%') AND
           (layer = 'user') = (pack_id LIKE 'user/%'))
);

-- rule_pack_artifacts: the local artifacts ("本地制品"). state available =
-- listed by the catalog, bytes not fetched; downloaded = canonical bytes
-- kept here (never sent to a node unless an enabled mount references them).
CREATE TABLE rule_pack_artifacts (
    pack_id text NOT NULL REFERENCES rule_packs(pack_id) ON DELETE CASCADE,
    version text NOT NULL CHECK (char_length(version) BETWEEN 5 AND 64),
    engine text NOT NULL CHECK (engine IN ('waf_v2', 'cc_v2', 'acl', 'challenge', 'modsecurity')),
    engine_min_version integer NOT NULL CHECK (engine_min_version BETWEEN 1 AND 1000),
    name text NOT NULL CHECK (char_length(name) BETWEEN 1 AND 128),
    sha256 text NOT NULL CHECK (sha256 ~ '^[0-9a-f]{64}$'),
    size_bytes integer NOT NULL CHECK (size_bytes BETWEEN 1 AND 1048576),
    content bytea,
    source text NOT NULL CHECK (source IN ('catalog', 'import', 'tenant')),
    state text NOT NULL CHECK (state IN ('available', 'downloaded')),
    downloaded_at timestamptz,
    created_by_user_id uuid NOT NULL REFERENCES users(id),
    created_at timestamptz NOT NULL,
    PRIMARY KEY (pack_id, version),
    UNIQUE (sha256),
    CHECK ((state = 'downloaded') = (content IS NOT NULL) AND (state = 'downloaded') = (downloaded_at IS NOT NULL)),
    CHECK (content IS NULL OR octet_length(content) = size_bytes)
);

ALTER TABLE rule_packs ADD CONSTRAINT rule_packs_current_version_349
    FOREIGN KEY (pack_id, current_version) REFERENCES rule_pack_artifacts(pack_id, version)
    DEFERRABLE INITIALLY DEFERRED;

-- rule_pack_enablements: the enablement overrides ("启用覆盖"). An absent
-- row is "inherit"; state inherit only carries allow_lower / priority /
-- params. rule_id names an exported rule (rule-level switch, enabled or
-- disabled only). level_object_id: NULL for the platform, the tenant scope
-- or the site otherwise.
CREATE TABLE rule_pack_enablements (
    id uuid PRIMARY KEY,
    level text NOT NULL CHECK (level IN ('platform', 'tenant', 'site')),
    level_object_id uuid,
    pack_id text NOT NULL REFERENCES rule_packs(pack_id) ON DELETE CASCADE,
    rule_id text CHECK (rule_id IS NULL OR rule_id ~ '^[a-z0-9][a-z0-9._-]{0,63}$'),
    state text NOT NULL CHECK (state IN ('inherit', 'enabled', 'disabled')),
    allow_lower boolean NOT NULL DEFAULT false,
    priority integer CHECK (priority IS NULL OR priority BETWEEN 0 AND 1000),
    params jsonb CHECK (params IS NULL OR jsonb_typeof(params) = 'object'),
    updated_by_user_id uuid NOT NULL REFERENCES users(id),
    updated_at timestamptz NOT NULL,
    CHECK ((level = 'platform') = (level_object_id IS NULL)),
    CHECK (rule_id IS NULL OR state <> 'inherit' AND priority IS NULL AND params IS NULL AND NOT allow_lower)
);
CREATE UNIQUE INDEX rule_pack_enablements_key_349 ON rule_pack_enablements
    (level, level_object_id, pack_id, rule_id) NULLS NOT DISTINCT;
CREATE INDEX rule_pack_enablements_object_349 ON rule_pack_enablements (level_object_id, pack_id);

-- site_security_mounts: the published security.mounts + resolved_sha256 of
-- a site (written only when resolution has no conflict). The site object
-- (g8c-objects) reads it; rule_pack_site_mount_artifacts keeps a mounted
-- artifact from being deleted.
CREATE TABLE site_security_mounts (
    site_id uuid PRIMARY KEY REFERENCES sites(id) ON DELETE CASCADE,
    revision bigint NOT NULL CHECK (revision >= 1),
    security jsonb NOT NULL CHECK (jsonb_typeof(security) = 'object'),
    resolved_sha256 text NOT NULL CHECK (resolved_sha256 ~ '^[0-9a-f]{64}$'),
    published_by_user_id uuid NOT NULL REFERENCES users(id),
    published_at timestamptz NOT NULL
);

CREATE TABLE rule_pack_site_mount_artifacts (
    site_id uuid NOT NULL REFERENCES site_security_mounts(site_id) ON DELETE CASCADE,
    pack_id text NOT NULL,
    version text NOT NULL,
    PRIMARY KEY (site_id, pack_id),
    FOREIGN KEY (pack_id, version) REFERENCES rule_pack_artifacts(pack_id, version) ON DELETE RESTRICT
);
CREATE INDEX rule_pack_site_mount_artifacts_artifact_349 ON rule_pack_site_mount_artifacts (pack_id, version);

GRANT SELECT, INSERT, UPDATE, DELETE ON rule_packs, rule_pack_artifacts, rule_pack_enablements,
    site_security_mounts, rule_pack_site_mount_artifacts TO cdnca_control_app;
GRANT SELECT ON rule_packs, rule_pack_artifacts, site_security_mounts, rule_pack_site_mount_artifacts
    TO cdnca_control_runtime;
