LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;

DO $migration_456_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 455 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 455 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=455 AND
        migration_id='455_system_mail_provider' AND
        checksum_sha256='2059ecff10cd7bac2ef831bf1bee5fb2980ae5ba90242d236949f34d677aab94' AND
        down_checksum_sha256='7722d8106b1dbaddce80877208f0198317fc094bc29f2e6231669c9adb1ffd8c' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR to_regclass('control_site_content') IS NOT NULL OR to_regclass('control_site_assets') IS NOT NULL OR
       to_regclass('site_theme_packages') IS NOT NULL THEN
        RAISE EXCEPTION 'migration 456 requires the exact verified 455 release head' USING ERRCODE='P4560';
    END IF;
END;
$migration_456_up$;

-- 456 (r136 control-site; allotted 456, numbered 456 on this branch so the
-- embedded set stays contiguous on the 455 head; the merge renumbers it).
-- The control plane's public website (官网): one content document per
-- platform scope, edited as a draft in the admin console and published to
-- GET /v1/control-site/content, and the website theme plugins (官网主题插件,
-- cdnca.site-theme/v1) that lay it out. The document holds the shared brand
-- and contact rail and, per layout renderer (jidun|xmf), that layout's
-- navigation, footer and pages, so switching plugins keeps every layout's
-- content. The website bundle holds no copy. A layout without content shows
-- the active plugin's seed; the migration inserts no rows.
--   draft / published     cdnca.control-site/v1 documents;
--   revision              optimistic concurrency of the draft;
--   published_revision    the draft revision that was published.
CREATE TABLE control_site_content (
    platform_scope_id uuid PRIMARY KEY REFERENCES access_scopes(id) ON DELETE RESTRICT,
    revision bigint NOT NULL CHECK (revision > 0),
    draft jsonb NOT NULL CHECK (jsonb_typeof(draft) = 'object' AND octet_length(draft::text) <= 1048576),
    published jsonb CHECK (published IS NULL OR (jsonb_typeof(published) = 'object' AND octet_length(published::text) <= 1048576)),
    published_revision bigint CHECK (published_revision IS NULL OR (published_revision > 0 AND published_revision <= revision)),
    updated_by_user_id uuid NOT NULL,
    updated_at timestamptz NOT NULL CHECK (isfinite(updated_at)),
    published_by_user_id uuid,
    published_at timestamptz CHECK (published_at IS NULL OR isfinite(published_at)),
    CHECK ((published IS NULL) = (published_revision IS NULL) AND (published IS NULL) = (published_at IS NULL) AND
           (published IS NULL) = (published_by_user_id IS NULL))
);
REVOKE ALL ON control_site_content FROM PUBLIC;
GRANT SELECT, INSERT, UPDATE ON control_site_content TO cdnca_control_app, cdnca_control_runtime;

-- Uploaded website images, content-addressed and immutable: documents
-- reference them by sha256 and GET /v1/control-site/assets/{sha256} serves
-- them. SVG is accepted only after the server rejects scripts, event
-- handlers, foreign objects and external references; it is served with a
-- sandboxing CSP.
CREATE TABLE control_site_assets (
    asset_sha256 bytea PRIMARY KEY CHECK (octet_length(asset_sha256) = 32),
    mime_type text NOT NULL CHECK (mime_type IN ('image/png', 'image/jpeg', 'image/webp', 'image/svg+xml', 'image/x-icon')),
    body bytea NOT NULL CHECK (octet_length(body) BETWEEN 1 AND 2097152 AND sha256(body) = asset_sha256),
    created_by_user_id uuid NOT NULL,
    created_at timestamptz NOT NULL CHECK (isfinite(created_at))
);
REVOKE ALL ON control_site_assets FROM PUBLIC;
GRANT SELECT, INSERT ON control_site_assets TO cdnca_control_app, cdnca_control_runtime;

CREATE TABLE control_site_write_requests (
    actor_scope_id uuid NOT NULL,
    actor_user_id uuid NOT NULL,
    operation text NOT NULL CHECK (operation IN ('control_site.save', 'control_site.publish', 'control_site.asset_upload')),
    idempotency_key text NOT NULL CHECK (char_length(idempotency_key) BETWEEN 1 AND 128),
    request_sha256 bytea NOT NULL CHECK (octet_length(request_sha256) = 32),
    response jsonb NOT NULL CHECK (jsonb_typeof(response) = 'object'),
    created_at timestamptz NOT NULL CHECK (isfinite(created_at)),
    PRIMARY KEY (actor_scope_id, actor_user_id, operation, idempotency_key)
);
REVOKE ALL ON control_site_write_requests FROM PUBLIC;
GRANT SELECT, INSERT ON control_site_write_requests TO cdnca_control_app, cdnca_control_runtime;

-- Website theme plugins, one row per theme id (an upgrade replaces the
-- package in place). Kept apart from theme_packages: those are console
-- themes with their own activation, error pages and source constraints.
-- installed_at NULL is a market plugin this installation may install but an
-- administrator has not (or has uninstalled); built-in plugins live in the
-- binary and get a row when installed. The validated package is kept as
-- uploaded; the columns are what the website reads.
CREATE TABLE site_theme_packages (
    theme_id text PRIMARY KEY CHECK (char_length(theme_id) <= 128 AND theme_id ~ '^(official\.site-[a-z][a-z0-9-]{0,31}|custom\.[a-z][a-z0-9-]{0,31}|market\.[a-z][a-z0-9]*([.-][a-z0-9]+)+)$'),
    version text NOT NULL CHECK (version ~ '^(0|[1-9][0-9]{0,4})\.(0|[1-9][0-9]{0,4})\.(0|[1-9][0-9]{0,4})$'),
    source text NOT NULL CHECK (source IN ('builtin', 'upload', 'market')),
    layout text NOT NULL CHECK (layout IN ('jidun', 'xmf')),
    name jsonb NOT NULL CHECK (jsonb_typeof(name) = 'object'),
    description jsonb NOT NULL CHECK (jsonb_typeof(description) = 'object'),
    tokens jsonb NOT NULL CHECK (jsonb_typeof(tokens) = 'object'),
    seed jsonb NOT NULL CHECK (jsonb_typeof(seed) = 'object' AND octet_length(seed::text) <= 1048576),
    package_sha256 bytea NOT NULL CHECK (octet_length(package_sha256) = 32),
    package_body bytea NOT NULL CHECK (octet_length(package_body) BETWEEN 1 AND 8388608 AND sha256(package_body) = package_sha256),
    created_by_user_id uuid NOT NULL,
    created_at timestamptz NOT NULL CHECK (isfinite(created_at)),
    updated_at timestamptz NOT NULL CHECK (isfinite(updated_at)),
    installed_by_user_id uuid,
    installed_at timestamptz CHECK (installed_at IS NULL OR isfinite(installed_at)),
    CHECK ((installed_at IS NULL) = (installed_by_user_id IS NULL)),
    CHECK ((source = 'builtin') = (theme_id LIKE 'official.%') AND (source = 'upload') = (theme_id LIKE 'custom.%') AND
           (source = 'market') = (theme_id LIKE 'market.%')),
    CHECK (source = 'market' OR installed_at IS NOT NULL)
);
REVOKE ALL ON site_theme_packages FROM PUBLIC;
GRANT SELECT, INSERT, UPDATE, DELETE ON site_theme_packages TO cdnca_control_app, cdnca_control_runtime;

-- A plugin's illustrations by slot, served by digest like uploaded images.
CREATE TABLE site_theme_images (
    theme_id text NOT NULL REFERENCES site_theme_packages(theme_id) ON DELETE CASCADE,
    slot text NOT NULL CHECK (slot ~ '^[a-z0-9][a-z0-9-]{0,47}$'),
    image_sha256 bytea NOT NULL CHECK (octet_length(image_sha256) = 32),
    mime_type text NOT NULL CHECK (mime_type IN ('image/png', 'image/jpeg', 'image/webp', 'image/svg+xml', 'image/x-icon')),
    body bytea NOT NULL CHECK (octet_length(body) BETWEEN 1 AND 2097152 AND sha256(body) = image_sha256),
    PRIMARY KEY (theme_id, slot)
);
CREATE INDEX site_theme_images_sha256 ON site_theme_images(image_sha256);
REVOKE ALL ON site_theme_images FROM PUBLIC;
GRANT SELECT, INSERT, DELETE ON site_theme_images TO cdnca_control_app, cdnca_control_runtime;

-- An administrator's parameters for an installed plugin: token overrides
-- and replacement images ("asset:<sha256>" of control_site_assets) by slot.
-- Kept apart from the package, so an upgrade keeps them; uninstalling drops
-- them.
CREATE TABLE site_theme_customizations (
    theme_id text PRIMARY KEY REFERENCES site_theme_packages(theme_id) ON DELETE CASCADE,
    revision bigint NOT NULL CHECK (revision > 0),
    tokens jsonb NOT NULL CHECK (jsonb_typeof(tokens) = 'object'),
    images jsonb NOT NULL CHECK (jsonb_typeof(images) = 'object'),
    updated_by_user_id uuid NOT NULL,
    updated_at timestamptz NOT NULL CHECK (isfinite(updated_at))
);
REVOKE ALL ON site_theme_customizations FROM PUBLIC;
GRANT SELECT, INSERT, UPDATE ON site_theme_customizations TO cdnca_control_app, cdnca_control_runtime;

-- The active website theme of the platform scope. An active plugin cannot
-- be uninstalled.
CREATE TABLE site_theme_activations (
    platform_scope_id uuid PRIMARY KEY REFERENCES access_scopes(id) ON DELETE RESTRICT,
    theme_id text NOT NULL REFERENCES site_theme_packages(theme_id) ON DELETE RESTRICT,
    revision bigint NOT NULL CHECK (revision > 0),
    activated_by_user_id uuid NOT NULL,
    activated_at timestamptz NOT NULL CHECK (isfinite(activated_at))
);
REVOKE ALL ON site_theme_activations FROM PUBLIC;
GRANT SELECT, INSERT, UPDATE ON site_theme_activations TO cdnca_control_app, cdnca_control_runtime;
