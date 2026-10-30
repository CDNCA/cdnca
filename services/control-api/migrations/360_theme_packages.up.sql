LOCK TABLE schema_migrations, platform_brand_assets, platform_brand_asset_write_requests IN ACCESS EXCLUSIVE MODE;

DO $migration_360_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 359 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 359 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=359 AND
        migration_id='359_waf_subscription_rule_packs' AND
        checksum_sha256='d725cc551e38bbfb452048697a7fb9b23ea71c959e736548a5b082dfeb2b78e5' AND
        down_checksum_sha256='f72ab2b9ab9b71ac685cec05ca07618a1e559b506599325b0053f97af63c5e88' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR to_regclass(current_schema() || '.theme_packages') IS NOT NULL THEN
        RAISE EXCEPTION 'migration 360 requires the exact verified 359 release head' USING ERRCODE='P3600';
    END IF;
END;
$migration_360_up$;

-- PA-17 theme packages (ADR 0007 §7, cdnca.theme/v1). A package is stored
-- once per content digest with what the control plane renders from it (CSS,
-- token JSON, default error pages, brand images). Download and activation are
-- separate: a row here is "downloaded"; the latest theme_activations row is the
-- one active theme. Rows are never deleted (error page publications pin a
-- package by digest); removal only marks them.
CREATE TABLE theme_packages (
    package_sha256 bytea PRIMARY KEY CHECK (octet_length(package_sha256) = 32),
    theme_id text NOT NULL CHECK (theme_id ~ '^(default|official\.[a-z][a-z0-9-]{0,31}|custom\.[a-z][a-z0-9-]{0,31})$'),
    version text NOT NULL CHECK (version ~ '^[0-9]{1,5}\.[0-9]{1,5}\.[0-9]{1,5}$'),
    source text NOT NULL CHECK (source IN ('builtin', 'upload')),
    requires_feature text NOT NULL DEFAULT '' CHECK (requires_feature = '' OR requires_feature ~ '^theme\.[a-z][a-z0-9.-]{0,63}$'),
    package_body bytea NOT NULL CHECK (octet_length(package_body) BETWEEN 1 AND 8388608 AND sha256(package_body) = package_sha256),
    css_sha256 bytea NOT NULL CHECK (octet_length(css_sha256) = 32),
    css_body bytea NOT NULL CHECK (octet_length(css_body) BETWEEN 1 AND 65536 AND sha256(css_body) = css_sha256),
    json_sha256 bytea NOT NULL CHECK (octet_length(json_sha256) = 32),
    json_body bytea NOT NULL CHECK (octet_length(json_body) BETWEEN 1 AND 262144 AND sha256(json_body) = json_sha256),
    downloaded_by_user_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    downloaded_at timestamptz NOT NULL,
    removed_by_user_id uuid REFERENCES users(id) ON DELETE RESTRICT,
    removed_at timestamptz,
    CHECK ((source = 'builtin') = (theme_id !~ '^custom\.')),
    CHECK (source = 'builtin' OR requires_feature = ''),
    CHECK ((removed_at IS NULL) = (removed_by_user_id IS NULL))
);
CREATE INDEX theme_packages_css_360 ON theme_packages(css_sha256);
CREATE INDEX theme_packages_json_360 ON theme_packages(json_sha256);
CREATE INDEX theme_packages_theme_360 ON theme_packages(theme_id, downloaded_at DESC);

CREATE TABLE theme_assets (
    asset_sha256 bytea PRIMARY KEY CHECK (octet_length(asset_sha256) = 32),
    mime_type text NOT NULL CHECK (mime_type IN ('image/x-icon', 'image/vnd.microsoft.icon', 'image/png', 'image/jpeg')),
    body bytea NOT NULL CHECK (octet_length(body) BETWEEN 1 AND 2097152 AND sha256(body) = asset_sha256)
);

CREATE TABLE theme_package_assets (
    package_sha256 bytea NOT NULL REFERENCES theme_packages(package_sha256) ON DELETE RESTRICT,
    slot text NOT NULL CHECK (slot IN ('favicon', 'logo', 'login_ad', 'logo_dark', 'login_background', 'app_icon')),
    asset_sha256 bytea NOT NULL REFERENCES theme_assets(asset_sha256) ON DELETE RESTRICT,
    PRIMARY KEY (package_sha256, slot)
);

CREATE TABLE theme_error_pages (
    package_sha256 bytea NOT NULL REFERENCES theme_packages(package_sha256) ON DELETE RESTRICT,
    category text NOT NULL CHECK (category IN ('edge_connect', 'no_host', 'unknown_site')),
    status_code integer NOT NULL CHECK (
        (category = 'edge_connect' AND status_code IN (502, 503, 504)) OR
        (category = 'no_host' AND status_code = 400) OR
        (category = 'unknown_site' AND status_code = 404)
    ),
    body_sha256 bytea NOT NULL CHECK (octet_length(body_sha256) = 32),
    body bytea NOT NULL CHECK (octet_length(body) BETWEEN 1 AND 1048576 AND sha256(body) = body_sha256),
    PRIMARY KEY (package_sha256, category, status_code)
);

CREATE TABLE theme_activations (
    revision bigint PRIMARY KEY CHECK (revision > 0),
    platform_scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE RESTRICT,
    package_sha256 bytea NOT NULL REFERENCES theme_packages(package_sha256) ON DELETE RESTRICT,
    activated_by_user_id uuid NOT NULL,
    request_id text NOT NULL CHECK (request_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'),
    activated_at timestamptz NOT NULL,
    FOREIGN KEY (platform_scope_id, activated_by_user_id) REFERENCES memberships(scope_id, user_id) ON DELETE RESTRICT
);

CREATE FUNCTION validate_theme_activation_360()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    PERFORM pg_advisory_xact_lock(hashtextextended('theme-activation', 0));
    IF NEW.revision <> COALESCE((SELECT max(revision) FROM theme_activations), 0) + 1 OR
       NOT EXISTS (SELECT 1 FROM access_scopes WHERE id = NEW.platform_scope_id AND kind = 'platform' AND tenant_id IS NULL) OR
       NOT EXISTS (SELECT 1 FROM theme_packages WHERE package_sha256 = NEW.package_sha256 AND removed_at IS NULL) THEN
        RAISE EXCEPTION 'invalid theme activation' USING ERRCODE = 'P3601';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER theme_activations_validate_360
BEFORE INSERT ON theme_activations
FOR EACH ROW EXECUTE FUNCTION validate_theme_activation_360();

CREATE FUNCTION protect_theme_facts_360()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_TABLE_NAME <> 'theme_packages' OR TG_OP <> 'UPDATE' THEN
        RAISE EXCEPTION 'theme facts are immutable' USING ERRCODE = 'P3603';
    END IF;
    IF ROW(NEW.package_sha256, NEW.theme_id, NEW.version, NEW.source, NEW.requires_feature, NEW.package_body,
           NEW.css_sha256, NEW.css_body, NEW.json_sha256, NEW.json_body, NEW.downloaded_by_user_id, NEW.downloaded_at)
       IS NOT DISTINCT FROM
       ROW(OLD.package_sha256, OLD.theme_id, OLD.version, OLD.source, OLD.requires_feature, OLD.package_body,
           OLD.css_sha256, OLD.css_body, OLD.json_sha256, OLD.json_body, OLD.downloaded_by_user_id, OLD.downloaded_at) THEN
        -- Only the removal mark moves, and never off the active package.
        IF NEW.removed_at IS NOT NULL AND NEW.package_sha256 = (
            SELECT package_sha256 FROM theme_activations ORDER BY revision DESC LIMIT 1
        ) THEN
            RAISE EXCEPTION 'the active theme package cannot be removed' USING ERRCODE = 'P3602';
        END IF;
        RETURN NEW;
    END IF;
    RAISE EXCEPTION 'theme facts are immutable' USING ERRCODE = 'P3603';
END;
$$;

CREATE TRIGGER theme_packages_protected_360
BEFORE UPDATE OR DELETE ON theme_packages
FOR EACH ROW EXECUTE FUNCTION protect_theme_facts_360();
CREATE TRIGGER theme_assets_protected_360
BEFORE UPDATE OR DELETE ON theme_assets
FOR EACH ROW EXECUTE FUNCTION protect_theme_facts_360();
CREATE TRIGGER theme_package_assets_protected_360
BEFORE UPDATE OR DELETE ON theme_package_assets
FOR EACH ROW EXECUTE FUNCTION protect_theme_facts_360();
CREATE TRIGGER theme_error_pages_protected_360
BEFORE UPDATE OR DELETE ON theme_error_pages
FOR EACH ROW EXECUTE FUNCTION protect_theme_facts_360();
CREATE TRIGGER theme_activations_protected_360
BEFORE UPDATE OR DELETE ON theme_activations
FOR EACH ROW EXECUTE FUNCTION protect_theme_facts_360();

-- Theme brand slots (ADR 0007 §7.2) on top of 203's favicon/logo/login_ad.
ALTER TABLE platform_brand_assets
    DROP CONSTRAINT platform_brand_assets_slot_check,
    DROP CONSTRAINT platform_brand_assets_reference_check,
    DROP CONSTRAINT platform_brand_assets_check,
    ADD CONSTRAINT platform_brand_assets_slot_check_360 CHECK (slot IN ('favicon', 'logo', 'login_ad', 'logo_dark', 'login_background', 'app_icon')),
    ADD CONSTRAINT platform_brand_assets_reference_check_360 CHECK (reference ~ '^asset://brand/(favicon|logo|login_ad|logo_dark|login_background|app_icon)/[0-9a-f]{64}$'),
    ADD CONSTRAINT platform_brand_assets_media_check_360 CHECK (
        (slot IN ('logo', 'logo_dark', 'app_icon') AND mime_type = 'image/png') OR
        (slot IN ('login_ad', 'login_background') AND mime_type = 'image/jpeg') OR
        (slot = 'favicon' AND mime_type IN ('image/x-icon', 'image/vnd.microsoft.icon', 'image/png'))
    );
ALTER TABLE platform_brand_asset_write_requests
    DROP CONSTRAINT platform_brand_asset_write_requests_slot_check,
    ADD CONSTRAINT platform_brand_asset_write_requests_slot_check_360 CHECK (slot IN ('favicon', 'logo', 'login_ad', 'logo_dark', 'login_background', 'app_icon'));

REVOKE ALL ON theme_packages, theme_assets, theme_package_assets, theme_error_pages, theme_activations FROM PUBLIC;
REVOKE ALL ON FUNCTION validate_theme_activation_360(), protect_theme_facts_360() FROM PUBLIC;
GRANT SELECT, INSERT, UPDATE ON theme_packages TO cdnca_control_app;
GRANT SELECT, INSERT ON theme_assets, theme_package_assets, theme_error_pages, theme_activations TO cdnca_control_app;
GRANT SELECT ON theme_packages, theme_assets, theme_package_assets, theme_error_pages, theme_activations TO cdnca_control_runtime;
