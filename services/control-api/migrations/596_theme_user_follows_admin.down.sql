LOCK TABLE schema_migrations, theme_activations, theme_packages IN ACCESS EXCLUSIVE MODE;

DO $migration_596_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 596 OR
       (SELECT max(version) FROM schema_migrations) <> 596 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=596 AND
        migration_id='596_theme_user_follows_admin' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 596 down requires the exact verified migration head' USING ERRCODE='P5961';
    END IF;
    -- 回到 595 只能把跟随行钉成当时的管理端包（旧语义）；当时既无管理端激活、也没存内置 default 包的，拒绝。
    IF EXISTS (
        SELECT 1 FROM theme_activations follow WHERE follow.package_sha256 IS NULL AND NOT EXISTS (
            SELECT 1 FROM theme_activations admin WHERE admin.slot IN ('admin', 'all') AND admin.revision < follow.revision
        ) AND NOT EXISTS (SELECT 1 FROM theme_packages WHERE theme_id = 'default' AND source = 'builtin')
    ) THEN
        RAISE EXCEPTION 'migration 596 down cannot pin a following user console theme' USING ERRCODE='P5962';
    END IF;
END;
$migration_596_down$;

ALTER TABLE theme_activations DISABLE TRIGGER theme_activations_protected_360;
UPDATE theme_activations follow SET package_sha256 = COALESCE(
    (SELECT admin.package_sha256 FROM theme_activations admin WHERE admin.slot IN ('admin', 'all') AND admin.revision < follow.revision
     ORDER BY admin.revision DESC LIMIT 1),
    (SELECT package_sha256 FROM theme_packages WHERE theme_id = 'default' AND source = 'builtin' ORDER BY downloaded_at DESC LIMIT 1))
WHERE follow.package_sha256 IS NULL;
ALTER TABLE theme_activations ENABLE TRIGGER theme_activations_protected_360;

ALTER TABLE theme_activations DROP CONSTRAINT theme_activations_user_follows_596,
    ALTER COLUMN package_sha256 SET NOT NULL;

CREATE OR REPLACE FUNCTION validate_theme_activation_360()
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

CREATE OR REPLACE FUNCTION protect_theme_facts_360()
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

REVOKE ALL ON FUNCTION validate_theme_activation_360(), protect_theme_facts_360() FROM PUBLIC;
