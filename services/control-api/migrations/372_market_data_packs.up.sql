LOCK TABLE schema_migrations, rule_pack_artifacts, theme_packages IN ACCESS EXCLUSIVE MODE;

DO $migration_372_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 371 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 371 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=371 AND
        migration_id='371_certificate_expiry_events' AND
        checksum_sha256='60dbd16e73b00fd63bead192aecc901118eaf5ab1d507e607da512bae46e0db5' AND
        down_checksum_sha256='059e2a6a2c3c5498edd5ddb314728ccd3f99a336b731a64d3ec1dd26e353a98e' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR to_regclass(current_schema() || '.market_data_pack_sources') IS NOT NULL THEN
        RAISE EXCEPTION 'migration 372 requires the exact verified 371 release head' USING ERRCODE='P3720';
    END IF;
END;
$migration_372_up$;

-- 372（r136 pa18-manifest 占位：本分支先接在 371 之后以便测试；合入时主会话改为 371、守卫指向 370）。
-- PA-18 (ADR 0007 §8.1, §5.4): developer rule packs and third-party themes
-- bought on the plugin market reach this control plane as artifact catalog
-- entries market_rule_pack/<plugin id> and market_theme/<plugin id> of an authorized plugin
-- installation. artifactsync downloads them (resident) and materializes them
-- here as downloaded local artifacts, source 'market': a developer-layer pack
-- (dev/<publisher>/<name>, never enabled by itself) and a theme
-- market.<plugin id> (never activated by itself). An entry that is no longer
-- served (authorization disabled or uninstalled) is marked withdrawn: the
-- bytes stay, it cannot be enabled / activated again until it is served.
ALTER TABLE rule_pack_artifacts DROP CONSTRAINT rule_pack_artifacts_source_359;
ALTER TABLE rule_pack_artifacts ADD CONSTRAINT rule_pack_artifacts_source_372
    CHECK (source IN ('catalog', 'import', 'tenant', 'subscription', 'market'));
ALTER TABLE rule_pack_artifacts ADD CONSTRAINT rule_pack_artifacts_market_layer_372
    CHECK (source <> 'market' OR pack_id LIKE 'dev/%');

-- 360 left these CHECKs unnamed: drop them by what they say, not by the
-- generated name.
DO $migration_372_theme_checks$
DECLARE
    item record;
    dropped integer := 0;
BEGIN
    FOR item IN SELECT conname, pg_get_constraintdef(oid) AS definition FROM pg_constraint
        WHERE conrelid = 'theme_packages'::regclass AND contype = 'c' LOOP
        IF item.definition LIKE '%theme_id ~%official%custom%' OR
           item.definition LIKE '%source = ANY%builtin%upload%' OR
           item.definition LIKE '%source = ''builtin''::text) = (theme_id !~%' OR
           item.definition LIKE '%source = ''builtin''::text) OR (requires_feature = %' THEN
            EXECUTE format('ALTER TABLE theme_packages DROP CONSTRAINT %I', item.conname);
            dropped := dropped + 1;
        END IF;
    END LOOP;
    IF dropped <> 4 THEN
        RAISE EXCEPTION 'migration 372 expected the four 360 theme_packages checks, found %', dropped USING ERRCODE='P3723';
    END IF;
END;
$migration_372_theme_checks$;
ALTER TABLE theme_packages ADD CONSTRAINT theme_packages_theme_id_372 CHECK (theme_id ~
    '^(default|official\.[a-z][a-z0-9-]{0,31}|custom\.[a-z][a-z0-9-]{0,31}|market\.[a-z][a-z0-9]*([.-][a-z0-9]+)+)$');
ALTER TABLE theme_packages ADD CONSTRAINT theme_packages_source_372 CHECK (source IN ('builtin', 'upload', 'market'));
ALTER TABLE theme_packages ADD CONSTRAINT theme_packages_source_id_372 CHECK (
    (source = 'builtin') = (theme_id ~ '^(default|official\.)') AND
    (source = 'upload') = (theme_id ~ '^custom\.') AND
    (source = 'market') = (theme_id ~ '^market\.'));
ALTER TABLE theme_packages ADD CONSTRAINT theme_packages_feature_372 CHECK (source = 'builtin' OR requires_feature = '');

-- One row per materialized market artifact: which catalog entry it came from
-- and whether that entry is still served.
CREATE TABLE market_data_pack_sources (
    artifact_id text PRIMARY KEY CHECK (artifact_id ~ '^(market_rule_pack|market_theme)/[a-z0-9]+([.-][a-z0-9]+)+$'),
    kind text NOT NULL CHECK (kind IN ('market_rule_pack', 'market_theme')),
    plugin_id text NOT NULL,
    version text NOT NULL CHECK (char_length(version) BETWEEN 5 AND 64),
    revision bigint NOT NULL CHECK (revision > 0),
    sha256 text NOT NULL CHECK (sha256 ~ '^[0-9a-f]{64}$'),
    -- rule pack: pack_id; theme: theme id.
    local_name text NOT NULL CHECK (char_length(local_name) BETWEEN 3 AND 160),
    status text NOT NULL CHECK (status IN ('active', 'withdrawn')),
    materialized_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    CHECK (artifact_id = kind || '/' || plugin_id),
    CHECK (kind <> 'market_rule_pack' OR local_name LIKE 'dev/%'),
    CHECK (kind <> 'market_theme' OR local_name = 'market.' || plugin_id)
);

REVOKE ALL ON market_data_pack_sources FROM PUBLIC;
GRANT SELECT, INSERT, UPDATE ON market_data_pack_sources TO cdnca_control_app;
GRANT SELECT ON market_data_pack_sources TO cdnca_control_runtime;
