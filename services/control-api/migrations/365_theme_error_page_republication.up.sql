LOCK TABLE schema_migrations, edge_system_republication_heads, edge_system_republication_attempts, theme_activations
    IN ACCESS EXCLUSIVE MODE;

DO $migration_365_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 364 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 364 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=364 AND
        migration_id='364_module_entitlement_republication' AND
        checksum_sha256='53e3b8f018f9f4702dac9a3802a2c5cd68e556f00940cc3d9c75a71bdd7b5398' AND
        down_checksum_sha256='f7e9d1e030cf9e790622b63ce553ab4a822988c57ed4b6ef94342189fefc95c8' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR (SELECT count(*) FROM pg_constraint WHERE connamespace=current_schema()::regnamespace AND conname IN (
        'edge_system_republication_heads_triggers_check', 'edge_system_republication_attempts_triggers_check',
        'edge_system_republication_attempts_check')) <> 3
       OR to_regclass(current_schema() || '.theme_error_page_republications') IS NOT NULL THEN
        RAISE EXCEPTION 'migration 365 requires the exact verified 364 release head' USING ERRCODE='P3650';
    END IF;
END;
$migration_365_up$;

-- r136 theme-republish (user 10-18): activating a theme republishes every
-- tenant scope's error pages through the system republication channel
-- (trigger theme_activation), so node default error pages follow the theme
-- without a tenant publish. One row per (activation, scope) that had published
-- error pages: its progress and the error page rollout that delivered it.
CREATE TABLE theme_error_page_republications (
    activation_revision bigint NOT NULL REFERENCES theme_activations(revision) ON DELETE RESTRICT,
    scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE RESTRICT,
    state text NOT NULL CHECK (state IN ('pending', 'published', 'skipped', 'failed')),
    rollout_id uuid REFERENCES rollouts(id) ON DELETE RESTRICT,
    node_count integer NOT NULL DEFAULT 0 CHECK (node_count BETWEEN 0 AND 10000),
    error_class text CHECK (error_class IS NULL OR char_length(error_class) BETWEEN 1 AND 256),
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    PRIMARY KEY (activation_revision, scope_id),
    CONSTRAINT theme_error_page_republications_rollout_365_check CHECK ((state = 'published') = (rollout_id IS NOT NULL))
);

CREATE INDEX theme_error_page_republications_scope_365_idx
    ON theme_error_page_republications (scope_id, activation_revision) WHERE state = 'pending';

ALTER TABLE edge_system_republication_heads
    DROP CONSTRAINT edge_system_republication_heads_triggers_check,
    ADD CONSTRAINT edge_system_republication_heads_triggers_check CHECK (cardinality(triggers) BETWEEN 1 AND 10 AND
        triggers <@ ARRAY['node_capability', 'traffic_enforcement', 'line_group', 'node_sync', 'domain_ownership',
            'secondary_verification', 'rule_catalog', 'challenge_delivery', 'module_entitlement',
            'theme_activation']::text[]);

-- An error page republication publishes no edge_config_publications row: its
-- attempt names the error page rollout instead.
ALTER TABLE edge_system_republication_attempts
    DROP CONSTRAINT edge_system_republication_attempts_triggers_check,
    ADD CONSTRAINT edge_system_republication_attempts_triggers_check CHECK (cardinality(triggers) BETWEEN 1 AND 10),
    ADD COLUMN error_page_rollout_id uuid REFERENCES rollouts(id) ON DELETE RESTRICT,
    DROP CONSTRAINT edge_system_republication_attempts_check,
    ADD CONSTRAINT edge_system_republication_attempts_check CHECK (
        (outcome = 'published') = (publication_id IS NOT NULL OR error_page_rollout_id IS NOT NULL));

-- An error page publication (edgepublish.ErrorPagePublisher, contract 1) has
-- no edge_config_publications row, so 046's rollout contract refused every one
-- of them, the tenant's own publish included. Its audited fact is the
-- edge_error_page.publish success event naming the rollout, written in the
-- same transaction, for a configuration whose one artifact is the error page
-- snapshot.
DO $migration_365_contract$
DECLARE
    definition text;
    needle text := E'        RAISE EXCEPTION ''contract rollout requires an audited publication or security activation fact''\n            USING ERRCODE = ''P0001'';';
    replacement text := E'        IF NEW.action = ''apply'' AND EXISTS (\n'
        || E'            SELECT 1 FROM configuration_artifacts artifact\n'
        || E'            WHERE artifact.config_version_id = NEW.config_version_id AND artifact.ordinal = 1\n'
        || E'              AND artifact.kind = ''configuration''\n'
        || E'              AND artifact.media_type = ''application/vnd.cdnca.edge-error-page-snapshot+json;version=1''\n'
        || E'              AND NOT EXISTS (SELECT 1 FROM configuration_artifacts other\n'
        || E'                WHERE other.config_version_id = NEW.config_version_id AND other.ordinal <> 1)\n'
        || E'        ) AND EXISTS (\n'
        || E'            SELECT 1 FROM audit_events event\n'
        || E'            WHERE event.action = ''edge_error_page.publish'' AND event.result = ''success''\n'
        || E'              AND event.resource_type = ''edge_error_page_bundle''\n'
        || E'              AND event.payload->>''rollout_id'' = NEW.id::text\n'
        || E'              AND event.payload->>''configuration_scope_id'' = NEW.configuration_scope_id::text\n'
        || E'              AND event.payload->>''config_version_id'' = NEW.config_version_id::text\n'
        || E'        ) THEN\n'
        || E'            RETURN NULL;\n'
        || E'        END IF;\n' || needle;
BEGIN
    SELECT pg_get_functiondef('assert_rollout_contract_046()'::regprocedure) INTO definition;
    IF strpos(definition, needle) = 0 OR strpos(definition, 'edge-error-page-snapshot') > 0 THEN
        RAISE EXCEPTION 'migration 365 cannot find the rollout contract guard' USING ERRCODE = 'P3652';
    END IF;
    EXECUTE replace(definition, needle, replacement);
END;
$migration_365_contract$;

REVOKE ALL ON theme_error_page_republications FROM PUBLIC;
GRANT SELECT, INSERT, UPDATE ON theme_error_page_republications TO cdnca_control_app, cdnca_control_runtime;
