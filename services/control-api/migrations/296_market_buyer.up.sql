LOCK TABLE schema_migrations, permissions, access_scopes, roles, role_permissions IN ACCESS EXCLUSIVE MODE;

DO $migration_296_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 295 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 295 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=295 AND
        migration_id='295_config_version_telemetry_site_bindings' AND
        checksum_sha256='e58da204e315ca5c377f33e6db12857e74b89b313cd487d42f8a52969c1ca275' AND
        down_checksum_sha256='9cc674c7ebe732414135aec2ce5e50a746b9f6043d899d977691fa7d0ae730bc' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR checksum_sha256 IS NULL OR
        down_checksum_sha256 IS NULL OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR to_regclass(current_schema() || '.plugin_security_advisories') IS NOT NULL OR
            EXISTS (SELECT 1 FROM permissions WHERE name IN
                ('marketplace.browse','marketplace.purchase','marketplace.sell')) THEN
        RAISE EXCEPTION 'migration 296 requires the exact verified 295 release head' USING ERRCODE='P2960';
    END IF;
END;
$migration_296_up$;

-- Buyer-side marketplace (docs/architecture/marketplace-buildout.md §4.1, §5.3).
-- Allocated to M7 as 294; renumbered to 296 after 294 (runtime patch removal) and 295 (v2 telemetry) landed first.
-- The old sites.manage/platform.admin gate keeps working for one release.
INSERT INTO permissions(name, description) VALUES
    ('marketplace.browse', 'Browse marketplace plugins, offers, licenses and advisories'),
    ('marketplace.purchase', 'Place marketplace orders, renew, cancel, dispute and acknowledge advisories'),
    ('marketplace.sell', 'List node offers and confirm buyer payments on the node market');

INSERT INTO role_permissions(role_id, permission_name)
SELECT role.id, permission.name
FROM roles role
JOIN access_scopes scope ON scope.id = role.scope_id AND scope.kind = 'platform'
CROSS JOIN (VALUES ('marketplace.browse'), ('marketplace.purchase'), ('marketplace.sell')) AS permission(name)
WHERE role.system_role AND role.name IN ('platform_owner', 'platform_admin')
ON CONFLICT DO NOTHING;

-- Plugin security advisories as the license service delivers them to this
-- installation (license 069, cdnca.plugin-security-advisory-sync/v1). The
-- advisory sync writes them here; withdrawn ones stop being delivered and are
-- kept as 'withdrawn' so their acknowledgements keep a parent.
-- Buyer selection limits (price cap, quality floor) live on the market
-- subscription itself (market 022, PUT /v1/subscriptions/{id}/selection).
CREATE TABLE plugin_security_advisories (
    id uuid PRIMARY KEY,
    plugin_id text NOT NULL CHECK (plugin_id ~ '^[a-z0-9]+([.-][a-z0-9]+)+$' AND char_length(plugin_id) <= 128),
    affected_versions text NOT NULL CHECK (char_length(affected_versions) BETWEEN 1 AND 256),
    fixed_version text NOT NULL DEFAULT '' CHECK (char_length(fixed_version) <= 128),
    severity text NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low')),
    action text NOT NULL CHECK (action IN ('notify', 'disable', 'uninstall_recommended')),
    title text NOT NULL CHECK (char_length(title) BETWEEN 1 AND 200),
    body text NOT NULL DEFAULT '' CHECK (char_length(body) <= 20000),
    status text NOT NULL CHECK (status IN ('published', 'withdrawn')),
    published_at timestamptz NOT NULL,
    received_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    CHECK (updated_at >= received_at)
);
CREATE INDEX plugin_security_advisories_plugin_296_idx ON plugin_security_advisories (plugin_id, published_at DESC);

-- One acknowledgement per (advisory, access scope): the platform and every
-- tenant that installed the plugin each confirm on their own. Facts are
-- durable; reported_at is set once when the platform acknowledgement reached
-- the license service (tenant acknowledgements stay local).
CREATE TABLE plugin_security_advisory_acks (
    advisory_id uuid NOT NULL REFERENCES plugin_security_advisories(id) ON DELETE RESTRICT,
    scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE RESTRICT,
    acknowledged_by uuid NOT NULL,
    disposition text NOT NULL CHECK (disposition IN ('disabled', 'upgraded', 'uninstalled', 'accepted_risk', 'not_affected')),
    note text NOT NULL DEFAULT '' CHECK (char_length(note) <= 500),
    acknowledged_at timestamptz NOT NULL,
    reported_at timestamptz,
    PRIMARY KEY (advisory_id, scope_id),
    CHECK (reported_at IS NULL OR reported_at >= acknowledged_at)
);

CREATE FUNCTION protect_plugin_advisory_ack_296() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF TG_OP IN ('DELETE', 'TRUNCATE') THEN
        RAISE EXCEPTION 'advisory acknowledgements are durable' USING ERRCODE='P2961';
    END IF;
    IF ROW(NEW.advisory_id, NEW.scope_id, NEW.acknowledged_by, NEW.disposition, NEW.note, NEW.acknowledged_at)
       IS DISTINCT FROM ROW(OLD.advisory_id, OLD.scope_id, OLD.acknowledged_by, OLD.disposition, OLD.note, OLD.acknowledged_at)
       OR OLD.reported_at IS NOT NULL THEN
        RAISE EXCEPTION 'advisory acknowledgements are immutable' USING ERRCODE='P2961';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER plugin_security_advisory_acks_protect_296 BEFORE UPDATE OR DELETE ON plugin_security_advisory_acks
FOR EACH ROW EXECUTE FUNCTION protect_plugin_advisory_ack_296();
CREATE TRIGGER plugin_security_advisory_acks_no_truncate_296 BEFORE TRUNCATE ON plugin_security_advisory_acks
FOR EACH STATEMENT EXECUTE FUNCTION protect_plugin_advisory_ack_296();

REVOKE ALL ON FUNCTION protect_plugin_advisory_ack_296() FROM PUBLIC;
GRANT SELECT, INSERT, UPDATE ON plugin_security_advisories TO cdnca_control_app, cdnca_control_runtime;
GRANT SELECT, INSERT, UPDATE ON plugin_security_advisory_acks TO cdnca_control_app, cdnca_control_runtime;
