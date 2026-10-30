LOCK TABLE schema_migrations, nodes, node_write_requests IN ACCESS EXCLUSIVE MODE;

DO $migration_279_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 278 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 278 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=278 AND
        migration_id='278_realtime_empty_source_roster' AND
        checksum_sha256='bedcacd807cab19ca5fcc4f6f380e21c6d757da66dc6a2f6b3df0d5da7b90fe4' AND
        down_checksum_sha256='3b7df217a8d2de7ce84ad14c2145a99c9bbe11bee9ecb5a4a7efdda19e6ecf49' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR checksum_sha256 IS NULL OR
        down_checksum_sha256 IS NULL OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR to_regclass(current_schema() || '.node_monitoring_overrides') IS NOT NULL THEN
        RAISE EXCEPTION 'migration 279 requires the exact verified 278 release head' USING ERRCODE='P2790';
    END IF;
END;
$migration_279_up$;

-- A per-node monitoring override overlays the active platform policy. Every
-- write advances revision by one and rows are never deleted (clearing writes
-- NULL fields), so a node's delivered config_revision, defined as
-- active platform revision + override revision, is strictly increasing.
CREATE TABLE node_monitoring_overrides (
    node_id uuid PRIMARY KEY REFERENCES nodes(id) ON DELETE RESTRICT,
    scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE RESTRICT,
    monitor_enabled boolean,
    protocol text CHECK (protocol IS NULL OR protocol IN ('tcp','http','ping')),
    probe_timeout_ms integer CHECK (probe_timeout_ms IS NULL OR probe_timeout_ms BETWEEN 100 AND 60000),
    monitor_port integer CHECK (monitor_port IS NULL OR monitor_port BETWEEN 1 AND 65535),
    monitor_action text CHECK (monitor_action IS NULL OR monitor_action IN ('none','pause')),
    revision bigint NOT NULL CHECK (revision BETWEEN 1 AND 1048576),
    updated_by_user_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    CHECK (updated_at >= created_at),
    FOREIGN KEY (scope_id, node_id) REFERENCES nodes(scope_id, id) ON DELETE RESTRICT
);

CREATE FUNCTION protect_node_monitoring_override_279() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF TG_OP = 'DELETE' OR TG_OP = 'TRUNCATE' THEN
        RAISE EXCEPTION 'node monitoring overrides are never deleted' USING ERRCODE='P2791';
    END IF;
    IF TG_OP = 'INSERT' THEN
        IF NEW.revision <> 1 OR NEW.updated_at IS DISTINCT FROM NEW.created_at THEN
            RAISE EXCEPTION 'node monitoring override must start at revision 1' USING ERRCODE='P2792';
        END IF;
        RETURN NEW;
    END IF;
    IF ROW(NEW.node_id, NEW.scope_id, NEW.created_at) IS DISTINCT FROM ROW(OLD.node_id, OLD.scope_id, OLD.created_at) OR
       NEW.revision <> OLD.revision + 1 OR NEW.updated_at < OLD.updated_at THEN
        RAISE EXCEPTION 'node monitoring override identity or revision is immutable' USING ERRCODE='P2792';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER node_monitoring_overrides_protect_279
BEFORE INSERT OR UPDATE OR DELETE ON node_monitoring_overrides
FOR EACH ROW EXECUTE FUNCTION protect_node_monitoring_override_279();
CREATE TRIGGER node_monitoring_overrides_no_truncate_279
BEFORE TRUNCATE ON node_monitoring_overrides
FOR EACH STATEMENT EXECUTE FUNCTION protect_node_monitoring_override_279();
REVOKE ALL ON FUNCTION protect_node_monitoring_override_279() FROM PUBLIC;
GRANT SELECT, INSERT, UPDATE ON node_monitoring_overrides TO cdnca_control_app, cdnca_control_runtime;

ALTER TABLE node_write_requests
    DROP CONSTRAINT node_write_requests_operation_check,
    ADD CONSTRAINT node_write_requests_operation_check
        CHECK (operation IN ('node.create', 'node.update', 'node.batch_admin_state', 'node.monitoring_override'));
