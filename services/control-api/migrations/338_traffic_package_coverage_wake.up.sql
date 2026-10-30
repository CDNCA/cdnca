LOCK TABLE schema_migrations, traffic_package_cycle_deductions, traffic_package_grants,
    package_addon_assignments, package_traffic_enforcement_schedule IN ACCESS EXCLUSIVE MODE;

DO $migration_338_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 337 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 337 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=337 AND
        migration_id='337_acme_http01_node_generations' AND
        checksum_sha256='b1623133b8240241628bea733cf6c19564e7aeaeab008336d95c3b4af5f9ef8a' AND
        down_checksum_sha256='da3a494d77514017a42aae878b2460f86c4c48092d442aaf15605b4158457659' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR to_regprocedure(current_schema() || '.wake_package_traffic_enforcement_338()') IS NOT NULL THEN
        RAISE EXCEPTION 'migration 338 requires the exact verified 337 release head' USING ERRCODE='P3380';
    END IF;
END;
$migration_338_up$;

-- FX58b: pages show package coverage per cycle; period_key is an opaque
-- digest, so every deduction row also records its cycle bounds. Rows written
-- before 338 have none.
ALTER TABLE traffic_package_cycle_deductions
    ADD COLUMN cycle_starts_at timestamptz,
    ADD COLUMN cycle_ends_at timestamptz,
    ADD CONSTRAINT traffic_package_cycle_deductions_cycle_338 CHECK (
        (cycle_starts_at IS NULL AND cycle_ends_at IS NULL) OR cycle_ends_at > cycle_starts_at);

-- Buying or granting a traffic package (or a traffic add-on) makes the
-- tenant's subscriptions due at once and wakes listening enforcement workers
-- after commit, so recovery does not wait for the evaluation interval.
CREATE FUNCTION wake_package_traffic_enforcement_338()
RETURNS trigger LANGUAGE plpgsql AS $function$
BEGIN
    IF TG_TABLE_NAME = 'package_addon_assignments' THEN
        IF NEW.kind <> 'traffic' THEN
            RETURN NULL;
        END IF;
        UPDATE package_traffic_enforcement_schedule SET next_evaluation_at = 'epoch'
        WHERE tenant_scope_id = NEW.tenant_scope_id AND subscription_id = NEW.subscription_id;
    ELSE
        UPDATE package_traffic_enforcement_schedule SET next_evaluation_at = 'epoch'
        WHERE tenant_scope_id = NEW.tenant_scope_id;
    END IF;
    PERFORM pg_notify('package_traffic_enforcement_wake', NEW.tenant_scope_id::text);
    RETURN NULL;
END;
$function$;

CREATE TRIGGER traffic_package_grants_wake_enforcement_338
AFTER INSERT ON traffic_package_grants
FOR EACH ROW EXECUTE FUNCTION wake_package_traffic_enforcement_338();
CREATE TRIGGER package_addon_assignments_wake_enforcement_338
AFTER INSERT OR UPDATE ON package_addon_assignments
FOR EACH ROW EXECUTE FUNCTION wake_package_traffic_enforcement_338();
