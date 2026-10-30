LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;

DO $migration_321_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 320 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 320 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=320 AND
        migration_id='320_retention_cleanup' AND
        checksum_sha256='95a73b22348a55322f13fa7c0605004c71d102abb5f1977beae57317e5909eb5' AND
        down_checksum_sha256='d1c616198a0041b502f01b7ad5f8da0d4c9c09aa0e9b8efa0b971eed00c6231b' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 321 requires the exact verified 320 release head' USING ERRCODE='P3210';
    END IF;
END;
$migration_321_up$;

-- FX33: node availability alert state, independent of the monitor failure
-- action. A node is alerted offline even when monitor_action=none (no serving
-- hold); the hold in node_serving_holds still decides DNS removal only.
CREATE TABLE node_availability_alert_states (
    node_id uuid PRIMARY KEY REFERENCES nodes(id) ON DELETE RESTRICT,
    offline boolean NOT NULL,
    reason_code text NOT NULL CHECK (reason_code ~ '^[a-z][a-z0-9_]{0,63}$'),
    revision bigint NOT NULL CHECK (revision > 0),
    offline_since timestamptz,
    changed_at timestamptz NOT NULL CHECK (isfinite(changed_at)),
    CHECK (offline = (offline_since IS NOT NULL))
);

GRANT SELECT, INSERT, UPDATE ON node_availability_alert_states TO cdnca_control_app, cdnca_control_runtime;
