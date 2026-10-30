LOCK TABLE schema_migrations,
    control_upgrade_rollout_plans,
    control_upgrade_node_commands,
    control_upgrade_outbox,
    control_upgrade_status_receipts
IN ACCESS EXCLUSIVE MODE;

DO $$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 105 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 105 OR EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE migration_id IS NULL
           OR checksum_sha256 IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$'
           OR down_checksum_sha256 IS NULL OR down_checksum_sha256 !~ '^[0-9a-f]{64}$'
           OR integrity_state IS DISTINCT FROM 'verified'
           OR metadata_recorded_at IS NULL OR applied_at IS NULL
    ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version=105 AND migration_id='105_upgrade_canary_active_probe_lkg'
          AND checksum_sha256='aef23962ee9538fbc4724684ec8fc87edc2a2af33f76aa8a76b6992769af0d7b'
          AND integrity_state='verified'
          AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
    ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version=104 AND migration_id='104_background_job_settlement_dlq'
          AND checksum_sha256='fac89e12c1c307327e4855a6cde1366026fb2914605723db14acd980519f3a5e'
          AND down_checksum_sha256='76a85290403d0bddbba56c2245a4391d644b897592d2b2ecb00db8ccf1e8ae12'
          AND integrity_state='verified'
          AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
    ) THEN
        RAISE EXCEPTION 'migration 105 rollback requires the exact verified 105 head'
            USING ERRCODE='P1050';
    END IF;
    IF EXISTS (
        SELECT 1 FROM control_upgrade_status_receipts
        WHERE convert_from(status_bytes,'UTF8')::jsonb->>'schema'=
              'cdnca.edge.upgrade.status/v2'
    ) THEN
        RAISE EXCEPTION 'migration 105 rollback would discard v2 active probe evidence'
            USING ERRCODE='P1051';
    END IF;
END;
$$;

DROP TRIGGER control_upgrade_status_semantics_105 ON control_upgrade_status_receipts;
DROP TRIGGER control_upgrade_status_validate_105 ON control_upgrade_status_receipts;

DROP FUNCTION validate_control_upgrade_status_semantics_105();
DROP FUNCTION validate_control_upgrade_status_105();

CREATE TRIGGER control_upgrade_status_validate_093
BEFORE INSERT OR UPDATE OR DELETE ON control_upgrade_status_receipts
FOR EACH ROW EXECUTE FUNCTION validate_control_upgrade_status_093();

CREATE TRIGGER control_upgrade_status_semantics_096
BEFORE INSERT ON control_upgrade_status_receipts
FOR EACH ROW EXECUTE FUNCTION validate_control_upgrade_status_semantics_096();
