LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;

DO $migration_202$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 201 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 201 OR
       NOT EXISTS (SELECT 1 FROM schema_migrations WHERE version=201 AND migration_id='201_notification_delivery_policy_unsupported_defaults' AND checksum_sha256='f40139a07ef14cf3e7ea15d17bdde73b859dd12d055002695cc5ede115fb1769' AND down_checksum_sha256='b0664011116cf73e77a8b49efcffbdb1234ed0fd49f51885b0151ded550de204' AND integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL) THEN
        RAISE EXCEPTION 'migration 202 requires the exact verified 201 release head' USING ERRCODE='P2020';
    END IF;
END;
$migration_202$;

INSERT INTO notification_event_policies(
    event_type, enabled, sms_enabled, email_enabled, repeat_count, interval_hours, supported, updated_at
)
VALUES ('package.monitor.traffic.warning', false, false, false, 1, 24, false, now());

