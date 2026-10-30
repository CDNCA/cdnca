LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;

DO $migration_201$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 200 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 200 OR
       NOT EXISTS (SELECT 1 FROM schema_migrations WHERE version=200 AND migration_id='200_notification_delivery_policy' AND checksum_sha256='b625c5e3fec8eb53bd34ff4d92f7062d60d3b4579c1984a8309b4604979c2e6b' AND down_checksum_sha256='6e3ebfcd05ba18a9e5666cc034c4bd6ed7b806faea7e04985db2de8ec8c81863' AND integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL) THEN
        RAISE EXCEPTION 'migration 201 requires the exact verified 200 release head' USING ERRCODE='P2001';
    END IF;
END;
$migration_201$;

UPDATE notification_event_policies
SET enabled=false, sms_enabled=false, email_enabled=false, updated_at=now()
WHERE supported=false;
