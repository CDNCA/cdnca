LOCK TABLE schema_migrations, notification_control_idempotency_receipts IN ACCESS EXCLUSIVE MODE;

DO $migration_250_down$
BEGIN
    IF (SELECT max(version) FROM schema_migrations) IS DISTINCT FROM 250 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version = 250 AND migration_id = '250_notification_policy_write_receipts'
          AND checksum_sha256 = '63e8869b5d4b5c4e0239168f99e401fd9b5e1a6ba79b295937058658bee95589'
          AND integrity_state = 'verified'
    ) THEN
        RAISE EXCEPTION 'migration 250 rollback requires the verified 250 head' USING ERRCODE = 'P2500';
    END IF;
    IF EXISTS (
        SELECT 1 FROM notification_control_idempotency_receipts WHERE operation = 'notification.policy.update'
    ) THEN
        RAISE EXCEPTION 'retain migration 250 during binary rollback to preserve notification policy write receipts'
            USING ERRCODE = 'P2501';
    END IF;
END;
$migration_250_down$;

ALTER TABLE notification_control_idempotency_receipts
    DROP CONSTRAINT notification_control_idempotency_receipts_operation_check,
    ADD CONSTRAINT notification_control_idempotency_receipts_operation_check CHECK (operation IN (
        'notification.channels.update',
        'notification.template.put',
        'notification.subscription.update'
    ));
