LOCK TABLE schema_migrations, notification_control_idempotency_receipts IN ACCESS EXCLUSIVE MODE;

DO $migration_250$
BEGIN
    IF (SELECT max(version) FROM schema_migrations) IS DISTINCT FROM 249 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version = 249 AND migration_id = '249_l4_group_actor_references'
          AND checksum_sha256 = 'ce80b5cc68df493ae3496f7b282f718fb62106b4dcc401e4a616a2eb5b1bf95a'
          AND down_checksum_sha256 = '632ca581fc225ba72c673df3a72ad295fd5afa431d9989510408d370da7e5244'
          AND integrity_state = 'verified'
    ) THEN
        RAISE EXCEPTION 'migration 250 requires the exact verified 249 release head' USING ERRCODE = 'P2500';
    END IF;
END;
$migration_250$;

ALTER TABLE notification_control_idempotency_receipts
    DROP CONSTRAINT notification_control_idempotency_receipts_operation_check,
    ADD CONSTRAINT notification_control_idempotency_receipts_operation_check CHECK (operation IN (
        'notification.channels.update',
        'notification.template.put',
        'notification.subscription.update',
        'notification.policy.update'
    ));
