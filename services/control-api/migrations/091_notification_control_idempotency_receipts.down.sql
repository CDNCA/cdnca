LOCK TABLE schema_migrations,
    notification_control_idempotency_receipts,
    audit_events
IN ACCESS EXCLUSIVE MODE;

DO $$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 91 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 91 OR EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$'
           OR down_checksum_sha256 !~ '^[0-9a-f]{64}$'
           OR integrity_state <> 'verified' OR metadata_recorded_at IS NULL OR applied_at IS NULL
    ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version = 91
          AND migration_id = '091_notification_control_idempotency_receipts'
          AND checksum_sha256 = '9c556085f7396024a5011f74b06e0a6e3b83f5f6c5ab050b4b5c7b2ad036758c'
          AND integrity_state = 'verified'
    ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version = 90
          AND migration_id = '090_package_offer_publication'
          AND checksum_sha256 = '1bfa2cccb6b15dab981cf73b23754c7a1751f2f60921dda5959f51fef545b284'
          AND down_checksum_sha256 = '9450025870421a3d594f3a9e210bd463ba3021b3ac19b815dee5a127ddaf5c9b'
          AND integrity_state = 'verified'
    ) THEN
        RAISE EXCEPTION 'migration 091 rollback requires the verified 091 head'
            USING ERRCODE = 'P9100';
    END IF;
    IF EXISTS (SELECT 1 FROM notification_control_idempotency_receipts) THEN
        RAISE EXCEPTION 'migration 091 rollback would discard notification control idempotency receipts'
            USING ERRCODE = 'P9101';
    END IF;
END;
$$;

DROP INDEX audit_events_notification_control_denied_identity_091;

DROP TRIGGER notification_control_idempotency_receipts_complete_091
    ON notification_control_idempotency_receipts;
DROP TRIGGER notification_control_idempotency_receipts_no_truncate_091
    ON notification_control_idempotency_receipts;
DROP TRIGGER notification_control_idempotency_receipts_protect_091
    ON notification_control_idempotency_receipts;
DROP FUNCTION require_notification_control_idempotency_receipt_completion_091();
DROP FUNCTION protect_notification_control_idempotency_receipt_091();
DROP TABLE notification_control_idempotency_receipts;
