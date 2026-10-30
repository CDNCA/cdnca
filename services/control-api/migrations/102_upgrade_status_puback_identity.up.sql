LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;

DO $$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 101 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 101 OR EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE migration_id IS NULL
           OR checksum_sha256 IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$'
           OR down_checksum_sha256 IS NULL OR down_checksum_sha256 !~ '^[0-9a-f]{64}$'
           OR integrity_state IS DISTINCT FROM 'verified'
           OR metadata_recorded_at IS NULL OR applied_at IS NULL
    ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version=101 AND migration_id='101_upgrade_dual_sequence'
          AND checksum_sha256='198238a302b07d49751543329dfa51361fecd6238ba7bc0ec59a8dd96c34cb18'
          AND down_checksum_sha256='c857d874f78d5c51fa7702852c0bc6325baf7b788ed4b555f705c56ffaa6fa42'
          AND integrity_state='verified' AND metadata_recorded_at IS NOT NULL
          AND applied_at IS NOT NULL
    ) OR to_regclass(format('%I.%I',current_schema(),'control_upgrade_status_receipts')) IS NULL OR EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema=current_schema() AND table_name='control_upgrade_status_receipts'
          AND column_name IN ('delivery_stream','delivery_consumer','delivery_sequence')
    ) THEN
        RAISE EXCEPTION 'migration 102 requires the exact verified 101 release head'
            USING ERRCODE='P1020';
    END IF;
END;
$$;

LOCK TABLE control_upgrade_status_receipts IN ACCESS EXCLUSIVE MODE;

-- legacy rows remain nullable and are never guessed
ALTER TABLE control_upgrade_status_receipts
    ADD COLUMN delivery_stream text,
    ADD COLUMN delivery_consumer text,
    ADD COLUMN delivery_sequence bigint,
    ADD CONSTRAINT control_upgrade_status_receipts_delivery_shape_102 CHECK (
        (delivery_stream IS NULL AND delivery_consumer IS NULL AND delivery_sequence IS NULL) OR
        (delivery_stream='AGENT_DEPLOYMENT_STATUS' AND
         delivery_consumer ~ '^[A-Za-z0-9_-]{1,128}$' AND delivery_sequence>0)
    ),
    ADD CONSTRAINT control_upgrade_status_receipts_delivery_102_uk
        UNIQUE (delivery_stream, delivery_sequence);

CREATE FUNCTION validate_control_upgrade_status_puback_identity_102()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP='UPDATE' AND ROW(
        NEW.delivery_stream,NEW.delivery_consumer,NEW.delivery_sequence
    ) IS DISTINCT FROM ROW(
        OLD.delivery_stream,OLD.delivery_consumer,OLD.delivery_sequence
    ) THEN
        RAISE EXCEPTION 'control upgrade status PubAck facts are immutable'
            USING ERRCODE='P1022';
    END IF;
    IF TG_OP='INSERT' AND (
        NEW.delivery_stream IS DISTINCT FROM 'AGENT_DEPLOYMENT_STATUS' OR
        NEW.delivery_consumer IS NULL OR NEW.delivery_consumer !~ '^[A-Za-z0-9_-]{1,128}$' OR
        NEW.delivery_sequence IS NULL OR NEW.delivery_sequence<=0
    ) THEN
        RAISE EXCEPTION 'new control upgrade status requires exact PubAck delivery facts'
            USING ERRCODE='P1022';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER control_upgrade_status_puback_identity_102
BEFORE INSERT OR UPDATE ON control_upgrade_status_receipts
FOR EACH ROW EXECUTE FUNCTION validate_control_upgrade_status_puback_identity_102();

REVOKE ALL ON FUNCTION validate_control_upgrade_status_puback_identity_102() FROM PUBLIC;
