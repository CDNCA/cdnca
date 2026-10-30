LOCK TABLE schema_migrations,
    dns_reconcile_commit_facts,
    dns_reconcile_cancel_facts
IN ACCESS EXCLUSIVE MODE;

DO $$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 112 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 112 OR EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE migration_id IS NULL OR checksum_sha256 IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$'
           OR down_checksum_sha256 IS NULL OR down_checksum_sha256 !~ '^[0-9a-f]{64}$'
           OR integrity_state IS DISTINCT FROM 'verified' OR metadata_recorded_at IS NULL OR applied_at IS NULL
    ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version=112 AND migration_id='112_dns_reconcile_actor_receipts'
          AND checksum_sha256='d26988f21844ba759a0345ad1aed1fd3d40156c6a22dd2e382736987348a8017'
          AND integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
    ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version=111 AND migration_id='111_firewall_command_outbox'
          AND checksum_sha256='dd1f37db9068df613adcb435ec46686b5d6a4e23593cb987ea67d1412a42d3e6'
          AND down_checksum_sha256='a40154439408384a46855ec22a9c50729855f363fb45ebd3d09c18df5febf99c'
          AND integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
    ) THEN
        RAISE EXCEPTION 'migration 112 rollback requires the exact verified release head' USING ERRCODE='P1120';
    END IF;
    IF EXISTS (SELECT 1 FROM dns_reconcile_commit_facts WHERE actor_user_id IS NOT NULL) OR
       EXISTS (SELECT 1 FROM dns_reconcile_cancel_facts WHERE actor_user_id IS NOT NULL) THEN
        RAISE EXCEPTION 'migration 112 rollback would discard actor receipt identity' USING ERRCODE='P1121';
    END IF;
END;
$$;

DROP TRIGGER dns_reconcile_cancel_facts_actor_valid_112 ON dns_reconcile_cancel_facts;
DROP TRIGGER dns_reconcile_commit_facts_actor_valid_112 ON dns_reconcile_commit_facts;
DROP FUNCTION validate_dns_reconcile_actor_receipt_112();

ALTER TABLE dns_reconcile_cancel_facts
    DROP CONSTRAINT dns_reconcile_cancel_facts_actor_user_112_fk,
    DROP COLUMN actor_user_id;
ALTER TABLE dns_reconcile_commit_facts
    DROP CONSTRAINT dns_reconcile_commit_facts_actor_user_112_fk,
    DROP COLUMN actor_user_id;
