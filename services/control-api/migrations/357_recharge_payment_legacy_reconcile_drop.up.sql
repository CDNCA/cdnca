LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;

DO $migration_357_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 356 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 356 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=356 AND
        migration_id='356_site_cache_shared_across_domains' AND
        checksum_sha256='dd69f72578e5a6d56f3e3cf5eced55a2ceb8e99700426077439240db0bf0accc' AND
        down_checksum_sha256='4eff66a3efa731a8504eb4781175c71c4b18229eccffd9b4e75fefcf2c991301' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 357 requires the exact verified 356 release head' USING ERRCODE='P3570';
    END IF;
END;
$migration_357_up$;

-- r136 pa21: recharge collection runs only over payment_channels. The
-- environment-defined Alipay/WeChat providers and their reconcile job queue
-- (152) are removed; unsettled provider results are queried again through
-- payment_channel_reconcile_schedule (298). 1.0.35 is installed fresh, so
-- queued jobs are not carried over.
DROP TRIGGER recharge_payment_reconcile_receipts_append_only_v1 ON recharge_payment_reconcile_receipts_v1;
DROP TRIGGER recharge_payment_reconcile_jobs_guard_v1 ON recharge_payment_reconcile_jobs_v1;
DROP TABLE recharge_payment_reconcile_receipts_v1;
DROP TABLE recharge_payment_reconcile_jobs_v1;
DROP FUNCTION guard_recharge_payment_reconcile_job_152();
