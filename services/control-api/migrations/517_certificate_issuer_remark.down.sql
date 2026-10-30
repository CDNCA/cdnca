-- 517（r136 fp-cert）回退：删订单签发机构/名称/备注、资产备注、用户默认签发机构。
LOCK TABLE schema_migrations, certificate_orders, certificate_assets, certificate_user_defaults IN ACCESS EXCLUSIVE MODE;

DO $migration_517_down$
BEGIN
    IF (SELECT max(version) FROM schema_migrations) <> 517 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=517 AND
        migration_id='517_certificate_issuer_remark' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 517 down requires the exact verified migration head' USING ERRCODE='P5172';
    END IF;
END;
$migration_517_down$;

DROP TRIGGER certificate_orders_metadata_immutable_517 ON certificate_orders;
DROP FUNCTION protect_certificate_order_metadata_517();
ALTER TABLE certificate_user_defaults
    DROP CONSTRAINT certificate_user_defaults_issuer_517_check,
    DROP COLUMN issuer;
ALTER TABLE certificate_assets DROP COLUMN remark;
ALTER TABLE certificate_orders DROP COLUMN remark, DROP COLUMN name, DROP COLUMN issuer;
