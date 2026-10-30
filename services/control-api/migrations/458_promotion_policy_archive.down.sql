LOCK TABLE schema_migrations, promotion_policies, promotion_write_requests IN ACCESS EXCLUSIVE MODE;

DO $migration_458_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 458 OR
       (SELECT max(version) FROM schema_migrations) <> 458 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=458 AND
        migration_id='458_promotion_policy_archive' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 458 down requires the exact verified migration head' USING ERRCODE='P4581';
    END IF;
    -- Rolling back would silently re-activate archived discounts and coupons.
    IF EXISTS (SELECT 1 FROM promotion_policies WHERE archived_at IS NOT NULL) OR
       EXISTS (SELECT 1 FROM promotion_write_requests WHERE operation = 'promotion.policy.archive') THEN
        RAISE EXCEPTION 'migration 458 rollback would re-activate archived promotion policies' USING ERRCODE='P4583';
    END IF;
END;
$migration_458_down$;

ALTER TABLE promotion_write_requests DROP CONSTRAINT promotion_write_requests_operation_check;
ALTER TABLE promotion_write_requests ADD CONSTRAINT promotion_write_requests_operation_check CHECK (operation IN (
    'promotion.policy.publish',
    'promotion.quote.create',
    'promotion.reserve',
    'promotion.consume',
    'promotion.release',
    'promotion.renewal.bind',
    'promotion.adjustment.decide'
));

DROP TRIGGER package_orders_reject_archived_promotion ON package_orders;
DROP FUNCTION reject_archived_promotion_order_458();
DROP TRIGGER promotion_reservations_reject_archived ON promotion_reservations;
DROP FUNCTION reject_archived_promotion_reservation_458();
DROP TRIGGER promotion_quote_policies_reject_archived ON promotion_quote_policies;
DROP FUNCTION reject_archived_promotion_quote_policy_458();

DROP TRIGGER promotion_policies_append_only ON promotion_policies;
CREATE TRIGGER promotion_policies_append_only
BEFORE UPDATE OR DELETE ON promotion_policies
FOR EACH ROW EXECUTE FUNCTION prevent_promotion_append_mutation();
DROP FUNCTION protect_promotion_policy_archive_458();

DROP INDEX promotion_policies_archived_idx;
ALTER TABLE promotion_policies
    DROP CONSTRAINT promotion_policies_archive_actor,
    DROP COLUMN archived_by_user_id,
    DROP COLUMN archived_at;
