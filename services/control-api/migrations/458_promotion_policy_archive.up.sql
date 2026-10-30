LOCK TABLE schema_migrations, promotion_policies, promotion_write_requests, promotion_quote_policies,
    promotion_reservations IN ACCESS EXCLUSIVE MODE;

DO $migration_458_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 457 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 457 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=457 AND
        migration_id='457_package_automatic_publication' AND
        checksum_sha256='44cc376395c751b96952f0bc0eacbc714b864482a67a9fe0e2a887baca234482' AND
        down_checksum_sha256='43594d404e26c6ee3de3da44c931122a97bead7a4f42961f1d357be34db16f56' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema=current_schema() AND table_name='promotion_policies' AND column_name='archived_at'
       ) THEN
        RAISE EXCEPTION 'migration 458 requires the exact verified 457 release head' USING ERRCODE='P4580';
    END IF;
END;
$migration_458_up$;

-- 458 (r136 fix-finance E4; allotted 458, numbered 458 on this branch so the
-- embedded set stays contiguous on the 456 head; the merge renumbers it).
-- Promotion policies (discounts and coupons) are append-only facts that
-- quotes, reservations and orders pin, so they are archived, never deleted.
-- archived_at is set once (NULL -> timestamp) and never cleared: an archived
-- policy no longer applies to new quotes or reservations, and the admin list
-- hides it unless the archived filter asks for it. Facts already priced with
-- it (quotes, consumed reservations, renewal snapshots) stay as they were.
ALTER TABLE promotion_policies
    ADD COLUMN archived_at timestamptz CHECK (archived_at IS NULL OR isfinite(archived_at)),
    ADD COLUMN archived_by_user_id uuid,
    ADD CONSTRAINT promotion_policies_archive_actor
        CHECK ((archived_at IS NULL) = (archived_by_user_id IS NULL));

CREATE INDEX promotion_policies_archived_idx ON promotion_policies (archived_at) WHERE archived_at IS NOT NULL;

-- promotion_policies stays append-only except for the one-way archive stamp.
CREATE FUNCTION protect_promotion_policy_archive_458()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'UPDATE'
       AND OLD.archived_at IS NULL AND NEW.archived_at IS NOT NULL AND NEW.archived_by_user_id IS NOT NULL
       AND NEW.id = OLD.id AND NEW.coupon_code IS NOT DISTINCT FROM OLD.coupon_code
       AND NEW.created_by_scope_id = OLD.created_by_scope_id AND NEW.created_by_user_id = OLD.created_by_user_id
       AND NEW.created_at = OLD.created_at THEN
        IF NOT EXISTS (
            SELECT 1 FROM audit_events
            WHERE action = 'promotion.policy.archive' AND resource_type = 'promotion_policy'
              AND resource_id = OLD.id::text AND actor_user_id = NEW.archived_by_user_id AND result = 'success'
        ) THEN
            RAISE EXCEPTION 'promotion policy archive requires matching audit';
        END IF;
        RETURN NEW;
    END IF;
    RAISE EXCEPTION '% is append-only', TG_TABLE_NAME;
END;
$$;

DROP TRIGGER promotion_policies_append_only ON promotion_policies;
CREATE TRIGGER promotion_policies_append_only
BEFORE UPDATE OR DELETE ON promotion_policies
FOR EACH ROW EXECUTE FUNCTION protect_promotion_policy_archive_458();

-- New quotes and reservations cannot carry an archived policy. Renewal
-- snapshot sources (source_kind renewal_snapshot) keep the price the
-- subscriber already bought, so only fresh policy applications are refused.
CREATE FUNCTION reject_archived_promotion_quote_policy_458()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.source_kind = 'policy' AND EXISTS (
        SELECT 1 FROM promotion_policies WHERE id = NEW.policy_id AND archived_at IS NOT NULL
    ) THEN
        RAISE EXCEPTION 'promotion policy is archived' USING ERRCODE='P4582';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER promotion_quote_policies_reject_archived
BEFORE INSERT ON promotion_quote_policies
FOR EACH ROW EXECUTE FUNCTION reject_archived_promotion_quote_policy_458();

CREATE FUNCTION reject_archived_promotion_reservation_458()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM promotion_quote_policies item
        JOIN promotion_policies policy ON policy.id = item.policy_id
        WHERE item.quote_id = NEW.quote_id AND item.source_kind = 'policy' AND policy.archived_at IS NOT NULL
    ) THEN
        RAISE EXCEPTION 'promotion policy is archived' USING ERRCODE='P4582';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER promotion_reservations_reject_archived
BEFORE INSERT ON promotion_reservations
FOR EACH ROW EXECUTE FUNCTION reject_archived_promotion_reservation_458();

-- An order placed after the archive cannot use a quote that applies the
-- archived policy, even when the quote was reserved before. A paid order's
-- later consumption is left alone (the money already moved).
CREATE FUNCTION reject_archived_promotion_order_458()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.promotion_quote_id IS NOT NULL AND EXISTS (
        SELECT 1 FROM promotion_quote_policies item
        JOIN promotion_policies policy ON policy.id = item.policy_id
        WHERE item.quote_id = NEW.promotion_quote_id AND item.source_kind = 'policy' AND policy.archived_at IS NOT NULL
    ) THEN
        RAISE EXCEPTION 'promotion policy is archived' USING ERRCODE='P4582';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER package_orders_reject_archived_promotion
BEFORE INSERT ON package_orders
FOR EACH ROW EXECUTE FUNCTION reject_archived_promotion_order_458();

ALTER TABLE promotion_write_requests DROP CONSTRAINT promotion_write_requests_operation_check;
ALTER TABLE promotion_write_requests ADD CONSTRAINT promotion_write_requests_operation_check CHECK (operation IN (
    'promotion.policy.publish',
    'promotion.policy.archive',
    'promotion.quote.create',
    'promotion.reserve',
    'promotion.consume',
    'promotion.release',
    'promotion.renewal.bind',
    'promotion.adjustment.decide'
));
