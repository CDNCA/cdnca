LOCK TABLE package_subscription_entitlement_versions IN ACCESS EXCLUSIVE MODE;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM package_subscription_entitlement_versions) THEN
        RAISE EXCEPTION 'migration 059 rollback requires package entitlement facts to be absent';
    END IF;
END;
$$;

DROP TRIGGER package_entitlement_versions_assign_commit_sequence
    ON package_subscription_entitlement_versions;
DROP FUNCTION assign_package_entitlement_commit_sequence();
DROP INDEX package_entitlement_versions_tenant_commit_sequence_idx;
DROP TABLE package_subscription_entitlement_commit_watermarks;
ALTER TABLE package_subscription_entitlement_versions DROP COLUMN commit_sequence;
