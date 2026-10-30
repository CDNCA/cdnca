ALTER TABLE control_installation_entitlement
    DROP CONSTRAINT IF EXISTS control_installation_current_lease_fk;
DROP TABLE IF EXISTS entitlement_cached_leases;
DROP TABLE IF EXISTS entitlement_verification_keys;
DROP TABLE IF EXISTS control_installation_entitlement;
