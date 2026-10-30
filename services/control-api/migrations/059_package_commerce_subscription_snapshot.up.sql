ALTER TABLE package_subscription_entitlement_versions
    ADD COLUMN commit_sequence bigint NOT NULL DEFAULT 0 CHECK (commit_sequence >= 0);
ALTER TABLE package_subscription_entitlement_versions
    ALTER COLUMN commit_sequence DROP DEFAULT;

CREATE TABLE package_subscription_entitlement_commit_watermarks (
    tenant_scope_id uuid PRIMARY KEY REFERENCES access_scopes(id) ON DELETE RESTRICT,
    committed_through bigint NOT NULL CHECK (committed_through > 0)
);

CREATE FUNCTION assign_package_entitlement_commit_sequence()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.commit_sequence IS NOT NULL THEN
        RAISE EXCEPTION 'package entitlement commit sequence is server assigned';
    END IF;
    INSERT INTO package_subscription_entitlement_commit_watermarks (
        tenant_scope_id, committed_through
    ) VALUES (NEW.tenant_scope_id, 1)
    ON CONFLICT (tenant_scope_id) DO UPDATE
    SET committed_through = package_subscription_entitlement_commit_watermarks.committed_through + 1
    RETURNING committed_through INTO NEW.commit_sequence;
    RETURN NEW;
END;
$$;

CREATE TRIGGER package_entitlement_versions_assign_commit_sequence
BEFORE INSERT ON package_subscription_entitlement_versions
FOR EACH ROW EXECUTE FUNCTION assign_package_entitlement_commit_sequence();

CREATE UNIQUE INDEX package_entitlement_versions_tenant_commit_sequence_idx
    ON package_subscription_entitlement_versions (tenant_scope_id, commit_sequence)
    WHERE commit_sequence > 0;
