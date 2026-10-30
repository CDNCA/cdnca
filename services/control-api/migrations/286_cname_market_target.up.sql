LOCK TABLE schema_migrations, dns_cname_retargets IN ACCESS EXCLUSIVE MODE;

DO $migration_286_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 285 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 285 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=285 AND
        migration_id='285_site_supply_binding' AND
        checksum_sha256='675876fba0ec984412e09367a456ad6724fc9d10739af07b4d32bbe1a57b776a' AND
        down_checksum_sha256='1cfbe5ea8bd87748d941fe2f5e713a3583644b6d3471b5dffbefd49557089446' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR checksum_sha256 IS NULL OR
        down_checksum_sha256 IS NULL OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR EXISTS (
        SELECT 1 FROM information_schema.columns WHERE table_schema=current_schema()
          AND table_name='dns_cname_retargets' AND column_name='target_cname'
       ) OR to_regprocedure(current_schema() || '.protect_dns_cname_retarget_280()') IS NULL THEN
        RAISE EXCEPTION 'migration 286 requires the exact verified 285 release head' USING ERRCODE='P2860';
    END IF;
END;
$migration_286_up$;

-- A site bound to a node market supply publishes its CNAME hostname as a
-- CNAME to the market's supply name instead of A/AAAA records of a local
-- node group (docs/marketplace/02-supply-model.md §2). A retarget carries
-- either addresses or one CNAME target, never both.
ALTER TABLE dns_cname_retargets
    ADD COLUMN target_cname text CHECK (target_cname IS NULL OR (
        char_length(target_cname) BETWEEN 1 AND 253 AND target_cname = lower(target_cname)
        AND target_cname ~ '^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+\.?$')),
    DROP CONSTRAINT dns_cname_retargets_check,
    ADD CONSTRAINT dns_cname_retargets_target_286_check CHECK (
        (target_cname IS NULL AND cardinality(target_a) + cardinality(target_aaaa) > 0) OR
        (target_cname IS NOT NULL AND cardinality(target_a) + cardinality(target_aaaa) = 0));

-- Same guard as 280, with target_cname immutable as well.
CREATE FUNCTION protect_dns_cname_retarget_286() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF TG_OP = 'DELETE' OR TG_OP = 'TRUNCATE' THEN
        RAISE EXCEPTION 'CNAME retarget facts are durable' USING ERRCODE='P2801';
    END IF;
    IF TG_OP = 'INSERT' THEN
        IF NEW.state <> 'pending' OR NEW.child_task_id IS NOT NULL THEN
            RAISE EXCEPTION 'CNAME retarget must start pending' USING ERRCODE='P2802';
        END IF;
        RETURN NEW;
    END IF;
    IF ROW(NEW.id, NEW.tenant_id, NEW.tenant_scope_id, NEW.allocation_id, NEW.base_job_id, NEW.sequence,
           NEW.site_id, NEW.node_group_id, NEW.node_group_revision, NEW.zone_id, NEW.zone_revision,
           NEW.owner_name, NEW.target_a, NEW.target_aaaa, NEW.target_cname, NEW.ttl, NEW.target_digest, NEW.actor_user_id,
           NEW.request_id, NEW.created_at) IS DISTINCT FROM
       ROW(OLD.id, OLD.tenant_id, OLD.tenant_scope_id, OLD.allocation_id, OLD.base_job_id, OLD.sequence,
           OLD.site_id, OLD.node_group_id, OLD.node_group_revision, OLD.zone_id, OLD.zone_revision,
           OLD.owner_name, OLD.target_a, OLD.target_aaaa, OLD.target_cname, OLD.ttl, OLD.target_digest, OLD.actor_user_id,
           OLD.request_id, OLD.created_at) OR
       OLD.state IN ('committed', 'failed', 'superseded') OR NEW.updated_at < OLD.updated_at OR
       (OLD.child_task_id IS NOT NULL AND NEW.child_task_id IS DISTINCT FROM OLD.child_task_id) OR
       NOT ((OLD.state = 'pending' AND NEW.state IN ('pending', 'applying', 'failed', 'superseded')) OR
            (OLD.state = 'applying' AND NEW.state IN ('applying', 'committed', 'failed', 'superseded'))) THEN
        RAISE EXCEPTION 'CNAME retarget transition is invalid' USING ERRCODE='P2802';
    END IF;
    RETURN NEW;
END;
$$;
DROP TRIGGER dns_cname_retargets_protect_280 ON dns_cname_retargets;
DROP TRIGGER dns_cname_retargets_no_truncate_280 ON dns_cname_retargets;
CREATE TRIGGER dns_cname_retargets_protect_286
BEFORE INSERT OR UPDATE OR DELETE ON dns_cname_retargets
FOR EACH ROW EXECUTE FUNCTION protect_dns_cname_retarget_286();
CREATE TRIGGER dns_cname_retargets_no_truncate_286
BEFORE TRUNCATE ON dns_cname_retargets
FOR EACH STATEMENT EXECUTE FUNCTION protect_dns_cname_retarget_286();
DROP FUNCTION protect_dns_cname_retarget_280();
REVOKE ALL ON FUNCTION protect_dns_cname_retarget_286() FROM PUBLIC;
