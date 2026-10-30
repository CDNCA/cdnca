LOCK TABLE schema_migrations, dns_cname_retargets IN ACCESS EXCLUSIVE MODE;

DO $migration_286_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 286 OR
       (SELECT max(version) FROM schema_migrations) <> 286 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=286 AND
        migration_id='286_cname_market_target' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 286 down requires the exact verified migration head' USING ERRCODE='P2860';
    END IF;
    -- Retarget facts are durable: a CNAME retarget cannot be expressed in the
    -- 285 schema, so rolling back after one was written must not silently drop it.
    IF EXISTS (SELECT 1 FROM dns_cname_retargets WHERE target_cname IS NOT NULL) THEN
        RAISE EXCEPTION 'migration 286 down refused: CNAME retargets exist; restore from backup instead'
            USING ERRCODE='P2861';
    END IF;
END;
$migration_286_down$;

DROP TRIGGER dns_cname_retargets_protect_286 ON dns_cname_retargets;
DROP TRIGGER dns_cname_retargets_no_truncate_286 ON dns_cname_retargets;
ALTER TABLE dns_cname_retargets
    DROP CONSTRAINT dns_cname_retargets_target_286_check,
    DROP COLUMN target_cname,
    ADD CONSTRAINT dns_cname_retargets_check CHECK (cardinality(target_a) + cardinality(target_aaaa) > 0);
CREATE FUNCTION protect_dns_cname_retarget_280() RETURNS trigger
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
           NEW.owner_name, NEW.target_a, NEW.target_aaaa, NEW.ttl, NEW.target_digest, NEW.actor_user_id,
           NEW.request_id, NEW.created_at) IS DISTINCT FROM
       ROW(OLD.id, OLD.tenant_id, OLD.tenant_scope_id, OLD.allocation_id, OLD.base_job_id, OLD.sequence,
           OLD.site_id, OLD.node_group_id, OLD.node_group_revision, OLD.zone_id, OLD.zone_revision,
           OLD.owner_name, OLD.target_a, OLD.target_aaaa, OLD.ttl, OLD.target_digest, OLD.actor_user_id,
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
CREATE TRIGGER dns_cname_retargets_protect_280
BEFORE INSERT OR UPDATE OR DELETE ON dns_cname_retargets
FOR EACH ROW EXECUTE FUNCTION protect_dns_cname_retarget_280();
CREATE TRIGGER dns_cname_retargets_no_truncate_280
BEFORE TRUNCATE ON dns_cname_retargets
FOR EACH STATEMENT EXECUTE FUNCTION protect_dns_cname_retarget_280();
DROP FUNCTION protect_dns_cname_retarget_286();
REVOKE ALL ON FUNCTION protect_dns_cname_retarget_280() FROM PUBLIC;
