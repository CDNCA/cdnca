LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;
DO $$
BEGIN
    IF (SELECT max(version) FROM schema_migrations) <> 263 OR
       NOT EXISTS (SELECT 1 FROM schema_migrations WHERE version = 263 AND integrity_state = 'verified') THEN
        RAISE EXCEPTION 'migration 263 rollback requires verified 263 head' USING ERRCODE='P2631';
    END IF;
END;
$$;

DO $$ BEGIN
 IF EXISTS(SELECT 1 FROM package_addon_products) OR EXISTS(SELECT 1 FROM package_addon_assignments) THEN
  RAISE EXCEPTION 'retain addon facts: roll back application code instead';
 END IF;
END $$;
DROP FUNCTION package_addon_effective_limits(uuid,timestamptz);
DROP FUNCTION package_addon_effective_base_limits(uuid,timestamptz);
DROP TABLE package_addon_write_receipts;
DROP TABLE package_addon_assignments;
DROP TABLE package_addon_products;
DROP FUNCTION require_package_addon_audit();
DROP FUNCTION protect_package_addon_assignment();
DROP FUNCTION protect_package_addon_product();

DROP TRIGGER edge_command_outbox_state_172 ON edge_command_outbox;
DROP FUNCTION enforce_edge_outbox_state_172();
CREATE FUNCTION enforce_edge_outbox_state_172()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF OLD.status = NEW.status THEN
        RETURN NEW;
    END IF;
    IF OLD.status IN ('pending', 'failed') AND NEW.status = 'publishing' THEN
        RETURN NEW;
    END IF;
    IF OLD.status IN ('pending') AND NEW.status IN ('cancelled', 'held') THEN
        RETURN NEW;
    END IF;
    IF OLD.status = 'held' AND NEW.status IN ('pending','cancelled') THEN
        RETURN NEW;
    END IF;
    IF OLD.status = 'publishing' AND NEW.status IN ('published', 'failed') THEN
        RETURN NEW;
    END IF;
    RAISE EXCEPTION 'invalid edge outbox state transition' USING ERRCODE = 'P1725';
END;
$$;
CREATE TRIGGER edge_command_outbox_state_172 BEFORE UPDATE OF status ON edge_command_outbox
FOR EACH ROW EXECUTE FUNCTION enforce_edge_outbox_state_172();
