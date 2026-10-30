LOCK TABLE schema_migrations,
    dns_reconcile_commit_facts,
    dns_reconcile_cancel_facts
IN ACCESS EXCLUSIVE MODE;

DO $$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 111 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 111 OR EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE migration_id IS NULL OR checksum_sha256 IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$'
           OR down_checksum_sha256 IS NULL OR down_checksum_sha256 !~ '^[0-9a-f]{64}$'
           OR integrity_state IS DISTINCT FROM 'verified' OR metadata_recorded_at IS NULL OR applied_at IS NULL
    ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version=111 AND migration_id='111_firewall_command_outbox'
          AND checksum_sha256='dd1f37db9068df613adcb435ec46686b5d6a4e23593cb987ea67d1412a42d3e6'
          AND down_checksum_sha256='a40154439408384a46855ec22a9c50729855f363fb45ebd3d09c18df5febf99c'
          AND integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
    ) THEN
        RAISE EXCEPTION 'migration 112 requires the exact verified 111 release head' USING ERRCODE='P1120';
    END IF;
END;
$$;

ALTER TABLE dns_reconcile_commit_facts
    ADD COLUMN actor_user_id uuid NULL;
ALTER TABLE dns_reconcile_cancel_facts
    ADD COLUMN actor_user_id uuid NULL;

ALTER TABLE dns_reconcile_commit_facts
    ADD CONSTRAINT dns_reconcile_commit_facts_actor_user_112_fk
    FOREIGN KEY (actor_user_id) REFERENCES users(id) ON DELETE RESTRICT;
ALTER TABLE dns_reconcile_cancel_facts
    ADD CONSTRAINT dns_reconcile_cancel_facts_actor_user_112_fk
    FOREIGN KEY (actor_user_id) REFERENCES users(id) ON DELETE RESTRICT;

CREATE FUNCTION validate_dns_reconcile_actor_receipt_112()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    canonical_actor uuid;
BEGIN
    IF NEW.actor_user_id IS NULL THEN
        RAISE EXCEPTION 'DNS reconcile actor identity is required' USING ERRCODE='P1121';
    END IF;

    IF TG_TABLE_NAME = 'dns_reconcile_commit_facts' THEN
        SELECT actor_user_id INTO canonical_actor
        FROM dns_reconcile_commit_facts
        WHERE tenant_id=NEW.tenant_id AND job_id=NEW.job_id
        ORDER BY fact_sequence ASC
        LIMIT 1;
        IF FOUND AND canonical_actor IS NULL THEN
            RAISE EXCEPTION 'DNS reconcile legacy actor identity cannot be continued' USING ERRCODE='P1122';
        END IF;
        IF FOUND AND canonical_actor IS DISTINCT FROM NEW.actor_user_id THEN
            RAISE EXCEPTION 'DNS reconcile actor identity drift' USING ERRCODE='P1123';
        END IF;
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER dns_reconcile_commit_facts_actor_valid_112
BEFORE INSERT ON dns_reconcile_commit_facts
FOR EACH ROW EXECUTE FUNCTION validate_dns_reconcile_actor_receipt_112();
CREATE TRIGGER dns_reconcile_cancel_facts_actor_valid_112
BEFORE INSERT ON dns_reconcile_cancel_facts
FOR EACH ROW EXECUTE FUNCTION validate_dns_reconcile_actor_receipt_112();
