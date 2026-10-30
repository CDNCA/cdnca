LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;

DO $$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 103 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 103 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version=103 AND migration_id='103_certificate_renewal_retry_after_failed_child'
          AND checksum_sha256='356d6bbee4f13cd68df4958156fc175663c500bf2c644630d35f8e5568483cf6'
          AND integrity_state='verified' AND metadata_recorded_at IS NOT NULL
          AND applied_at IS NOT NULL
    ) THEN
        RAISE EXCEPTION 'migration 103 rollback requires the exact verified 103 head'
            USING ERRCODE='P1030';
    END IF;
    IF EXISTS (
        SELECT 1 FROM acme_renewal_claim_facts
        WHERE event_type='claim_reopened' OR reopened_from_order_id IS NOT NULL
    ) THEN
        RAISE EXCEPTION 'claim_reopened facts exist; rollback is unsafe'
            USING ERRCODE='P1031';
    END IF;
END;
$$;

LOCK TABLE acme_renewal_claim_facts IN ACCESS EXCLUSIVE MODE;

CREATE OR REPLACE FUNCTION validate_acme_renewal_claim_fact_048()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    source_order certificate_orders%ROWTYPE;
    previous acme_renewal_claim_facts%ROWTYPE;
    renewal_order certificate_orders%ROWTYPE;
    database_now timestamptz := statement_timestamp();
BEGIN
    SELECT * INTO source_order
    FROM certificate_orders
    WHERE scope_id = NEW.tenant_scope_id AND id = NEW.source_order_id
    FOR UPDATE;
    IF source_order.id IS NULL
       OR NOT source_order.auto_renew
       OR source_order.status NOT IN ('active', 'renewal_due')
       OR source_order.created_by_user_id IS DISTINCT FROM NEW.actor_user_id
       OR NOT acme_runtime_actor_is_active_048(NEW.tenant_scope_id, NEW.actor_user_id)
       OR NEW.occurred_at < database_now - interval '5 minutes'
       OR NEW.occurred_at > database_now + interval '1 minute' THEN
        RAISE EXCEPTION 'ACME renewal claim source or actor is invalid' USING ERRCODE = 'P0001';
    END IF;

    IF NEW.revision = 1 THEN
        IF NEW.event_type <> 'claim_created' OR NEW.status <> 'active'
           OR NEW.fence_token IS DISTINCT FROM NEW.lease_token
           OR NEW.lease_expires_at <= database_now THEN
            RAISE EXCEPTION 'invalid initial ACME renewal claim' USING ERRCODE = 'P0001';
        END IF;
        RETURN NEW;
    END IF;

    SELECT * INTO previous
    FROM acme_renewal_claim_facts
    WHERE tenant_scope_id = NEW.tenant_scope_id
      AND source_order_id = NEW.source_order_id
      AND revision = NEW.revision - 1;
    IF NOT FOUND OR previous.status = 'completed' OR NEW.occurred_at < previous.occurred_at THEN
        RAISE EXCEPTION 'ACME renewal claim revision is not contiguous'
            USING ERRCODE = 'P0001';
    END IF;

    IF NEW.event_type = 'lease_taken_over' THEN
        IF NEW.status <> 'active'
           OR NEW.fence_token IS DISTINCT FROM NEW.lease_token
           OR NEW.lease_token IS NOT DISTINCT FROM previous.lease_token
           OR NEW.lease_expires_at <= database_now
           OR NOT (
               (previous.status = 'active' AND previous.lease_expires_at <= database_now)
               OR (previous.status = 'retry_wait' AND previous.next_attempt_at <= database_now)
           ) THEN
            RAISE EXCEPTION 'invalid ACME renewal lease takeover' USING ERRCODE = 'P0001';
        END IF;
        RETURN NEW;
    END IF;

    IF previous.status <> 'active' OR previous.lease_expires_at <= database_now
       OR NEW.fence_token IS DISTINCT FROM previous.lease_token THEN
        RAISE EXCEPTION 'ACME renewal lease fence rejected the event'
            USING ERRCODE = 'P0001';
    END IF;
    IF NEW.event_type = 'retry_scheduled' THEN
        IF NEW.status <> 'retry_wait' THEN
            RAISE EXCEPTION 'invalid ACME renewal retry event' USING ERRCODE = 'P0001';
        END IF;
        RETURN NEW;
    END IF;
    IF NEW.event_type = 'completed' AND NEW.status = 'completed' THEN
        SELECT * INTO renewal_order
        FROM certificate_orders
        WHERE scope_id = NEW.tenant_scope_id AND id = NEW.renewal_order_id;
        IF renewal_order.id IS NULL
           OR renewal_order.renewal_of_order_id IS DISTINCT FROM NEW.source_order_id
           OR renewal_order.status IS DISTINCT FROM 'pending'
           OR renewal_order.dns_provider_id IS DISTINCT FROM source_order.dns_provider_id
           OR renewal_order.domains IS DISTINCT FROM source_order.domains
           OR renewal_order.challenge_type IS DISTINCT FROM source_order.challenge_type
           OR renewal_order.auto_renew IS DISTINCT FROM source_order.auto_renew
           OR renewal_order.created_by_user_id IS DISTINCT FROM NEW.actor_user_id THEN
            RAISE EXCEPTION 'ACME renewal claim result is not a child order'
                USING ERRCODE = 'P0001';
        END IF;
        RETURN NEW;
    END IF;
    RAISE EXCEPTION 'invalid ACME renewal claim event' USING ERRCODE = 'P0001';
END;
$$;

ALTER TABLE acme_renewal_claim_facts
    DROP CONSTRAINT acme_renewal_claim_reopened_source_fk_103,
    DROP CONSTRAINT acme_renewal_claim_facts_event_type_check,
    DROP CONSTRAINT acme_renewal_claim_facts_check,
    DROP COLUMN reopened_from_order_id;

ALTER TABLE acme_renewal_claim_facts
    ADD CONSTRAINT acme_renewal_claim_facts_event_type_check CHECK (event_type IN (
        'claim_created', 'lease_taken_over', 'retry_scheduled', 'completed'
    )),
    ADD CONSTRAINT acme_renewal_claim_facts_check CHECK (
        (
            status = 'active'
            AND lease_token IS NOT NULL AND fence_token = lease_token
            AND lease_expires_at > occurred_at
            AND next_attempt_at IS NULL AND failure_code IS NULL
            AND renewal_order_id IS NULL
        ) OR (
            status = 'retry_wait'
            AND lease_token IS NULL AND lease_expires_at IS NULL
            AND next_attempt_at > occurred_at AND failure_code IS NOT NULL
            AND renewal_order_id IS NULL
        ) OR (
            status = 'completed'
            AND lease_token IS NULL AND lease_expires_at IS NULL
            AND next_attempt_at IS NULL AND failure_code IS NULL
            AND renewal_order_id IS NOT NULL
        )
    );
