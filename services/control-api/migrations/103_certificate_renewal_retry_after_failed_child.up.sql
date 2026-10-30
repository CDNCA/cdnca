LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;

DO $$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 102 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 102 OR EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE migration_id IS NULL
           OR checksum_sha256 IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$'
           OR down_checksum_sha256 IS NULL OR down_checksum_sha256 !~ '^[0-9a-f]{64}$'
           OR integrity_state IS DISTINCT FROM 'verified'
           OR metadata_recorded_at IS NULL OR applied_at IS NULL
    ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version=102 AND migration_id='102_upgrade_status_puback_identity'
          AND checksum_sha256='1350b63f8f7ae54dccee84aeaee13b1923704c6fab61e8c2d1ddf91e79b79700'
          AND down_checksum_sha256='5a1f9908c9a56a94ab9ea1f603477022aab59267e206224d9b1ebb94e6e56ddd'
          AND integrity_state='verified' AND metadata_recorded_at IS NOT NULL
          AND applied_at IS NOT NULL
    ) THEN
        RAISE EXCEPTION 'migration 103 requires the exact verified 102 release head'
            USING ERRCODE='P1030';
    END IF;
END;
$$;

LOCK TABLE acme_renewal_claim_facts IN ACCESS EXCLUSIVE MODE;

ALTER TABLE acme_renewal_claim_facts
    ADD COLUMN reopened_from_order_id uuid,
    ADD CONSTRAINT acme_renewal_claim_reopened_source_fk_103
        FOREIGN KEY (tenant_scope_id, reopened_from_order_id)
        REFERENCES certificate_orders(scope_id, id) ON DELETE RESTRICT;

ALTER TABLE acme_renewal_claim_facts
    DROP CONSTRAINT acme_renewal_claim_facts_event_type_check,
    DROP CONSTRAINT acme_renewal_claim_facts_check;

ALTER TABLE acme_renewal_claim_facts
    ADD CONSTRAINT acme_renewal_claim_facts_event_type_check CHECK (event_type IN (
        'claim_created', 'lease_taken_over', 'retry_scheduled', 'claim_reopened', 'completed'
    )),
    ADD CONSTRAINT acme_renewal_claim_facts_check CHECK (
        (
            status = 'active'
            AND lease_token IS NOT NULL AND fence_token = lease_token
            AND lease_expires_at > occurred_at
            AND next_attempt_at IS NULL AND failure_code IS NULL
            AND renewal_order_id IS NULL
            AND (
                (event_type IN ('claim_created', 'lease_taken_over') AND reopened_from_order_id IS NULL)
                OR (event_type = 'claim_reopened' AND reopened_from_order_id IS NOT NULL)
            )
        ) OR (
            status = 'retry_wait'
            AND event_type = 'retry_scheduled'
            AND lease_token IS NULL AND lease_expires_at IS NULL
            AND next_attempt_at > occurred_at AND failure_code IS NOT NULL
            AND renewal_order_id IS NULL AND reopened_from_order_id IS NULL
        ) OR (
            status = 'completed'
            AND event_type = 'completed'
            AND lease_token IS NULL AND lease_expires_at IS NULL
            AND next_attempt_at IS NULL AND failure_code IS NULL
            AND renewal_order_id IS NOT NULL AND reopened_from_order_id IS NULL
        )
    );

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
    IF NOT FOUND OR NEW.occurred_at < previous.occurred_at THEN
        RAISE EXCEPTION 'ACME renewal claim revision is not contiguous'
            USING ERRCODE = 'P0001';
    END IF;

    IF previous.status = 'completed' THEN
        IF NEW.event_type <> 'claim_reopened' OR NEW.status <> 'active'
           OR NEW.fence_token IS DISTINCT FROM NEW.lease_token
           OR NEW.lease_expires_at <= database_now
           OR NEW.reopened_from_order_id IS NULL THEN
            RAISE EXCEPTION 'invalid ACME renewal claim reopen' USING ERRCODE = 'P0001';
        END IF;
        SELECT * INTO renewal_order
        FROM certificate_orders
        WHERE scope_id = NEW.tenant_scope_id AND id = NEW.reopened_from_order_id;
        IF renewal_order.id IS NULL
           OR renewal_order.status IS DISTINCT FROM 'failed'
           OR renewal_order.renewal_of_order_id IS DISTINCT FROM NEW.source_order_id
           OR renewal_order.created_by_user_id IS DISTINCT FROM NEW.actor_user_id
           OR previous.renewal_order_id IS DISTINCT FROM NEW.reopened_from_order_id THEN
            RAISE EXCEPTION 'claim_reopened event must bind the exact failed child'
                USING ERRCODE = 'P0001';
        END IF;
        RETURN NEW;
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
        RAISE EXCEPTION 'ACME renewal claim lease fence rejected the event'
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

REVOKE ALL ON FUNCTION validate_acme_renewal_claim_fact_048() FROM PUBLIC;
