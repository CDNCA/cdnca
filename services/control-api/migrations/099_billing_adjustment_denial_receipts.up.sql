LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE;

DO $$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 98 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 98 OR EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE migration_id IS NULL
           OR checksum_sha256 IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$'
           OR down_checksum_sha256 IS NULL OR down_checksum_sha256 !~ '^[0-9a-f]{64}$'
           OR integrity_state IS DISTINCT FROM 'verified'
           OR metadata_recorded_at IS NULL OR applied_at IS NULL
    ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version=98 AND migration_id='098_analytics_ingest_history_authority'
          AND checksum_sha256='7e1ec92c377a0486ec2551334150d99ea58a61a0bc27b18054e8b33b23989102'
          AND down_checksum_sha256='4a475ca2db6eb6aeb8e79883fa3f26345314a3331e5319d5fbbe7140f2e969cc'
          AND integrity_state='verified' AND metadata_recorded_at IS NOT NULL
          AND applied_at IS NOT NULL
    ) THEN
        RAISE EXCEPTION 'migration 099 requires the exact verified 098 release head'
            USING ERRCODE = 'P9900';
    END IF;
END;
$$;

LOCK TABLE memberships, audit_events IN SHARE ROW EXCLUSIVE MODE;

CREATE TABLE billing_adjustment_denial_receipts (
    id uuid PRIMARY KEY CHECK (id<>'00000000-0000-0000-0000-000000000000'::uuid),
    actor_scope_id uuid NOT NULL,
    actor_user_id uuid NOT NULL,
    operation text NOT NULL CHECK (operation='billing.adjustment.create'),
    request_key text NOT NULL CHECK (request_key ~ '^[A-Za-z0-9._-]{1,128}$'),
    request_id text NOT NULL CHECK (request_id ~ '^[A-Za-z0-9._-]{1,128}$'),
    request_digest bytea NOT NULL CHECK (octet_length(request_digest)=32),
    response_code text NOT NULL CHECK (response_code='permission_denied'),
    response_digest bytea NOT NULL CHECK (
        octet_length(response_digest)=32 AND
        response_digest=sha256(convert_to('{"code":"permission_denied"}','UTF8'))
    ),
    created_at timestamptz NOT NULL CHECK (isfinite(created_at)),
    FOREIGN KEY (actor_scope_id, actor_user_id)
        REFERENCES memberships(scope_id, user_id) ON DELETE RESTRICT,
    UNIQUE (actor_scope_id, actor_user_id, operation, request_key),
    UNIQUE (actor_scope_id, actor_user_id, operation, request_id)
);

CREATE UNIQUE INDEX audit_events_billing_adjustment_denied_identity_099
ON audit_events (scope_id, actor_user_id, action, request_id)
WHERE result='denied'
  AND actor_user_id IS NOT NULL
  AND action='billing.adjustment.create';

CREATE FUNCTION prevent_billing_adjustment_denial_receipt_mutation_099()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'billing adjustment denial receipts are immutable'
        USING ERRCODE = 'P9902';
END;
$$;

CREATE TRIGGER billing_adjustment_denial_receipts_immutable_099
BEFORE UPDATE OR DELETE ON billing_adjustment_denial_receipts
FOR EACH ROW EXECUTE FUNCTION prevent_billing_adjustment_denial_receipt_mutation_099();

CREATE TRIGGER billing_adjustment_denial_receipts_no_truncate_099
BEFORE TRUNCATE ON billing_adjustment_denial_receipts
FOR EACH STATEMENT EXECUTE FUNCTION prevent_billing_adjustment_denial_receipt_mutation_099();

REVOKE ALL ON FUNCTION prevent_billing_adjustment_denial_receipt_mutation_099() FROM PUBLIC;
