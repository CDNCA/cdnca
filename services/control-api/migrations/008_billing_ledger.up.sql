INSERT INTO permissions (name, description) VALUES
    ('billing.account.read', 'Read the active tenant billing balance and ledger'),
    ('billing.adjustments.manage', 'Create audited manual tenant balance adjustments');

INSERT INTO role_permissions (role_id, permission_name)
SELECT roles.id, 'billing.account.read'
FROM roles
WHERE roles.system_role AND roles.name IN ('tenant_owner', 'tenant_viewer')
ON CONFLICT DO NOTHING;

CREATE TABLE billing_accounts (
    id uuid PRIMARY KEY,
    scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE RESTRICT,
    kind text NOT NULL CHECK (kind IN ('tenant_liability', 'platform_clearing')),
    currency text NOT NULL DEFAULT 'CNY' CHECK (currency = 'CNY'),
    balance_minor bigint NOT NULL DEFAULT 0,
    revision bigint NOT NULL DEFAULT 1 CHECK (revision > 0),
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    UNIQUE (scope_id, kind),
    CHECK (kind <> 'tenant_liability' OR (balance_minor >= 0 AND id = scope_id))
);

CREATE INDEX billing_accounts_scope_idx ON billing_accounts (scope_id);

CREATE FUNCTION assert_billing_account_scope()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    actual_scope_kind text;
BEGIN
    SELECT kind INTO actual_scope_kind FROM access_scopes WHERE id = NEW.scope_id;
    IF actual_scope_kind IS NULL
       OR (NEW.kind = 'tenant_liability' AND actual_scope_kind <> 'tenant')
       OR (NEW.kind = 'platform_clearing' AND actual_scope_kind <> 'platform') THEN
        RAISE EXCEPTION 'billing account kind % is invalid for scope kind %', NEW.kind, actual_scope_kind;
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER billing_accounts_scope_kind
BEFORE INSERT OR UPDATE ON billing_accounts
FOR EACH ROW EXECUTE FUNCTION assert_billing_account_scope();

CREATE TABLE billing_transactions (
    id uuid PRIMARY KEY,
    target_scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE RESTRICT,
    operation text NOT NULL CHECK (operation = 'manual_adjustment'),
    direction text NOT NULL CHECK (direction IN ('credit', 'debit')),
    amount_minor bigint NOT NULL CHECK (amount_minor > 0),
    currency text NOT NULL DEFAULT 'CNY' CHECK (currency = 'CNY'),
    reason text NOT NULL CHECK (reason = btrim(reason) AND char_length(reason) BETWEEN 1 AND 500),
    created_by_user_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    created_at timestamptz NOT NULL
);

CREATE INDEX billing_transactions_scope_created_idx
    ON billing_transactions (target_scope_id, created_at DESC, id DESC);

CREATE TABLE billing_postings (
    id uuid PRIMARY KEY,
    transaction_id uuid NOT NULL REFERENCES billing_transactions(id) ON DELETE RESTRICT,
    account_id uuid NOT NULL REFERENCES billing_accounts(id) ON DELETE RESTRICT,
    side text NOT NULL CHECK (side IN ('debit', 'credit')),
    amount_minor bigint NOT NULL CHECK (amount_minor > 0),
    balance_after_minor bigint NOT NULL,
    created_at timestamptz NOT NULL,
    UNIQUE (transaction_id, account_id)
);

CREATE INDEX billing_postings_account_created_idx
    ON billing_postings (account_id, created_at DESC, transaction_id DESC);

CREATE FUNCTION prevent_billing_ledger_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION '% is append-only', TG_TABLE_NAME;
END;
$$;

CREATE TRIGGER billing_transactions_append_only
BEFORE UPDATE OR DELETE ON billing_transactions
FOR EACH ROW EXECUTE FUNCTION prevent_billing_ledger_mutation();

CREATE TRIGGER billing_postings_append_only
BEFORE UPDATE OR DELETE ON billing_postings
FOR EACH ROW EXECUTE FUNCTION prevent_billing_ledger_mutation();

CREATE FUNCTION assert_billing_transaction_balanced()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    target_transaction_id uuid;
    transaction_amount bigint;
    transaction_direction text;
    posting_count bigint;
    debit_total numeric;
    credit_total numeric;
    tenant_side_count bigint;
    clearing_side_count bigint;
BEGIN
    IF TG_TABLE_NAME = 'billing_transactions' THEN
        target_transaction_id := NEW.id;
    ELSE
        target_transaction_id := NEW.transaction_id;
    END IF;

    SELECT transaction.amount_minor,
           transaction.direction,
           count(posting.id),
           COALESCE(sum(posting.amount_minor) FILTER (WHERE posting.side = 'debit'), 0),
           COALESCE(sum(posting.amount_minor) FILTER (WHERE posting.side = 'credit'), 0),
           count(posting.id) FILTER (
               WHERE account.kind = 'tenant_liability'
                 AND account.scope_id = transaction.target_scope_id
                 AND posting.side = CASE transaction.direction WHEN 'credit' THEN 'credit' ELSE 'debit' END
           ),
           count(posting.id) FILTER (
               WHERE account.kind = 'platform_clearing'
                 AND posting.side = CASE transaction.direction WHEN 'credit' THEN 'debit' ELSE 'credit' END
           )
    INTO transaction_amount, transaction_direction, posting_count, debit_total, credit_total,
         tenant_side_count, clearing_side_count
    FROM billing_transactions transaction
    LEFT JOIN billing_postings posting ON posting.transaction_id = transaction.id
    LEFT JOIN billing_accounts account ON account.id = posting.account_id
    WHERE transaction.id = target_transaction_id
    GROUP BY transaction.id;

    IF transaction_amount IS NULL THEN
        RETURN NULL;
    END IF;
    IF posting_count <> 2
       OR debit_total <> transaction_amount
       OR credit_total <> transaction_amount
       OR tenant_side_count <> 1
       OR clearing_side_count <> 1 THEN
        RAISE EXCEPTION 'billing transaction % is not a balanced two-entry adjustment', target_transaction_id;
    END IF;
    RETURN NULL;
END;
$$;

CREATE CONSTRAINT TRIGGER billing_transactions_balanced
AFTER INSERT ON billing_transactions
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION assert_billing_transaction_balanced();

CREATE CONSTRAINT TRIGGER billing_postings_balanced
AFTER INSERT ON billing_postings
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION assert_billing_transaction_balanced();

CREATE FUNCTION assert_billing_account_reconciled()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    target_account_id uuid;
    cached_balance bigint;
    cached_revision bigint;
    posting_balance numeric;
    posting_count bigint;
BEGIN
    IF TG_TABLE_NAME = 'billing_accounts' THEN
        target_account_id := NEW.id;
    ELSE
        target_account_id := NEW.account_id;
    END IF;

    SELECT account.balance_minor,
           account.revision,
           COALESCE(sum(CASE posting.side WHEN 'credit' THEN posting.amount_minor ELSE -posting.amount_minor END), 0),
           count(posting.id)
    INTO cached_balance, cached_revision, posting_balance, posting_count
    FROM billing_accounts account
    LEFT JOIN billing_postings posting ON posting.account_id = account.id
    WHERE account.id = target_account_id
    GROUP BY account.id;

    IF cached_balance IS NULL THEN
        RETURN NULL;
    END IF;
    IF cached_balance <> posting_balance OR cached_revision <> posting_count + 1 THEN
        RAISE EXCEPTION 'billing account % cache does not match immutable postings', target_account_id;
    END IF;
    RETURN NULL;
END;
$$;

CREATE CONSTRAINT TRIGGER billing_accounts_reconciled
AFTER INSERT OR UPDATE ON billing_accounts
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION assert_billing_account_reconciled();

CREATE CONSTRAINT TRIGGER billing_posting_accounts_reconciled
AFTER INSERT ON billing_postings
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION assert_billing_account_reconciled();

CREATE TABLE billing_write_requests (
    id uuid PRIMARY KEY,
    actor_user_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    actor_scope_id uuid NOT NULL REFERENCES access_scopes(id) ON DELETE RESTRICT,
    operation text NOT NULL CHECK (operation = 'billing.adjustment.create'),
    idempotency_key text NOT NULL CHECK (char_length(idempotency_key) BETWEEN 1 AND 128),
    request_digest bytea NOT NULL CHECK (octet_length(request_digest) = 32),
    target_account_id uuid NOT NULL REFERENCES billing_accounts(id) ON DELETE RESTRICT,
    transaction_id uuid REFERENCES billing_transactions(id) ON DELETE RESTRICT,
    response_status integer CHECK (response_status BETWEEN 200 AND 299),
    response_body jsonb CHECK (response_body IS NULL OR jsonb_typeof(response_body) = 'object'),
    created_at timestamptz NOT NULL,
    completed_at timestamptz,
    UNIQUE (actor_user_id, operation, idempotency_key),
    CHECK (
        (completed_at IS NULL AND transaction_id IS NULL AND response_status IS NULL AND response_body IS NULL) OR
        (completed_at IS NOT NULL AND transaction_id IS NOT NULL AND response_status IS NOT NULL AND response_body IS NOT NULL)
    )
);

CREATE INDEX billing_write_requests_scope_created_idx
    ON billing_write_requests (actor_scope_id, created_at DESC);
