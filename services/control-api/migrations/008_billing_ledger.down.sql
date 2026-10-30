DROP TABLE billing_write_requests;
DROP TRIGGER billing_posting_accounts_reconciled ON billing_postings;
DROP TRIGGER billing_accounts_reconciled ON billing_accounts;
DROP FUNCTION assert_billing_account_reconciled();
DROP TRIGGER billing_postings_balanced ON billing_postings;
DROP TRIGGER billing_transactions_balanced ON billing_transactions;
DROP FUNCTION assert_billing_transaction_balanced();
DROP TRIGGER billing_postings_append_only ON billing_postings;
DROP TRIGGER billing_transactions_append_only ON billing_transactions;
DROP FUNCTION prevent_billing_ledger_mutation();
DROP TABLE billing_postings;
DROP TABLE billing_transactions;
DROP TRIGGER billing_accounts_scope_kind ON billing_accounts;
DROP FUNCTION assert_billing_account_scope();
DROP TABLE billing_accounts;

DELETE FROM role_permissions
WHERE permission_name IN ('billing.account.read', 'billing.adjustments.manage');
DELETE FROM permissions
WHERE name IN ('billing.account.read', 'billing.adjustments.manage');
