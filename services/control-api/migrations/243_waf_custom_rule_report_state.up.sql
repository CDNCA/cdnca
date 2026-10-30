CREATE TABLE waf_custom_rule_report_state (
    installation_id uuid PRIMARY KEY,
    sequence bigint NOT NULL CHECK (sequence > 0),
    request_id text NOT NULL,
    observed_at timestamptz NOT NULL,
    policies jsonb NOT NULL,
    policies_digest bytea NOT NULL CHECK (octet_length(policies_digest) = 32),
    sent_at timestamptz,
    updated_at timestamptz NOT NULL
);

CREATE INDEX waf_custom_rule_report_state_pending_idx
    ON waf_custom_rule_report_state (sent_at, updated_at)
    WHERE sent_at IS NULL;
