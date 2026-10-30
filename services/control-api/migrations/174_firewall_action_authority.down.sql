LOCK TABLE schema_migrations,firewall_action_policy_heads,firewall_action_policy_revisions,
    firewall_action_write_receipts,firewall_action_publication_outbox IN ACCESS EXCLUSIVE MODE;

DO $migration_174_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations)<>174 OR
       (SELECT min(version) FROM schema_migrations)<>1 OR
       (SELECT max(version) FROM schema_migrations)<>174 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version=174 AND migration_id='174_firewall_action_authority' AND
              checksum_sha256='d73f059af5beffa4fe3d76b9ff1a360b02a1a40a0a4be0a3cab085f3900d082a' AND
              integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
    ) THEN
        RAISE EXCEPTION 'migration 174 rollback requires the exact verified 174 head'
            USING ERRCODE='P1747';
    END IF;
    IF EXISTS (SELECT 1 FROM firewall_action_policy_heads) OR
       EXISTS (SELECT 1 FROM firewall_action_policy_revisions) OR
       EXISTS (SELECT 1 FROM firewall_action_write_receipts) OR
       EXISTS (SELECT 1 FROM firewall_action_publication_outbox) THEN
        RAISE EXCEPTION 'migration 174 rollback would discard firewall action facts'
            USING ERRCODE='P1748';
    END IF;
END;
$migration_174_down$;

DROP TRIGGER firewall_action_outbox_no_truncate_174 ON firewall_action_publication_outbox;
DROP TRIGGER firewall_action_heads_no_truncate_174 ON firewall_action_policy_heads;
DROP TRIGGER firewall_action_receipts_no_truncate_174 ON firewall_action_write_receipts;
DROP TRIGGER firewall_action_revisions_no_truncate_174 ON firewall_action_policy_revisions;
DROP TRIGGER firewall_action_outbox_guard_174 ON firewall_action_publication_outbox;
DROP TRIGGER firewall_action_head_guard_174 ON firewall_action_policy_heads;
DROP TRIGGER firewall_action_receipts_immutable_174 ON firewall_action_write_receipts;
DROP TRIGGER firewall_action_revisions_immutable_174 ON firewall_action_policy_revisions;

DROP INDEX firewall_action_publication_ready_174_idx;
ALTER TABLE firewall_action_policy_heads
    DROP CONSTRAINT firewall_action_policy_heads_current_revision_174;
DROP TABLE firewall_action_publication_outbox;
DROP TABLE firewall_action_write_receipts;
DROP TABLE firewall_action_policy_revisions;
DROP TABLE firewall_action_policy_heads;

DROP FUNCTION guard_firewall_action_outbox_174();
DROP FUNCTION guard_firewall_action_head_174();
DROP FUNCTION prevent_firewall_action_fact_truncate_174();
DROP FUNCTION prevent_firewall_action_fact_mutation_174();
