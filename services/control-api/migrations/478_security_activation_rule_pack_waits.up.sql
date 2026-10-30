LOCK TABLE schema_migrations, security_activation_capability_waits IN ACCESS EXCLUSIVE MODE;

DO $migration_478_up$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 477 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 477 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=477 AND
        migration_id='477_node_deployment_status_refusals' AND
        checksum_sha256='445b7595d367691174f01a1fb193144526222565cbe8caf953034f8415ac095a' AND
        down_checksum_sha256='58ee2b8ca38547f22daeb290cde5dbce20586e35d93a391fa18969d9dd0d77b0' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) OR EXISTS (
        SELECT 1 FROM schema_migrations WHERE integrity_state IS DISTINCT FROM 'verified' OR
        migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
        down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR metadata_recorded_at IS NULL OR applied_at IS NULL
       ) OR to_regclass(current_schema() || '.security_activation_capability_waits') IS NULL OR EXISTS (
        SELECT 1 FROM pg_attribute WHERE attrelid='security_activation_capability_waits'::regclass AND
        attname='wait_kind' AND NOT attisdropped
       ) THEN
        RAISE EXCEPTION 'migration 478 requires the exact verified 477 release head' USING ERRCODE='P4780';
    END IF;
END;
$migration_478_up$;

-- r136 sa-rulepack-wait: a security activation refused because a target
-- node has not applied a rule pack the site uses (rule_pack_unavailable)
-- waits like one refused for node capability (306): the activation worker
-- starts it again once every target node's applied node artifact set holds
-- the packs (node_artifact_applied_items, written from the node's receipt).
-- Same one-waiting-row-per-site-and-kind index, same supersede rules.
ALTER TABLE security_activation_capability_waits
    ADD COLUMN wait_kind text NOT NULL DEFAULT 'capability' CHECK (wait_kind IN ('capability', 'rule_pack')),
    ADD COLUMN rule_pack_sha256 text[],
    ALTER COLUMN capability DROP NOT NULL,
    ALTER COLUMN required_api_version DROP NOT NULL,
    ADD CONSTRAINT security_activation_capability_waits_kind_478_check CHECK (
        (wait_kind = 'capability' AND capability IS NOT NULL AND required_api_version IS NOT NULL AND
            rule_pack_sha256 IS NULL) OR
        (wait_kind = 'rule_pack' AND capability IS NULL AND required_api_version IS NULL AND
            cardinality(rule_pack_sha256) BETWEEN 1 AND 64 AND
            array_to_string(rule_pack_sha256, ',') ~ '^[0-9a-f]{64}(,[0-9a-f]{64})*$')
    );
