LOCK TABLE schema_migrations, l4_line_switch_workload_grants, l4_line_switch_drain_plans, l4_node_drain_counters,
    l4_line_target_events, l4_line_target_heads, l4_line_switches IN ACCESS EXCLUSIVE MODE;

DO $migration_139$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 139 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 139 OR EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE migration_id IS NULL OR migration_id = '' OR
              checksum_sha256 IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR
              down_checksum_sha256 IS NULL OR down_checksum_sha256 !~ '^[0-9a-f]{64}$' OR
              integrity_state IS DISTINCT FROM 'verified' OR
              metadata_recorded_at IS NULL OR applied_at IS NULL
    ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version = 139 AND migration_id = '139_l4_line_switches' AND
              checksum_sha256 = '2ad9c5bdb52acc550197197113b581ea36e123826275121f68c48e687cdbc680' AND
              integrity_state = 'verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
    ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version = 138 AND migration_id = '138_challenge_publication_facts' AND
              checksum_sha256 = '14399e504508dbe31dd78711d22ef2c2f4e5a20aad0fc299ee355553e3a3ae9e' AND
              down_checksum_sha256 = '063b1504731a6b630aed43fe46a60247ef9bc86893d4330755209a6720a04218' AND
              integrity_state = 'verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
    ) THEN
        RAISE EXCEPTION 'migration 139 rollback requires the exact verified 139 head'
            USING ERRCODE = 'P1390';
    END IF;
    IF EXISTS (SELECT 1 FROM l4_line_switches) OR
       EXISTS (SELECT 1 FROM l4_line_switch_workload_grants) OR
       EXISTS (SELECT 1 FROM l4_line_target_heads) OR
       EXISTS (SELECT 1 FROM l4_line_target_events) OR
       EXISTS (SELECT 1 FROM l4_node_drain_counters) OR
       EXISTS (SELECT 1 FROM l4_line_switch_drain_plans) THEN
        RAISE EXCEPTION 'migration 139 rollback would discard durable L4 line switch state'
            USING ERRCODE = 'P1396';
    END IF;
END;
$migration_139$;

DROP TRIGGER l4_line_switch_drain_plans_no_truncate_139 ON l4_line_switch_drain_plans;
DROP TRIGGER l4_line_switch_drain_plans_protected_139 ON l4_line_switch_drain_plans;
DROP TRIGGER l4_line_switch_workload_grants_no_truncate_139 ON l4_line_switch_workload_grants;
DROP TRIGGER l4_line_switch_workload_grants_protected_139 ON l4_line_switch_workload_grants;
DROP TRIGGER l4_node_drain_counters_no_truncate_139 ON l4_node_drain_counters;
DROP TRIGGER l4_node_drain_counters_protected_139 ON l4_node_drain_counters;
DROP TRIGGER l4_line_target_events_no_truncate_139 ON l4_line_target_events;
DROP TRIGGER l4_line_target_events_protected_139 ON l4_line_target_events;
DROP TRIGGER l4_line_target_heads_no_truncate_139 ON l4_line_target_heads;
DROP TRIGGER l4_line_target_heads_protected_139 ON l4_line_target_heads;
DROP TRIGGER l4_line_switches_no_truncate_139 ON l4_line_switches;
DROP TRIGGER l4_line_switches_protected_139 ON l4_line_switches;
DROP TABLE l4_line_switch_workload_grants;
DROP TABLE l4_line_switch_drain_plans;
DROP TABLE l4_node_drain_counters;
DROP TABLE l4_line_target_events;
DROP TABLE l4_line_target_heads;
DROP TABLE l4_line_switches;
DROP FUNCTION protect_l4_line_switch_drain_plan_139();
DROP FUNCTION protect_l4_line_switch_workload_grant_139();
DROP FUNCTION protect_l4_node_drain_counter_139();
DROP FUNCTION protect_l4_line_target_event_139();
DROP FUNCTION protect_l4_line_target_head_139();
DROP FUNCTION prevent_l4_line_switch_truncate_139();
DROP FUNCTION protect_l4_line_switch_139();
DROP FUNCTION state_document_identity_139(jsonb,uuid,uuid,text,bigint,timestamptz,timestamptz);
