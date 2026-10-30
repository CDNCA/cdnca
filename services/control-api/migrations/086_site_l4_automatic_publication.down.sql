DO $$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 86 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 86 OR EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$'
           OR down_checksum_sha256 !~ '^[0-9a-f]{64}$'
           OR integrity_state <> 'verified' OR metadata_recorded_at IS NULL OR applied_at IS NULL
    ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version = 86 AND migration_id = '086_site_l4_automatic_publication'
          AND integrity_state = 'verified'
    ) THEN
        RAISE EXCEPTION 'migration 086 rollback requires the verified 086 head'
            USING ERRCODE = 'P8601';
    END IF;
END;
$$;

LOCK TABLE schema_migrations,
    edge_automatic_publication_policy_facts,
    edge_automatic_publication_requests,
    edge_automatic_publication_request_state_facts
IN ACCESS EXCLUSIVE MODE;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM edge_automatic_publication_policy_facts) OR
       EXISTS (
        SELECT 1 FROM edge_automatic_publication_requests
        WHERE actor_scope_kind = 'platform' OR actor_scope_id <> target_scope_id
    ) OR EXISTS (
        SELECT 1
        FROM edge_automatic_publication_requests request_row
        LEFT JOIN LATERAL (
            SELECT sequence,state
            FROM edge_automatic_publication_request_state_facts
            WHERE request_id=request_row.id ORDER BY sequence DESC LIMIT 1
        ) state ON true
        WHERE state.sequence IS NULL OR state.state IN ('pending', 'leased', 'retry_wait', 'reconciling')
    ) OR EXISTS (
        SELECT 1 FROM edge_automatic_publication_request_state_facts WHERE sequence > 1
    ) OR EXISTS (
        SELECT request_id
        FROM edge_automatic_publication_request_state_facts
        GROUP BY request_id
        HAVING min(sequence) <> 1 OR max(sequence) <> count(*)
    ) THEN
        RAISE EXCEPTION 'migration 086 rollback would discard automatic publication policy, actor, worker, or nonterminal facts'
            USING ERRCODE = 'P8601';
    END IF;
END;
$$;

DROP TRIGGER edge_automatic_publication_state_validate_086 ON edge_automatic_publication_request_state_facts;
DROP FUNCTION validate_edge_automatic_publication_state_086();
DROP TRIGGER edge_automatic_publication_request_validate_086 ON edge_automatic_publication_requests;
DROP FUNCTION validate_edge_automatic_publication_request_086();
DROP TRIGGER edge_automatic_publication_policy_validate_086 ON edge_automatic_publication_policy_facts;
DROP FUNCTION validate_edge_automatic_publication_policy_086();

DROP TRIGGER edge_automatic_publication_states_no_truncate_086 ON edge_automatic_publication_request_state_facts;
DROP TRIGGER edge_automatic_publication_states_immutable_086 ON edge_automatic_publication_request_state_facts;
DROP TRIGGER edge_automatic_publication_requests_no_truncate_086 ON edge_automatic_publication_requests;
DROP TRIGGER edge_automatic_publication_requests_immutable_086 ON edge_automatic_publication_requests;
DROP TRIGGER edge_automatic_publication_policy_facts_no_truncate_086 ON edge_automatic_publication_policy_facts;
DROP TRIGGER edge_automatic_publication_policy_facts_immutable_086 ON edge_automatic_publication_policy_facts;
DROP FUNCTION prevent_edge_automatic_publication_fact_mutation_086();

DROP TABLE edge_automatic_publication_request_state_facts;
DROP TABLE edge_automatic_publication_requests;
DROP TABLE edge_automatic_publication_policy_facts;
