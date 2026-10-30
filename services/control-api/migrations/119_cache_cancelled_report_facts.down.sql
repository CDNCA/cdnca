LOCK TABLE schema_migrations,
    cache_operations,
    cache_operation_commands,
    cache_operation_node_targets,
    cache_operation_node_attempts,
    cache_operation_target_results,
    audit_events
IN ACCESS EXCLUSIVE MODE;

DO $$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 119 OR
       (SELECT min(version) FROM schema_migrations) <> 1 OR
       (SELECT max(version) FROM schema_migrations) <> 119 OR EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE migration_id IS NULL OR checksum_sha256 IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$'
           OR down_checksum_sha256 IS NULL OR down_checksum_sha256 !~ '^[0-9a-f]{64}$'
           OR integrity_state IS DISTINCT FROM 'verified' OR metadata_recorded_at IS NULL OR applied_at IS NULL
    ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version=119 AND migration_id='119_cache_cancelled_report_facts'
          AND checksum_sha256='2a7e7b88433941e3e9eae3567476d261efb5382d9a1dca4900e852a2dcd6b318'
          AND integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
    ) OR NOT EXISTS (
        SELECT 1 FROM schema_migrations
        WHERE version=118 AND migration_id='118_certificate_publication_claims'
          AND checksum_sha256='7190a136a8c7685eb20538f86c67541a183d5631b9924d16aeb2cba511a72499'
          AND down_checksum_sha256='a9535f404e8f4630bb1c0c02fca4c3ace0612021ca023603fe6ac9af76be5f1a'
          AND integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
    ) THEN
        RAISE EXCEPTION 'migration 119 rollback requires the exact verified 119 head'
            USING ERRCODE='P1190';
    END IF;
    IF EXISTS (
        SELECT 1 FROM cache_operation_target_results
        WHERE source='report' AND state='cancelled'
    ) OR EXISTS (
        SELECT 1 FROM cache_operation_node_attempts
        WHERE state='cancelled' AND report_sequence>0
    ) THEN
        RAISE EXCEPTION 'migration 119 rollback would discard agent-reported cache cancellation facts'
            USING ERRCODE='P1192';
    END IF;
END;
$$;

ALTER TABLE cache_operation_node_attempts
    DROP CONSTRAINT cache_operation_node_attempts_report_state_check,
    ADD CONSTRAINT cache_operation_node_attempts_check1 CHECK (
        (state='running' AND report_sequence=0 AND report_digest IS NULL AND
         error_code IS NULL AND completed_at IS NULL) OR
        (state IN ('succeeded','partial_failed','failed') AND report_sequence>0 AND
         report_digest IS NOT NULL AND completed_at IS NOT NULL) OR
        (state IN ('cancelled','lease_expired') AND report_sequence=0 AND
         report_digest IS NULL AND error_code IS NOT NULL AND completed_at IS NOT NULL)
    );

ALTER TABLE cache_operation_target_results
    DROP CONSTRAINT cache_operation_target_results_source_state_check,
    ADD CONSTRAINT cache_operation_target_results_check CHECK (
        (source='report' AND attempt IS NOT NULL AND state IN ('succeeded','failed') AND
         sequence>0 AND report_digest IS NOT NULL AND command_id IS NULL AND
         ((state='succeeded' AND error_code IS NULL) OR
          (state='failed' AND error_code IS NOT NULL))) OR
        (source='lease_expire' AND attempt IS NOT NULL AND state='failed' AND
         sequence=0 AND report_digest IS NULL AND command_id IS NULL AND
         error_code='retries_exhausted') OR
        (source='cancel' AND state='cancelled' AND sequence=0 AND
         report_digest IS NULL AND command_id IS NOT NULL AND error_code='cancelled')
);

CREATE OR REPLACE FUNCTION validate_cache_operation_integrity()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    checked_operation_id uuid;
    operation_row cache_operations%ROWTYPE;
    actual_targets integer;
    actual_nodes integer;
    actual_items integer;
    actual_completed integer;
    actual_succeeded integer;
    actual_failed integer;
    actual_cancelled integer;
BEGIN
    IF TG_TABLE_NAME = 'audit_events' THEN
        IF NEW.action NOT LIKE 'cache.operation.%' THEN
            RETURN NULL;
        END IF;
        BEGIN
            checked_operation_id := NEW.resource_id::uuid;
        EXCEPTION WHEN invalid_text_representation THEN
            RAISE EXCEPTION 'cache operation integrity violation: invalid audit resource';
        END;
    ELSIF TG_TABLE_NAME = 'cache_operations' THEN
        checked_operation_id := COALESCE(NEW.id, OLD.id);
    ELSE
        checked_operation_id := COALESCE(NEW.operation_id, OLD.operation_id);
    END IF;

    SELECT * INTO operation_row FROM cache_operations WHERE id = checked_operation_id;
    IF NOT FOUND THEN
        RETURN NULL;
    END IF;

    SELECT count(*)::integer INTO actual_targets
    FROM cache_operation_targets WHERE operation_id = operation_row.id;
    SELECT count(*)::integer INTO actual_nodes
    FROM cache_operation_nodes WHERE operation_id = operation_row.id;
    SELECT count(*)::integer,
           count(*) FILTER (WHERE state IN ('succeeded', 'failed', 'cancelled'))::integer,
           count(*) FILTER (WHERE state = 'succeeded')::integer,
           count(*) FILTER (WHERE state = 'failed')::integer,
           count(*) FILTER (WHERE state = 'cancelled')::integer
    INTO actual_items, actual_completed, actual_succeeded, actual_failed, actual_cancelled
    FROM cache_operation_node_targets WHERE operation_id = operation_row.id;
    IF actual_targets <> operation_row.target_count OR actual_nodes <> operation_row.node_count OR
       actual_items <> operation_row.total_count OR
       ROW(actual_completed, actual_succeeded, actual_failed, actual_cancelled) IS DISTINCT FROM
       ROW(operation_row.completed_count, operation_row.succeeded_count,
           operation_row.failed_count, operation_row.cancelled_count) THEN
        RAISE EXCEPTION 'cache operation integrity violation: operation aggregate mismatch';
    END IF;
    IF 1 <> (
        SELECT count(*) FROM audit_events event
        WHERE event.scope_id = operation_row.scope_id
          AND event.action = 'cache.operation.create'
          AND event.resource_type = 'cache_operation'
          AND event.resource_id = operation_row.id::text AND event.result = 'success'
    ) THEN
        RAISE EXCEPTION 'cache operation integrity violation: creation audit missing or ambiguous';
    END IF;

    IF EXISTS (
        SELECT 1 FROM cache_operation_target_results result
        LEFT JOIN cache_operation_node_attempts attempt
          ON attempt.scope_id = result.scope_id AND attempt.operation_id = result.operation_id
         AND attempt.node_id = result.node_id AND attempt.attempt = result.attempt
        LEFT JOIN cache_operation_commands command ON command.id = result.command_id
        LEFT JOIN audit_events event ON event.id = result.audit_event_id
        WHERE result.operation_id = operation_row.id AND (
            event.id IS NULL OR event.scope_id <> result.scope_id OR
            event.resource_type <> 'cache_operation' OR event.resource_id <> result.operation_id::text OR
            event.result <> 'success' OR
            (result.source <> 'cancel' AND event.payload->>'node_id' <> result.node_id::text) OR
            event.action <> CASE result.source
                WHEN 'report' THEN 'cache.operation.report'
                WHEN 'lease_expire' THEN 'cache.operation.lease_expire'
                ELSE 'cache.operation.cancel'
            END OR
            (result.source <> 'cancel' AND event.payload->>'attempt' <> result.attempt::text) OR
            (result.source = 'report' AND (
                attempt.state NOT IN ('succeeded', 'partial_failed', 'failed') OR
                attempt.report_sequence <> result.sequence OR
                attempt.report_digest IS DISTINCT FROM result.report_digest OR
                event.payload->>'sequence' <> result.sequence::text
            )) OR
            (result.source = 'lease_expire' AND attempt.state <> 'lease_expired') OR
            (result.source = 'cancel' AND (
                command.id IS NULL OR command.scope_id <> result.scope_id OR
                command.operation_id <> result.operation_id OR command.command <> 'cancel' OR
                command.completed_at IS NULL OR event.actor_user_id IS DISTINCT FROM command.actor_user_id OR
                event.payload->>'command_id' <> command.id::text
            ))
        )
    ) THEN
        RAISE EXCEPTION 'cache operation integrity violation: invalid result support fact';
    END IF;

    IF EXISTS (
        SELECT 1 FROM cache_operation_node_attempts attempt
        WHERE attempt.operation_id = operation_row.id AND 1 <> (
            SELECT count(*) FROM audit_events event
            WHERE event.scope_id = attempt.scope_id
              AND event.action = 'cache.operation.claim'
              AND event.resource_type = 'cache_operation'
              AND event.resource_id = attempt.operation_id::text AND event.result = 'success'
              AND event.payload->>'node_id' = attempt.node_id::text
              AND event.payload->>'attempt' = attempt.attempt::text
              AND event.payload->>'lease_id' = attempt.lease_id::text
              AND event.payload->>'target_count' = attempt.target_count::text
        )
    ) THEN
        RAISE EXCEPTION 'cache operation integrity violation: attempt claim audit missing or ambiguous';
    END IF;

    IF EXISTS (
        SELECT 1 FROM cache_operation_node_attempts attempt
        LEFT JOIN LATERAL (
            SELECT count(*)::integer AS result_count,
                   count(*) FILTER (WHERE result.state = 'succeeded')::integer AS succeeded_count,
                   count(*) FILTER (WHERE result.state = 'failed')::integer AS failed_count,
                   count(*) FILTER (WHERE result.state = 'cancelled')::integer AS cancelled_count,
                   count(DISTINCT result.audit_event_id)::integer AS audit_count,
                   count(DISTINCT result.command_id)::integer AS command_count
            FROM cache_operation_target_results result
            WHERE result.operation_id = attempt.operation_id AND result.node_id = attempt.node_id
              AND result.attempt = attempt.attempt
              AND result.source = CASE
                  WHEN attempt.state IN ('succeeded', 'partial_failed', 'failed') THEN 'report'
                  WHEN attempt.state = 'lease_expired' THEN 'lease_expire'
                  WHEN attempt.state = 'cancelled' THEN 'cancel'
                  ELSE 'report'
              END
        ) result_stats ON true
        WHERE attempt.operation_id = operation_row.id AND attempt.state <> 'running' AND (
            (attempt.state = 'succeeded' AND
             (result_stats.result_count <> attempt.target_count OR
              result_stats.succeeded_count <> attempt.target_count OR result_stats.audit_count <> 1)) OR
            (attempt.state = 'failed' AND
             (result_stats.result_count <> attempt.target_count OR
              result_stats.failed_count <> attempt.target_count OR result_stats.audit_count <> 1)) OR
            (attempt.state = 'partial_failed' AND
             (result_stats.result_count <> attempt.target_count OR
              result_stats.succeeded_count = 0 OR result_stats.failed_count = 0 OR
              result_stats.succeeded_count + result_stats.failed_count <> attempt.target_count OR
              result_stats.audit_count <> 1)) OR
            (attempt.state = 'cancelled' AND
             (result_stats.result_count <> attempt.target_count OR
              result_stats.cancelled_count <> attempt.target_count OR
              result_stats.audit_count <> 1 OR result_stats.command_count <> 1)) OR
            (attempt.state = 'lease_expired' AND (
                1 <> (
                    SELECT count(*) FROM audit_events event
                    WHERE event.scope_id = attempt.scope_id
                      AND event.action = 'cache.operation.lease_expire'
                      AND event.resource_type = 'cache_operation'
                      AND event.resource_id = attempt.operation_id::text AND event.result = 'success'
                      AND event.payload->>'node_id' = attempt.node_id::text
                      AND event.payload->>'attempt' = attempt.attempt::text
                ) OR
                (attempt.attempt < operation_row.max_attempts AND result_stats.result_count <> 0) OR
                (attempt.attempt = operation_row.max_attempts AND
                 (result_stats.result_count <> attempt.target_count OR
                  result_stats.failed_count <> attempt.target_count OR result_stats.audit_count <> 1))
            )))
    ) THEN
        RAISE EXCEPTION 'cache operation integrity violation: attempt result mismatch';
    END IF;

    IF EXISTS (
        SELECT 1 FROM cache_operation_nodes node
        LEFT JOIN LATERAL (
            SELECT count(*)::integer AS total_count,
                   count(*) FILTER (WHERE projection.state IN ('succeeded','failed','cancelled'))::integer AS completed_count,
                   count(*) FILTER (WHERE projection.state = 'succeeded')::integer AS succeeded_count,
                   count(*) FILTER (WHERE projection.state = 'failed')::integer AS failed_count,
                   count(*) FILTER (WHERE projection.state = 'cancelled')::integer AS cancelled_count,
                   count(*) FILTER (WHERE projection.state = 'running')::integer AS running_count,
                   count(*) FILTER (
                       WHERE projection.state = 'running' AND projection.attempt = node.attempt
                   )::integer AS current_running_count,
                   count(*) FILTER (WHERE projection.state = 'queued')::integer AS queued_count
            FROM cache_operation_node_targets projection
            WHERE projection.operation_id = node.operation_id AND projection.node_id = node.node_id
        ) projection_stats ON true
        LEFT JOIN LATERAL (
            SELECT count(*)::integer AS attempt_count,
                   COALESCE(max(attempt.attempt), 0)::integer AS maximum_attempt,
                   count(*) FILTER (WHERE attempt.state = 'running')::integer AS running_count
            FROM cache_operation_node_attempts attempt
            WHERE attempt.operation_id = node.operation_id AND attempt.node_id = node.node_id
        ) attempt_stats ON true
        LEFT JOIN cache_operation_node_attempts running_attempt
          ON running_attempt.operation_id = node.operation_id
         AND running_attempt.node_id = node.node_id
         AND running_attempt.attempt = node.attempt AND running_attempt.state = 'running'
        WHERE node.operation_id = operation_row.id AND (
            ROW(node.total_count, node.completed_count, node.succeeded_count,
                node.failed_count, node.cancelled_count) IS DISTINCT FROM
            ROW(projection_stats.total_count, projection_stats.completed_count,
                projection_stats.succeeded_count, projection_stats.failed_count,
                projection_stats.cancelled_count) OR
            node.attempt <> attempt_stats.attempt_count OR
            node.attempt <> attempt_stats.maximum_attempt OR
            (node.state = 'running' AND
             (attempt_stats.running_count <> 1 OR projection_stats.running_count = 0 OR
              projection_stats.running_count <> projection_stats.current_running_count OR
              running_attempt.target_count IS DISTINCT FROM projection_stats.current_running_count OR
              running_attempt.lease_id IS DISTINCT FROM node.lease_id OR
              running_attempt.worker_id IS DISTINCT FROM node.lease_owner OR
              running_attempt.lease_expires_at IS DISTINCT FROM node.lease_expires_at)) OR
            (node.state <> 'running' AND attempt_stats.running_count <> 0) OR
            (node.state = 'queued' AND projection_stats.queued_count = 0) OR
            (node.state IN ('succeeded','partial_failed','failed','cancelled') AND
             projection_stats.completed_count <> projection_stats.total_count) OR
            (node.state = 'succeeded' AND projection_stats.succeeded_count <> projection_stats.total_count) OR
            (node.state = 'failed' AND projection_stats.failed_count <> projection_stats.total_count) OR
            (node.state = 'partial_failed' AND
             (projection_stats.failed_count = 0 OR
              projection_stats.failed_count = projection_stats.total_count OR
              projection_stats.cancelled_count <> 0)) OR
            (node.state = 'cancelled' AND projection_stats.cancelled_count = 0)
        )
    ) THEN
        RAISE EXCEPTION 'cache operation integrity violation: node aggregate mismatch';
    END IF;

    IF EXISTS (
        SELECT 1 FROM cache_operation_node_targets projection
        WHERE projection.operation_id = operation_row.id
          AND projection.state IN ('succeeded','failed','cancelled')
          AND NOT EXISTS (
              SELECT 1 FROM cache_operation_target_results result
              WHERE result.operation_id = projection.operation_id
                AND result.node_id = projection.node_id
                AND result.target_ordinal = projection.target_ordinal
                AND COALESCE(result.attempt, 0) = projection.attempt
                AND result.state = projection.state AND result.sequence = projection.sequence
                AND result.error_code IS NOT DISTINCT FROM projection.error_code
          )
    ) THEN
        RAISE EXCEPTION 'cache operation integrity violation: terminal projection has no result fact';
    END IF;

    IF operation_row.state IN ('succeeded','partial_failed','failed','cancelled') AND
       actual_completed <> actual_items THEN
        RAISE EXCEPTION 'cache operation integrity violation: terminal operation is incomplete';
    END IF;
    IF operation_row.state IN ('queued','running') AND actual_completed = actual_items THEN
        RAISE EXCEPTION 'cache operation integrity violation: completed projections require a terminal operation';
    END IF;
    IF operation_row.state = 'succeeded' AND
       (actual_succeeded <> actual_items OR actual_failed <> 0 OR actual_cancelled <> 0) THEN
        RAISE EXCEPTION 'cache operation integrity violation: succeeded aggregate mismatch';
    END IF;
    IF operation_row.state = 'failed' AND actual_failed <> actual_items THEN
        RAISE EXCEPTION 'cache operation integrity violation: failed aggregate mismatch';
    END IF;
    IF operation_row.state = 'partial_failed' AND
       (actual_failed = 0 OR actual_failed = actual_items OR actual_cancelled <> 0) THEN
        RAISE EXCEPTION 'cache operation integrity violation: partial failure aggregate mismatch';
    END IF;
    IF operation_row.state = 'cancelled' AND (
        actual_cancelled = 0 OR operation_row.cancel_requested_at IS NULL OR
        NOT EXISTS (
            SELECT 1 FROM cache_operation_commands command
            JOIN audit_events event
              ON event.scope_id = command.scope_id
             AND event.action = 'cache.operation.cancel'
             AND event.resource_type = 'cache_operation'
             AND event.resource_id = command.operation_id::text
             AND event.actor_user_id = command.actor_user_id AND event.result = 'success'
            WHERE command.scope_id = operation_row.scope_id
              AND command.operation_id = operation_row.id AND command.command = 'cancel'
              AND command.completed_at IS NOT NULL
              AND event.payload->>'command_id' = command.id::text
        )
    ) THEN
        RAISE EXCEPTION 'cache operation integrity violation: cancellation support missing';
    END IF;
    IF operation_row.state <> 'cancelled' AND actual_cancelled <> 0 THEN
        RAISE EXCEPTION 'cache operation integrity violation: unexpected cancelled projection';
    END IF;
    IF operation_row.state = 'queued' AND EXISTS (
        SELECT 1 FROM cache_operation_nodes node
        WHERE node.operation_id = operation_row.id AND node.state = 'running'
    ) THEN
        RAISE EXCEPTION 'cache operation integrity violation: queued operation has running node';
    END IF;
    IF operation_row.state = 'queued' AND NOT EXISTS (
        SELECT 1 FROM cache_operation_nodes node
        WHERE node.operation_id = operation_row.id AND node.state = 'queued'
    ) THEN
        RAISE EXCEPTION 'cache operation integrity violation: queued operation has no queued node';
    END IF;
    IF operation_row.state = 'running' AND NOT EXISTS (
        SELECT 1 FROM cache_operation_nodes node
        WHERE node.operation_id = operation_row.id AND node.state IN ('queued','running')
    ) THEN
        RAISE EXCEPTION 'cache operation integrity violation: running operation has no pending node';
    END IF;
    IF operation_row.state = 'queued' AND EXISTS (
        SELECT 1 FROM cache_operation_node_attempts attempt
        WHERE attempt.operation_id = operation_row.id
    ) AND NOT EXISTS (
        SELECT 1 FROM cache_operation_commands command
        JOIN audit_events event
          ON event.scope_id = command.scope_id
         AND event.actor_user_id = command.actor_user_id
         AND event.action = 'cache.operation.retry'
         AND event.resource_type = 'cache_operation'
         AND event.resource_id = command.operation_id::text AND event.result = 'success'
        WHERE command.scope_id = operation_row.scope_id
          AND command.operation_id = operation_row.id AND command.command = 'retry'
          AND command.completed_at IS NOT NULL
          AND event.payload->>'command_id' = command.id::text
    ) THEN
        RAISE EXCEPTION 'cache operation integrity violation: retry support missing';
    END IF;
    RETURN NULL;
END;
$$;
