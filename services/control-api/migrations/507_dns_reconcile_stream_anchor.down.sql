-- 507（r136 l4-s6）回退：存在以转发为锚的 DNS 任务/认领/CNAME 事实时拒绝（507 前无法表达）。
LOCK TABLE schema_migrations, dns_reconcile_tasks, dns_reconcile_provider_mutation_claims, cname_allocation_targets,
    cname_allocation_requests, cname_record_retirements, dns_cname_retargets, l4_forwards IN ACCESS EXCLUSIVE MODE;

DO $migration_507_down$
BEGIN
    IF (SELECT count(*) FROM schema_migrations) <> 507 OR
       (SELECT max(version) FROM schema_migrations) <> 507 OR NOT EXISTS (
        SELECT 1 FROM schema_migrations WHERE version=507 AND
        migration_id='507_dns_reconcile_stream_anchor' AND
        integrity_state='verified' AND metadata_recorded_at IS NOT NULL AND applied_at IS NOT NULL
       ) THEN
        RAISE EXCEPTION 'migration 507 down requires the exact verified migration head' USING ERRCODE='P5071';
    END IF;
    IF EXISTS (SELECT 1 FROM dns_reconcile_tasks WHERE site_id IS NULL) OR
       EXISTS (SELECT 1 FROM dns_reconcile_provider_mutation_claims WHERE site_id IS NULL) OR
       EXISTS (SELECT 1 FROM cname_allocation_targets WHERE site_id IS NULL) OR
       EXISTS (SELECT 1 FROM cname_allocation_requests WHERE site_id IS NULL) OR
       EXISTS (SELECT 1 FROM cname_record_retirements WHERE site_id IS NULL) OR
       EXISTS (SELECT 1 FROM dns_cname_retargets WHERE site_id IS NULL) THEN
        RAISE EXCEPTION 'retain stream-anchored DNS facts during binary rollback' USING ERRCODE='P5072';
    END IF;
END;
$migration_507_down$;

DROP TRIGGER l4_forwards_provider_mutation_claim_guard_507 ON l4_forwards;
DROP FUNCTION block_dns_stream_claimed_authority_mutation_507();
CREATE OR REPLACE FUNCTION validate_dns_reconcile_cancel_fact_076()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    task_site_id uuid;
    cancellation record;
BEGIN
    SELECT site_id INTO task_site_id FROM dns_reconcile_tasks
    WHERE tenant_id=NEW.tenant_id AND job_id=NEW.job_id FOR UPDATE;
    IF NOT FOUND OR task_site_id <> NEW.site_id THEN
        RAISE EXCEPTION USING ERRCODE='55000', MESSAGE='DNS cancellation does not match task';
    END IF;
    SELECT source,status,occurred_at INTO cancellation FROM dns_reconcile_task_events
    WHERE tenant_id=NEW.tenant_id AND job_id=NEW.job_id
      AND event_sequence=NEW.event_sequence;
    IF NOT FOUND OR cancellation.source <> 'control' OR cancellation.status <> 'cancelled' OR
       cancellation.occurred_at <> NEW.created_at THEN
        RAISE EXCEPTION USING ERRCODE='55000', MESSAGE='DNS cancellation fact is not canonical';
    END IF;
    RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION dns_reconcile_background_job_cancel_094(
    previous_job background_jobs,
    cancelled_job background_jobs
)
RETURNS boolean
LANGUAGE sql
STABLE
PARALLEL UNSAFE
AS $$
    SELECT previous_job.kind='dns_reconcile' AND
        previous_job.state IN ('queued','running') AND
        previous_job.cancel_requested_at IS NULL AND cancelled_job.state='cancelled' AND
        cancelled_job.attempt=previous_job.attempt AND
        cancelled_job.max_attempts=previous_job.max_attempts AND
        cancelled_job.total_count=previous_job.total_count AND
        cancelled_job.completed_count=previous_job.total_count AND
        cancelled_job.succeeded_count=previous_job.succeeded_count AND
        cancelled_job.failed_count=previous_job.failed_count AND
        cancelled_job.cancelled_count=previous_job.cancelled_count+
            (previous_job.total_count-previous_job.completed_count) AND
        cancelled_job.lease_id IS NULL AND cancelled_job.lease_owner IS NULL AND
        cancelled_job.lease_expires_at IS NULL AND cancelled_job.claimable_at IS NULL AND
        cancelled_job.last_error_code='cancelled' AND cancelled_job.completed_at IS NOT NULL AND
        cancelled_job.cancel_requested_at=cancelled_job.completed_at AND
        cancelled_job.updated_at=cancelled_job.completed_at AND
        ROW(cancelled_job.id,cancelled_job.tenant_id,cancelled_job.kind,cancelled_job.subject,
            cancelled_job.idempotency_key,cancelled_job.request_digest,cancelled_job.request_id,
            cancelled_job.trace_id,cancelled_job.created_at,cancelled_job.started_at)
        IS NOT DISTINCT FROM
        ROW(previous_job.id,previous_job.tenant_id,previous_job.kind,previous_job.subject,
            previous_job.idempotency_key,previous_job.request_digest,previous_job.request_id,
            previous_job.trace_id,previous_job.created_at,previous_job.started_at) AND EXISTS (
            SELECT 1
            FROM dns_reconcile_cancel_facts fact
            JOIN dns_reconcile_tasks task
              ON task.tenant_id=fact.tenant_id AND task.job_id=fact.job_id
            JOIN dns_reconcile_task_events event
              ON event.tenant_id=fact.tenant_id AND event.job_id=fact.job_id
             AND event.event_sequence=fact.event_sequence
            WHERE fact.tenant_id=previous_job.tenant_id AND fact.job_id=previous_job.id
              AND fact.job_transition_xact_id=pg_current_xact_id()
              AND fact.site_id=task.site_id
              AND fact.expected_task_revision=fact.event_sequence
              AND event.source='control' AND event.status='cancelled'
              AND event.error_class='cancelled' AND event.error_code='cancelled'
              AND event.occurred_at=fact.created_at
              AND cancelled_job.cancel_requested_at=fact.created_at
              AND NOT EXISTS (
                  SELECT 1 FROM dns_reconcile_task_events later
                  WHERE later.tenant_id=fact.tenant_id AND later.job_id=fact.job_id
                    AND later.event_sequence>fact.event_sequence
              )
        )
$$;

CREATE OR REPLACE FUNCTION dns_reconcile_cancel_final_094(cancelled_job background_jobs)
RETURNS boolean
LANGUAGE sql
STABLE
PARALLEL UNSAFE
AS $$
    SELECT cancelled_job.kind='dns_reconcile' AND cancelled_job.state='cancelled' AND
        cancelled_job.job_command_operation='dns_cancel' AND
        cancelled_job.job_command_xact_id=pg_current_xact_id() AND
        cancelled_job.cancel_requested_at IS NOT NULL AND
        cancelled_job.cancel_requested_at=cancelled_job.completed_at AND
        cancelled_job.cancel_requested_at=cancelled_job.updated_at AND
        cancelled_job.lease_id IS NULL AND cancelled_job.lease_owner IS NULL AND
        cancelled_job.lease_expires_at IS NULL AND cancelled_job.claimable_at IS NULL AND
        cancelled_job.last_error_code='cancelled' AND EXISTS (
            SELECT 1
            FROM dns_reconcile_cancel_facts fact
            JOIN dns_reconcile_tasks task
              ON task.tenant_id=fact.tenant_id AND task.job_id=fact.job_id
            JOIN dns_reconcile_task_events event
              ON event.tenant_id=fact.tenant_id AND event.job_id=fact.job_id
             AND event.event_sequence=fact.event_sequence
            WHERE fact.tenant_id=cancelled_job.tenant_id AND fact.job_id=cancelled_job.id
              AND fact.job_transition_xact_id=cancelled_job.job_command_xact_id
              AND fact.site_id=task.site_id
              AND fact.expected_task_revision=fact.event_sequence
              AND event.source='control' AND event.status='cancelled'
              AND event.error_class='cancelled' AND event.error_code='cancelled'
              AND event.occurred_at=fact.created_at
              AND cancelled_job.cancel_requested_at=fact.created_at
              AND NOT EXISTS (
                  SELECT 1 FROM dns_reconcile_task_events later
                  WHERE later.tenant_id=fact.tenant_id AND later.job_id=fact.job_id
                    AND later.event_sequence>fact.event_sequence
              )
        ) AND EXISTS (
            SELECT 1
            FROM (
                SELECT count(*)::integer AS total,
                    count(*) FILTER (WHERE state='succeeded')::integer AS succeeded,
                    count(*) FILTER (WHERE state='failed')::integer AS failed,
                    count(*) FILTER (WHERE state='cancelled')::integer AS cancelled,
                    count(*) FILTER (WHERE state='pending')::integer AS pending
                FROM background_job_items item
                WHERE item.tenant_id=cancelled_job.tenant_id AND item.job_id=cancelled_job.id
            ) items
            WHERE items.pending=0 AND cancelled_job.total_count=items.total
              AND cancelled_job.completed_count=items.total
              AND cancelled_job.succeeded_count=items.succeeded
              AND cancelled_job.failed_count=items.failed
              AND cancelled_job.cancelled_count=items.cancelled
        )
$$;

CREATE OR REPLACE FUNCTION bind_dns_reconcile_task_site_089()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.provider_mutation_site_revision IS NOT NULL OR
       NEW.provider_mutation_site_config_digest IS NOT NULL THEN
        RAISE EXCEPTION 'DNS reconcile task site authority must be database bound'
            USING ERRCODE = 'P8902';
    END IF;
    SELECT site.revision,dns_reconcile_site_config_digest_089(site)
    INTO NEW.provider_mutation_site_revision,NEW.provider_mutation_site_config_digest
    FROM sites site
    WHERE site.scope_id=NEW.tenant_scope_id AND site.id=NEW.site_id AND site.deleted_at IS NULL
    FOR KEY SHARE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'DNS reconcile task site authority is unavailable'
            USING ERRCODE = 'P8902';
    END IF;
    RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION protect_dns_reconcile_provider_mutation_claim_089()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    valid_binding boolean;
    takeover boolean;
    renewal boolean;
    renewal_lease timestamptz;
BEGIN
    IF TG_OP IN ('DELETE','TRUNCATE') THEN
        RAISE EXCEPTION 'DNS provider mutation claim facts cannot be deleted or truncated'
            USING ERRCODE = 'P8902';
    END IF;

    SELECT EXISTS (
        SELECT 1
        FROM dns_reconcile_operations operation
        JOIN dns_reconcile_tasks task
          ON task.tenant_id=operation.tenant_id AND task.job_id=operation.job_id
        JOIN access_scopes scope
          ON scope.id=task.tenant_scope_id AND scope.kind='tenant' AND scope.tenant_id=task.tenant_id
        JOIN sites site
          ON site.scope_id=task.tenant_scope_id AND site.id=task.site_id AND site.deleted_at IS NULL
        JOIN dns_zones zone
          ON zone.scope_id=task.tenant_scope_id AND zone.id=task.zone_id
        JOIN dns_providers provider
          ON provider.scope_id=zone.scope_id AND provider.id=zone.provider_id
        WHERE operation.tenant_id=NEW.tenant_id
          AND operation.client_request_id=NEW.client_request_id
          AND operation.job_id=NEW.job_id
          AND operation.phase=NEW.phase
          AND operation.ordinal=NEW.operation_ordinal
          AND task.site_id=NEW.site_id
          AND task.zone_id=NEW.zone_id
          AND provider.id=NEW.provider_id
          AND task.provider_mutation_site_revision=NEW.expected_site_revision
          AND task.provider_mutation_site_config_digest=NEW.site_config_digest
          AND site.revision=NEW.expected_site_revision
          AND zone.revision=NEW.expected_zone_revision
          AND provider.revision=NEW.expected_provider_revision
          AND dns_reconcile_operation_digest_089(operation.operation)=NEW.operation_digest
          AND dns_reconcile_site_config_digest_089(site)=NEW.site_config_digest
          AND dns_reconcile_authority_digest_089(task.tenant_scope_id,site,zone,provider)=NEW.authority_digest
          AND dns_reconcile_provider_config_digest_089(zone,provider)=NEW.provider_config_digest
          AND dns_reconcile_credential_digest_089(provider.credential_key_id,provider.credential_ciphertext)=NEW.credential_digest
    ) INTO valid_binding;
    IF NOT valid_binding THEN
        RAISE EXCEPTION 'invalid DNS provider mutation claim identity or digest'
            USING ERRCODE = 'P8902';
    END IF;

    IF TG_OP = 'INSERT' THEN
        IF NEW.state <> 'claimed' OR NEW.claimed_at IS DISTINCT FROM statement_timestamp() OR
           NEW.lease_expires_at IS DISTINCT FROM statement_timestamp()+interval '2 minutes' OR
           NEW.recovery_not_before IS NOT NULL OR NEW.provider_record_id IS NOT NULL OR
           NEW.final_zone_revision IS NOT NULL OR NEW.finalized_at IS NOT NULL THEN
            RAISE EXCEPTION 'invalid initial DNS provider mutation claim'
                USING ERRCODE = 'P8902';
        END IF;
        RETURN NEW;
    END IF;

    IF ROW(NEW.tenant_id,NEW.client_request_id,NEW.job_id,NEW.phase,NEW.operation_ordinal,
           NEW.site_id,NEW.zone_id,NEW.provider_id,NEW.expected_zone_revision,
           NEW.expected_provider_revision,NEW.expected_site_revision,NEW.site_config_digest,
           NEW.operation_digest,NEW.authority_digest,NEW.provider_config_digest,NEW.credential_digest)
       IS DISTINCT FROM
       ROW(OLD.tenant_id,OLD.client_request_id,OLD.job_id,OLD.phase,OLD.operation_ordinal,
           OLD.site_id,OLD.zone_id,OLD.provider_id,OLD.expected_zone_revision,
           OLD.expected_provider_revision,OLD.expected_site_revision,OLD.site_config_digest,
           OLD.operation_digest,OLD.authority_digest,OLD.provider_config_digest,OLD.credential_digest) THEN
        RAISE EXCEPTION 'DNS provider mutation claim identity and digests are immutable'
            USING ERRCODE = 'P8902';
    END IF;

    IF NEW.provider_request_id IS DISTINCT FROM OLD.provider_request_id THEN
        RAISE EXCEPTION 'DNS provider mutation claim provider request id is immutable'
            USING ERRCODE = 'P8902';
    END IF;

    IF OLD.recovery_not_before IS NOT NULL AND
       NEW.recovery_not_before IS DISTINCT FROM OLD.recovery_not_before THEN
        RAISE EXCEPTION 'DNS provider mutation recovery time is immutable'
            USING ERRCODE = 'P8902';
    END IF;

    renewal_lease := GREATEST(OLD.lease_expires_at,statement_timestamp()+interval '17 minutes 30 seconds');
    renewal := OLD.state='claimed' AND NEW.state='claimed' AND NEW.claim_id=OLD.claim_id AND
        NEW.claimed_at=OLD.claimed_at AND OLD.lease_expires_at > statement_timestamp() AND
        NEW.lease_expires_at=renewal_lease AND NEW.provider_record_id IS NULL AND
        NEW.final_zone_revision IS NULL AND NEW.finalized_at IS NULL AND
        NEW.recovery_not_before IS NOT DISTINCT FROM OLD.recovery_not_before;
    IF renewal THEN
        RETURN NEW;
    END IF;

    takeover := OLD.state IN ('claimed','uncertain','not_applied') AND
        NEW.state = CASE WHEN OLD.state='not_applied' THEN 'claimed' ELSE OLD.state END AND
        OLD.lease_expires_at <= statement_timestamp() AND NEW.claim_id <> OLD.claim_id AND
        NEW.lease_expires_at=statement_timestamp()+interval '2 minutes' AND
        NEW.claimed_at=statement_timestamp() AND
        ((OLD.state='not_applied' AND NEW.recovery_not_before IS NULL) OR
         (OLD.state<>'not_applied' AND NEW.recovery_not_before IS NOT DISTINCT FROM OLD.recovery_not_before));
    IF takeover THEN
        IF NEW.state='claimed' AND (NEW.provider_record_id IS NOT NULL OR
           NEW.final_zone_revision IS NOT NULL OR NEW.finalized_at IS NOT NULL) THEN
            RAISE EXCEPTION 'invalid DNS provider mutation claim takeover'
                USING ERRCODE = 'P8902';
        END IF;
        RETURN NEW;
    END IF;

    IF NEW.claim_id <> OLD.claim_id OR NEW.claimed_at <> OLD.claimed_at OR
       NEW.lease_expires_at > OLD.lease_expires_at THEN
        RAISE EXCEPTION 'invalid DNS provider mutation claim token or lease transition'
            USING ERRCODE = 'P8902';
    END IF;
    IF OLD.state='claimed' AND NEW.state='uncertain' THEN
        IF NEW.recovery_not_before IS NOT NULL OR NEW.provider_request_id IS NULL OR
           NEW.provider_record_id IS NOT NULL OR NEW.final_zone_revision IS NOT NULL OR
           NEW.finalized_at IS NOT NULL THEN
            RAISE EXCEPTION 'DNS provider mutation recovery time must be database assigned'
                USING ERRCODE = 'P8902';
        END IF;
        NEW.recovery_not_before := clock_timestamp() + interval '2 minutes';
        RETURN NEW;
    END IF;
    IF OLD.state='uncertain' AND NEW.state='not_applied' AND
       NOT (OLD.recovery_not_before<=clock_timestamp()) THEN
        RAISE EXCEPTION 'DNS provider mutation recovery window has not elapsed'
            USING ERRCODE = 'P8902';
    END IF;
    IF OLD.state IN ('claimed','uncertain') AND NEW.state='succeeded' AND
       NEW.recovery_not_before IS NOT DISTINCT FROM OLD.recovery_not_before AND
       NEW.provider_request_id IS NOT NULL AND NEW.provider_record_id IS NOT NULL AND
       NEW.final_zone_revision=NEW.expected_zone_revision+1 AND
       NEW.finalized_at>=statement_timestamp() AND NEW.finalized_at<=clock_timestamp() THEN
        RETURN NEW;
    END IF;
    IF OLD.state IN ('claimed','uncertain') AND NEW.state IN ('not_applied','conflict') AND
       NEW.recovery_not_before IS NOT DISTINCT FROM OLD.recovery_not_before AND
       NEW.provider_record_id IS NULL AND NEW.final_zone_revision=NEW.expected_zone_revision AND
       NEW.finalized_at>=statement_timestamp() AND NEW.finalized_at<=clock_timestamp() THEN
        RETURN NEW;
    END IF;
    RAISE EXCEPTION 'invalid DNS provider mutation claim transition or finalize'
        USING ERRCODE = 'P8902';
END;
$$;

CREATE OR REPLACE FUNCTION protect_dns_reconcile_provider_recovery_continuation_089()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    valid_grant boolean;
BEGIN
    IF TG_OP IN ('DELETE','TRUNCATE') THEN
        RAISE EXCEPTION 'DNS provider recovery continuation facts cannot be deleted or truncated'
            USING ERRCODE = 'P8902';
    END IF;
    IF TG_OP='UPDATE' THEN
        IF ROW(NEW.tenant_id,NEW.client_request_id,NEW.claim_id,NEW.job_id,
               NEW.continuation_attempt,NEW.previous_item_attempt,NEW.previous_item_sequence,
               NEW.result_attempts,NEW.event_sequence,NEW.recovery_event_sequence,
               NEW.recovery_result_digest,NEW.granted_at)
           IS DISTINCT FROM
           ROW(OLD.tenant_id,OLD.client_request_id,OLD.claim_id,OLD.job_id,
               OLD.continuation_attempt,OLD.previous_item_attempt,OLD.previous_item_sequence,
               OLD.result_attempts,OLD.event_sequence,OLD.recovery_event_sequence,
               OLD.recovery_result_digest,OLD.granted_at) OR
           OLD.consumed_at IS NOT NULL OR NEW.consumed_at IS NULL THEN
            RAISE EXCEPTION 'DNS provider recovery continuation fact is immutable'
                USING ERRCODE = 'P8902';
        END IF;
        IF NOT EXISTS (
            SELECT 1 FROM background_jobs job
            JOIN background_job_items item
              ON item.tenant_id=job.tenant_id AND item.job_id=job.id AND item.item_id='reconcile'
            WHERE job.tenant_id=OLD.tenant_id AND job.id=OLD.job_id
              AND job.kind='dns_reconcile' AND job.state='queued'
              AND job.attempt=OLD.continuation_attempt-1
              AND job.max_attempts=OLD.continuation_attempt
              AND job.claimable_at=OLD.granted_at AND job.updated_at=OLD.granted_at
              AND item.state='pending' AND item.attempt=OLD.previous_item_attempt
              AND item.sequence=OLD.previous_item_sequence
        ) THEN
            RAISE EXCEPTION 'DNS provider recovery continuation was not atomically applied'
                USING ERRCODE = 'P8902';
        END IF;
        IF NOT EXISTS (
            SELECT 1
            FROM dns_reconcile_provider_mutation_claims claim
            JOIN dns_reconcile_operations operation
              ON operation.tenant_id=claim.tenant_id AND operation.job_id=claim.job_id
             AND operation.phase=claim.phase AND operation.ordinal=claim.operation_ordinal
            JOIN dns_reconcile_task_events previous_event
              ON previous_event.tenant_id=claim.tenant_id AND previous_event.job_id=claim.job_id
             AND previous_event.event_sequence=OLD.event_sequence
            JOIN dns_reconcile_task_events recovery_event
              ON recovery_event.tenant_id=claim.tenant_id AND recovery_event.job_id=claim.job_id
             AND recovery_event.event_sequence=OLD.recovery_event_sequence
            WHERE claim.tenant_id=OLD.tenant_id AND claim.client_request_id=OLD.client_request_id
              AND claim.claim_id=OLD.claim_id AND claim.job_id=OLD.job_id AND claim.phase='apply'
              AND OLD.recovery_event_sequence=OLD.event_sequence+1
              AND recovery_event.source='control' AND recovery_event.status='applying'
              AND COALESCE(recovery_event.error_class,'')='' AND recovery_event.error_code IS NULL
              AND sha256(convert_to(recovery_event.result_snapshot::text,'UTF8'))=OLD.recovery_result_digest
              AND recovery_event.result_snapshot->>'TenantID'=claim.tenant_id::text
              AND recovery_event.result_snapshot->>'SiteID'=claim.site_id::text
              AND recovery_event.result_snapshot->>'ZoneID'=claim.zone_id::text
              AND recovery_event.result_snapshot->>'Status'='applying'
              AND recovery_event.result_snapshot->>'ErrorClass'=''
              AND recovery_event.result_snapshot->>'ErrorCode'=''
              AND recovery_event.result_snapshot->'CompensationPlan'='[]'::jsonb
              AND (recovery_event.result_snapshot-'UpdatedAt'-'Status'-'ErrorClass'-'ErrorCode'-'CompensationPlan'-'Operations')=
                  (previous_event.result_snapshot-'UpdatedAt'-'Status'-'ErrorClass'-'ErrorCode'-'CompensationPlan'-'Operations')
              AND ((recovery_event.result_snapshot->'Operations')-(claim.operation_ordinal-1))=
                  ((previous_event.result_snapshot->'Operations')-(claim.operation_ordinal-1))
              AND ((recovery_event.result_snapshot->'Operations'->(claim.operation_ordinal-1))-
                   'Status'-'ErrorClass'-'ErrorCode')=
                  ((previous_event.result_snapshot->'Operations'->(claim.operation_ordinal-1))-
                   'Status'-'ErrorClass'-'ErrorCode')
              AND recovery_event.result_snapshot->'Operations'->(claim.operation_ordinal-1)->>'ClientRequestID'=
                  claim.client_request_id
              AND recovery_event.result_snapshot->'Operations'->(claim.operation_ordinal-1)->'Operation'=
                  operation.operation
              AND recovery_event.result_snapshot->'Operations'->(claim.operation_ordinal-1)->>'Status'='planned'
              AND recovery_event.result_snapshot->'Operations'->(claim.operation_ordinal-1)->>'ErrorClass'=''
              AND recovery_event.result_snapshot->'Operations'->(claim.operation_ordinal-1)->>'ErrorCode'=''
              AND recovery_event.result_snapshot->'Operations'->(claim.operation_ordinal-1)->'Attempts'=
                  to_jsonb(OLD.result_attempts)
        ) THEN
            RAISE EXCEPTION 'DNS provider recovery continuation event is invalid'
                USING ERRCODE = 'P8902';
        END IF;
        NEW.consumed_at := clock_timestamp();
        RETURN NEW;
    END IF;
	IF EXISTS (
		SELECT 1 FROM dns_reconcile_provider_recovery_continuations continuation
		WHERE continuation.tenant_id=NEW.tenant_id AND
		      (continuation.job_id=NEW.job_id OR
		       (continuation.client_request_id=NEW.client_request_id AND continuation.claim_id=NEW.claim_id))
	) THEN
		RAISE EXCEPTION 'DNS provider recovery continuation grant already exists'
			USING ERRCODE = 'P8902';
	END IF;

    SELECT EXISTS (
        SELECT 1
        FROM dns_reconcile_provider_mutation_claims claim
        JOIN background_jobs job
          ON job.tenant_id=claim.tenant_id AND job.id=claim.job_id
        JOIN background_job_items item
          ON item.tenant_id=job.tenant_id AND item.job_id=job.id AND item.item_id='reconcile'
        JOIN dns_zones zone ON zone.id=claim.zone_id
        JOIN LATERAL (
            SELECT event.event_sequence,event.error_code,event.result_snapshot
            FROM dns_reconcile_task_events event
            WHERE event.tenant_id=claim.tenant_id AND event.job_id=claim.job_id
            ORDER BY event.event_sequence DESC LIMIT 1
        ) latest ON true
        WHERE claim.tenant_id=NEW.tenant_id AND claim.client_request_id=NEW.client_request_id
          AND claim.claim_id=NEW.claim_id AND claim.job_id=NEW.job_id AND claim.phase='apply'
          AND claim.state IN ('succeeded','not_applied','conflict')
          AND zone.revision=claim.final_zone_revision
          AND job.kind='dns_reconcile' AND job.state IN ('failed','partial_failed')
          AND job.attempt=job.max_attempts AND job.attempt>=1
          AND job.cancel_requested_at IS NULL
          AND NEW.continuation_attempt=job.attempt+1 AND NEW.continuation_attempt<=1001
          AND NEW.recovery_event_sequence=NEW.event_sequence+1
          AND item.state='failed' AND item.attempt=NEW.previous_item_attempt
          AND item.sequence=NEW.previous_item_sequence
          AND latest.event_sequence=NEW.event_sequence
          AND latest.error_code IN ('provider_recovery_pending','provider_recovery_persistence_failed')
          AND latest.result_snapshot -> 'Operations' ->
              (claim.operation_ordinal-1) ->> 'ClientRequestID'=claim.client_request_id
          AND latest.result_snapshot -> 'Operations' ->
              (claim.operation_ordinal-1) ->> 'Status'='transient_failed'
          AND latest.result_snapshot -> 'Operations' ->
              (claim.operation_ordinal-1) ->> 'ErrorCode'=latest.error_code
          AND latest.result_snapshot -> 'Operations' ->
              (claim.operation_ordinal-1) -> 'Attempts'=to_jsonb(NEW.result_attempts)
    ) INTO valid_grant;
    IF NOT valid_grant THEN
        RAISE EXCEPTION 'invalid DNS provider recovery continuation grant'
            USING ERRCODE = 'P8902';
    END IF;
    NEW.granted_at := clock_timestamp();
    NEW.consumed_at := NULL;
    RETURN NEW;
END;
$$;

DROP FUNCTION dns_reconcile_anchor_507(uuid,uuid,uuid,dns_zones,dns_providers);
DROP FUNCTION dns_reconcile_stream_config_digest_507(l4_forwards);

DROP TRIGGER dns_cname_retargets_stream_507 ON dns_cname_retargets;
ALTER TABLE dns_cname_retargets DROP CONSTRAINT dns_cname_retargets_anchor_507,
    DROP CONSTRAINT dns_cname_retargets_stream_507_fk, DROP COLUMN stream_id, ALTER COLUMN site_id SET NOT NULL;
ALTER TABLE cname_record_retirements DROP CONSTRAINT cname_record_retirements_anchor_507, ALTER COLUMN site_id SET NOT NULL;
DROP INDEX cname_allocation_requests_stream_507_uidx;
ALTER TABLE cname_allocation_requests DROP CONSTRAINT cname_allocation_requests_anchor_507, ALTER COLUMN site_id SET NOT NULL;
ALTER TABLE cname_allocation_targets DROP CONSTRAINT cname_allocation_targets_anchor_507, ALTER COLUMN site_id SET NOT NULL;
DROP INDEX dns_reconcile_provider_mutation_claims_stream_507_idx;
ALTER TABLE dns_reconcile_provider_mutation_claims DROP CONSTRAINT dns_reconcile_provider_mutation_claims_anchor_507,
    DROP COLUMN stream_id, ALTER COLUMN site_id SET NOT NULL;
DROP INDEX dns_reconcile_tasks_stream_507_idx;
ALTER TABLE dns_reconcile_tasks DROP CONSTRAINT dns_reconcile_tasks_anchor_507,
    DROP CONSTRAINT dns_reconcile_tasks_stream_507_fk, DROP COLUMN stream_id, ALTER COLUMN site_id SET NOT NULL;
