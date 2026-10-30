LOCK TABLE access_scopes IN ACCESS EXCLUSIVE MODE;
LOCK TABLE sites IN ACCESS EXCLUSIVE MODE;
LOCK TABLE dns_reconcile_provider_reports IN ACCESS EXCLUSIVE MODE;
LOCK TABLE dns_reconcile_propagation_attempts IN ACCESS EXCLUSIVE MODE;
LOCK TABLE dns_reconcile_task_events IN ACCESS EXCLUSIVE MODE;
LOCK TABLE dns_reconcile_cancel_facts IN ACCESS EXCLUSIVE MODE;
LOCK TABLE dns_reconcile_commit_facts IN ACCESS EXCLUSIVE MODE;
LOCK TABLE dns_reconcile_operations IN ACCESS EXCLUSIVE MODE;
LOCK TABLE dns_reconcile_tasks IN ACCESS EXCLUSIVE MODE;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM dns_reconcile_tasks)
       OR EXISTS (SELECT 1 FROM dns_reconcile_operations)
       OR EXISTS (SELECT 1 FROM dns_reconcile_provider_reports)
       OR EXISTS (SELECT 1 FROM dns_reconcile_propagation_attempts)
       OR EXISTS (SELECT 1 FROM dns_reconcile_task_events)
       OR EXISTS (SELECT 1 FROM dns_reconcile_cancel_facts)
       OR EXISTS (SELECT 1 FROM dns_reconcile_commit_facts) THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'cannot roll back DNS reconcile migration while facts exist';
    END IF;
END;
$$;

DROP TRIGGER dns_reconcile_commit_facts_no_truncate_076 ON dns_reconcile_commit_facts;
DROP TRIGGER dns_reconcile_cancel_facts_no_truncate_076 ON dns_reconcile_cancel_facts;
DROP TRIGGER dns_reconcile_task_events_no_truncate_076 ON dns_reconcile_task_events;
DROP TRIGGER dns_reconcile_propagation_no_truncate_076 ON dns_reconcile_propagation_attempts;
DROP TRIGGER dns_reconcile_provider_reports_no_truncate_076 ON dns_reconcile_provider_reports;
DROP TRIGGER dns_reconcile_operations_no_truncate_076 ON dns_reconcile_operations;
DROP TRIGGER dns_reconcile_tasks_no_truncate_076 ON dns_reconcile_tasks;
DROP TRIGGER dns_reconcile_commit_facts_append_only_076 ON dns_reconcile_commit_facts;
DROP TRIGGER dns_reconcile_cancel_facts_append_only_076 ON dns_reconcile_cancel_facts;
DROP TRIGGER dns_reconcile_task_events_append_only_076 ON dns_reconcile_task_events;
DROP TRIGGER dns_reconcile_propagation_append_only_076 ON dns_reconcile_propagation_attempts;
DROP TRIGGER dns_reconcile_provider_reports_append_only_076 ON dns_reconcile_provider_reports;
DROP TRIGGER dns_reconcile_operations_append_only_076 ON dns_reconcile_operations;
DROP TRIGGER dns_reconcile_tasks_append_only_076 ON dns_reconcile_tasks;
DROP TRIGGER dns_reconcile_commit_facts_insert_validated_076 ON dns_reconcile_commit_facts;
DROP TRIGGER dns_reconcile_cancel_facts_insert_validated_076 ON dns_reconcile_cancel_facts;
DROP TRIGGER dns_reconcile_task_events_insert_validated_076 ON dns_reconcile_task_events;
DROP TRIGGER dns_reconcile_propagation_insert_validated_076 ON dns_reconcile_propagation_attempts;
DROP TRIGGER dns_reconcile_provider_reports_insert_validated_076 ON dns_reconcile_provider_reports;
DROP TRIGGER dns_reconcile_tasks_insert_validated_076 ON dns_reconcile_tasks;

DROP FUNCTION validate_dns_reconcile_commit_fact_076();
DROP FUNCTION validate_dns_reconcile_cancel_fact_076();
DROP FUNCTION validate_dns_reconcile_task_event_076();
DROP FUNCTION validate_dns_reconcile_propagation_076();
DROP FUNCTION validate_dns_reconcile_provider_report_076();
DROP FUNCTION assert_dns_reconcile_live_claim_076(uuid,uuid,integer,uuid,text,timestamptz);
DROP FUNCTION validate_dns_reconcile_task_076();
DROP FUNCTION protect_dns_reconcile_fact_076();

DROP TABLE dns_reconcile_cancel_facts;
DROP TABLE dns_reconcile_commit_facts;
DROP TABLE dns_reconcile_task_events;
DROP TABLE dns_reconcile_propagation_attempts;
DROP TABLE dns_reconcile_provider_reports;
DROP TABLE dns_reconcile_operations;
DROP TABLE dns_reconcile_tasks;

DROP INDEX sites_scope_id_id_076_idx;
DROP INDEX access_scopes_id_tenant_076_idx;
