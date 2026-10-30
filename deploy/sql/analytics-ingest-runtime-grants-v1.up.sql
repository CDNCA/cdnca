BEGIN;
SET LOCAL lock_timeout = '5s';
GRANT EXECUTE ON FUNCTION
    analytics_ingest_mark_prepared_098(uuid,numeric,bytea,timestamptz),
    analytics_ingest_mark_broker_ack_observed_098(uuid,numeric,bytea,timestamptz),
    analytics_history_schedule_recovery_098(uuid,text,timestamptz),
    analytics_history_claim_recovery_098(uuid,text,uuid,timestamptz,timestamptz),
    analytics_history_reconcile_recovery_098(uuid,uuid,numeric,numeric,timestamptz),
    analytics_history_complete_recovery_098(uuid,uuid,timestamptz)
TO cdnca_control_app;
COMMIT;
