ALTER TABLE l4_session_facts_v1 DROP COLUMN IF EXISTS checkpointed_bytes_down;

ALTER TABLE l4_session_facts_v1 DROP COLUMN IF EXISTS checkpointed_bytes_up;

DROP TABLE IF EXISTS l4_usage_checkpoints_v1 SYNC;
