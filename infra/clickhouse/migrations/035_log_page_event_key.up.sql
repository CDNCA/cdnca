-- The log list resolves its candidates' versions anywhere in the
-- retention (an event's occurred_at may change between versions), so
-- selected_rows tests every index row of the scope against the candidate set.
-- event_id is a ~68-byte string; the page tests a 16-byte sipHash128 key
-- instead (10M rows: 152 MiB against 657 MiB, and a set a fifth the size). A
-- clash between two event IDs (~2^-128, as accepted for 030's digests) would
-- add the other event to the candidates.
-- MATERIALIZE COLUMN is a background mutation; parts it has not reached yet
-- compute the key from event_id when read, with the same result.
ALTER TABLE access_event_query_index_state_v1
    ADD COLUMN IF NOT EXISTS event_key UInt128 MATERIALIZED reinterpretAsUInt128(sipHash128(event_id));

ALTER TABLE security_event_query_index_state_v1
    ADD COLUMN IF NOT EXISTS event_key UInt128 MATERIALIZED reinterpretAsUInt128(sipHash128(event_id));

ALTER TABLE access_event_query_index_state_v1 MATERIALIZE COLUMN event_key;

ALTER TABLE security_event_query_index_state_v1 MATERIALIZE COLUMN event_key;
